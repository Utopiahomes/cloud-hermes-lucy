"""Run one operator-authorized R1 protected recovery handoff.

This utility is intended for a quarantined, one-off Render job. It replays the
independent authority and cost journals through their exact PostgreSQL recovery
logins, obtains the final writer pauses, finalizes cost recovery, and uses the
offline migration login only for the atomic activation handoff.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import boto3  # type: ignore[import-untyped]
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ProgrammingError

from lucy.authority_recovery import PostgresAuthorityReplayStore
from lucy.cost_recovery import PostgresCostReplayStore
from lucy.db import create_session_factory
from lucy.readiness import R1_SCHEMA_REVISION
from lucy.recovery_coordinator import (
    PostgresRecoveryActivator,
    RecoveryCoordinator,
    RecoveryStreamTarget,
)
from lucy.recovery_journal import (
    RecoveryJournalError,
    RecoveryJournalHeadV1,
    RecoveryStreamBindingV1,
    RecoveryStreamKind,
)
from lucy.recovery_journal_aws import AwsDynamoRecoveryJournal

AUTHORIZATION = "security-v1.3-protected-recovery-handoff"
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_DATABASE_NAME = re.compile(r"lucy(?:_[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class ProtectedRecoveryError(RuntimeError):
    """The protected handoff failed closed while admission remained quarantined."""


@dataclass(frozen=True)
class ProtectedRecoveryConfig:
    migration_url: URL
    authority_recovery_url: URL
    cost_recovery_url: URL
    region: str
    account_id: str
    role_arn: str
    authority_table: str
    cost_table: str
    authority_binding: RecoveryStreamBindingV1
    cost_binding: RecoveryStreamBindingV1
    authority_witness: RecoveryJournalHeadV1
    cost_witness: RecoveryJournalHeadV1
    target_runtime_epoch: UUID
    binding_manifest_digest: str

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> ProtectedRecoveryConfig:
        values = os.environ if environment is None else environment
        if (
            values.get("RENDER") != "true"
            or values.get("LUCY_ENVIRONMENT") != "production"
            or values.get("LUCY_SECURITY_BASELINE") != "v1.3"
        ):
            raise ProtectedRecoveryError("recovery requires the production Render runtime")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise ProtectedRecoveryError("transcript capture must remain disabled")
        if values.get("LUCY_PROTECTED_RECOVERY_AUTHORIZATION") != AUTHORIZATION:
            raise ProtectedRecoveryError("the exact protected recovery authorization is required")
        if values.get("AWS_ACCESS_KEY_ID") or values.get("AWS_SECRET_ACCESS_KEY"):
            raise ProtectedRecoveryError("static AWS credentials are prohibited")

        migration = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        authority_url = _database_url(
            _required(values, "LUCY_AUTHORITY_RECOVERY_DATABASE_URL")
        )
        cost_url = _database_url(_required(values, "LUCY_COST_RECOVERY_DATABASE_URL"))
        if not str(migration.username).endswith("_recovery_activation"):
            raise ProtectedRecoveryError("activation requires its exact temporary login")
        if not str(authority_url.username).endswith("_authority_recovery"):
            raise ProtectedRecoveryError("authority replay requires its exact recovery login")
        if not str(cost_url.username).endswith("_cost_recovery"):
            raise ProtectedRecoveryError("cost replay requires its exact recovery login")
        targets = {
            (url.host, url.port or 5432, url.database)
            for url in (migration, authority_url, cost_url)
        }
        if len(targets) != 1:
            raise ProtectedRecoveryError("recovery database identities target different databases")

        try:
            authority_binding = RecoveryStreamBindingV1.model_validate_json(
                _required(values, "LUCY_AUTHORITY_RECOVERY_STREAM_BINDING_JSON")
            )
            cost_binding = RecoveryStreamBindingV1.model_validate_json(
                _required(values, "LUCY_COST_RECOVERY_STREAM_BINDING_JSON")
            )
            authority_witness = RecoveryJournalHeadV1.model_validate_json(
                _required(values, "LUCY_AUTHORITY_RECOVERY_WITNESS_JSON")
            )
            cost_witness = RecoveryJournalHeadV1.model_validate_json(
                _required(values, "LUCY_COST_RECOVERY_WITNESS_JSON")
            )
            target_epoch = UUID(_required(values, "LUCY_RECOVERY_TARGET_RUNTIME_EPOCH"))
        except (ValidationError, ValueError) as exc:
            raise ProtectedRecoveryError("recovery binding, witness, or epoch is invalid") from exc

        region = _required(values, "AWS_REGION")
        account_id = _required(values, "LUCY_AWS_ACCOUNT_ID")
        role_arn = _required(values, "AWS_ROLE_ARN")
        manifest = _required(values, "LUCY_RECOVERY_BINDING_MANIFEST_DIGEST")
        authority_table = _required(values, "LUCY_AUTHORITY_RECOVERY_JOURNAL_TABLE")
        cost_table = _required(values, "LUCY_COST_RECOVERY_JOURNAL_TABLE")
        if (
            region != "us-east-1"
            or re.fullmatch(r"\d{12}", account_id) is None
            or _DIGEST.fullmatch(manifest) is None
            or authority_table == cost_table
        ):
            raise ProtectedRecoveryError("recovery cloud binding is invalid")
        expected_role_prefix = f"arn:aws:iam::{account_id}:role/"
        bindings = (authority_binding, cost_binding)
        if (
            authority_binding.stream_kind is not RecoveryStreamKind.AUTHORITY
            or cost_binding.stream_kind is not RecoveryStreamKind.COST
            or authority_binding.stream_id == cost_binding.stream_id
            or any(binding.recovery_identity != role_arn for binding in bindings)
            or not role_arn.startswith(expected_role_prefix)
            or any(binding.binding_manifest_digest != manifest for binding in bindings)
            or authority_binding.authority_epoch != cost_binding.authority_epoch
        ):
            raise ProtectedRecoveryError("recovery stream bindings are not jointly isolated")
        _require_witness(authority_witness, authority_binding)
        _require_witness(cost_witness, cost_binding)

        return cls(
            migration_url=migration,
            authority_recovery_url=authority_url,
            cost_recovery_url=cost_url,
            region=region,
            account_id=account_id,
            role_arn=role_arn,
            authority_table=authority_table,
            cost_table=cost_table,
            authority_binding=authority_binding,
            cost_binding=cost_binding,
            authority_witness=authority_witness,
            cost_witness=cost_witness,
            target_runtime_epoch=target_epoch,
            binding_manifest_digest=manifest,
        )


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise ProtectedRecoveryError(f"missing required configuration: {name}")
    return value


def _database_url(raw: str) -> URL:
    try:
        parsed = make_url(raw)
    except Exception as exc:
        raise ProtectedRecoveryError("recovery database URL is invalid") from exc
    if (
        parsed.drivername not in {"postgresql", "postgresql+psycopg"}
        or not parsed.username
        or not parsed.password
        or parsed.host is None
        or _PRIVATE_RENDER_HOST.fullmatch(parsed.host) is None
        or parsed.database is None
        or _DATABASE_NAME.fullmatch(parsed.database) is None
        or parsed.port not in (None, 5432)
    ):
        raise ProtectedRecoveryError("recovery requires a private Render PostgreSQL URL")
    return parsed.set(drivername="postgresql+psycopg").update_query_dict(
        {"sslmode": "require"}
    )


def _require_witness(
    witness: RecoveryJournalHeadV1, binding: RecoveryStreamBindingV1
) -> None:
    if (
        witness.stream_kind is not binding.stream_kind
        or witness.stream_id != binding.stream_id
        or witness.authority_epoch != binding.authority_epoch
        or witness.independent_store_id != binding.independent_store_id
        or witness.binding_manifest_digest != binding.binding_manifest_digest
    ):
        raise ProtectedRecoveryError("recovery witness differs from its immutable binding")


def _verify_actual_role(config: ProtectedRecoveryConfig, identity: Mapping[str, Any]) -> None:
    role_name = config.role_arn.rsplit("/", 1)[-1]
    expected_prefix = f"arn:aws:sts::{config.account_id}:assumed-role/{role_name}/"
    if identity.get("Account") != config.account_id or not str(identity.get("Arn", "")).startswith(
        expected_prefix
    ):
        raise ProtectedRecoveryError("active AWS workload identity differs")


def _verify_database_identity(url: URL, expected_login: str) -> None:
    sessions = create_session_factory(url.render_as_string(hide_password=False))
    with sessions() as session:
        row = session.execute(
            text(
                "SELECT current_user,r.rolcanlogin,r.rolsuper,r.rolinherit,"
                "r.rolcreaterole,r.rolcreatedb,r.rolreplication,r.rolbypassrls,"
                "(SELECT version_num FROM public.alembic_version),"
                "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
                "lucy.capture_boundary_safe_v1(),"
                "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) "
                "FROM pg_catalog.pg_roles r WHERE r.rolname=current_user"
            )
        ).one()
    if tuple(row) != (
        expected_login,
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        R1_SCHEMA_REVISION,
        "quarantined",
        True,
        True,
    ):
        raise ProtectedRecoveryError("recovery database identity or boundary differs")


def _verify_migration_identity(url: URL) -> None:
    """Attest the temporary non-elevated activation principal and exact grants."""

    sessions = create_session_factory(url.render_as_string(hide_password=False))
    with sessions() as session:
        row = session.execute(
            text(
                "SELECT session_user,current_user,r.rolcanlogin,r.rolsuper,r.rolinherit,"
                "r.rolcreaterole,"
                "r.rolcreatedb,r.rolreplication,r.rolbypassrls,"
                "(SELECT n.nspowner::regrole::text FROM pg_namespace n "
                " WHERE n.nspname='lucy'),"
                "(SELECT version_num FROM public.alembic_version),"
                "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
                "lucy.capture_boundary_safe_v1(),"
                "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),"
                "pg_has_role(current_user,'lucy_migration','MEMBER'),"
                "pg_has_role(current_user,'lucy_authority_function_owner','MEMBER'),"
                "pg_has_role(current_user,'lucy_cost_function_owner','MEMBER'),"
                "has_schema_privilege(current_user,'lucy','CREATE'),"
                "has_table_privilege(current_user,'lucy.lifecycle','SELECT'),"
                "has_table_privilege(current_user,'lucy.runtime_admission','SELECT'),"
                "has_column_privilege(current_user,'lucy.runtime_admission','state','UPDATE'),"
                "has_column_privilege(current_user,'lucy.runtime_admission','storage_epoch','UPDATE'),"
                "has_column_privilege(current_user,'lucy.runtime_admission','updated_at','UPDATE'),"
                "has_column_privilege(current_user,'lucy.runtime_admission','singleton','UPDATE'),"
                "has_table_privilege(current_user,'lucy.restored_recovery_heads_v1','SELECT'),"
                "has_column_privilege(current_user,'lucy.restored_recovery_heads_v1','updated_at','UPDATE'),"
                "has_column_privilege(current_user,'lucy.restored_recovery_heads_v1','sequence','UPDATE'),"
                "has_table_privilege(current_user,'lucy.restored_cost_admission_v1','SELECT'),"
                "has_column_privilege(current_user,'lucy.restored_cost_admission_v1','updated_at','UPDATE'),"
                "has_column_privilege(current_user,'lucy.restored_cost_admission_v1',"
                "'state','UPDATE'),"
                "has_table_privilege(current_user,'public.alembic_version','SELECT') "
                "FROM pg_catalog.pg_roles r WHERE r.rolname=current_user"
            )
        ).one()
    expected_login = str(url.username)
    if tuple(row) != (
        expected_login,
        expected_login,
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        "lucy_migration",
        R1_SCHEMA_REVISION,
        "quarantined",
        True,
        True,
        False,
        False,
        False,
        False,
        True,
        True,
        True,
        True,
        True,
        False,
        True,
        True,
        False,
        True,
        True,
        False,
        True,
    ):
        raise ProtectedRecoveryError("activation identity or boundary differs")


def _database_stage[T](stage: str, operation: Callable[[], T]) -> T:
    """Label a database boundary without exposing SQL or parameter values."""

    try:
        return operation()
    except ProgrammingError as exc:
        raise ProtectedRecoveryError(f"{stage} failed at database boundary") from exc


def run(config: ProtectedRecoveryConfig) -> dict[str, Any]:
    sts: Any = boto3.client("sts", region_name=config.region)
    _verify_actual_role(config, sts.get_caller_identity())
    _database_stage(
        "activation identity attestation",
        lambda: _verify_migration_identity(config.migration_url),
    )
    _database_stage(
        "authority identity attestation",
        lambda: _verify_database_identity(
            config.authority_recovery_url, str(config.authority_recovery_url.username)
        ),
    )
    _database_stage(
        "cost identity attestation",
        lambda: _verify_database_identity(
            config.cost_recovery_url, str(config.cost_recovery_url.username)
        ),
    )

    dynamo: Any = boto3.client("dynamodb", region_name=config.region)
    authority_journal = AwsDynamoRecoveryJournal.from_configuration(
        dynamo,
        region=config.region,
        account_id=config.account_id,
        table_name=config.authority_table,
        binding=config.authority_binding,
    )
    cost_journal = AwsDynamoRecoveryJournal.from_configuration(
        dynamo,
        region=config.region,
        account_id=config.account_id,
        table_name=config.cost_table,
        binding=config.cost_binding,
    )
    authority_store = PostgresAuthorityReplayStore(
        create_session_factory(
            config.authority_recovery_url.render_as_string(hide_password=False)
        ),
        config.authority_binding,
    )
    cost_store = PostgresCostReplayStore(
        create_session_factory(config.cost_recovery_url.render_as_string(hide_password=False)),
        config.cost_binding,
    )
    coordinator = RecoveryCoordinator(
        (
            RecoveryStreamTarget(
                authority_journal, authority_store, config.authority_witness
            ),
            RecoveryStreamTarget(cost_journal, cost_store, config.cost_witness),
        ),
        PostgresRecoveryActivator(
            create_session_factory(config.migration_url.render_as_string(hide_password=False))
        ),
        cost_finalizer=cost_store,
        binding_manifest_digest=config.binding_manifest_digest,
    )
    handoff = _database_stage(
        "coordinated replay",
        lambda: coordinator.recover_and_activate(
            target_runtime_epoch=config.target_runtime_epoch
        ),
    )
    return {
        "contract": "lucy.protected-recovery-handoff.v1.3",
        "status": "passed",
        "recovery_id": str(handoff.recovery_id),
        "target_runtime_epoch": str(handoff.target_runtime_epoch),
        "binding_manifest_digest": handoff.binding_manifest_digest,
        "streams": [
            {
                "stream_kind": pause.stream_kind.value,
                "stream_id": str(pause.stream_id),
                "held_head_sequence": pause.held_head_sequence,
                "held_head_digest": pause.held_head_digest,
                "fencing_generation": pause.fencing_generation,
                "expires_at": pause.expires_at.isoformat(),
            }
            for pause in handoff.pauses
        ],
        "transcript_capture_enabled": False,
        "static_aws_credentials": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        raise ProtectedRecoveryError("this recovery utility accepts no command-line values")
    try:
        report = run(ProtectedRecoveryConfig.from_environment())
    except (ProtectedRecoveryError, RecoveryJournalError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
