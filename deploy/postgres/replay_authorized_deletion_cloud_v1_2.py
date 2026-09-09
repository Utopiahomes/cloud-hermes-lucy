"""Replay one proven authorized deletion into a quarantined PostgreSQL restore.

The caller supplies content-free signed contracts already read from the exact
immutable AWS intent and receipt records.  This utility verifies historical
trust and every cross-contract binding before the database can remove restored
payloads or derived memory.  It never reads evidence plaintext or wrapped keys.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import psycopg
from pydantic import ValidationError
from sqlalchemy.engine import URL, make_url

from lucy.authorized_deletion_recovery import (
    AuthorizedDeletionRecoveryError,
    build_authorized_deletion_recovery_contract,
    verify_authorized_deletion_recovery,
)
from lucy.contracts.security_v1_2 import (
    ContractTrustStore,
    DeletionTargetManifestV1,
    DeploymentEnvironment,
    ExecutorReceiptV1,
    SensitiveActionPermitV2,
    SensitiveExecutionGrantV1,
    VerificationKeyV1,
)

AUTHORIZATION = "security-v1.2-authorized-deletion-restore-replay"
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LUCY_DATABASE = re.compile(r"lucy(?:_[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAINTENANCE_LOCK = 0x4C5543594D53
_ADMISSION_LOCK = 0x4C5543594144


class RecoveryReplayError(RuntimeError):
    """The recovery replay failed closed before admission could reopen."""


@dataclass(frozen=True)
class RecoveryReplayConfig:
    migration_url: URL
    bundle: Mapping[str, Any]
    policy_keys: tuple[VerificationKeyV1, ...]
    receipt_keys: tuple[VerificationKeyV1, ...]
    executor_identity: str
    executor_alias_arn: str
    executor_version: int
    receipt_key_id: str
    recovered_storage_epoch: int
    authority_evidence_digest: str

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> RecoveryReplayConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise RecoveryReplayError("replay requires the production Render runtime")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise RecoveryReplayError("transcript capture must remain disabled")
        if values.get("LUCY_AUTHORIZED_DELETION_RECOVERY_AUTHORIZATION") != AUTHORIZATION:
            raise RecoveryReplayError("the exact reviewed recovery authorization is required")
        migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if (
            migration_url.username != "lucy_migration"
            or migration_url.host is None
            or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
            or migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
        ):
            raise RecoveryReplayError("replay requires the private Lucy migration login")
        try:
            bundle = json.loads(_required(values, "LUCY_AUTHORIZED_DELETION_BUNDLE_JSON"))
            policy_keys = _keys(_required(values, "LUCY_POLICY_TRUST_STORE_JSON"))
            receipt_keys = _keys(
                _required(values, "LUCY_EXECUTOR_RECEIPT_TRUST_STORE_JSON")
            )
        except (json.JSONDecodeError, TypeError, ValidationError, ValueError) as exc:
            raise RecoveryReplayError("recovery bundle or trust inventory is invalid") from exc
        if not isinstance(bundle, dict) or set(bundle) != {
            "permit",
            "manifest",
            "execution_grant",
            "receipt",
        }:
            raise RecoveryReplayError("recovery bundle has an unexpected shape")
        digest = _required(values, "LUCY_AUTHORITY_EVIDENCE_DIGEST")
        if _DIGEST.fullmatch(digest) is None:
            raise RecoveryReplayError("authority evidence digest is invalid")
        return cls(
            migration_url=migration_url,
            bundle=bundle,
            policy_keys=policy_keys,
            receipt_keys=receipt_keys,
            executor_identity=_required(values, "LUCY_DELETION_EXECUTOR_IDENTITY"),
            executor_alias_arn=_required(values, "LUCY_DELETION_EXECUTOR_ALIAS_ARN"),
            executor_version=_positive_int(values, "LUCY_DELETION_EXECUTOR_VERSION"),
            receipt_key_id=_required(values, "LUCY_DELETION_RECEIPT_KEY_ARN"),
            recovered_storage_epoch=_positive_int(
                values, "LUCY_SECURITY_STORAGE_EPOCH"
            ),
            authority_evidence_digest=digest,
        )


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise RecoveryReplayError(f"missing required configuration: {name}")
    return value


def _positive_int(values: Mapping[str, str], name: str) -> int:
    try:
        value = int(_required(values, name))
    except ValueError as exc:
        raise RecoveryReplayError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise RecoveryReplayError(f"{name} must be a positive integer")
    return value


def _keys(raw: str) -> tuple[VerificationKeyV1, ...]:
    payload = json.loads(raw)
    if not isinstance(payload, list) or not payload:
        raise ValueError("trust inventory must be a nonempty list")
    return tuple(VerificationKeyV1.model_validate(item) for item in payload)


def _database_url(raw: str) -> URL:
    parsed = make_url(raw)
    if parsed.drivername not in {"postgresql", "postgresql+psycopg"}:
        raise RecoveryReplayError("only PostgreSQL psycopg URLs are accepted")
    if not parsed.username or not parsed.password or not parsed.host or not parsed.database:
        raise RecoveryReplayError("database URL requires user, password, host, and database")
    return parsed.set(drivername="postgresql+psycopg").update_query_dict({"sslmode": "require"})


def _conninfo(url: URL) -> str:
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


def _verified_contract(config: RecoveryReplayConfig) -> dict[str, Any]:
    try:
        permit = SensitiveActionPermitV2.model_validate(config.bundle["permit"])
        manifest = DeletionTargetManifestV1.model_validate(config.bundle["manifest"])
        grant = SensitiveExecutionGrantV1.model_validate(config.bundle["execution_grant"])
        receipt = ExecutorReceiptV1.model_validate(config.bundle["receipt"])
        proof = verify_authorized_deletion_recovery(
            permit=permit,
            manifest=manifest,
            grant=grant,
            receipt=receipt,
            policy_trust_store=ContractTrustStore(config.policy_keys),
            receipt_trust_store=ContractTrustStore(config.receipt_keys),
            environment=DeploymentEnvironment.PRODUCTION,
            executor_identity=config.executor_identity,
            executor_alias_arn=config.executor_alias_arn,
            executor_version=config.executor_version,
            receipt_key_id=config.receipt_key_id,
        )
        return build_authorized_deletion_recovery_contract(
            proof=proof,
            permit=permit,
            manifest=manifest,
            receipt=receipt,
            recovered_storage_epoch=config.recovered_storage_epoch,
            authority_evidence_digest=config.authority_evidence_digest,
        )
    except (ValidationError, AuthorizedDeletionRecoveryError, ValueError) as exc:
        raise RecoveryReplayError("signed deletion authority verification failed") from exc


def run(config: RecoveryReplayConfig) -> dict[str, Any]:
    contract = _verified_contract(config)
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '10s'")
        connection.execute("SET LOCAL statement_timeout = '120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_ADMISSION_LOCK,))
        tls = connection.execute(
            "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
        ).fetchone()
        boundary = connection.execute(
            "SELECT (SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1()"
        ).fetchone()
        if tls != (True,) or boundary != ("quarantined", True):
            raise RecoveryReplayError("database is outside the reviewed recovery boundary")
        row = connection.execute(
            "SELECT lucy.apply_authorized_deletion_recovery_v1(%s::jsonb)",
            (json.dumps(contract, separators=(",", ":"), sort_keys=True),),
        ).fetchone()
        if row is None or not isinstance(row[0], dict) or row[0].get("state") != "FINALITY_PENDING":
            raise RecoveryReplayError("database did not confirm authorized deletion replay")
    return {
        "contract": "lucy.authorized-deletion-restore-replay.v1",
        "status": "passed",
        "operation_id": contract["operation_id"],
        "manifest_id": contract["manifest_id"],
        "target_count": contract["target_count"],
        "recovery_digest": contract["recovery_digest"],
        "authority_evidence_digest": contract["authority_evidence_digest"],
        "replayed": bool(row[0].get("replayed")),
    }


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        raise RecoveryReplayError("this deployment utility accepts no command-line values")
    try:
        report = run(RecoveryReplayConfig.from_environment())
    except RecoveryReplayError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
