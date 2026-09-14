"""Replay one proven scoped deletion into a quarantined PostgreSQL restore.

The operator supplies only the durable, content-free V1.3 contract bundle and
historical verification-key inventories.  This utility verifies the complete
signed chain before calling the single quarantined PostgreSQL recovery gate.
It never reads evidence plaintext, ciphertext, or wrapped data keys.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import psycopg
from pydantic import ValidationError
from sqlalchemy.engine import URL, make_url

from lucy.authorized_deletion_recovery import (
    AuthorizedDeletionRecoveryError,
    build_authorized_deletion_recovery_contract_v2,
    build_authorized_deletion_recovery_contract_v3,
    verify_authorized_deletion_recovery_v2,
    verify_authorized_deletion_recovery_v3,
)
from lucy.contracts.security_v1_2 import DeploymentEnvironment
from lucy.contracts.security_v1_3 import (
    DeletionTargetManifestV2,
    DeletionTargetManifestV3,
    ExecutorReceiptV2,
    SensitiveActionPermitV3,
    SensitiveExecutionGrantV2,
    V13ContractVerifier,
    V13VerificationKeyV1,
)

AUTHORIZATION = "security-v1.3-scoped-authorized-deletion-restore-replay"
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LUCY_DATABASE = re.compile(r"lucy(?:_[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAINTENANCE_LOCK = 0x4C5543594D53
_ADMISSION_LOCK = 0x4C5543594144


class ScopedRecoveryReplayError(RuntimeError):
    """The scoped recovery replay failed closed before admission could reopen."""


@dataclass(frozen=True)
class ScopedRecoveryReplayConfig:
    migration_url: URL
    bundle: Mapping[str, Any]
    policy_keys: tuple[V13VerificationKeyV1, ...]
    receipt_keys: tuple[V13VerificationKeyV1, ...]
    environment: DeploymentEnvironment
    realm_id: UUID
    workspace_id: UUID
    caller_identity: str
    executor_identity: str
    executor_alias_arn: str
    executor_version: int
    receipt_key_id: str
    authority_evidence_digest: str

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> ScopedRecoveryReplayConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise ScopedRecoveryReplayError("replay requires the production Render runtime")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise ScopedRecoveryReplayError("transcript capture must remain disabled")
        if values.get("LUCY_AUTHORIZED_DELETION_RECOVERY_AUTHORIZATION") != AUTHORIZATION:
            raise ScopedRecoveryReplayError("the exact reviewed recovery authorization is required")
        migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if (
            migration_url.username != "lucy_migration"
            or migration_url.host is None
            or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
            or migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
        ):
            raise ScopedRecoveryReplayError("replay requires the private Lucy migration login")
        try:
            bundle = json.loads(_required(values, "LUCY_AUTHORIZED_DELETION_BUNDLE_JSON"))
            policy_keys = _keys(_required(values, "LUCY_V13_POLICY_TRUST_STORE_JSON"))
            receipt_keys = _keys(_required(values, "LUCY_V13_RECEIPT_TRUST_STORE_JSON"))
            realm_id = UUID(_required(values, "LUCY_RECOVERY_REALM_ID"))
            workspace_id = UUID(_required(values, "LUCY_RECOVERY_WORKSPACE_ID"))
        except (json.JSONDecodeError, TypeError, ValidationError, ValueError) as exc:
            raise ScopedRecoveryReplayError(
                "recovery bundle, scope, or trust inventory is invalid"
            ) from exc
        if not isinstance(bundle, dict) or set(bundle) != {
            "permit",
            "manifest",
            "execution_grant",
            "receipt",
        }:
            raise ScopedRecoveryReplayError("recovery bundle has an unexpected shape")
        digest = _required(values, "LUCY_AUTHORITY_EVIDENCE_DIGEST")
        if _DIGEST.fullmatch(digest) is None:
            raise ScopedRecoveryReplayError("authority evidence digest is invalid")
        return cls(
            migration_url=migration_url,
            bundle=bundle,
            policy_keys=policy_keys,
            receipt_keys=receipt_keys,
            environment=DeploymentEnvironment.PRODUCTION,
            realm_id=realm_id,
            workspace_id=workspace_id,
            caller_identity=_required(values, "LUCY_DELETION_CALLER_IDENTITY"),
            executor_identity=_required(values, "LUCY_DELETION_EXECUTOR_IDENTITY"),
            executor_alias_arn=_required(values, "LUCY_DELETION_EXECUTOR_ALIAS_ARN"),
            executor_version=_positive_int(values, "LUCY_DELETION_EXECUTOR_VERSION"),
            receipt_key_id=_required(values, "LUCY_DELETION_RECEIPT_KEY_ARN"),
            authority_evidence_digest=digest,
        )


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise ScopedRecoveryReplayError(f"missing required configuration: {name}")
    return value


def _positive_int(values: Mapping[str, str], name: str) -> int:
    try:
        value = int(_required(values, name))
    except ValueError as exc:
        raise ScopedRecoveryReplayError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise ScopedRecoveryReplayError(f"{name} must be a positive integer")
    return value


def _keys(raw: str) -> tuple[V13VerificationKeyV1, ...]:
    payload = json.loads(raw)
    if not isinstance(payload, list) or not payload:
        raise ValueError("trust inventory must be a nonempty list")
    return tuple(V13VerificationKeyV1.model_validate(item) for item in payload)


def _database_url(raw: str) -> URL:
    parsed = make_url(raw)
    if parsed.drivername not in {"postgresql", "postgresql+psycopg"}:
        raise ScopedRecoveryReplayError("only PostgreSQL psycopg URLs are accepted")
    if not parsed.username or not parsed.password or not parsed.host or not parsed.database:
        raise ScopedRecoveryReplayError("database URL requires user, password, host, and database")
    return parsed.set(drivername="postgresql+psycopg").update_query_dict({"sslmode": "require"})


def _conninfo(url: URL) -> str:
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


def _verified_contract(config: ScopedRecoveryReplayConfig) -> dict[str, Any]:
    try:
        permit = SensitiveActionPermitV3.model_validate(config.bundle["permit"])
        grant = SensitiveExecutionGrantV2.model_validate(config.bundle["execution_grant"])
        receipt = ExecutorReceiptV2.model_validate(config.bundle["receipt"])
        if (
            permit.target_scope.security_realm_id != config.realm_id
            or permit.workspace_id != config.workspace_id
        ):
            raise AuthorizedDeletionRecoveryError("reviewed recovery scope mismatch")
        manifest_value = config.bundle["manifest"]
        if not isinstance(manifest_value, dict):
            raise ValueError("deletion manifest must be an object")
        manifest_identity = (
            manifest_value.get("contract_version"),
            manifest_value.get("object_type"),
        )
        policy_verifier = V13ContractVerifier(config.policy_keys)
        receipt_verifier = V13ContractVerifier(config.receipt_keys)
        checked_at = datetime.now(UTC)
        if manifest_identity == ("3", "lucy.deletion-target-manifest.v3"):
            manifest_v3 = DeletionTargetManifestV3.model_validate(manifest_value)
            proof_v3 = verify_authorized_deletion_recovery_v3(
                permit=permit,
                manifest=manifest_v3,
                grant=grant,
                receipt=receipt,
                policy_verifier=policy_verifier,
                receipt_verifier=receipt_verifier,
                environment=config.environment,
                caller_identity=config.caller_identity,
                executor_identity=config.executor_identity,
                executor_alias_arn=config.executor_alias_arn,
                executor_version=config.executor_version,
                receipt_key_id=config.receipt_key_id,
                checked_at=checked_at,
            )
            return build_authorized_deletion_recovery_contract_v3(
                proof=proof_v3,
                permit=permit,
                manifest=manifest_v3,
                grant=grant,
                receipt=receipt,
                authority_evidence_digest=config.authority_evidence_digest,
            )
        if manifest_identity == ("2", "lucy.deletion-target-manifest.v2"):
            manifest_v2 = DeletionTargetManifestV2.model_validate(manifest_value)
            proof_v2 = verify_authorized_deletion_recovery_v2(
                permit=permit,
                manifest=manifest_v2,
                grant=grant,
                receipt=receipt,
                policy_verifier=policy_verifier,
                receipt_verifier=receipt_verifier,
                environment=config.environment,
                caller_identity=config.caller_identity,
                executor_identity=config.executor_identity,
                executor_alias_arn=config.executor_alias_arn,
                executor_version=config.executor_version,
                receipt_key_id=config.receipt_key_id,
                checked_at=checked_at,
            )
            return build_authorized_deletion_recovery_contract_v2(
                proof=proof_v2,
                permit=permit,
                manifest=manifest_v2,
                grant=grant,
                receipt=receipt,
                authority_evidence_digest=config.authority_evidence_digest,
            )
        raise ValueError("deletion manifest version is unsupported")
    except (ValidationError, AuthorizedDeletionRecoveryError, ValueError) as exc:
        raise ScopedRecoveryReplayError(
            "signed scoped deletion authority verification failed"
        ) from exc


def run(config: ScopedRecoveryReplayConfig) -> dict[str, Any]:
    contract = _verified_contract(config)
    contract_version = contract.get("contract_version")
    if contract_version not in {"2", "3"}:
        raise ScopedRecoveryReplayError("verified recovery contract version is unsupported")
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
            raise ScopedRecoveryReplayError("database is outside the reviewed recovery boundary")
        row = connection.execute(
            f"SELECT lucy.apply_scoped_authorized_deletion_recovery_v{contract_version}(%s::jsonb)",
            (json.dumps(contract, separators=(",", ":"), sort_keys=True),),
        ).fetchone()
        if row is None or not isinstance(row[0], dict) or row[0].get("state") != "FINALITY_PENDING":
            raise ScopedRecoveryReplayError("database did not confirm scoped deletion replay")
    return {
        "contract": f"lucy.authorized-deletion-restore-replay.v{contract_version}",
        "status": "passed",
        "operation_id": contract["operation_id"],
        "manifest_id": contract["manifest_id"],
        "realm_id": str(config.realm_id),
        "workspace_id": str(config.workspace_id),
        "target_count": contract["target_count"],
        "recovery_digest": contract["recovery_digest"],
        "authority_evidence_digest": contract["authority_evidence_digest"],
        "replayed": bool(row[0].get("replayed")),
    }


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        raise ScopedRecoveryReplayError("this deployment utility accepts no command-line values")
    try:
        report = run(ScopedRecoveryReplayConfig.from_environment())
    except ScopedRecoveryReplayError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
