from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

import deploy.postgres.replay_authorized_deletion_cloud_v1_3 as replay
from deploy.postgres.replay_authorized_deletion_cloud_v1_3 import (
    AUTHORIZATION,
    ScopedRecoveryReplayConfig,
    ScopedRecoveryReplayError,
)

NOW = datetime(2026, 9, 9, 12, 0, tzinfo=UTC)
REALM_ID = UUID("11111111-1111-4111-8111-111111111111")
WORKSPACE_ID = UUID("22222222-2222-4222-8222-222222222222")


def _key(*, purpose: str, algorithm: str, key_id: str, issuer: str) -> dict[str, Any]:
    public_key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    import base64

    return {
        "contract_version": "1",
        "object_type": "lucy.v13-verification-key.v1",
        "key_id": key_id,
        "issuer": issuer,
        "environment": "production",
        "purpose": purpose,
        "algorithm": algorithm,
        "public_key_b64": base64.b64encode(public_key).decode("ascii"),
        "status": "active",
        "valid_from": (NOW - timedelta(days=1)).isoformat(),
        "issuance_not_after": (NOW + timedelta(days=1)).isoformat(),
        "verify_not_after": (NOW + timedelta(days=30)).isoformat(),
        "compromise_suspected_from": None,
    }


def _environment() -> dict[str, str]:
    bundle = {"permit": {}, "manifest": {}, "execution_grant": {}, "receipt": {}}
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_AUTHORIZED_DELETION_RECOVERY_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_6tns"
        ),
        "LUCY_AUTHORIZED_DELETION_BUNDLE_JSON": json.dumps(bundle),
        "LUCY_V13_POLICY_TRUST_STORE_JSON": json.dumps(
            [
                _key(
                    purpose="policy_notary_v13",
                    algorithm="Ed25519",
                    key_id="policy",
                    issuer="policy",
                )
            ]
        ),
        "LUCY_V13_RECEIPT_TRUST_STORE_JSON": json.dumps(
            [
                _key(
                    purpose="deletion_receipt_v13",
                    algorithm="Ed25519",
                    key_id="receipt",
                    issuer="executor",
                )
            ]
        ),
        "LUCY_RECOVERY_REALM_ID": str(REALM_ID),
        "LUCY_RECOVERY_WORKSPACE_ID": str(WORKSPACE_ID),
        "LUCY_DELETION_CALLER_IDENTITY": "arn:aws:iam::123456789012:role/utopia-workflow",
        "LUCY_DELETION_EXECUTOR_IDENTITY": "lucy-utopia-deletion-v13",
        "LUCY_DELETION_EXECUTOR_ALIAS_ARN": (
            "arn:aws:lambda:us-east-1:123456789012:function:lucy-utopia-deletion-v13:production"
        ),
        "LUCY_DELETION_EXECUTOR_VERSION": "3",
        "LUCY_DELETION_RECEIPT_KEY_ARN": "arn:aws:kms:us-east-1:123456789012:key/key-id",
        "LUCY_AUTHORITY_EVIDENCE_DIGEST": "a" * 64,
    }


def test_config_requires_exact_production_capture_off_scope() -> None:
    config = ScopedRecoveryReplayConfig.from_environment(_environment())
    assert config.realm_id == REALM_ID
    assert config.workspace_id == WORKSPACE_ID
    assert config.migration_url.username == "lucy_migration"

    for key, value in {
        "RENDER": "false",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "true",
        "LUCY_AUTHORIZED_DELETION_RECOVERY_AUTHORIZATION": "wrong",
        "LUCY_RECOVERY_REALM_ID": "not-a-uuid",
        "LUCY_MIGRATION_DATABASE_URL": "postgresql://lucy_migration:x@example.com/other",
    }.items():
        with pytest.raises(ScopedRecoveryReplayError):
            ScopedRecoveryReplayConfig.from_environment(_environment() | {key: value})


class _Result:
    def __init__(self, row: tuple[Any, ...] | None = None) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class _Connection:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, _parameters: object = None) -> _Result:
        normalized = " ".join(statement.split())
        self.statements.append(normalized)
        if "FROM pg_stat_ssl" in normalized:
            return _Result((True,))
        if "FROM lucy.runtime_admission" in normalized:
            return _Result(("quarantined", True))
        if "apply_scoped_authorized_deletion_recovery_v" in normalized:
            return _Result(({"state": "FINALITY_PENDING", "replayed": False},))
        return _Result()


def test_run_uses_only_locked_quarantined_scoped_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = ScopedRecoveryReplayConfig.from_environment(_environment())
    connection = _Connection()
    contract = {
        "contract_version": "2",
        "operation_id": "33333333-3333-4333-8333-333333333333",
        "manifest_id": "44444444-4444-4444-8444-444444444444",
        "target_count": 2,
        "recovery_digest": "b" * 64,
        "authority_evidence_digest": "a" * 64,
    }
    monkeypatch.setattr(replay, "_verified_contract", lambda _config: contract)
    monkeypatch.setattr(replay.psycopg, "connect", lambda *_args, **_kwargs: connection)

    report = replay.run(config)

    assert report["status"] == "passed"
    assert report["realm_id"] == str(REALM_ID)
    assert sum("pg_advisory_xact_lock" in item for item in connection.statements) == 2
    assert (
        sum(
            "apply_scoped_authorized_deletion_recovery_v2" in item
            for item in connection.statements
        )
        == 1
    )
    assert any("lucy.capture_boundary_safe_v1()" in item for item in connection.statements)


def test_run_dispatches_verified_v3_contract_to_v3_database_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = ScopedRecoveryReplayConfig.from_environment(_environment())
    connection = _Connection()
    contract = {
        "contract_version": "3",
        "operation_id": "33333333-3333-4333-8333-333333333333",
        "manifest_id": "44444444-4444-4444-8444-444444444444",
        "target_count": 5,
        "recovery_digest": "b" * 64,
        "authority_evidence_digest": "a" * 64,
    }
    monkeypatch.setattr(replay, "_verified_contract", lambda _config: contract)
    monkeypatch.setattr(replay.psycopg, "connect", lambda *_args, **_kwargs: connection)

    report = replay.run(config)

    assert report["contract"] == "lucy.authorized-deletion-restore-replay.v3"
    assert report["target_count"] == 5
    assert sum(
        "apply_scoped_authorized_deletion_recovery_v3" in item
        for item in connection.statements
    ) == 1


def test_run_fails_closed_outside_quarantine(monkeypatch: pytest.MonkeyPatch) -> None:
    config = ScopedRecoveryReplayConfig.from_environment(_environment())
    connection = _Connection()
    original_execute = connection.execute

    def execute(statement: str, parameters: object = None) -> _Result:
        if "FROM lucy.runtime_admission" in statement:
            return _Result(("ready", True))
        return original_execute(statement, parameters)

    monkeypatch.setattr(connection, "execute", execute)
    monkeypatch.setattr(replay, "_verified_contract", lambda _config: {"contract_version": "2"})
    monkeypatch.setattr(replay.psycopg, "connect", lambda *_args, **_kwargs: connection)

    with pytest.raises(ScopedRecoveryReplayError, match="outside"):
        replay.run(config)
