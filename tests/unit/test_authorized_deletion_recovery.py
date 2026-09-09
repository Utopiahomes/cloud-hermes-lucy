from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import deploy.postgres.replay_authorized_deletion_cloud_v1_2 as replay
from deploy.postgres.replay_authorized_deletion_cloud_v1_2 import (
    AUTHORIZATION,
    RecoveryReplayConfig,
    RecoveryReplayError,
)

NOW = datetime(2026, 9, 8, 15, 0, tzinfo=UTC)
ROOT = Path(__file__).parents[2]


def test_capture_safety_migration_is_exact_and_fail_closed() -> None:
    source = (
        ROOT
        / "migrations"
        / "versions"
        / "0021_recovery_capture_safety.py"
    ).read_text(encoding="utf-8")
    assert "NOT EXISTS (" in source
    assert "FROM lucy.conversation_capture_states" in source
    assert "FROM lucy.capture_receipts r" in source
    assert "^cloud-acceptance-" in source
    assert "r.source_turn_id = regexp_replace(" in source
    assert "FROM lucy.evidence e" in source
    assert "e.source = 'hermes'" in source
    assert "OR NOT lucy.capture_boundary_safe_v1() THEN" in source


def _key(*, purpose: str, algorithm: str, key_id: str, issuer: str) -> dict[str, Any]:
    return {
        "contract_version": "1",
        "object_type": "lucy.verification-key.v1",
        "key_id": key_id,
        "issuer": issuer,
        "purpose": purpose,
        "algorithm": algorithm,
        "environment": "production",
        "public_key_b64": "AA==",
        "valid_from": (NOW - timedelta(days=1)).isoformat(),
        "issuance_not_after": (NOW + timedelta(days=1)).isoformat(),
        "verify_not_after": (NOW + timedelta(days=30)).isoformat(),
        "status": "active",
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
        "LUCY_POLICY_TRUST_STORE_JSON": json.dumps(
            [
                _key(
                    purpose="policy_notary",
                    algorithm="Ed25519",
                    key_id="policy-notary.production.1",
                    issuer="lucy-policy.production",
                )
            ]
        ),
        "LUCY_EXECUTOR_RECEIPT_TRUST_STORE_JSON": json.dumps(
            [
                _key(
                    purpose="deletion_receipt",
                    algorithm="ECDSA_SHA_256",
                    key_id="arn:aws:kms:us-east-1:123456789012:key/receipt-key",
                    issuer="lucy-deletion-executor",
                )
            ]
        ),
        "LUCY_DELETION_EXECUTOR_IDENTITY": "lucy-deletion-executor",
        "LUCY_DELETION_EXECUTOR_ALIAS_ARN": (
            "arn:aws:lambda:us-east-1:123456789012:"
            "function:lucy-deletion-executor:production"
        ),
        "LUCY_DELETION_EXECUTOR_VERSION": "13",
        "LUCY_DELETION_RECEIPT_KEY_ARN": (
            "arn:aws:kms:us-east-1:123456789012:key/receipt-key"
        ),
        "LUCY_SECURITY_STORAGE_EPOCH": "1",
        "LUCY_AUTHORITY_EVIDENCE_DIGEST": "a" * 64,
    }


def test_recovery_config_requires_exact_private_capture_off_boundary() -> None:
    config = RecoveryReplayConfig.from_environment(_environment())
    assert config.migration_url.username == "lucy_migration"
    assert config.executor_version == 13

    for key, value in {
        "RENDER": "false",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "true",
        "LUCY_AUTHORIZED_DELETION_RECOVERY_AUTHORIZATION": "wrong",
        "LUCY_MIGRATION_DATABASE_URL": "postgresql://lucy_migration:x@example.com/other",
        "LUCY_AUTHORITY_EVIDENCE_DIGEST": "not-a-digest",
    }.items():
        with pytest.raises(RecoveryReplayError):
            RecoveryReplayConfig.from_environment(_environment() | {key: value})


def test_recovery_config_accepts_render_pitr_database_suffix() -> None:
    environment = {
        key: value.replace("lucy_6tns", "lucy_6tns_eymz")
        for key, value in _environment().items()
    }
    assert RecoveryReplayConfig.from_environment(environment).migration_url.database == (
        "lucy_6tns_eymz"
    )


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
        if "apply_authorized_deletion_recovery_v1" in normalized:
            return _Result(({"state": "FINALITY_PENDING", "replayed": False},))
        return _Result()


def test_run_uses_only_locked_quarantined_database_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = RecoveryReplayConfig.from_environment(_environment())
    connection = _Connection()
    contract = {
        "operation_id": "11111111-1111-4111-8111-111111111111",
        "manifest_id": "22222222-2222-4222-8222-222222222222",
        "target_count": 1,
        "recovery_digest": "b" * 64,
        "authority_evidence_digest": "a" * 64,
    }
    monkeypatch.setattr(replay, "_verified_contract", lambda _config: contract)
    monkeypatch.setattr(replay.psycopg, "connect", lambda *_args, **_kwargs: connection)

    report = replay.run(config)

    assert report["status"] == "passed"
    assert report["target_count"] == 1
    assert sum("pg_advisory_xact_lock" in item for item in connection.statements) == 2
    assert (
        sum(
            "apply_authorized_deletion_recovery_v1" in item
            for item in connection.statements
        )
        == 1
    )
    assert any(
        "lucy.capture_boundary_safe_v1()" in item for item in connection.statements
    )
    assert all(
        "NOT EXISTS(SELECT 1 FROM lucy.capture_receipts WHERE capture_enabled)" not in item
        for item in connection.statements
    )
