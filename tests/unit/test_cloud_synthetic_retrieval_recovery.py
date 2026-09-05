from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

import deploy.postgres.recover_expired_synthetic_retrieval_cloud_v1_2 as recovery
from deploy.postgres.recover_expired_synthetic_retrieval_cloud_v1_2 import (
    AUTHORIZATION,
    RecoveryConfig,
    RecoveryError,
)

OPERATION_ID = UUID("ee6c04b1-95c0-4bf8-a5fd-8566f0f0e8e1")
NOW = datetime(2026, 9, 5, 6, 0, tzinfo=UTC)


class _Result:
    def __init__(self, one: tuple[Any, ...] | None = None, *, rowcount: int = -1) -> None:
        self._one = one
        self.rowcount = rowcount

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._one


class _Connection:
    def __init__(self, config: RecoveryConfig, *, action: str = "evidence.retrieve") -> None:
        self.config = config
        self.action = action
        self.outcome = "pending"
        self.completed_at: datetime | None = None
        self.result: dict[str, Any] | None = None
        self.state = "EXECUTING"
        self.event_count = 0
        self.statements: list[str] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, parameters: object = None) -> _Result:
        normalized = " ".join(statement.split())
        self.statements.append(normalized)
        if normalized.startswith("SET LOCAL") or "pg_advisory_xact_lock" in normalized:
            return _Result()
        if "FROM pg_stat_ssl" in normalized:
            return _Result((True,))
        if "FROM lucy.runtime_admission" in normalized:
            return _Result(("quarantined",))
        if "FROM lucy.conversation_capture_states" in normalized:
            return _Result((False, False))
        if "FROM lucy.security_contract_epochs" in normalized:
            return _Result(
                (self.config.storage_epoch, self.config.registry_epoch, self.config.key_epoch)
            )
        if "coalesce(bool_and(id=" in normalized:
            return _Result((1, True) if self.outcome == "pending" else (0, False))
        if normalized.startswith("SELECT o.outcome"):
            return _Result(
                (
                    self.outcome,
                    self.completed_at,
                    self.result,
                    "cloud-acceptance-retrieve:00000000-0000-4000-8000-000000000001",
                    self.action,
                    self.state,
                    True,
                    True,
                    True,
                    "lucy_evidence_workflow",
                    1,
                    0,
                    0,
                    True,
                    True,
                    True,
                )
            )
        if "FROM lucy.sensitive_operation_events_v1" in normalized:
            return _Result((self.event_count,))
        if normalized == "SELECT clock_timestamp()":
            return _Result((NOW,))
        if normalized.startswith("UPDATE lucy.sensitive_operations_v1"):
            self.state = "FAILED_FINAL"
            return _Result(rowcount=1)
        if normalized.startswith("UPDATE lucy.operations"):
            self.outcome = "failed"
            self.completed_at = NOW
            self.result = dict(recovery._RESULT)
            return _Result(rowcount=1)
        if normalized.startswith("SELECT lucy.append_sensitive_event_v1"):
            self.event_count += 1
            return _Result((None,))
        raise AssertionError(f"unexpected SQL: {normalized}")


def _environment() -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_SYNTHETIC_RETRIEVAL_RECOVERY_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_6tns"
        ),
        "LUCY_SYNTHETIC_RETRIEVAL_OPERATION_ID": str(OPERATION_ID),
        "LUCY_EXPECTED_RETRIEVAL_EXECUTOR_VERSION": "3",
        "LUCY_SECURITY_STORAGE_EPOCH": "1",
        "LUCY_SECURITY_REGISTRY_EPOCH": "1",
        "LUCY_SECURITY_KEY_EPOCH": "1",
    }


def test_recovery_config_requires_exact_private_quarantined_boundary() -> None:
    config = RecoveryConfig.from_environment(_environment())
    assert config.operation_id == OPERATION_ID
    assert config.expected_retrieval_version == 3

    for key, value in {
        "RENDER": "false",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "true",
        "LUCY_SYNTHETIC_RETRIEVAL_RECOVERY_AUTHORIZATION": "wrong",
        "LUCY_MIGRATION_DATABASE_URL": "postgresql://x:y@example.com/other",
        "LUCY_SYNTHETIC_RETRIEVAL_OPERATION_ID": "not-a-uuid",
    }.items():
        changed = _environment() | {key: value}
        with pytest.raises(RecoveryError):
            RecoveryConfig.from_environment(changed)


def test_recovery_closes_only_the_exact_synthetic_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = RecoveryConfig.from_environment(_environment())
    connection = _Connection(config)
    monkeypatch.setattr(recovery.psycopg, "connect", lambda *_args, **_kwargs: connection)

    report = recovery.run(config)

    assert report["terminal_state"] == "FAILED_FINAL"
    assert report["executor_effect"] == "unknown"
    assert report["evidence_preserved"] is True
    assert connection.outcome == "failed"
    assert connection.state == "FAILED_FINAL"
    assert connection.event_count == 1
    assert sum(statement.startswith("UPDATE ") for statement in connection.statements) == 2
    assert not any(
        statement.startswith(("DELETE ", "INSERT ")) for statement in connection.statements
    )


def test_recovery_refuses_non_retrieval_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = RecoveryConfig.from_environment(_environment())
    connection = _Connection(config, action="evidence.delete")
    monkeypatch.setattr(recovery.psycopg, "connect", lambda *_args, **_kwargs: connection)

    with pytest.raises(RecoveryError, match="outside the approved recovery boundary"):
        recovery.run(config)

    assert not any(statement.startswith("UPDATE ") for statement in connection.statements)


def test_capture_gate_allows_only_evidence_linked_synthetic_receipts() -> None:
    query = " ".join(recovery._CAPTURE_SAFETY_QUERY.split())
    assert "WHERE r.capture_enabled AND NOT" in query
    assert "^cloud-acceptance-" in query
    assert "source_turn_id=regexp_replace" in query
    assert "e.source_conversation_id='telegram:' || r.source_conversation_id" in query
