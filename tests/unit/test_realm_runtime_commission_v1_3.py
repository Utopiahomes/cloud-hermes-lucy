from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

import deploy.postgres.commission_realm_runtime_v1_3 as commission
from tests.unit.test_realm_cloud_bootstrap_v1_3 import HOST, _stamp


def _environment() -> dict[str, str]:
    stamp = _stamp()
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_MIGRATION_DATABASE_URL": (
            f"postgresql://lucy_migration:migration-secret@{HOST}:5432/lucy_example"
        ),
        "LUCY_REALM_SECURITY_STAMP_JSON": stamp.model_dump_json(),
        "LUCY_REALM_SECURITY_STAMP_SHA256": stamp.digest_hex(),
        "LUCY_STORAGE_EPOCH": str(uuid4()),
    }


def test_config_keeps_realm_epoch_distinct_from_runtime_epoch() -> None:
    environment = _environment()
    config = commission.CommissionConfig.from_environment("open", environment)
    assert config.stamp is not None
    assert config.runtime_epoch is not None
    assert config.stamp.storage_epoch == 1
    assert str(config.runtime_epoch) == environment["LUCY_STORAGE_EPOCH"]
    assert config.migration_url.query["sslmode"] == "require"


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("RENDER", "false", "production Render"),
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true", "capture must remain disabled"),
        (
            "LUCY_MIGRATION_DATABASE_URL",
            "postgresql://lucy_migration:x@public.example.com/lucy_example",
            "private Render",
        ),
        ("LUCY_STORAGE_EPOCH", "1", "commissioning input is invalid"),
    ],
)
def test_config_fails_closed(key: str, value: str, message: str) -> None:
    environment = _environment()
    environment[key] = value
    with pytest.raises(commission.CommissionError, match=message):
        commission.CommissionConfig.from_environment("open", environment)


def test_each_action_has_a_distinct_exact_authorization() -> None:
    assert set(commission.AUTHORIZATIONS) == {"status", "open", "quarantine"}
    assert len(set(commission.AUTHORIZATIONS.values())) == 3


def test_synthetic_capture_receipt_exceptions_are_exact_and_named() -> None:
    approved = commission._approved_synthetic_receipts(
        '[{"source_conversation_id":"synthetic-commission-1",'
        '"source_turn_id":"synthetic-turn-1"}]'
    )
    assert approved == frozenset({("synthetic-commission-1", "synthetic-turn-1")})
    with pytest.raises(commission.CommissionError, match="invalid"):
        commission._approved_synthetic_receipts(
            '[{"source_conversation_id":"real-customer",'
            '"source_turn_id":"synthetic-turn-1"}]'
        )


class _Connection:
    def __init__(self) -> None:
        self.statements: list[tuple[str, object | None]] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, params: object | None = None) -> Any:
        self.statements.append((statement, params))
        return self


def _patched_connection(
    monkeypatch: pytest.MonkeyPatch,
    *,
    state: str = "quarantined",
    pending: int = 0,
    sessions: int = 0,
) -> tuple[commission.CommissionConfig, _Connection]:
    config = commission.CommissionConfig.from_environment("open", _environment())
    connection = _Connection()
    monkeypatch.setattr(commission.psycopg, "connect", lambda _url: connection)
    monkeypatch.setattr(
        commission,
        "_verify_target_boundary",
        lambda *_args: (state, config.runtime_epoch if state == "ready" else None),
    )
    monkeypatch.setattr(commission, "_verify_reviewed_revision", lambda *_args: None)
    monkeypatch.setattr(commission, "_work_in_flight", lambda *_args: pending)
    monkeypatch.setattr(commission, "_finality_pending", lambda *_args: 0)
    monkeypatch.setattr(commission, "_capture_blockers", lambda *_args: ())
    monkeypatch.setattr(commission, "_verify_open_boundary", lambda *_args: None)
    monkeypatch.setattr(commission, "_runtime_sessions", lambda *_args: sessions)
    return config, connection


def test_open_is_exactly_authorized_and_blocks_unresolved_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, connection = _patched_connection(monkeypatch, pending=1)
    with pytest.raises(commission.CommissionError, match="unresolved"):
        commission.run(config, "open", commission.AUTHORIZATIONS["open"])
    assert not any("UPDATE lucy.runtime_admission" in sql for sql, _ in connection.statements)


def test_open_sets_only_the_independent_runtime_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    config, connection = _patched_connection(monkeypatch)
    report = commission.run(config, "open", commission.AUTHORIZATIONS["open"])
    updates = [(sql, params) for sql, params in connection.statements if sql.startswith("UPDATE")]
    assert updates == [
        (
            "UPDATE lucy.runtime_admission SET state='ready',storage_epoch=%s,updated_at=now() "
            "WHERE singleton",
            (config.runtime_epoch,),
        )
    ]
    assert report["runtime_admission"] == "ready"
    assert report["capture_enabled"] is False


def test_quarantine_does_not_rotate_the_runtime_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    environment = _environment()
    for key in (
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED",
        "LUCY_REALM_SECURITY_STAMP_JSON",
        "LUCY_REALM_SECURITY_STAMP_SHA256",
        "LUCY_STORAGE_EPOCH",
    ):
        environment.pop(key)
    config = commission.CommissionConfig.from_environment("quarantine", environment)
    connection = _Connection()
    monkeypatch.setattr(commission.psycopg, "connect", lambda _url: connection)
    monkeypatch.setattr(
        commission,
        "_verify_target_boundary",
        lambda *_args: ("ready", uuid4()),
    )
    report = commission.run(
        config, "quarantine", commission.AUTHORIZATIONS["quarantine"]
    )
    updates = [sql for sql, _ in connection.statements if sql.startswith("UPDATE")]
    assert updates == [
        "UPDATE lucy.runtime_admission SET state='quarantined',updated_at=now() WHERE singleton"
    ]
    assert report["runtime_admission"] == "quarantined"


def test_quarantine_config_does_not_require_capture_or_realm_material() -> None:
    environment = _environment()
    for key in (
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED",
        "LUCY_REALM_SECURITY_STAMP_JSON",
        "LUCY_REALM_SECURITY_STAMP_SHA256",
        "LUCY_STORAGE_EPOCH",
    ):
        environment.pop(key)
    config = commission.CommissionConfig.from_environment("quarantine", environment)
    assert config.stamp is None
    assert config.runtime_epoch is None
    assert config.declared_capture_enabled is None
    assert config.approved_synthetic_receipts == frozenset()


def test_wrong_authorization_never_opens_a_database_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = commission.CommissionConfig.from_environment("open", _environment())
    monkeypatch.setattr(
        commission.psycopg,
        "connect",
        lambda _url: pytest.fail("database must not be opened"),
    )
    with pytest.raises(commission.CommissionError, match="exact commissioning"):
        commission.run(config, "open", "wrong")


class _Rows:
    def __init__(self, rows: list[tuple[object, ...]]) -> None:
        self._rows = rows

    def fetchone(self) -> tuple[object, ...] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[tuple[object, ...]]:
        return self._rows


class _CaptureConnection:
    def __init__(self, enabled_receipts: list[tuple[object, ...]]) -> None:
        self._enabled_receipts = enabled_receipts

    def execute(self, statement: str, _params: object | None = None) -> _Rows:
        if "NOT lucy.capture_boundary_safe_v1" in statement:
            return _Rows([(False,)])
        if "scoped_capture_states_v1" in statement:
            return _Rows([(False,)])
        if "scoped_capture_receipts_v1" in statement:
            return _Rows(self._enabled_receipts)
        raise AssertionError("unexpected capture query")


def test_scoped_capture_blocks_open_unless_every_enabled_receipt_is_exactly_approved() -> None:
    environment = _environment()
    config = commission.CommissionConfig.from_environment("open", environment)
    receipt = ("synthetic-commission-1", "synthetic-turn-1")
    assert commission._capture_enabled(_CaptureConnection([receipt]), config) is True  # type: ignore[arg-type]
    environment["LUCY_APPROVED_SYNTHETIC_CAPTURE_RECEIPTS_JSON"] = (
        '[{"source_conversation_id":"synthetic-commission-1",'
        '"source_turn_id":"synthetic-turn-1"}]'
    )
    config = commission.CommissionConfig.from_environment("open", environment)
    assert commission._capture_enabled(_CaptureConnection([receipt]), config) is False  # type: ignore[arg-type]


def test_capture_blockers_are_content_free_and_specific() -> None:
    environment = _environment()
    config = commission.CommissionConfig.from_environment("open", environment)
    receipt = ("synthetic-commission-1", "synthetic-turn-1")
    connection = _CaptureConnection([receipt])
    connection.execute = lambda statement, _params=None: (  # type: ignore[method-assign]
        _Rows([(True,)])
        if "NOT lucy.capture_boundary_safe_v1" in statement
        else _Rows([(True,)])
        if "scoped_capture_states_v1" in statement
        else _Rows([receipt])
    )
    assert commission._capture_blockers(connection, config) == (  # type: ignore[arg-type]
        "legacy_capture_boundary_unsafe",
        "scoped_capture_mode_enabled",
        "unapproved_capture_receipt",
    )
    with pytest.raises(
        commission.CommissionError,
        match="legacy_capture_boundary_unsafe,scoped_capture_mode_enabled,unapproved_capture_receipt",
    ):
        blockers = commission._capture_blockers(connection, config)  # type: ignore[arg-type]
        commission._verify_open_boundary(connection, config, blockers)  # type: ignore[arg-type]


def test_main_never_echoes_unexpected_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "never-print-this-database-secret"
    monkeypatch.setattr(commission.os, "environ", _environment())
    monkeypatch.setattr(
        commission,
        "run",
        lambda *_args: (_ for _ in ()).throw(RuntimeError(secret)),
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "commission_realm_runtime_v1_3",
            "status",
            "--authorization",
            commission.AUTHORIZATIONS["status"],
        ],
    )
    assert commission.main() == 1
    output = capsys.readouterr().out
    assert secret not in output
    assert '"error_type": "RuntimeError"' in output
