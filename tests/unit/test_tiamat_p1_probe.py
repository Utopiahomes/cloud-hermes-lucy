from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import psycopg
import pytest

ROOT = Path(__file__).resolve().parents[2]


def _module() -> ModuleType:
    path = ROOT / "deploy" / "postgres" / "probe_tiamat_p1_v1.py"
    spec = importlib.util.spec_from_file_location("probe_tiamat_p1_v1", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _Connection:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, statement: str) -> _Connection:
        self.statements.append(statement)
        return self


def test_each_probe_rolls_back_success_and_permission_failure() -> None:
    module = _module()
    connection = _Connection()
    result = module._attempt(connection, lambda: True)
    assert result == {"supported": True}
    assert connection.statements == [
        "SAVEPOINT p1_probe",
        "ROLLBACK TO SAVEPOINT p1_probe",
        "RELEASE SAVEPOINT p1_probe",
    ]

    connection.statements.clear()

    def rejected() -> None:
        raise psycopg.errors.InsufficientPrivilege("denied")

    result = module._attempt(connection, rejected)
    assert result == {"supported": False, "sqlstate": "42501"}
    assert connection.statements == [
        "SAVEPOINT p1_probe",
        "ROLLBACK TO SAVEPOINT p1_probe",
        "RELEASE SAVEPOINT p1_probe",
    ]


def test_probe_refuses_non_tls_owner_url(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    monkeypatch.setenv("TIAMAT_P1_OWNER_DATABASE_URL", "postgresql://owner:secret@private/tiamat")
    with pytest.raises(ValueError, match="must require TLS"):
        module.run(expected_ledger="6177502f-3a93-429c-b68b-0ed726d1447f")


def test_gate_diagnostic_is_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    ledger = "6177502f-3a93-429c-b68b-0ed726d1447f"
    statements: list[str] = []

    class _Cursor:
        def __init__(self, rows: list[tuple[object, ...]]) -> None:
            self.rows = rows

        def fetchone(self) -> tuple[object, ...]:
            return self.rows[0]

        def fetchall(self) -> list[tuple[object, ...]]:
            return self.rows

    class _ReadOnlyConnection:
        def __enter__(self) -> _ReadOnlyConnection:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def execute(self, statement: str) -> _Cursor:
            statements.append(statement)
            if statement.startswith("SET LOCAL tiamat.environment"):
                return _Cursor([])
            if "ledger_identity" in statement:
                return _Cursor([(ledger,)])
            if "restore_gate" in statement:
                return _Cursor([("staging", True)])
            if "pg_stat_ssl" in statement:
                return _Cursor([(True,)])
            raise AssertionError("unexpected statement")

    monkeypatch.setenv(
        "TIAMAT_P1_OWNER_DATABASE_URL",
        "postgresql://owner:private@db/tiamat?sslmode=require",
    )
    monkeypatch.setattr(module.psycopg, "connect", lambda *_args, **_kwargs: _ReadOnlyConnection())
    result = module.diagnose_gate(expected_ledger=ledger)
    assert result["staging_gate_blocked"] is True
    assert len(statements) == 4
    assert statements[0] == "SET LOCAL tiamat.environment = 'staging'"
    assert all(statement.lstrip().upper().startswith("SELECT") for statement in statements[1:])


@pytest.mark.parametrize("runtime_can_execute", [True, False])
def test_revoke_requires_effective_runtime_privilege_change(runtime_can_execute: bool) -> None:
    module = _module()

    class _Cursor:
        def fetchone(self) -> tuple[bool]:
            return (runtime_can_execute,)

    class _Connection:
        def __init__(self) -> None:
            self.calls = 0

        def execute(self, _statement: object, _params: object = None) -> _Cursor:
            self.calls += 1
            return _Cursor()

    connection = _Connection()
    effective = module._revoke_effective(connection, "pg_control_system")
    assert effective is (not runtime_can_execute)
    assert connection.calls == 2
