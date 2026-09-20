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
