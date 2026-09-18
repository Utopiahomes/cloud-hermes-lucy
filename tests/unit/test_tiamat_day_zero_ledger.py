from __future__ import annotations

import importlib.util
import sys
from contextlib import nullcontext
from pathlib import Path
from types import ModuleType
from uuid import UUID, uuid4

import pytest

from lucy.shared_execution import recovery

ROOT = Path(__file__).resolve().parents[2]


class _Connection:
    def __init__(self, *, ledger_id: UUID, storage_epoch: UUID, occupied: bool = False) -> None:
        self.ledger_id = ledger_id
        self.storage_epoch = storage_epoch
        self.occupied = occupied

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def transaction(self) -> object:
        return nullcontext()

    def execute(self, statement: str, params: object = None) -> _Result:
        del params
        normalized = " ".join(statement.split())
        if "SELECT ledger_id FROM tiamat.ledger_identity" in normalized:
            return _Result((self.ledger_id,))
        if "SELECT count(*) FROM tiamat." in normalized:
            return _Result((1 if self.occupied else 0,))
        if "SELECT storage_epoch, recovery_generation" in normalized:
            return _Result(
                (self.storage_epoch, 1, True, "initial_reconciliation_required")
            )
        return _Result(None)


class _Result:
    def __init__(self, row: tuple[object, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...] | None:
        return self._row


def _deploy_module(name: str) -> ModuleType:
    path = ROOT / "deploy" / "postgres" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_initialization_returns_database_owned_identity_and_empty_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_id, storage_epoch = uuid4(), uuid4()
    connection = _Connection(ledger_id=ledger_id, storage_epoch=storage_epoch)
    monkeypatch.setattr(recovery.psycopg, "connect", lambda _: connection)

    identity = recovery.initialize_environment(
        "postgresql://synthetic",
        environment="staging",
        storage_epoch=storage_epoch,
        recovery_generation=1,
    )
    initializer = _deploy_module("initialize_tiamat_ledger_v1")
    monkeypatch.setattr(initializer, "initialize_environment", lambda *_, **__: identity)
    checkpoint = initializer.initialize_day_zero(
        database_url="postgresql://synthetic",
        environment="staging",
        storage_epoch=storage_epoch,
        recovery_generation=1,
    )

    assert identity.ledger_id == ledger_id
    assert checkpoint == {
        "environment": "staging",
        "ledger_id": str(ledger_id),
        "storage_epoch": str(storage_epoch),
        "recovery_generation": 1,
        "release_inventory": {"state": "not_installed"},
        "release_heads": [],
        "settlement_position": [],
    }


def test_initialization_refuses_nonempty_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _Connection(ledger_id=uuid4(), storage_epoch=uuid4(), occupied=True)
    monkeypatch.setattr(recovery.psycopg, "connect", lambda _: connection)

    with pytest.raises(recovery.RecoveryRejected, match="empty execution ledger"):
        recovery.initialize_environment(
            "postgresql://synthetic",
            environment="staging",
            storage_epoch=connection.storage_epoch,
            recovery_generation=1,
        )


def test_command_requires_exact_initialization_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage_epoch = uuid4()
    initializer = _deploy_module("initialize_tiamat_ledger_v1")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "initialize_tiamat_ledger_v1.py",
            "--database-url",
            "postgresql://synthetic",
            "--environment",
            "staging",
            "--storage-epoch",
            str(storage_epoch),
            "--recovery-generation",
            "1",
        ],
    )
    monkeypatch.setattr(
        initializer,
        "initialize_day_zero",
        lambda **_: pytest.fail("initializer must not write without confirmation"),
    )

    with pytest.raises(ValueError, match="confirmation must equal"):
        initializer.main()
