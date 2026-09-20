from __future__ import annotations

from contextlib import nullcontext
from typing import Any
from uuid import uuid4

import pytest

from lucy.shared_execution import postgres_ledger
from lucy.shared_execution.postgres_ledger import (
    DispatchBlocked,
    LedgerScope,
    PostgresExecutionLedger,
    RecoveryWitness,
)


class _Result:
    def __init__(self, row: Any) -> None:
        self.row = row

    def fetchone(self) -> Any:
        return self.row


class _Connection:
    def __init__(self, witness: RecoveryWitness, *, attestation_current: bool = False) -> None:
        self.witness = witness
        self.attestation_current = attestation_current
        self.statements: list[str] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def transaction(self) -> Any:
        return nullcontext()

    def execute(self, statement: str, params: Any = None) -> _Result:
        del params
        self.statements.append(statement)
        if "FROM tiamat.restore_gate" in statement:
            return _Result(
                {
                    "storage_epoch": self.witness.storage_epoch,
                    "recovery_generation": self.witness.recovery_generation,
                    "coordinator_generation": 7,
                    "dispatch_blocked": False,
                }
            )
        if "tiamat.verify_attestation_current" in statement:
            return _Result({"current": self.attestation_current})
        if "to_regprocedure" in statement:
            return _Result({"pre_d1": False})
        if "tiamat.consume_startup_attestation" in statement:
            return _Result((7,))
        return _Result(None)


def _ledger() -> tuple[PostgresExecutionLedger, RecoveryWitness]:
    witness = RecoveryWitness("staging", uuid4(), 2)
    return PostgresExecutionLedger("postgresql://synthetic", witness), witness


def test_default_runtime_refuses_legacy_coordinator_acquisition() -> None:
    ledger, _ = _ledger()
    with pytest.raises(DispatchBlocked, match="attestation is required"):
        ledger.acquire_coordinator_generation()


def test_legacy_test_path_refuses_a_d1_database(monkeypatch: pytest.MonkeyPatch) -> None:
    _, witness = _ledger()
    connection = _Connection(witness)
    monkeypatch.setattr(postgres_ledger.psycopg, "connect", lambda *_a, **_kw: connection)
    ledger = PostgresExecutionLedger(
        "postgresql://synthetic", witness, legacy_pre_d1_test_only=True
    )

    with pytest.raises(DispatchBlocked, match="disabled on a D1 database"):
        ledger.acquire_coordinator_generation()
    assert not any("UPDATE tiamat.restore_gate" in sql for sql in connection.statements)


def test_consume_rejects_unshaped_digest_before_database_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger, _ = _ledger()
    monkeypatch.setattr(
        postgres_ledger.psycopg,
        "connect",
        lambda *_args, **_kwargs: pytest.fail("invalid digest reached the database"),
    )
    with pytest.raises(ValueError, match="lowercase sha256"):
        ledger.consume_startup_attestation("not-a-digest")


def test_attested_acquisition_calls_single_database_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger, witness = _ledger()
    connection = _Connection(witness)
    monkeypatch.setattr(postgres_ledger.psycopg, "connect", lambda *_a, **_kw: connection)

    assert ledger.consume_startup_attestation("a" * 64) == 7
    assert sum("tiamat.consume_startup_attestation" in sql for sql in connection.statements) == 1
    assert not any("UPDATE tiamat.restore_gate" in sql for sql in connection.statements)


def test_dispatch_rechecks_attestation_before_mutating_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger, witness = _ledger()
    connection = _Connection(witness, attestation_current=False)
    monkeypatch.setattr(postgres_ledger.psycopg, "connect", lambda *_a, **_kw: connection)
    scope = LedgerScope("issuer", "caller", "realm", "staging", "partition")

    with pytest.raises(DispatchBlocked, match="no longer current"):
        ledger.dispatch(
            scope,
            uuid4(),
            coordinator_generation=7,
            record_generation=1,
            owner_id=uuid4(),
        )
    assert any("tiamat.verify_attestation_current" in sql for sql in connection.statements)
    assert not any("UPDATE tiamat.execution_records" in sql for sql in connection.statements)


def test_legacy_dispatch_cannot_bypass_d1_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, witness = _ledger()
    connection = _Connection(witness)
    monkeypatch.setattr(postgres_ledger.psycopg, "connect", lambda *_a, **_kw: connection)
    ledger = PostgresExecutionLedger(
        "postgresql://synthetic", witness, legacy_pre_d1_test_only=True
    )
    scope = LedgerScope("issuer", "caller", "realm", "staging", "partition")

    with pytest.raises(DispatchBlocked, match="disabled on a D1 database"):
        ledger.dispatch(
            scope,
            uuid4(),
            coordinator_generation=7,
            record_generation=1,
            owner_id=uuid4(),
        )
    assert not any("UPDATE tiamat.execution_records" in sql for sql in connection.statements)
