from __future__ import annotations

from typing import Any
from uuid import uuid4

import psycopg
import pytest

from lucy.shared_execution.recovery_anchor import RecoveryAnchorIdentity
from lucy.shared_execution.recovery_checkpoint import RecoveryCheckpointRejected
from lucy.shared_execution.startup_attestation import LedgerRecoveryCheckpointSource

DIGEST = "c" * 64


class _Result:
    def __init__(self, row: dict[str, Any] | None) -> None:
        self._row = row

    def fetchone(self) -> dict[str, Any] | None:
        return self._row


class _Connection:
    def __init__(self, row: dict[str, Any] | None, *, failure: Exception | None = None) -> None:
        self.row = row
        self.failure = failure
        self.executed: list[str] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, query: str, params: tuple[Any, ...] | None = None) -> _Result:
        normalized = " ".join(query.split())
        self.executed.append(normalized)
        if "set_config" in normalized:
            return _Result(None)
        if self.failure is not None:
            raise self.failure
        return _Result(self.row)


def _source(monkeypatch: pytest.MonkeyPatch, connection: _Connection) -> Any:
    monkeypatch.setattr(
        "lucy.shared_execution.startup_attestation.psycopg.connect",
        lambda *_args, **_kwargs: connection,
    )
    return LedgerRecoveryCheckpointSource("postgresql://recovery@example/tiamat")


def test_the_digest_comes_from_the_generation_the_gate_is_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    connection = _Connection(
        {
            "checkpoint_sha256": DIGEST,
            "ledger_id": identity.ledger_id,
            "storage_epoch": identity.storage_epoch,
            "release_inventory": {"generation": 1, "jws_sha256": "b" * 64},
        }
    )

    retained = _source(monkeypatch, connection).read_checkpoint(identity)

    assert retained.checkpoint_sha256 == DIGEST
    assert retained.release_inventory_installed
    joined = " ".join(connection.executed)
    assert "JOIN tiamat.recovery_checkpoints" in joined
    assert "bound.recovery_generation = gate.recovery_generation" in joined


def test_a_generation_without_a_retained_checkpoint_yields_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())

    with pytest.raises(RecoveryCheckpointRejected, match="checkpoint_binding_absent"):
        _source(monkeypatch, _Connection(None)).read_checkpoint(identity)


def test_a_checkpoint_bound_to_another_ledger_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    connection = _Connection(
        {
            "checkpoint_sha256": DIGEST,
            "release_inventory": {"generation": 1, "jws_sha256": "b" * 64},
            "ledger_id": uuid4(),
            "storage_epoch": identity.storage_epoch,
        }
    )

    with pytest.raises(RecoveryCheckpointRejected, match="identity_mismatch"):
        _source(monkeypatch, connection).read_checkpoint(identity)


def test_a_checkpoint_from_another_storage_epoch_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    connection = _Connection(
        {
            "checkpoint_sha256": DIGEST,
            "release_inventory": {"generation": 1, "jws_sha256": "b" * 64},
            "ledger_id": identity.ledger_id,
            "storage_epoch": uuid4(),
        }
    )

    with pytest.raises(RecoveryCheckpointRejected, match="identity_mismatch"):
        _source(monkeypatch, connection).read_checkpoint(identity)


def test_an_unreachable_ledger_is_a_rejection_the_issuer_can_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    connection = _Connection(None, failure=psycopg.OperationalError("unreachable"))

    with pytest.raises(RecoveryCheckpointRejected, match="checkpoint_binding_unavailable"):
        _source(monkeypatch, connection).read_checkpoint(identity)
