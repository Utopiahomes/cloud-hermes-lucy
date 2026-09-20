from __future__ import annotations

from contextlib import nullcontext
from typing import Any
from uuid import uuid4

import pytest

from lucy.shared_execution.recovery import (
    AnchorFloorRecord,
    RecoveryRejected,
    authorize_reconciled_state,
    quarantine_environment,
)
from lucy.shared_execution.recovery_anchor import (
    RecoveryAnchorRejected,
    require_monotonic_anchor_floor,
)

FIRST = "a" * 64
SECOND = "b" * 64


class _Result:
    def __init__(self, rows: list[tuple[Any, ...]] | None = None, rowcount: int = 1) -> None:
        self._rows = rows or []
        self.rowcount = rowcount

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows


class _Connection:
    """Answer only the statements these recovery-gate commands actually issue."""

    def __init__(
        self,
        *,
        storage_epoch: Any,
        floor_supported: bool = True,
        floor_version: int = 0,
        floor_digest: str | None = None,
        recovery_generation: int = 1,
    ) -> None:
        self.storage_epoch = storage_epoch
        self.floor_supported = floor_supported
        self.floor_version = floor_version
        self.floor_digest = floor_digest
        self.recovery_generation = recovery_generation
        self.executed: list[str] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def transaction(self) -> Any:
        return nullcontext()

    def execute(self, query: str, params: tuple[Any, ...] | None = None) -> _Result:
        normalized = " ".join(query.split())
        self.executed.append(normalized)
        if "information_schema.columns" in normalized:
            return _Result([(1 if self.floor_supported else 0,)])
        if "SELECT anchor_floor_version" in normalized:
            return _Result([(self.floor_version, self.floor_digest)])
        if "SET anchor_floor_version" in normalized:
            return _Result()
        if "SELECT storage_epoch" in normalized:
            return _Result([(self.storage_epoch, self.recovery_generation, True)])
        if "settlement_status = 'pending_reconciliation'" in normalized:
            return _Result([(0,)])
        if "FROM tiamat.trust_inventories" in normalized:
            return _Result([])
        if "FROM tiamat.release_heads" in normalized:
            return _Result([])
        if normalized.startswith("UPDATE tiamat."):
            return _Result()
        raise AssertionError(f"unexpected query: {normalized}")

    @property
    def floor_writes(self) -> list[str]:
        return [query for query in self.executed if "SET anchor_floor_version" in query]


def _patch(monkeypatch: pytest.MonkeyPatch, connection: _Connection) -> None:
    monkeypatch.setattr(
        "lucy.shared_execution.recovery.psycopg.connect",
        lambda *_args, **_kwargs: connection,
    )


def test_floor_rule_advances_only_upward() -> None:
    assert require_monotonic_anchor_floor(
        current_version=0, current_sha256=None, candidate_version=1, candidate_sha256=FIRST
    )
    assert require_monotonic_anchor_floor(
        current_version=1, current_sha256=FIRST, candidate_version=2, candidate_sha256=SECOND
    )
    assert not require_monotonic_anchor_floor(
        current_version=2, current_sha256=SECOND, candidate_version=2, candidate_sha256=SECOND
    )


@pytest.mark.parametrize(
    ("candidate_version", "candidate_sha256"),
    [(1, FIRST), (2, FIRST)],
)
def test_floor_rule_rejects_rollback_and_conflicting_bytes(
    candidate_version: int, candidate_sha256: str
) -> None:
    with pytest.raises(RecoveryAnchorRejected, match="recovery_anchor_floor_rollback"):
        require_monotonic_anchor_floor(
            current_version=2,
            current_sha256=SECOND,
            candidate_version=candidate_version,
            candidate_sha256=candidate_sha256,
        )


def test_floor_rule_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        require_monotonic_anchor_floor(
            current_version=0, current_sha256=None, candidate_version=0, candidate_sha256=FIRST
        )
    with pytest.raises(ValueError):
        require_monotonic_anchor_floor(
            current_version=1, current_sha256=None, candidate_version=2, candidate_sha256=SECOND
        )


def test_quarantine_records_the_anchor_it_was_performed_under(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _Connection(storage_epoch=uuid4())
    _patch(monkeypatch, connection)

    quarantine_environment(
        "postgresql://recovery@example/tiamat",
        environment="staging",
        reason="restore_review",
        anchor_floor=AnchorFloorRecord(transition_version=2, transition_sha256=SECOND),
    )

    assert connection.floor_writes
    assert any("dispatch_blocked = true" in query for query in connection.executed)


def test_quarantine_on_a_d1_ledger_requires_an_anchor_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _Connection(storage_epoch=uuid4())
    _patch(monkeypatch, connection)

    with pytest.raises(RecoveryRejected, match="anchor floor record is required"):
        quarantine_environment(
            "postgresql://recovery@example/tiamat",
            environment="staging",
            reason="restore_review",
        )

    assert not any("dispatch_blocked = true" in query for query in connection.executed)


def test_quarantine_rejects_a_floor_below_the_stored_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _Connection(storage_epoch=uuid4(), floor_version=3, floor_digest=SECOND)
    _patch(monkeypatch, connection)

    with pytest.raises(RecoveryRejected, match="anchor floor cannot move backward"):
        quarantine_environment(
            "postgresql://recovery@example/tiamat",
            environment="staging",
            reason="restore_review",
            anchor_floor=AnchorFloorRecord(transition_version=2, transition_sha256=FIRST),
        )

    assert not connection.floor_writes


def test_pre_d1_ledger_keeps_its_existing_quarantine_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _Connection(storage_epoch=uuid4(), floor_supported=False)
    _patch(monkeypatch, connection)

    quarantine_environment(
        "postgresql://recovery@example/tiamat",
        environment="staging",
        reason="restore_review",
    )

    assert not connection.floor_writes
    assert any("dispatch_blocked = true" in query for query in connection.executed)

    with pytest.raises(RecoveryRejected, match="does not record an anchor floor"):
        quarantine_environment(
            "postgresql://recovery@example/tiamat",
            environment="staging",
            reason="restore_review",
            anchor_floor=AnchorFloorRecord(transition_version=1, transition_sha256=FIRST),
        )


def test_authorize_records_the_anchor_it_was_performed_under(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage_epoch = uuid4()
    connection = _Connection(storage_epoch=storage_epoch, floor_version=1, floor_digest=FIRST)
    _patch(monkeypatch, connection)

    authorize_reconciled_state(
        "postgresql://recovery@example/tiamat",
        environment="staging",
        expected_storage_epoch=storage_epoch,
        current_recovery_generation=1,
        next_recovery_generation=2,
        unresolved_provider_liabilities=0,
        anchor_floor=AnchorFloorRecord(transition_version=2, transition_sha256=SECOND),
    )

    assert connection.floor_writes
    assert any("dispatch_blocked = false" in query for query in connection.executed)


def test_authorize_on_a_d1_ledger_requires_an_anchor_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage_epoch = uuid4()
    connection = _Connection(storage_epoch=storage_epoch)
    _patch(monkeypatch, connection)

    with pytest.raises(RecoveryRejected, match="anchor floor record is required"):
        authorize_reconciled_state(
            "postgresql://recovery@example/tiamat",
            environment="staging",
            expected_storage_epoch=storage_epoch,
            current_recovery_generation=1,
            next_recovery_generation=2,
            unresolved_provider_liabilities=0,
        )

    assert not any("dispatch_blocked = false" in query for query in connection.executed)
