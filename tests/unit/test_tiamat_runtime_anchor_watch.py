from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from lucy.shared_execution.recovery_anchor import (
    PostgresContinuityBeacon,
    RecoveryAnchorIdentity,
    RecoveryAnchorKey,
    RecoveryAnchorRejected,
    VerifiedAnchorTransition,
    VerifiedRecoveryWitness,
)
from lucy.shared_execution.runtime_anchor_watch import (
    RuntimeAnchorWatch,
    RuntimeAuthorityClosed,
)

NOW = datetime(2026, 9, 22, 12, tzinfo=UTC)
CHECKPOINT = "a" * 64


def _transition(
    identity: RecoveryAnchorIdentity,
    *,
    continuity: str = "continuity_established",
    status: str = "reconciled",
    not_after: datetime = NOW + timedelta(hours=1),
    body: bytes = b"runtime-watch-transition",
) -> VerifiedAnchorTransition:
    witness = VerifiedRecoveryWitness(
        identity=identity,
        recovery_generation=1,
        witness_revision=1,
        status=status,  # type: ignore[arg-type]
        checkpoint_digest=CHECKPOINT,
        release_heads_sha256="b" * 64,
        checkpoint_settlement_position_sha256="c" * 64,
        witness_inventory_digest="d" * 64,
        exact_jws=b"runtime-watch-witness",
        not_before=NOW - timedelta(minutes=5),
        not_after=not_after,
    )
    return VerifiedAnchorTransition(
        witness=witness,
        transition_version=1,
        previous_transition_sha256=None,
        continuity=continuity,  # type: ignore[arg-type]
        beacon=PostgresContinuityBeacon("1", 1, "0/100", CHECKPOINT)
        if continuity == "continuity_established"
        else None,
        exact_jws=body,
    )


class _Anchor:
    def __init__(self, result: VerifiedAnchorTransition | Exception) -> None:
        self.result = result

    def read(self, key: RecoveryAnchorKey) -> VerifiedAnchorTransition:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def install(self, *args: object, **kwargs: object) -> VerifiedAnchorTransition:
        raise AssertionError("a watching process never writes the anchor")


class _Ledger:
    def __init__(self, *, failing: bool = False) -> None:
        self.blocked: list[str] = []
        self.failing = failing

    def block_dispatch(self, reason: str) -> None:
        if self.failing:
            raise RuntimeError("ledger unreachable")
        self.blocked.append(reason)


def _watch(
    anchor: _Anchor, ledger: _Ledger, *, consumed: str | None = None, now: datetime = NOW
) -> RuntimeAnchorWatch:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    current = _transition(identity)
    return RuntimeAnchorWatch(
        anchor=anchor,
        identity=identity,
        consumed_transition_sha256=consumed or current.exact_sha256,
        ledger=ledger,
        clock=lambda: now,
    )


def test_matching_established_authority_keeps_dispatch_open() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    transition = _transition(identity)
    ledger = _Ledger()
    watch = RuntimeAnchorWatch(
        anchor=_Anchor(transition),
        identity=identity,
        consumed_transition_sha256=transition.exact_sha256,
        ledger=ledger,
        clock=lambda: NOW,
    )

    assert watch.refresh() == "authority_current"
    assert watch.closed_reason is None
    watch.require_open()
    assert ledger.blocked == []


def test_an_unavailable_anchor_preserves_the_verified_interval() -> None:
    """An outage is not a withdrawal: only the claimant's own bound still applies."""

    ledger = _Ledger()
    watch = _watch(_Anchor(RecoveryAnchorRejected("recovery_anchor_unavailable")), ledger)

    assert watch.refresh() == "anchor_unavailable"
    assert watch.closed_reason is None
    assert ledger.blocked == []


def test_an_unverifiable_record_closes_dispatch() -> None:
    """A record which cannot be verified is not authority, so it fails closed."""

    ledger = _Ledger()
    watch = _watch(_Anchor(RecoveryAnchorRejected("recovery_anchor_record_invalid")), ledger)

    assert watch.refresh() == "authority_withdrawn"
    assert watch.closed_reason == "recovery_anchor_unverifiable"
    assert ledger.blocked == ["recovery_anchor_unverifiable"]
    with pytest.raises(RuntimeAuthorityClosed):
        watch.require_open()


def test_an_observed_quarantine_closes_dispatch_and_blocks_the_gate() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    consumed = _transition(identity)
    quarantined = _transition(
        identity, continuity="quarantined", status="quarantined", body=b"quarantine-transition"
    )
    ledger = _Ledger()
    watch = RuntimeAnchorWatch(
        anchor=_Anchor(quarantined),
        identity=identity,
        consumed_transition_sha256=consumed.exact_sha256,
        ledger=ledger,
        clock=lambda: NOW,
    )

    assert watch.refresh() == "authority_withdrawn"
    # The head moved, which is enough on its own: this process's authority came from the record
    # it consumed, whatever the new one says.
    assert watch.closed_reason == "recovery_anchor_superseded"
    assert ledger.blocked == ["recovery_anchor_superseded"]


def test_the_same_record_turning_quarantined_closes_dispatch() -> None:
    """Continuity is checked even when the stored bytes are the ones this process consumed."""

    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    quarantined = _transition(identity, continuity="quarantined", status="quarantined")
    ledger = _Ledger()
    watch = RuntimeAnchorWatch(
        anchor=_Anchor(quarantined),
        identity=identity,
        consumed_transition_sha256=quarantined.exact_sha256,
        ledger=ledger,
        clock=lambda: NOW,
    )

    assert watch.refresh() == "authority_withdrawn"
    assert watch.closed_reason == "recovery_continuity_withdrawn"


def test_an_expired_witness_closes_dispatch() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    transition = _transition(identity)
    ledger = _Ledger()
    watch = RuntimeAnchorWatch(
        anchor=_Anchor(transition),
        identity=identity,
        consumed_transition_sha256=transition.exact_sha256,
        ledger=ledger,
        clock=lambda: NOW + timedelta(hours=2),
    )

    assert watch.refresh() == "authority_withdrawn"
    assert watch.closed_reason == "recovery_witness_not_current"


def test_a_failed_gate_write_does_not_reopen_the_local_latch() -> None:
    """Draft 0.5 section 6: failure to write the database never reopens the latch."""

    ledger = _Ledger(failing=True)
    watch = _watch(_Anchor(RecoveryAnchorRejected("recovery_anchor_record_invalid")), ledger)

    assert watch.refresh() == "authority_withdrawn"
    assert watch.closed_reason == "recovery_anchor_unverifiable"
    with pytest.raises(RuntimeAuthorityClosed):
        watch.require_open()


def test_a_closed_latch_keeps_its_first_reason() -> None:
    """The first observation is the one that matters; later ones do not relabel it."""

    ledger = _Ledger()
    watch = _watch(_Anchor(RecoveryAnchorRejected("recovery_anchor_record_invalid")), ledger)
    watch.refresh()
    watch.close("something_else")

    assert watch.closed_reason == "recovery_anchor_unverifiable"
