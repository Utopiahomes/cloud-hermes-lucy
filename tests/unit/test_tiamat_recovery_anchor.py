from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from lucy.shared_execution.recovery_anchor import (
    InMemoryExternalRecoveryAnchor,
    PostgresContinuityBeacon,
    PostgresContinuityBeaconReader,
    RecoveryAnchorIdentity,
    RecoveryAnchorRejected,
    VerifiedAnchorTransition,
    VerifiedRecoveryWitness,
)

NOW = datetime(2026, 9, 18, 12, tzinfo=UTC)
CHECKPOINT_A = "a" * 64
CHECKPOINT_B = "b" * 64
INVENTORY_A = "c" * 64
INVENTORY_B = "d" * 64


def beacon(*, checkpoint: str = CHECKPOINT_A, lsn: str = "0/100") -> PostgresContinuityBeacon:
    return PostgresContinuityBeacon("test-system", 1, lsn, checkpoint)


def witness(
    identity: RecoveryAnchorIdentity,
    *,
    generation: int = 1,
    revision: int = 1,
    status: str = "reconciled",
    checkpoint: str = CHECKPOINT_A,
    inventory: str = INVENTORY_A,
    expires: datetime = NOW + timedelta(hours=2),
    marker: str = "one",
) -> VerifiedRecoveryWitness:
    return VerifiedRecoveryWitness(
        identity=identity,
        recovery_generation=generation,
        witness_revision=revision,
        status=status,  # type: ignore[arg-type]
        checkpoint_digest=checkpoint,
        release_heads_sha256="e" * 64,
        checkpoint_settlement_position_sha256="f" * 64,
        witness_inventory_digest=inventory,
        exact_jws=f"signed-witness:{generation}:{revision}:{status}:{checkpoint}:{marker}".encode(),
        not_before=NOW - timedelta(minutes=1),
        not_after=expires,
    )


def transition(
    item: VerifiedRecoveryWitness,
    *,
    version: int,
    previous: VerifiedAnchorTransition | None,
    continuity: str,
    item_beacon: PostgresContinuityBeacon | None = None,
    marker: str = "one",
) -> VerifiedAnchorTransition:
    return VerifiedAnchorTransition(
        witness=item,
        transition_version=version,
        previous_transition_sha256=None if previous is None else previous.exact_sha256,
        continuity=continuity,  # type: ignore[arg-type]
        beacon=item_beacon,
        exact_jws=(
            f"signed-anchor:{version}:{continuity}:{item.exact_sha256}:"
            f"{None if previous is None else previous.exact_sha256}:{marker}"
        ).encode(),
    )


def install_first(
    anchor: InMemoryExternalRecoveryAnchor, identity: RecoveryAnchorIdentity
) -> VerifiedAnchorTransition:
    first = transition(
        witness(identity),
        version=1,
        previous=None,
        continuity="continuity_established",
        item_beacon=beacon(),
    )
    return anchor.install(first, expected_transition_sha256=None, now=NOW)


def install_successor(
    anchor: InMemoryExternalRecoveryAnchor, item: VerifiedAnchorTransition
) -> VerifiedAnchorTransition:
    return anchor.install(item, expected_transition_sha256=item.previous_transition_sha256, now=NOW)


def test_ordinary_restart_requires_external_signed_beacon_after_normal_progress() -> None:
    anchor = InMemoryExternalRecoveryAnchor()
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = install_first(anchor, identity)

    restarted = anchor.require_dispatch_authority(
        identity, observed_beacon=beacon(lsn="0/200"), now=NOW + timedelta(minutes=30)
    )

    assert restarted.exact_sha256 == first.witness.exact_sha256


def test_established_transition_binds_the_signed_witness_and_beacon_checkpoint() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())

    with pytest.raises(ValueError, match="established continuity"):
        transition(
            witness(identity, checkpoint=CHECKPOINT_A),
            version=1,
            previous=None,
            continuity="continuity_established",
            item_beacon=beacon(checkpoint=CHECKPOINT_B),
        )


def test_signed_beacon_refresh_preserves_witness_and_allows_later_restart() -> None:
    anchor = InMemoryExternalRecoveryAnchor()
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = install_first(anchor, identity)
    refresh = transition(
        first.witness,
        version=2,
        previous=first,
        continuity="continuity_established",
        item_beacon=beacon(lsn="0/200"),
        marker="beacon-refresh",
    )
    install_successor(anchor, refresh)

    assert anchor.require_dispatch_authority(identity, observed_beacon=beacon(lsn="0/200"), now=NOW)


def test_witness_renewal_can_rotate_its_inventory_without_changing_checkpoint() -> None:
    anchor = InMemoryExternalRecoveryAnchor()
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = install_first(anchor, identity)
    renewal = witness(identity, revision=2, inventory=INVENTORY_B, marker="inventory-rotation")
    renewed = transition(
        renewal,
        version=2,
        previous=first,
        continuity="continuity_established",
        item_beacon=beacon(),
        marker="renewal",
    )
    install_successor(anchor, renewed)

    assert anchor.require_dispatch_authority(identity, observed_beacon=beacon(), now=NOW) == renewal


@pytest.mark.parametrize(
    ("candidate_kwargs", "reason"),
    [
        ({"revision": 2, "checkpoint": CHECKPOINT_B}, "invalid_renewal"),
        ({"generation": 2, "revision": 2}, "first_revision"),
    ],
)
def test_anchor_rejects_invalid_witness_successors(
    candidate_kwargs: dict[str, object], reason: str
) -> None:
    anchor = InMemoryExternalRecoveryAnchor()
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = install_first(anchor, identity)
    candidate = witness(identity, **candidate_kwargs)  # type: ignore[arg-type]
    bad = transition(
        candidate,
        version=2,
        previous=first,
        continuity="continuity_established",
        item_beacon=beacon(checkpoint=str(candidate_kwargs.get("checkpoint", CHECKPOINT_A))),
    )

    with pytest.raises(RecoveryAnchorRejected, match=reason):
        install_successor(anchor, bad)


def test_unsigned_transport_mutation_cannot_change_continuity_or_floor() -> None:
    anchor = InMemoryExternalRecoveryAnchor()
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = install_first(anchor, identity)
    # A caller with only a stale write request cannot manufacture the signed predecessor chain.
    forged = transition(
        first.witness,
        version=2,
        previous=None,
        continuity="recovery_pending",
        marker="forged",
    )
    with pytest.raises(RecoveryAnchorRejected, match="transition_chain_invalid"):
        anchor.install(forged, expected_transition_sha256=first.exact_sha256, now=NOW)


def test_quarantine_requires_recovery_pending_then_signed_continuity_beacon() -> None:
    anchor = InMemoryExternalRecoveryAnchor()
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    first = install_first(anchor, identity)
    quarantined = transition(
        witness(identity, generation=2, status="quarantined", marker="quarantine"),
        version=2,
        previous=first,
        continuity="quarantined",
    )
    install_successor(anchor, quarantined)
    with pytest.raises(RecoveryAnchorRejected, match="continuity_not_established"):
        anchor.require_dispatch_authority(identity, observed_beacon=beacon(), now=NOW)

    pending = transition(
        witness(identity, generation=3, checkpoint=CHECKPOINT_B, marker="reconciled"),
        version=3,
        previous=quarantined,
        continuity="recovery_pending",
    )
    install_successor(anchor, pending)
    established = transition(
        pending.witness,
        version=4,
        previous=pending,
        continuity="continuity_established",
        item_beacon=beacon(checkpoint=CHECKPOINT_B),
    )
    install_successor(anchor, established)

    assert anchor.require_dispatch_authority(
        identity, observed_beacon=beacon(checkpoint=CHECKPOINT_B), now=NOW
    ) == pending.witness


def test_stale_snapshot_beacon_and_expired_or_missing_anchor_fail_closed() -> None:
    anchor = InMemoryExternalRecoveryAnchor()
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    with pytest.raises(RecoveryAnchorRejected, match="unavailable"):
        anchor.require_dispatch_authority(identity, observed_beacon=beacon(), now=NOW)
    first = install_first(anchor, identity)
    with pytest.raises(RecoveryAnchorRejected, match="beacon_mismatch"):
        anchor.require_dispatch_authority(identity, observed_beacon=beacon(lsn="0/0FF"), now=NOW)
    expired = witness(identity, generation=2, expires=NOW - timedelta(seconds=1))
    blocked = transition(expired, version=2, previous=first, continuity="recovery_pending")
    with pytest.raises(RecoveryAnchorRejected, match="not_current"):
        install_successor(anchor, blocked)


def test_postgres_beacon_reader_uses_control_identity_timeline_and_flushed_wal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class Result:
        def fetchone(self):
            return {
                "system_identifier": "cluster-123",
                "timeline_id": 7,
                "flushed_wal_lsn": "0/2A0",
            }

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, query: str):
            captured["query"] = query
            return Result()

    def connect(*args: object, **kwargs: object) -> Connection:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return Connection()

    monkeypatch.setattr("psycopg.connect", connect)
    result = PostgresContinuityBeaconReader("postgresql+psycopg://example").read(
        checkpoint_digest=CHECKPOINT_A
    )

    assert result == PostgresContinuityBeacon("cluster-123", 7, "0/2A0", CHECKPOINT_A)
    assert "pg_control_system" in str(captured["query"])
    assert "pg_control_checkpoint" in str(captured["query"])
    assert "pg_current_wal_flush_lsn" in str(captured["query"])
