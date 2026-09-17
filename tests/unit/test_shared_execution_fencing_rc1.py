from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from lucy.shared_execution.fencing import FencedExecutionStore, FenceRejected

NOW = datetime(2026, 9, 17, 12, tzinfo=UTC)


def create(store: FencedExecutionStore):
    return store.create(
        caller="stoin:synth:utopia-homes-prime",
        idempotency_key=str(uuid4()),
        identity_digest="a" * 64,
        reserved_microusd=2_000,
        owner_id=uuid4(),
        now=NOW,
        execution_deadline=NOW + timedelta(seconds=15),
    )[0]


def test_admitted_expiry_proves_zero_dispatch_and_releases_at_zero() -> None:
    store = FencedExecutionStore()
    admitted = create(store)
    changed = store.reap(now=admitted.lease_expires_at)
    assert len(changed) == 1
    assert changed[0].state == "failed"
    assert changed[0].failure_code == "execution_aborted"
    assert changed[0].settled_microusd == 0


def test_dispatched_expiry_becomes_outcome_unknown_and_holds_reservation() -> None:
    store = FencedExecutionStore()
    admitted = create(store)
    dispatched = store.dispatch(
        admitted.execution_id, fence=admitted.fence, generation=admitted.generation
    )
    changed = store.reap(now=dispatched.lease_expires_at)
    assert changed[0].state == "outcome_unknown"
    assert changed[0].settlement_status == "pending_reconciliation"
    assert changed[0].settled_microusd is None


def test_stale_owner_cannot_complete_after_reaper_transition() -> None:
    store = FencedExecutionStore()
    admitted = create(store)
    dispatched = store.dispatch(
        admitted.execution_id, fence=admitted.fence, generation=admitted.generation
    )
    store.reap(now=dispatched.lease_expires_at)
    with pytest.raises(FenceRejected):
        store.complete(
            dispatched.execution_id,
            fence=dispatched.fence,
            generation=dispatched.generation,
            settled_microusd=10,
            eligible=True,
        )


def test_takeover_issues_new_epoch_and_fences_prior_owner() -> None:
    store = FencedExecutionStore()
    admitted = create(store)
    takeover = store.takeover(
        admitted.execution_id,
        owner_id=uuid4(),
        now=admitted.lease_expires_at,
    )
    assert takeover.fence.counter == admitted.fence.counter + 1
    with pytest.raises(FenceRejected):
        store.dispatch(
            admitted.execution_id,
            fence=admitted.fence,
            generation=admitted.generation,
        )


def test_eligibility_recheck_suppresses_candidate_before_completed_commit() -> None:
    store = FencedExecutionStore()
    admitted = create(store)
    dispatched = store.dispatch(
        admitted.execution_id, fence=admitted.fence, generation=admitted.generation
    )
    failed = store.complete(
        dispatched.execution_id,
        fence=dispatched.fence,
        generation=dispatched.generation,
        settled_microusd=20,
        eligible=False,
    )
    assert failed.state == "failed"
    assert failed.failure_code == "execution_invalidated"


def test_dispatch_commit_precedes_any_external_send_decision() -> None:
    store = FencedExecutionStore()
    admitted = create(store)
    # The only record state in which the caller may proceed to transport is the durable result
    # returned by dispatch; the admitted record itself is never send-eligible.
    assert admitted.state == "admitted"
    dispatched = store.dispatch(
        admitted.execution_id, fence=admitted.fence, generation=admitted.generation
    )
    assert dispatched.state == "dispatched"
    assert dispatched.generation == admitted.generation + 1
