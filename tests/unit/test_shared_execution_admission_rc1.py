from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from lucy.shared_execution.admission import (
    ConcurrencyLimited,
    LocalSpendingGrant,
    LocalSpendingPartition,
    SpendingAuthorityExhausted,
)

NOW = datetime(2026, 9, 17, 12, tzinfo=UTC)


def grant(
    release: str = "grant.1",
    *,
    period: str = "2026-09-17",
    period_start: datetime = NOW - timedelta(hours=12),
    period_end: datetime = NOW + timedelta(hours=12),
    predecessor: str | None = None,
    allowance: int = 20_000,
    concurrency: int = 2,
) -> LocalSpendingGrant:
    return LocalSpendingGrant(
        release_id=release,
        environment="local-test",
        partition_id="utopia-homes-public",
        budget_period_id=period,
        period_start=period_start,
        period_end=period_end,
        not_before=NOW - timedelta(hours=1),
        not_after=NOW + timedelta(hours=36),
        allowance_microusd=allowance,
        maximum_concurrency=concurrency,
        largest_per_call_microusd=2_000,
        contingency_reserve_microusd=2 * concurrency * 2_000,
        predecessor_release_id=predecessor,
    )


def partition() -> LocalSpendingPartition:
    value = LocalSpendingPartition("local-test", "utopia-homes-public")
    value.activate(grant())
    return value


def test_contingency_reserve_must_cover_two_times_concurrency_and_largest_call() -> None:
    with pytest.raises(ValueError, match="contingency"):
        LocalSpendingGrant(
            **{
                **grant().__dict__,
                "release_id": "too-small",
                "contingency_reserve_microusd": 7_999,
            }
        )


def test_active_concurrency_and_financial_exposure_are_distinct_gates() -> None:
    value = partition()
    first, second, third, fourth, fifth = (uuid4() for _ in range(5))
    value.reserve(first, 2_000, now=NOW)
    value.reserve(second, 2_000, now=NOW)
    with pytest.raises(ConcurrencyLimited):
        value.reserve(third, 2_000, now=NOW)
    value.mark_pending(first)
    value.reserve(third, 2_000, now=NOW)
    value.mark_pending(second)
    value.reserve(fourth, 2_000, now=NOW)
    value.mark_pending(third)
    with pytest.raises(SpendingAuthorityExhausted):
        value.reserve(fifth, 2_000, now=NOW)
    snapshot = value.snapshot(now=NOW)
    assert (snapshot.active, snapshot.pending) == (1, 3)


def test_timeout_to_pending_neither_frees_nor_double_counts_exposure() -> None:
    value = partition()
    execution_id = uuid4()
    value.reserve(execution_id, 2_000, now=NOW)
    before = value.snapshot(now=NOW)
    value.mark_pending(execution_id)
    after = value.snapshot(now=NOW)
    assert (before.active, before.pending) == (1, 0)
    assert (after.active, after.pending) == (0, 1)
    assert after.reserved_microusd == before.reserved_microusd == 2_000


def test_same_period_successor_does_not_replenish_spend_or_drop_obligations() -> None:
    value = partition()
    settled, pending = uuid4(), uuid4()
    value.reserve(settled, 2_000, now=NOW)
    value.settle(settled, 1_500)
    value.reserve(pending, 2_000, now=NOW)
    value.mark_pending(pending)
    value.activate(grant("grant.2", predecessor="grant.1"))
    snapshot = value.snapshot(now=NOW)
    assert snapshot.active_release_id == "grant.2"
    assert snapshot.period_spend_microusd == 1_500
    assert snapshot.pending == 1
    assert snapshot.available_microusd == 16_500


def test_new_period_renews_allowance_but_carries_unresolved_obligation() -> None:
    value = partition()
    pending = uuid4()
    value.reserve(pending, 2_000, now=NOW)
    value.mark_pending(pending)
    tomorrow = NOW + timedelta(days=1)
    value.activate(
        LocalSpendingGrant(
            release_id="grant.next",
            environment="local-test",
            partition_id="utopia-homes-public",
            budget_period_id="2026-09-18",
            period_start=tomorrow - timedelta(hours=12),
            period_end=tomorrow + timedelta(hours=12),
            not_before=NOW,
            not_after=tomorrow + timedelta(hours=36),
            allowance_microusd=20_000,
            maximum_concurrency=2,
            largest_per_call_microusd=2_000,
            contingency_reserve_microusd=8_000,
            predecessor_release_id="grant.1",
        )
    )
    snapshot = value.snapshot(now=tomorrow)
    assert snapshot.period_spend_microusd == 0
    assert snapshot.pending == 1
    assert snapshot.available_microusd == 18_000


def test_crossing_period_boundary_without_next_grant_fails_closed() -> None:
    value = partition()
    with pytest.raises(SpendingAuthorityExhausted):
        value.reserve(uuid4(), 2_000, now=NOW + timedelta(hours=13))


def test_activated_successor_never_falls_back_to_predecessor() -> None:
    value = partition()
    expired_successor = LocalSpendingGrant(
        **{
            **grant("grant.2", predecessor="grant.1").__dict__,
            "not_after": NOW + timedelta(minutes=1),
        }
    )
    value.activate(expired_successor)
    with pytest.raises(SpendingAuthorityExhausted):
        value.reserve(uuid4(), 2_000, now=NOW + timedelta(minutes=2))


def test_forfeiture_charges_full_reservation_and_releases_exposure_slot() -> None:
    value = partition()
    execution_id = uuid4()
    value.reserve(execution_id, 2_000, now=NOW)
    value.mark_pending(execution_id)
    value.forfeit(execution_id)
    snapshot = value.snapshot(now=NOW)
    assert snapshot.pending == 0
    assert snapshot.period_spend_microusd == 2_000
