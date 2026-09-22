"""The volatile replay cache stays inside RC1 section 15's limits."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from lucy.shared_execution.replay_cache import (
    MAXIMUM_REPLAY_WINDOW,
    InMemoryReplayCache,
    ReplayOutputMismatch,
    require_matching_response,
    response_body_digest,
)

ADMITTED = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
BODY = {"output": {"mode": "text", "content": "synthetic answer"}}


class _Clock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def _put(cache: InMemoryReplayCache, key: str = "key", execution_id: UUID | None = None) -> str:
    return cache.put(
        caller_id="caller",
        idempotency_key_digest=key,
        execution_id=execution_id or uuid4(),
        response_body=BODY,
        admitted_at=ADMITTED,
    )


def test_a_window_longer_than_ten_minutes_is_refused() -> None:
    with pytest.raises(ValueError, match="ten minutes"):
        InMemoryReplayCache(
            clock=_Clock(ADMITTED), window=MAXIMUM_REPLAY_WINDOW + timedelta(seconds=1)
        )


def test_content_is_gone_ten_minutes_after_admission_not_completion() -> None:
    clock = _Clock(ADMITTED + timedelta(minutes=9))  # a slow execution completes late
    cache = InMemoryReplayCache(clock=clock)
    _put(cache)
    assert cache.get(caller_id="caller", idempotency_key_digest="key") is not None

    clock.now = ADMITTED + MAXIMUM_REPLAY_WINDOW
    assert cache.get(caller_id="caller", idempotency_key_digest="key") is None
    assert len(cache) == 0


def test_the_entry_limit_evicts_the_oldest() -> None:
    cache = InMemoryReplayCache(clock=_Clock(ADMITTED), maximum_entries=2)
    for key in ("a", "b", "c"):
        _put(cache, key)
    assert cache.get(caller_id="caller", idempotency_key_digest="a") is None
    assert len(cache) == 2


def test_a_key_cannot_be_rebound_to_another_execution() -> None:
    cache = InMemoryReplayCache(clock=_Clock(ADMITTED))
    _put(cache)
    with pytest.raises(ReplayOutputMismatch):
        _put(cache)


def test_a_cached_body_must_match_execution_and_digest() -> None:
    cache = InMemoryReplayCache(clock=_Clock(ADMITTED))
    execution_id = uuid4()
    digest = _put(cache, execution_id=execution_id)
    cached = cache.get(caller_id="caller", idempotency_key_digest="key")
    assert cached is not None and digest == response_body_digest(BODY)

    served = require_matching_response(cached, execution_id=execution_id, ledger_digest=digest)
    assert served == BODY
    with pytest.raises(ReplayOutputMismatch, match="another execution"):
        require_matching_response(cached, execution_id=uuid4(), ledger_digest=digest)
    with pytest.raises(ReplayOutputMismatch):
        require_matching_response(cached, execution_id=execution_id, ledger_digest=None)
    with pytest.raises(ReplayOutputMismatch):
        require_matching_response(cached, execution_id=execution_id, ledger_digest="0" * 64)
