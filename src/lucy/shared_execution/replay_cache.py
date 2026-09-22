"""Volatile replay of a response body, within the limits RC1 section 15 sets.

RC1 allows request and response content to exist only in volatile process memory, for active
execution and eligible replay, for at most ten minutes from admission. It must not enter a
persistent cache, queue, disk, database, backup, trace, crash dump, log, error report, analytics
or accounting record, and encryption does not change that. This cache therefore lives in the
serving process and nowhere else.

When a replay arrives and the body is gone - the window passed, the entry was evicted, or the
process restarted - RC1 already defines the answer: the durable completion record still exists,
so the reply is ``idempotency_recovery_unavailable`` and nothing is dispatched again. Losing a
body costs the replay, never the accounting or the deduplication, which stay content-free in the
ledger.

The ledger records only a digest of the body. A cached body is served only when both its
execution id and its digest agree with that durable record.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol
from uuid import UUID

# RC1 section 15: at most ten minutes from admission.
MAXIMUM_REPLAY_WINDOW = timedelta(minutes=10)


class ReplayOutputMismatch(RuntimeError):
    """A cached body disagrees with the durable record, so it is not served."""


def response_body_digest(response_body: object) -> str:
    """Digest the exact response body, canonically, so both sides agree on the bytes."""

    return hashlib.sha256(
        json.dumps(
            response_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class CachedResponse:
    execution_id: UUID
    response_body: Any
    response_body_sha256: str
    expires_at: datetime


class ReplayCache(Protocol):
    """Volatile storage for a replayable body, bounded by RC1's ten-minute window."""

    def put(
        self,
        *,
        caller_id: str,
        idempotency_key_digest: str,
        execution_id: UUID,
        response_body: Any,
        admitted_at: datetime,
    ) -> str: ...

    def get(self, *, caller_id: str, idempotency_key_digest: str) -> CachedResponse | None: ...


class InMemoryReplayCache:
    """A bounded, expiring map held only in this process's memory.

    It is never written anywhere, so a restart empties it by design. The entry limit keeps memory
    bounded under load; evicting early only degrades replay to the contract's defined error.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], datetime],
        window: timedelta = MAXIMUM_REPLAY_WINDOW,
        maximum_entries: int = 10_000,
    ) -> None:
        if not timedelta(seconds=1) <= window <= MAXIMUM_REPLAY_WINDOW:
            raise ValueError("replay window must be between one second and ten minutes")
        if maximum_entries < 1:
            raise ValueError("replay cache must hold at least one entry")
        self._clock = clock
        self._window = window
        self._maximum_entries = maximum_entries
        self._lock = threading.Lock()
        self._entries: OrderedDict[tuple[str, str], CachedResponse] = OrderedDict()

    def put(
        self,
        *,
        caller_id: str,
        idempotency_key_digest: str,
        execution_id: UUID,
        response_body: Any,
        admitted_at: datetime,
    ) -> str:
        """Hold the body until ten minutes after admission and return its digest.

        The window runs from admission, not from completion, so a slow execution leaves less time
        for replay rather than extending how long content lives.
        """

        digest = response_body_digest(response_body)
        entry = CachedResponse(
            execution_id=execution_id,
            response_body=response_body,
            response_body_sha256=digest,
            expires_at=admitted_at + self._window,
        )
        key = (caller_id, idempotency_key_digest)
        with self._lock:
            self._drop_expired()
            existing = self._entries.get(key)
            if existing is not None and existing.execution_id != execution_id:
                raise ReplayOutputMismatch("replay cache holds another execution for this key")
            self._entries[key] = entry
            self._entries.move_to_end(key)
            while len(self._entries) > self._maximum_entries:
                self._entries.popitem(last=False)
        return digest

    def get(self, *, caller_id: str, idempotency_key_digest: str) -> CachedResponse | None:
        with self._lock:
            self._drop_expired()
            return self._entries.get((caller_id, idempotency_key_digest))

    def __len__(self) -> int:
        with self._lock:
            self._drop_expired()
            return len(self._entries)

    def _drop_expired(self) -> None:
        now = self._clock()
        for key in [key for key, entry in self._entries.items() if entry.expires_at <= now]:
            del self._entries[key]


def require_matching_response(
    cached: CachedResponse, *, execution_id: UUID, ledger_digest: str | None
) -> Any:
    """Serve a cached body only when execution and digest both agree with the ledger."""

    if cached.execution_id != execution_id:
        raise ReplayOutputMismatch("cached response belongs to another execution")
    if ledger_digest is None or cached.response_body_sha256 != ledger_digest:
        raise ReplayOutputMismatch("cached response does not match the recorded digest")
    if response_body_digest(cached.response_body) != ledger_digest:
        raise ReplayOutputMismatch("cached response does not hash to its recorded digest")
    return cached.response_body
