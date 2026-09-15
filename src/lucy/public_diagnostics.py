"""Bounded, content-free diagnostics for Public Lucy reproduction exercises."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from lucy.public_model_service import PublicModelDiagnostic


class PublicDiagnosticReceipt(BaseModel):
    """A short-lived receipt that contains no visitor or model-generated text."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["lucy.public-diagnostic-receipt.v1"]
    trace_id: UUID
    recorded_at: datetime
    environment: Literal["staging", "production"]
    cloud_release_id: str = Field(pattern=r"^[0-9a-f]{40}$")
    snapshot_version: int = Field(ge=1)
    snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_latency_ms: int = Field(ge=0)
    outcome: Literal["completed", "unavailable"]
    model: PublicModelDiagnostic | None = None


class PublicDiagnosticStore:
    """One-process TTL store with a hard entry bound and no persistent transcript."""

    def __init__(
        self,
        *,
        ttl_seconds: int,
        maximum_receipts: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds not in range(60, 86_401):
            raise ValueError("public diagnostic TTL is invalid")
        if maximum_receipts not in range(10, 10_001):
            raise ValueError("public diagnostic receipt bound is invalid")
        self._ttl_seconds = ttl_seconds
        self._maximum_receipts = maximum_receipts
        self._clock = clock
        self._receipts: dict[UUID, tuple[float, PublicDiagnosticReceipt]] = {}
        self._lock = threading.Lock()

    def put(self, receipt: PublicDiagnosticReceipt) -> None:
        now = self._clock()
        with self._lock:
            self._prune(now)
            if len(self._receipts) >= self._maximum_receipts:
                oldest = min(self._receipts, key=lambda item: self._receipts[item][0])
                del self._receipts[oldest]
            self._receipts[receipt.trace_id] = (now, receipt)

    def get(self, trace_id: UUID) -> PublicDiagnosticReceipt | None:
        now = self._clock()
        with self._lock:
            self._prune(now)
            item = self._receipts.get(trace_id)
            return None if item is None else item[1]

    def _prune(self, now: float) -> None:
        expired = [
            trace_id
            for trace_id, (recorded, _receipt) in self._receipts.items()
            if now - recorded > self._ttl_seconds
        ]
        for trace_id in expired:
            del self._receipts[trace_id]


def receipt_now() -> datetime:
    return datetime.now(UTC)
