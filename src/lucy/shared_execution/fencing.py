"""Content-free RC1 lease, fencing, and reaper reference state machine."""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

ExecutionState = Literal["admitted", "dispatched", "completed", "failed", "outcome_unknown"]


class FenceRejected(RuntimeError):
    pass


@dataclass(frozen=True, order=True)
class Fence:
    counter: int
    owner_id: UUID


@dataclass(frozen=True)
class FencedExecution:
    execution_id: UUID
    caller: str
    idempotency_key: str
    identity_digest: str
    state: ExecutionState
    generation: int
    fence: Fence
    lease_expires_at: datetime
    execution_deadline: datetime
    reserved_microusd: int
    settlement_status: Literal["settled", "pending_reconciliation"]
    settled_microusd: int | None
    failure_code: str | None


class FencedExecutionStore:
    """Thread-safe behavioral reference for the future durable CAS implementation."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[tuple[str, str], FencedExecution] = {}

    def create(
        self,
        *,
        caller: str,
        idempotency_key: str,
        identity_digest: str,
        reserved_microusd: int,
        owner_id: UUID,
        now: datetime,
        execution_deadline: datetime,
    ) -> tuple[FencedExecution, bool]:
        if now.tzinfo is None or execution_deadline.tzinfo is None or execution_deadline <= now:
            raise ValueError("execution times must be aware and ordered")
        key = (caller, idempotency_key)
        with self._lock:
            existing = self._records.get(key)
            if existing is not None:
                if existing.identity_digest != identity_digest:
                    raise ValueError("idempotency conflict")
                return existing, False
            record = FencedExecution(
                execution_id=uuid4(),
                caller=caller,
                idempotency_key=idempotency_key,
                identity_digest=identity_digest,
                state="admitted",
                generation=1,
                fence=Fence(1, owner_id),
                lease_expires_at=min(now + timedelta(seconds=5), execution_deadline),
                execution_deadline=execution_deadline,
                reserved_microusd=reserved_microusd,
                settlement_status="pending_reconciliation",
                settled_microusd=None,
                failure_code=None,
            )
            self._records[key] = record
            return record, True

    def dispatch(self, execution_id: UUID, *, fence: Fence, generation: int) -> FencedExecution:
        return self._transition(
            execution_id,
            expected="admitted",
            target="dispatched",
            fence=fence,
            generation=generation,
            lease_extension=timedelta(seconds=30),
        )

    def complete(
        self,
        execution_id: UUID,
        *,
        fence: Fence,
        generation: int,
        settled_microusd: int,
        eligible: bool,
    ) -> FencedExecution:
        if not eligible:
            return self.fail(
                execution_id,
                fence=fence,
                generation=generation,
                failure_code="execution_invalidated",
                settled_microusd=settled_microusd,
            )
        with self._lock:
            current, key = self._matching(execution_id, fence, generation, "dispatched")
            if settled_microusd < 0 or settled_microusd > current.reserved_microusd:
                raise ValueError("ordinary settlement is outside the reservation")
            updated = replace(
                current,
                state="completed",
                generation=current.generation + 1,
                lease_expires_at=current.execution_deadline,
                settlement_status="settled",
                settled_microusd=settled_microusd,
            )
            self._records[key] = updated
            return updated

    def fail(
        self,
        execution_id: UUID,
        *,
        fence: Fence,
        generation: int,
        failure_code: str,
        settled_microusd: int,
    ) -> FencedExecution:
        with self._lock:
            current, key = self._matching(
                execution_id, fence, generation, ("admitted", "dispatched")
            )
            if settled_microusd < 0 or settled_microusd > current.reserved_microusd:
                raise ValueError("ordinary settlement is outside the reservation")
            updated = replace(
                current,
                state="failed",
                generation=current.generation + 1,
                settlement_status="settled",
                settled_microusd=settled_microusd,
                failure_code=failure_code,
            )
            self._records[key] = updated
            return updated

    def takeover(
        self, execution_id: UUID, *, owner_id: UUID, now: datetime
    ) -> FencedExecution:
        with self._lock:
            current, key = self._find(execution_id)
            if current.state not in {"admitted", "dispatched"} or now < current.lease_expires_at:
                raise FenceRejected
            updated = replace(
                current,
                fence=Fence(current.fence.counter + 1, owner_id),
                generation=current.generation + 1,
                lease_expires_at=(
                    min(now + timedelta(seconds=5), current.execution_deadline)
                    if current.state == "admitted"
                    else current.execution_deadline + timedelta(seconds=30)
                ),
            )
            self._records[key] = updated
            return updated

    def reap(self, *, now: datetime) -> tuple[FencedExecution, ...]:
        changed: list[FencedExecution] = []
        with self._lock:
            for key, current in tuple(self._records.items()):
                if (
                    current.state not in {"admitted", "dispatched"}
                    or now < current.lease_expires_at
                ):
                    continue
                if current.state == "admitted":
                    updated = replace(
                        current,
                        state="failed",
                        generation=current.generation + 1,
                        settlement_status="settled",
                        settled_microusd=0,
                        failure_code="execution_aborted",
                    )
                else:
                    updated = replace(
                        current,
                        state="outcome_unknown",
                        generation=current.generation + 1,
                        settlement_status="pending_reconciliation",
                        settled_microusd=None,
                        failure_code="execution_outcome_unknown",
                    )
                self._records[key] = updated
                changed.append(updated)
        return tuple(changed)

    def get(self, execution_id: UUID) -> FencedExecution:
        with self._lock:
            return self._find(execution_id)[0]

    def _transition(
        self,
        execution_id: UUID,
        *,
        expected: ExecutionState,
        target: ExecutionState,
        fence: Fence,
        generation: int,
        lease_extension: timedelta,
    ) -> FencedExecution:
        with self._lock:
            current, key = self._matching(execution_id, fence, generation, expected)
            updated = replace(
                current,
                state=target,
                generation=current.generation + 1,
                lease_expires_at=current.execution_deadline + lease_extension,
            )
            self._records[key] = updated
            return updated

    def _matching(
        self,
        execution_id: UUID,
        fence: Fence,
        generation: int,
        state: ExecutionState | tuple[ExecutionState, ...],
    ) -> tuple[FencedExecution, tuple[str, str]]:
        current, key = self._find(execution_id)
        expected_states = (state,) if isinstance(state, str) else state
        if (
            current.state not in expected_states
            or current.fence != fence
            or current.generation != generation
        ):
            raise FenceRejected
        return current, key

    def _find(self, execution_id: UUID) -> tuple[FencedExecution, tuple[str, str]]:
        for key, record in self._records.items():
            if record.execution_id == execution_id:
                return record, key
        raise KeyError(execution_id)
