"""Topology-neutral RC1 grant, budget-period, and financial-exposure state machine."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID


class SpendingAuthorityExhausted(RuntimeError):
    pass


class ConcurrencyLimited(RuntimeError):
    pass


@dataclass(frozen=True)
class LocalSpendingGrant:
    release_id: str
    environment: str
    partition_id: str
    budget_period_id: str
    period_start: datetime
    period_end: datetime
    not_before: datetime
    not_after: datetime
    allowance_microusd: int
    maximum_concurrency: int
    largest_per_call_microusd: int
    contingency_reserve_microusd: int
    predecessor_release_id: str | None = None
    revoked: bool = False

    def __post_init__(self) -> None:
        if (
            not self.release_id
            or not self.environment
            or not self.partition_id
            or not self.budget_period_id
            or self.period_start.tzinfo is None
            or self.period_end.tzinfo is None
            or self.not_before.tzinfo is None
            or self.not_after.tzinfo is None
            or self.period_start >= self.period_end
            or self.not_before >= self.not_after
            or self.allowance_microusd < 1
            or self.maximum_concurrency < 1
            or self.largest_per_call_microusd < 1
        ):
            raise ValueError("spending grant is invalid")
        minimum_contingency = (
            2 * self.maximum_concurrency * self.largest_per_call_microusd
        )
        if self.contingency_reserve_microusd < minimum_contingency:
            raise ValueError("contingency reserve is below the RC1 minimum")

    def applicable(self, *, environment: str, now: datetime) -> bool:
        return (
            not self.revoked
            and self.environment == environment
            and self.not_before <= now < self.not_after
            and self.period_start <= now < self.period_end
        )


@dataclass(frozen=True)
class Exposure:
    execution_id: UUID
    reserved_microusd: int
    state: Literal["active", "pending_reconciliation"]


@dataclass(frozen=True)
class AdmissionSnapshot:
    active_release_id: str
    budget_period_id: str
    period_spend_microusd: int
    active: int
    pending: int
    reserved_microusd: int
    available_microusd: int


class LocalSpendingPartition:
    """Atomic in-process reference model for later durable storage."""

    def __init__(self, environment: str, partition_id: str) -> None:
        self._environment = environment
        self._partition_id = partition_id
        self._lock = threading.Lock()
        self._grants: dict[str, LocalSpendingGrant] = {}
        self._active_release_id: str | None = None
        self._period_spend_microusd = 0
        self._exposures: dict[UUID, Exposure] = {}

    def activate(self, grant: LocalSpendingGrant) -> None:
        if grant.environment != self._environment or grant.partition_id != self._partition_id:
            raise ValueError("grant is mapped to another spending partition")
        with self._lock:
            current = self._active_grant()
            if current is not None:
                if grant.predecessor_release_id != current.release_id:
                    raise ValueError("successor does not name the active predecessor")
                if grant.not_before < current.not_before:
                    raise ValueError("successor ordering moves backward")
                if grant.budget_period_id != current.budget_period_id:
                    self._period_spend_microusd = 0
            elif grant.predecessor_release_id is not None:
                raise ValueError("initial grant cannot name a predecessor")
            self._grants[grant.release_id] = grant
            self._active_release_id = grant.release_id

    def reserve(self, execution_id: UUID, maximum_microusd: int, *, now: datetime) -> None:
        with self._lock:
            grant = self._require_applicable_grant(now)
            existing = self._exposures.get(execution_id)
            if existing is not None:
                if existing.reserved_microusd != maximum_microusd:
                    raise ValueError("execution reservation conflicts")
                return
            active = sum(item.state == "active" for item in self._exposures.values())
            pending = len(self._exposures) - active
            if active >= grant.maximum_concurrency:
                raise ConcurrencyLimited
            if active + pending >= 2 * grant.maximum_concurrency:
                raise SpendingAuthorityExhausted
            if maximum_microusd < 1 or maximum_microusd > grant.largest_per_call_microusd:
                raise SpendingAuthorityExhausted
            held = sum(item.reserved_microusd for item in self._exposures.values())
            if self._period_spend_microusd + held + maximum_microusd > grant.allowance_microusd:
                raise SpendingAuthorityExhausted
            self._exposures[execution_id] = Exposure(
                execution_id=execution_id,
                reserved_microusd=maximum_microusd,
                state="active",
            )

    def mark_pending(self, execution_id: UUID) -> None:
        with self._lock:
            exposure = self._exposures[execution_id]
            self._exposures[execution_id] = Exposure(
                execution_id=execution_id,
                reserved_microusd=exposure.reserved_microusd,
                state="pending_reconciliation",
            )

    def settle(self, execution_id: UUID, actual_microusd: int) -> None:
        with self._lock:
            exposure = self._exposures[execution_id]
            if actual_microusd < 0 or actual_microusd > exposure.reserved_microusd:
                raise ValueError("ordinary settlement is outside the reservation")
            del self._exposures[execution_id]
            self._period_spend_microusd += actual_microusd

    def forfeit(self, execution_id: UUID) -> None:
        with self._lock:
            exposure = self._exposures[execution_id]
            if exposure.state != "pending_reconciliation":
                raise ValueError("only pending reconciliation may be forfeited")
            del self._exposures[execution_id]
            self._period_spend_microusd += exposure.reserved_microusd

    def snapshot(self, *, now: datetime) -> AdmissionSnapshot:
        with self._lock:
            grant = self._require_applicable_grant(now)
            active = sum(item.state == "active" for item in self._exposures.values())
            pending = len(self._exposures) - active
            held = sum(item.reserved_microusd for item in self._exposures.values())
            return AdmissionSnapshot(
                active_release_id=grant.release_id,
                budget_period_id=grant.budget_period_id,
                period_spend_microusd=self._period_spend_microusd,
                active=active,
                pending=pending,
                reserved_microusd=held,
                available_microusd=max(
                    0, grant.allowance_microusd - self._period_spend_microusd - held
                ),
            )

    def _active_grant(self) -> LocalSpendingGrant | None:
        if self._active_release_id is None:
            return None
        return self._grants[self._active_release_id]

    def _require_applicable_grant(self, now: datetime) -> LocalSpendingGrant:
        grant = self._active_grant()
        if grant is None or not grant.applicable(environment=self._environment, now=now):
            raise SpendingAuthorityExhausted
        return grant
