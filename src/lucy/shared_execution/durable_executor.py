"""Serve one execution against the durable fenced ledger.

The ordering rule lives here rather than in a caller: a provider is reached only from a
dispatch the ledger has already committed under this coordinator's fence, and the result is
settled through the same fence. A caller cannot reach the provider by another route, because it
never holds the provider itself.

This is deliberately narrow. It owns admission, the dispatch commit, the single provider call and
terminal settlement; profile authority, wire validation and the HTTP surface stay where they are.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from lucy.shared_execution.postgres_ledger import (
    DispatchBlocked,
    DurableFenceRejected,
    LedgerAdmission,
    LedgerRecord,
    LedgerScope,
    PostgresExecutionLedger,
)


class ExecutionRefused(RuntimeError):
    """The ledger refused this execution, so no provider was reached."""


@dataclass(frozen=True)
class ProviderOutcome:
    """What a provider reported, in the terms the ledger settles."""

    settled_microusd: int
    cost_reference_digest: str | None = None
    failure_code: str | None = None

    @property
    def state(self) -> str:
        return "failed" if self.failure_code else "completed"


class DispatchedProvider(Protocol):
    """Invoked only with a record the ledger has already committed as dispatched."""

    def __call__(self, dispatched: LedgerRecord) -> ProviderOutcome: ...


@dataclass(frozen=True)
class ExecutionOutcome:
    execution_id: UUID
    state: str
    settlement_status: str
    settled_microusd: int | None
    replayed: bool


class DurableExecutor:
    """Admit, commit dispatch, call the provider once, then settle, all under one fence."""

    def __init__(
        self,
        *,
        ledger: PostgresExecutionLedger,
        scope: LedgerScope,
        coordinator_generation: int,
        provider: DispatchedProvider,
    ) -> None:
        if coordinator_generation < 1:
            raise ValueError("coordinator generation is invalid")
        self._ledger = ledger
        self._scope = scope
        self._coordinator_generation = coordinator_generation
        self._provider = provider

    def shutdown(self) -> int:
        """Drain, then retire this fence. Retirement is generation-checked, not identity-checked.

        Retiring while work is still admitted or dispatched would strand it: the fence it was
        admitted under no longer settles, and a provider call may already have been sent. This
        does not quarantine; a gate already blocked stays blocked.
        """

        in_flight = self._ledger.in_flight_under_fence(self._scope, self._coordinator_generation)
        if in_flight:
            raise ExecutionRefused("in-flight work must drain before the fence is retired")
        try:
            return self._ledger.retire_coordinator(self._coordinator_generation)
        except (DispatchBlocked, DurableFenceRejected) as exc:
            raise ExecutionRefused(str(exc) or type(exc).__name__) from exc

    def execute(self, admission: LedgerAdmission, *, now: datetime) -> ExecutionOutcome:
        try:
            record, created = self._ledger.create_or_get(
                self._scope,
                admission,
                coordinator_generation=self._coordinator_generation,
                now=now,
            )
        except (DispatchBlocked, DurableFenceRejected) as exc:
            # A blocked gate or a fence this executor no longer holds; either way the
            # request is refused before anything is admitted.
            raise ExecutionRefused(str(exc) or type(exc).__name__) from exc
        if not created:
            # A settled execution replays from the ledger. An unsettled one belongs to whoever
            # holds its lease; this executor does not race it to the provider.
            return ExecutionOutcome(
                execution_id=record.execution_id,
                state=record.state,
                settlement_status=record.settlement_status,
                settled_microusd=record.settled_microusd,
                replayed=True,
            )
        try:
            dispatched = self._ledger.dispatch(
                self._scope,
                record.execution_id,
                coordinator_generation=self._coordinator_generation,
                record_generation=record.record_generation,
                owner_id=admission.owner_id,
            )
        except (DispatchBlocked, DurableFenceRejected) as exc:
            # The fence moved, the gate closed or the claimant is no longer current. No provider
            # call may follow an uncommitted dispatch.
            raise ExecutionRefused(str(exc) or type(exc).__name__) from exc
        if dispatched.state != "dispatched":
            raise ExecutionRefused("dispatch was not committed")
        outcome = self._provider(dispatched)
        settled = self._ledger.settle_terminal(
            self._scope,
            record.execution_id,
            coordinator_generation=self._coordinator_generation,
            record_generation=dispatched.record_generation,
            owner_id=admission.owner_id,
            state=outcome.state,
            settled_microusd=outcome.settled_microusd,
            failure_code=outcome.failure_code,
            provider_cost_reference_digest=outcome.cost_reference_digest,
        )
        return ExecutionOutcome(
            execution_id=settled.execution_id,
            state=settled.state,
            settlement_status=settled.settlement_status,
            settled_microusd=settled.settled_microusd,
            replayed=False,
        )
