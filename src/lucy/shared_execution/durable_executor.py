"""Serve one execution against the durable fenced ledger.

The ordering rule lives here rather than in a caller: a provider is reached only from a
dispatch the ledger has already committed under this coordinator's fence, and the result is
settled through the same fence. A caller cannot reach the provider by another route, because it
never holds the provider itself.

This is deliberately narrow. It owns admission, the dispatch commit, the single provider call and
terminal settlement; profile authority, wire validation and the HTTP surface stay where they are.
"""

from __future__ import annotations

import threading
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from lucy.shared_execution.postgres_ledger import (
    DispatchBlocked,
    DurableFenceRejected,
    LedgerAdmission,
    LedgerRecord,
    LedgerScope,
    PostgresExecutionLedger,
)
from lucy.shared_execution.replay_cache import ReplayCache, require_matching_response
from lucy.shared_execution.runtime_anchor_watch import (
    RuntimeAnchorWatch,
    RuntimeAuthorityClosed,
)


class ExecutionRefused(RuntimeError):
    """The ledger refused this execution, so no provider was reached."""


class IdempotencyRecoveryUnavailable(RuntimeError):
    """RC1's 409 idempotency_recovery_unavailable: completed durably, body no longer held."""

    def __init__(self, execution_id: UUID) -> None:
        super().__init__("idempotency_recovery_unavailable")
        self.execution_id = execution_id


@dataclass(frozen=True)
class ProviderOutcome:
    """What a provider reported, in the terms the ledger settles."""

    settled_microusd: int
    cost_reference_digest: str | None = None
    failure_code: str | None = None
    # The replayable response body: the output object and its usage counts. It goes to
    # the cache, never to the ledger, which keeps only its digest.
    response_body: Any | None = None

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
    response_body: Any | None = None


class DurableExecutor:
    """Admit, commit dispatch, call the provider once, then settle, all under one fence."""

    def __init__(
        self,
        *,
        ledger: PostgresExecutionLedger,
        scope: LedgerScope,
        coordinator_generation: int,
        provider: DispatchedProvider,
        watch: RuntimeAnchorWatch | None = None,
        replay_cache: ReplayCache | None = None,
    ) -> None:
        if coordinator_generation < 1:
            raise ValueError("coordinator generation is invalid")
        self._ledger = ledger
        self._scope = scope
        self._coordinator_generation = coordinator_generation
        self._provider = provider
        # Optional for now: the served runtime supplies one, the ledger-only proofs do not.
        self._watch = watch
        # Present when this executor serves a contract that replays response bodies. The cache is
        # not authority: the ledger records the digest, and a replay is served only if they agree.
        self._replay_cache = replay_cache
        self._intake_closed = False
        self._lock = threading.Lock()

    def _require_authority(self) -> None:
        if self._watch is None:
            return
        try:
            self._watch.require_open()
        except RuntimeAuthorityClosed as exc:
            raise ExecutionRefused(str(exc)) from exc

    def shutdown(self) -> int:
        """Close intake, then drain and retire. Retirement is generation-checked.

        Intake closes first so this executor admits nothing further, and the ledger performs the
        drain check and the generation move in one transaction, so a request cannot slip in
        between them. Retiring while work is still admitted or dispatched would strand it: the
        fence it was admitted under no longer settles, and a provider call may already have been
        sent. This does not quarantine; a gate already blocked stays blocked.
        """

        with self._lock:
            self._intake_closed = True
        try:
            return self._ledger.retire_coordinator(self._coordinator_generation)
        except (DispatchBlocked, DurableFenceRejected) as exc:
            raise ExecutionRefused(str(exc) or type(exc).__name__) from exc

    def execute(self, admission: LedgerAdmission, *, now: datetime) -> ExecutionOutcome:
        with self._lock:
            if self._intake_closed:
                raise ExecutionRefused("intake is closed for shutdown")
        self._require_authority()
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
                response_body=self._replayed_body(admission, record),
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
        # The final gate: a quarantine observed since admission must stop this send, even though
        # the ledger has already committed the dispatch.
        try:
            self._require_authority()
        except ExecutionRefused:
            # Retain the exposure if this fence can still write. Closing the latch also blocks the
            # gate, which invalidates the fence, so often it cannot: the record then stays
            # dispatched and unsettled, which is itself the liability reconciliation must resolve.
            # Either way nothing is sent and nothing is released.
            with suppress(DispatchBlocked, DurableFenceRejected):
                self._ledger.mark_outcome_unknown(
                    self._scope,
                    record.execution_id,
                    coordinator_generation=self._coordinator_generation,
                    record_generation=dispatched.record_generation,
                    owner_id=admission.owner_id,
                )
            raise
        outcome = self._provider(dispatched)
        # Hold the body in volatile memory before the ledger calls this complete, so a clean
        # completion always has its replay available for the window RC1 allows. The window runs
        # from admission. The ledger records only the body's digest, never the body.
        response_digest: str | None = None
        if self._replay_cache is not None and outcome.response_body is not None:
            response_digest = self._replay_cache.put(
                caller_id=self._scope.caller_id,
                idempotency_key_digest=admission.idempotency_key_digest,
                execution_id=record.execution_id,
                response_body=outcome.response_body,
                admitted_at=now,
            )
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
            response_body_sha256=response_digest,
        )
        return ExecutionOutcome(
            execution_id=settled.execution_id,
            state=settled.state,
            settlement_status=settled.settlement_status,
            settled_microusd=settled.settled_microusd,
            replayed=False,
            response_body=outcome.response_body,
        )

    def _replayed_body(self, admission: LedgerAdmission, record: LedgerRecord) -> Any | None:
        """Serve a replayed body only when the ledger and the cache agree on what it was.

        With the body gone, RC1 already defines the reply: the durable completion stands, the
        result is no longer available, and nothing is dispatched again under this key.
        """

        if self._replay_cache is None or record.state != "completed":
            return None
        cached = self._replay_cache.get(
            caller_id=self._scope.caller_id,
            idempotency_key_digest=admission.idempotency_key_digest,
        )
        if cached is None:
            # The window passed, the entry was evicted, or this process restarted. The execution,
            # its accounting and its deduplication are unaffected; only the body is gone.
            raise IdempotencyRecoveryUnavailable(record.execution_id)
        return require_matching_response(
            cached, execution_id=record.execution_id, ledger_digest=record.response_body_sha256
        )
