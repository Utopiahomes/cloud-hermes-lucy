"""Serve RC1 ``inference.execute`` through the durable executor.

This is the adapter between the private HTTP surface and the fenced ledger. It owns the steps the
executor deliberately does not: profile compatibility, the canonical identity and keyed
idempotency digests, the read-only duplicate lookup, replay eligibility against current authority,
and the mapping of every durable state onto RC1's frozen error table. It never holds content
beyond the executor's volatile replay cache, and it never answers a completed execution with an
empty body.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4

from lucy.shared_execution.api import ERRORS
from lucy.shared_execution.durable_executor import (
    DurableExecutor,
    ExecutionOutcome,
    ExecutionRefused,
    IdempotencyRecoveryUnavailable,
    ProviderOutcome,
    ReplayInvalidated,
)
from lucy.shared_execution.idempotency import IdempotencyDigestRing
from lucy.shared_execution.postgres_ledger import (
    DispatchBlocked,
    DurableFenceRejected,
    DurableIdempotencyConflict,
    LedgerAdmission,
    LedgerRecord,
    LedgerScope,
    LedgerUnavailable,
)
from lucy.shared_execution.service import (
    ExecutionProfile,
    ExecutionRejected,
    ProviderTransport,
    canonical_identity,
    provider_accounting_is_valid,
    provider_output_failure,
)
from lucy.shared_execution.wire import (
    CostReceipt,
    ExecutionRequest,
    ExecutionResponse,
    OutputResult,
    Usage,
)

OPERATION = "inference.execute"
CONTRACT_MAJOR = 1
# RC1 section 11: a duplicate never waits past the original deadline plus this settlement margin.
SETTLEMENT_MARGIN = timedelta(seconds=30)
_ACTIVE_STATES = frozenset({"admitted", "dispatched"})

# DispatchBlocked reasons that RC1 names specifically. Anything else - the restore gate, the
# startup attestation, the fence, the runtime latch, shutdown - means current authoritative state
# cannot be established, which RC1 answers with state_store_unavailable.
_REFUSAL_CODES = {
    "request-time concurrency is saturated": "rate_limited",
    "financial exposure is saturated": "spending_authority_exhausted",
    "spending authority is exhausted": "spending_authority_exhausted",
    "spending partition is blocked": "spending_authority_exhausted",
    "spending grant is not applicable": "spending_authority_exhausted",
    "provider route and rate release are quarantined": "privacy_route_unavailable",
    "signed profile authority is not active": "privacy_route_unavailable",
}


@dataclass(frozen=True)
class ServedProfile:
    """One locally admitted profile release and the exact route and rates it resolves to."""

    profile_id: str
    release_id: str
    allowed_modes: frozenset[Literal["text", "json_schema"]]
    maximum_output_tokens: int
    maximum_cost_microusd: int
    provider_route_id: str
    rate_release_id: str
    eligibility_generation: int
    deadline_ms: int
    # The privacy policy this release is admitted under. It is pinned into each record, so a
    # revocation of the policy is seen at dispatch, at the completed commit and on replay.
    privacy_policy_id: str
    privacy_policy_release_id: str

    def __post_init__(self) -> None:
        if (
            not self.profile_id
            or not self.release_id
            or not self.allowed_modes
            or self.maximum_output_tokens < 1
            or self.maximum_cost_microusd < 1
            or not 1 <= len(self.provider_route_id) <= 128
            or not 1 <= len(self.rate_release_id) <= 128
            or self.eligibility_generation < 1
            or not 1000 <= self.deadline_ms <= 18_000
            or not 1 <= len(self.privacy_policy_id) <= 128
            or not 1 <= len(self.privacy_policy_release_id) <= 128
        ):
            raise ValueError("served profile is invalid")

    def as_execution_profile(self) -> ExecutionProfile:
        return ExecutionProfile(
            profile_id=self.profile_id,
            release_id=self.release_id,
            allowed_modes=self.allowed_modes,
            maximum_output_tokens=self.maximum_output_tokens,
            maximum_cost_microusd=self.maximum_cost_microusd,
        )


class ProfileAuthority(Protocol):
    def current(self, profile_id: str) -> ServedProfile | None: ...


class ProfileCatalogue:
    """Locally known profile releases and their parameters. It never says which one is current.

    Which release is current is signed authority's answer, not this process's: see
    ``SignedProfileAuthority``. The catalogue only supplies the route, rates and bounds for a
    release that authority has made active, and a release it does not know is refused.
    """

    def __init__(self, profiles: tuple[ServedProfile, ...] = ()) -> None:
        self._lock = threading.Lock()
        self._releases: dict[tuple[str, str], ServedProfile] = {}
        for profile in profiles:
            self.add(profile)

    def add(self, profile: ServedProfile) -> None:
        with self._lock:
            self._releases[(profile.profile_id, profile.release_id)] = profile

    def get(self, profile_id: str, release_id: str) -> ServedProfile | None:
        with self._lock:
            return self._releases.get((profile_id, release_id))


class ActiveAuthorityReader(Protocol):
    def active_release_id(
        self, scope: LedgerScope, release_type: str, subject_id: str
    ) -> str | None: ...


class SignedProfileAuthority:
    """The current profile release, as signed authority in the ledger database has it.

    A profile is current only while its active signed release is one this process knows and
    that release's privacy policy is itself the active signed policy. Absent, staged, revoked
    or unknown authority yields no profile, so a successor activated in signed authority takes
    effect here without any local step, and nothing is admitted on authority that is not active.
    The ledger repeats the check atomically at admission; this read decides compatibility and
    replay eligibility.
    """

    def __init__(
        self,
        reader: ActiveAuthorityReader,
        scope: LedgerScope,
        catalogue: ProfileCatalogue,
    ) -> None:
        self._reader = reader
        self._scope = scope
        self._catalogue = catalogue

    def current(self, profile_id: str) -> ServedProfile | None:
        release_id = self._reader.active_release_id(self._scope, "execution_profile", profile_id)
        if release_id is None:
            return None
        profile = self._catalogue.get(profile_id, release_id)
        if profile is None:
            return None
        policy_release = self._reader.active_release_id(
            self._scope, "privacy_policy", profile.privacy_policy_id
        )
        return profile if policy_release == profile.privacy_policy_release_id else None


@dataclass(frozen=True)
class ServedWork:
    """What one committed dispatch is for. It exists only in this process's memory."""

    request: ExecutionRequest
    profile: ServedProfile


class ProviderCostUnavailable(RuntimeError):
    """The provider reported no usable charge, so no terminal settlement can be committed."""


class TransportProvider:
    """Call the provider transport for a committed dispatch and settle what it reports.

    A candidate that cannot be delivered becomes its RC1 failure code, settled at the reported
    charge. The replayable body is what a replay must reproduce: the profile it ran under, the
    output, the finish reason and the usage. The cost comes from the ledger each time.
    """

    def __init__(self, transport: ProviderTransport) -> None:
        self._transport = transport

    def __call__(self, dispatched: LedgerRecord, work: Any) -> ProviderOutcome:
        if not isinstance(work, ServedWork):
            raise TypeError("a served dispatch needs its admitted request")
        request, profile = work.request, work.profile
        result = self._transport.execute(request, profile.as_execution_profile())
        cost = result.cost_microusd
        if not isinstance(cost, int) or isinstance(cost, bool) or cost < 0:
            # Leaves the record dispatched; its lease resolves it to outcome_unknown and the
            # reservation is held for reconciliation rather than guessed at.
            raise ProviderCostUnavailable("provider charge is not an exact amount")
        if not provider_accounting_is_valid(result):
            return ProviderOutcome(settled_microusd=cost, failure_code="provider_response_invalid")
        failure = provider_output_failure(request, result)
        if failure is not None:
            return ProviderOutcome(settled_microusd=cost, failure_code=failure)
        body = {
            "execution_profile_id": profile.profile_id,
            "profile_release_id": profile.release_id,
            "output": {"mode": request.output.mode, "content": result.content},
            "finish_reason": "stop",
            "usage": {
                "input_tokens": result.input_tokens,
                "generated_tokens": result.generated_tokens,
                "output_tokens": result.output_tokens,
                "reasoning_tokens": result.reasoning_tokens,
            },
        }
        # The complete response stays within 131,072 bytes. A settled receipt at the full
        # reservation is the widest cost the envelope can carry without failing settlement.
        envelope = _response(
            body,
            request_id=uuid4(),
            execution_id=dispatched.execution_id,
            replayed=False,
            cost=CostReceipt(
                reserved_microusd=dispatched.reserved_microusd,
                settled_microusd=dispatched.reserved_microusd,
                settlement_status="settled",
            ),
        )
        if len(envelope.model_dump_json(by_alias=True).encode("utf-8")) > 131_072:
            return ProviderOutcome(
                settled_microusd=cost, failure_code="provider_response_too_large"
            )
        return ProviderOutcome(settled_microusd=cost, response_body=body)


class DurableExecutionService:
    """RC1 steps 8-15 over the durable executor, one executor per authenticated caller."""

    def __init__(
        self,
        *,
        executors: Mapping[str, DurableExecutor],
        profiles: ProfileAuthority,
        digests: IdempotencyDigestRing,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        poll_interval: float = 0.1,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not executors:
            raise ValueError("a served runtime needs at least one executor")
        if not all(executor.replays_responses for executor in executors.values()):
            # Without the volatile cache every duplicate of a completion would be unanswerable.
            raise ValueError("every served executor needs its volatile replay cache")
        self._executors = dict(executors)
        self._profiles = profiles
        self._digests = digests
        self._clock = clock
        self._poll_interval = poll_interval
        self._sleep = sleep

    def execute(
        self,
        *,
        caller: str,
        idempotency_key: str,
        request_id: UUID,
        request: ExecutionRequest,
        timeout_ms: int | None = None,
        received_at: datetime | None = None,
    ) -> ExecutionResponse:
        received = received_at or self._clock()
        executor = self._executors.get(caller)
        if executor is None:
            raise PermissionError("caller is not mapped to an execution scope")
        try:
            profile = self._profiles.current(request.execution_profile_id)
        except LedgerUnavailable as exc:
            raise ExecutionRejected("state_store_unavailable") from exc
        if profile is not None:
            _require_compatible(request, profile)
        identity = canonical_identity(request)
        current, *previous = self._digests.candidates(idempotency_key)

        digests = (current.digest, *(item.digest for item in previous))

        def eligible(record: LedgerRecord) -> bool:
            return self._replay_eligible(request.execution_profile_id, record)

        def lookup() -> LedgerRecord | None:
            return executor.lookup(
                operation=OPERATION,
                contract_major=CONTRACT_MAJOR,
                identity_digest=identity,
                idempotency_key_digests=digests,
            )

        try:
            record = lookup()
            if record is not None:
                outcome = executor.replay(
                    record, idempotency_key_digest=current.digest, replay_eligible=eligible
                )
            elif profile is None:
                # Nothing was admitted under this key, and no release is active to admit it now.
                raise ExecutionRejected("privacy_route_unavailable")
            else:
                now = self._clock()
                deadline_ms = min(timeout_ms or profile.deadline_ms, profile.deadline_ms)
                outcome = executor.execute(
                    LedgerAdmission(
                        idempotency_key_digest=current.digest,
                        identity_digest=identity,
                        digest_key_version=current.version,
                        operation=OPERATION,
                        contract_major=CONTRACT_MAJOR,
                        execution_profile_id=profile.profile_id,
                        profile_release_id=profile.release_id,
                        provider_route_id=profile.provider_route_id,
                        rate_release_id=profile.rate_release_id,
                        owner_id=uuid4(),
                        execution_deadline=now + timedelta(milliseconds=deadline_ms),
                        eligibility_generation=profile.eligibility_generation,
                        reserved_microusd=profile.maximum_cost_microusd,
                        lookup_idempotency_key_digests=tuple(
                            (item.version, item.digest) for item in previous
                        ),
                        privacy_policy_id=profile.privacy_policy_id,
                        privacy_policy_release_id=profile.privacy_policy_release_id,
                    ),
                    now=now,
                    work=ServedWork(request=request, profile=profile),
                    replay_eligible=eligible,
                )
            if outcome.state in _ACTIVE_STATES:
                outcome = self._await_change(
                    executor,
                    lookup,
                    idempotency_key_digest=current.digest,
                    replay_eligible=eligible,
                    attempt_limit=received + timedelta(milliseconds=timeout_ms or 0),
                )
        except DurableIdempotencyConflict as exc:
            raise ExecutionRejected("idempotency_conflict") from exc
        except IdempotencyRecoveryUnavailable as exc:
            raise _about(exc.record, "idempotency_recovery_unavailable") from exc
        except ReplayInvalidated as exc:
            raise _about(exc.record, "execution_invalidated") from exc
        except ExecutionRefused as exc:
            cause = exc.__cause__
            code = (
                _REFUSAL_CODES.get(str(cause), "state_store_unavailable")
                if isinstance(cause, DispatchBlocked)
                else "state_store_unavailable"
            )
            raise ExecutionRejected(code) from exc
        except (
            LedgerUnavailable,
            DispatchBlocked,
            DurableFenceRejected,
            ProviderCostUnavailable,
        ) as exc:
            # No terminal state could be established or committed, so none is claimed.
            raise ExecutionRejected("state_store_unavailable") from exc
        return _answer(outcome, request_id)

    def _await_change(
        self,
        executor: DurableExecutor,
        lookup: Callable[[], LedgerRecord | None],
        *,
        idempotency_key_digest: str,
        replay_eligible: Callable[[LedgerRecord], bool],
        attempt_limit: datetime,
    ) -> ExecutionOutcome:
        """RC1 section 11: a duplicate of an active record waits, bounded, for its outcome.

        The wait ends at the earlier of this attempt's own ceiling and the original deadline plus
        the settlement margin. It only reads: it never renews the owner's lease and never
        dispatches. Whatever state it then finds is answered as that state; request_in_progress
        remains only for a record that is still genuinely active.
        """

        while True:
            record = lookup()
            if record is None:
                raise LedgerUnavailable("the admitted record is no longer visible")
            if record.state not in _ACTIVE_STATES:
                return executor.replay(
                    record,
                    idempotency_key_digest=idempotency_key_digest,
                    replay_eligible=replay_eligible,
                )
            now = self._clock()
            limit = min(attempt_limit, record.execution_deadline + SETTLEMENT_MARGIN)
            if now >= limit:
                if record.lease_expires_at <= now:
                    # Lease expiry belongs to the fenced reaper. An elapsed lease it has not yet
                    # resolved is neither reported as active nor changed here.
                    raise LedgerUnavailable("lease elapsed without an authoritative transition")
                return executor.replay(
                    record,
                    idempotency_key_digest=idempotency_key_digest,
                    replay_eligible=replay_eligible,
                )
            self._sleep(min(self._poll_interval, (limit - now).total_seconds()))

    def _replay_eligible(self, profile_id: str, record: LedgerRecord) -> bool:
        """RC1: replay only while the exact admitted release and route are still current."""

        current = self._profiles.current(profile_id)
        return (
            current is not None
            and record.execution_profile_id == current.profile_id
            and record.profile_release_id == current.release_id
            and record.provider_route_id == current.provider_route_id
            and record.rate_release_id == current.rate_release_id
        )


def _require_compatible(request: ExecutionRequest, profile: ServedProfile) -> None:
    """RC1 step 9, with the messages the HTTP layer maps to its two 422 codes."""

    if request.output.mode not in profile.allowed_modes:
        raise ValueError("output contract exceeds the profile")
    if request.limits.max_output_tokens > profile.maximum_output_tokens:
        raise ValueError("output contract exceeds the profile")
    if request.limits.max_cost_microusd < profile.maximum_cost_microusd:
        raise ValueError("cost ceiling cannot reserve the complete profile maximum")


def _answer(outcome: ExecutionOutcome, request_id: UUID) -> ExecutionResponse:
    """Map one authoritative outcome onto a response or RC1's frozen error table."""

    if outcome.state == "completed":
        if outcome.response_body is None:
            # Unreachable through the executor, which raises first; kept so a completion can
            # never be answered with an empty body whatever changes around it.
            raise _receipted("idempotency_recovery_unavailable", outcome)
        return _response(
            outcome.response_body,
            request_id=request_id,
            execution_id=outcome.execution_id,
            replayed=outcome.replayed,
            cost=_receipt(outcome.reserved_microusd, outcome),
        )
    if outcome.state in {"admitted", "dispatched"}:
        raise _receipted("request_in_progress", outcome)
    if outcome.state == "outcome_unknown":
        raise _receipted("execution_outcome_unknown", outcome)
    if outcome.state == "failed" and outcome.failure_code in ERRORS:
        raise _receipted(outcome.failure_code, outcome)
    # A state or stored code this surface does not recognise is not reported as anything else.
    raise ExecutionRejected("state_store_unavailable")


def _response(
    body: Any, *, request_id: UUID, execution_id: UUID, replayed: bool, cost: CostReceipt
) -> ExecutionResponse:
    return ExecutionResponse(
        contract="stoin.inference.execute.response.v1",
        request_id=request_id,
        execution_id=execution_id,
        replayed=replayed,
        execution_profile_id=body["execution_profile_id"],
        profile_release_id=body["profile_release_id"],
        output=OutputResult.model_validate(body["output"]),
        finish_reason=body["finish_reason"],
        usage=Usage.model_validate(body["usage"]),
        cost=cost,
    )


def _about(record: LedgerRecord, code: str) -> ExecutionRejected:
    return ExecutionRejected(
        code,
        execution_id=record.execution_id,
        execution_state=record.state,
        cost=_receipt(record.reserved_microusd, record),
    )


def _receipted(code: str, outcome: ExecutionOutcome) -> ExecutionRejected:
    return ExecutionRejected(
        code,
        execution_id=outcome.execution_id,
        execution_state=outcome.state,
        cost=_receipt(outcome.reserved_microusd, outcome),
    )


def _receipt(reserved: int | None, state: ExecutionOutcome | LedgerRecord) -> CostReceipt:
    if reserved is None:
        raise ExecutionRejected("state_store_unavailable")
    settled = state.settlement_status in {"settled", "settlement_overrun"}
    return CostReceipt(
        reserved_microusd=reserved,
        settled_microusd=state.settled_microusd if settled else None,
        settlement_status=state.settlement_status,  # type: ignore[arg-type]
    )
