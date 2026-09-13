from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from lucy.governed_memory import ImportAttemptResultV1, ImportJobResultV1
from lucy.memory_extraction import (
    MemoryExtractionCompletionRejected,
    MemoryExtractionCoordinator,
    MemoryExtractionDispatchV1,
    MemoryExtractionProviderOutcomeV1,
    MemoryExtractionUnavailable,
    memory_extraction_job_id,
)
from lucy.memory_import import ImportManifestRecordV1, ImportManifestV2
from lucy.secret_filter import MemorySecretDetected

NOW = datetime(2026, 9, 12, 20, 0, tzinfo=UTC)
CAMPAIGN = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SCOPE = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
RESERVATION = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")


class AccountingSpy:
    def __init__(
        self, events: list[str], *, replayed: bool = False, job_replayed: bool = False,
        job_fails: bool = False
    ) -> None:
        self.events = events
        self.replayed = replayed
        self.job_replayed = job_replayed
        self.job_fails = job_fails
        self.settlements: list[tuple[int, str]] = []

    def reserve_attempt(
        self, campaign_id: UUID, *, attempt_key: str, reserved_microusd: int
    ) -> ImportAttemptResultV1:
        assert campaign_id == CAMPAIGN
        assert attempt_key == "pilot:batch-1:attempt-1"
        assert reserved_microusd == 5_000
        self.events.append("reserve")
        return ImportAttemptResultV1(
            reservation_id=RESERVATION, replayed=self.replayed
        )

    def register_job(self, **values: object) -> ImportJobResultV1:
        assert values["reservation_id"] == RESERVATION
        dispatch = values["dispatch"]
        assert isinstance(dispatch, MemoryExtractionDispatchV1)
        self.events.append("register-job")
        if self.job_fails:
            raise RuntimeError("synthetic uncertain job registration")
        return ImportJobResultV1(
            extraction_job_id=dispatch.extraction_job_id,
            replayed=self.job_replayed,
        )

    def settle_attempt(
        self, reservation_id: UUID, *, billed_microusd: int, result: str
    ) -> ImportAttemptResultV1:
        assert reservation_id == RESERVATION
        self.events.append(f"settle:{result}:{billed_microusd}")
        self.settlements.append((billed_microusd, result))
        return ImportAttemptResultV1(reservation_id=RESERVATION, replayed=False)


class EligibilitySpy:
    def __init__(self, events: list[str], *, fail_phase: str | None = None) -> None:
        self.events = events
        self.fail_phase = fail_phase

    def require_eligible(self, **values: object) -> None:
        phase = str(values["phase"])
        assert values["campaign_id"] == CAMPAIGN
        assert values["source_record_ids"] == ("conversation:node:message",)
        self.events.append(f"eligible:{phase}")
        if phase == self.fail_phase:
            raise PermissionError("synthetic source fence")


class ProviderSpy:
    def __init__(
        self,
        events: list[str],
        *,
        fail: bool = False,
        billed_microusd: int = 2_000,
        provider_policy_id: str = "policy-v1",
        model_route: str = "openrouter/private-model",
    ) -> None:
        self.events = events
        self.fail = fail
        self.billed_microusd = billed_microusd
        self.provider_policy_id = provider_policy_id
        self.model_route = model_route

    def infer(self, **_: object) -> MemoryExtractionProviderOutcomeV1:
        self.events.append("provider")
        if self.fail:
            raise TimeoutError("synthetic ambiguous timeout")
        return MemoryExtractionProviderOutcomeV1(
            output='{"candidates": []}',
            billed_microusd=self.billed_microusd,
            provider_policy_id=self.provider_policy_id,
            model_route=self.model_route,
            provider_reference_commitment="d" * 64,
        )


class OutcomeJournalSpy:
    def __init__(
        self,
        events: list[str],
        *,
        recovered: MemoryExtractionProviderOutcomeV1 | None = None,
        record_fails: bool = False,
    ) -> None:
        self.events = events
        self.recovered = recovered
        self.record_fails = record_fails

    def load(self, **_: object) -> MemoryExtractionProviderOutcomeV1 | None:
        self.events.append("outcome-load")
        return self.recovered

    def record(self, **values: object) -> MemoryExtractionProviderOutcomeV1:
        self.events.append("outcome-record")
        if self.record_fails:
            raise RuntimeError("synthetic uncertain outcome persistence")
        outcome = values["outcome"]
        assert isinstance(outcome, MemoryExtractionProviderOutcomeV1)
        return outcome


class CompletionSpy:
    def __init__(
        self,
        events: list[str],
        accounting: AccountingSpy,
        *,
        fail: bool = False,
        reject: bool = False,
    ) -> None:
        self.events = events
        self.accounting = accounting
        self.fail = fail
        self.reject = reject

    def complete_success(
        self,
        *,
        reservation_id: UUID,
        outcome: MemoryExtractionProviderOutcomeV1,
    ) -> None:
        self.events.append("complete")
        if self.reject:
            raise MemoryExtractionCompletionRejected("synthetic invalid output")
        if self.fail:
            raise RuntimeError("synthetic uncertain commit acknowledgement")
        self.accounting.settle_attempt(
            reservation_id,
            billed_microusd=outcome.billed_microusd,
            result="succeeded",
        )


def _manifest(*, expires_at: datetime | None = None) -> ImportManifestV2:
    return ImportManifestV2(
        campaign_id=CAMPAIGN,
        destination_content_scope_id=SCOPE,
        source_namespace="raymond-private/chatgpt-export",
        source_conversation_id="pilot:selection",
        parser_version="chatgpt-export-inventory-v1",
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="policy-v1",
        model_route="openrouter/private-model",
        token_accounting_version="conservative-v1",
        records=(
            ImportManifestRecordV1(
                source_record_id="conversation:node:message",
                content_commitment="a" * 64,
                byte_length=17,
                estimated_tokens=6,
                source_revision=1,
                role="owner",
                displayed=True,
            ),
        ),
        max_records=1,
        max_bytes=17,
        max_source_estimated_tokens=6,
        max_request_input_tokens=100,
        max_request_output_tokens=100,
        max_request_total_tokens=200,
        max_model_spend_microusd=10_000,
        max_attempts=3,
        expires_at=expires_at or NOW + timedelta(hours=1),
    )


def _dispatch(
    *, prompt: str = "synthetic history", **changes: object
) -> MemoryExtractionDispatchV1:
    attempt_key = "pilot:batch-1:attempt-1"
    request_commitment = "e" * 64
    values: dict[str, object] = {
        "extraction_job_id": memory_extraction_job_id(
            CAMPAIGN,
            attempt_key=attempt_key,
            request_commitment=request_commitment,
        ),
        "attempt_key": attempt_key,
        "source_record_ids": ("conversation:node:message",),
        "prompt": prompt,
        "input_tokens": 20,
        "output_tokens": 50,
        "request_bytes": len(prompt.encode("utf-8")),
        "request_commitment": request_commitment,
        "maximum_microusd": 5_000,
        "timeout_seconds": 30,
    }
    values.update(changes)
    return MemoryExtractionDispatchV1.model_validate(values)


def _coordinator(
    events: list[str],
    *,
    accounting: AccountingSpy | None = None,
    eligibility: EligibilitySpy | None = None,
    provider: ProviderSpy | None = None,
    outcome_journal: OutcomeJournalSpy | None = None,
    completion_fails: bool = False,
    completion_rejects: bool = False,
) -> tuple[MemoryExtractionCoordinator, AccountingSpy]:
    selected_accounting = accounting or AccountingSpy(events)
    selected_journal = outcome_journal or OutcomeJournalSpy(events)
    return (
        MemoryExtractionCoordinator(
            selected_accounting,
            eligibility or EligibilitySpy(events),
            provider or ProviderSpy(events),
            selected_journal,
            CompletionSpy(
                events,
                selected_accounting,
                fail=completion_fails,
                reject=completion_rejects,
            ),
            outcome_recovery=selected_journal,
            now=lambda: NOW,
        ),
        selected_accounting,
    )


def test_success_rechecks_sources_and_settles_before_returning_output() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(events)

    result = coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert result.state == "succeeded"
    assert result.output == '{"candidates": []}'
    assert result.billed_microusd == 2_000
    assert accounting.settlements == [(2_000, "succeeded")]
    assert events == [
        "eligible:admission",
        "reserve",
        "register-job",
        "eligible:pre_dispatch",
        "provider",
        "outcome-record",
        "eligible:post_dispatch",
        "complete",
        "settle:succeeded:2000",
    ]


def test_expired_outside_manifest_or_secret_input_never_reserves_or_dispatches() -> None:
    for manifest, dispatch, error in (
        (_manifest(expires_at=NOW), _dispatch(), MemoryExtractionUnavailable),
        (
            _manifest(),
            _dispatch(source_record_ids=("outside:record",)),
            ValueError,
        ),
        (
            _manifest(),
            _dispatch(prompt="api key: synthetic-secret-value-12345"),
            MemorySecretDetected,
        ),
    ):
        events: list[str] = []
        coordinator, _ = _coordinator(events)
        with pytest.raises(error):
            coordinator.execute(manifest=manifest, dispatch=dispatch)
        assert events == []


def test_source_change_before_dispatch_settles_zero_and_blocks_provider() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(
        events, eligibility=EligibilitySpy(events, fail_phase="pre_dispatch")
    )

    with pytest.raises(MemoryExtractionUnavailable, match="before provider dispatch"):
        coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert accounting.settlements == [(0, "discarded")]
    assert "provider" not in events


def test_source_change_during_call_charges_cost_but_discards_output() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(
        events, eligibility=EligibilitySpy(events, fail_phase="post_dispatch")
    )

    result = coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert result.state == "discarded" and result.output is None
    assert accounting.settlements == [(2_000, "discarded")]


def test_provider_failure_charges_full_reservation_and_requires_reconciliation() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(
        events, provider=ProviderSpy(events, fail=True)
    )

    with pytest.raises(MemoryExtractionUnavailable, match="full reservation charged"):
        coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert accounting.settlements == [(5_000, "failed")]


def test_policy_mismatch_is_billed_and_discarded() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(
        events, provider=ProviderSpy(events, provider_policy_id="wrong-policy")
    )

    result = coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert result.state == "discarded" and result.output is None
    assert "policy or model route" in (result.reason or "")
    assert accounting.settlements == [(2_000, "discarded")]


def test_replayed_job_never_repeats_provider_execution() -> None:
    events: list[str] = []
    accounting = AccountingSpy(events, replayed=True, job_replayed=True)
    coordinator, _ = _coordinator(events, accounting=accounting)

    result = coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert result.state == "reconciliation_required" and result.output is None
    assert events == [
        "eligible:admission", "reserve", "register-job", "outcome-load"
    ]


def test_fresh_reservation_with_replayed_job_never_repeats_provider_execution() -> None:
    """A reservation/job race cannot grant two callers the dispatch claim."""

    events: list[str] = []
    accounting = AccountingSpy(events, replayed=False, job_replayed=True)
    coordinator, _ = _coordinator(events, accounting=accounting)

    result = coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert result.state == "reconciliation_required" and result.output is None
    assert "provider" not in events
    assert events == [
        "eligible:admission", "reserve", "register-job", "outcome-load"
    ]


def test_replayed_job_without_recovery_capability_stops_before_provider() -> None:
    events: list[str] = []
    accounting = AccountingSpy(events, replayed=True, job_replayed=True)
    writer = OutcomeJournalSpy(events)
    coordinator = MemoryExtractionCoordinator(
        accounting,
        EligibilitySpy(events),
        ProviderSpy(events),
        writer,
        CompletionSpy(events, accounting),
        now=lambda: NOW,
    )

    result = coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert result.state == "reconciliation_required"
    assert "exact-job outcome recovery" in (result.reason or "")
    assert events == ["eligible:admission", "reserve", "register-job"]


def test_replayed_reservation_without_job_can_safely_begin_dispatch() -> None:
    events: list[str] = []
    accounting = AccountingSpy(events, replayed=True, job_replayed=False)
    coordinator, _ = _coordinator(events, accounting=accounting)

    result = coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert result.state == "succeeded"
    assert events.count("provider") == 1


def test_replayed_job_resumes_from_encrypted_outcome_without_provider_call() -> None:
    events: list[str] = []
    accounting = AccountingSpy(events, replayed=True, job_replayed=True)
    recovered = ProviderSpy(events).infer()
    events.clear()
    coordinator, _ = _coordinator(
        events,
        accounting=accounting,
        outcome_journal=OutcomeJournalSpy(events, recovered=recovered),
    )

    result = coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert result.state == "succeeded"
    assert "provider" not in events
    assert events.count("outcome-load") == 1


def test_recovered_billed_outcome_preserves_cost_when_pre_dispatch_fence_closes() -> None:
    events: list[str] = []
    accounting = AccountingSpy(events, replayed=False, job_replayed=True)
    recovered = ProviderSpy(events, billed_microusd=2_750).infer()
    events.clear()
    coordinator, _ = _coordinator(
        events,
        accounting=accounting,
        eligibility=EligibilitySpy(events, fail_phase="pre_dispatch"),
        outcome_journal=OutcomeJournalSpy(events, recovered=recovered),
    )

    with pytest.raises(MemoryExtractionUnavailable, match="before provider dispatch"):
        coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert "provider" not in events
    assert accounting.settlements == [(2_750, "discarded")]


def test_uncertain_outcome_persistence_never_completes_or_settles() -> None:
    events: list[str] = []
    accounting = AccountingSpy(events)
    coordinator, _ = _coordinator(
        events,
        accounting=accounting,
        outcome_journal=OutcomeJournalSpy(events, record_fails=True),
    )

    with pytest.raises(MemoryExtractionUnavailable, match="persistence is uncertain"):
        coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert "complete" not in events
    assert accounting.settlements == []


def test_uncertain_job_registration_never_dispatches_or_settles() -> None:
    events: list[str] = []
    accounting = AccountingSpy(events, job_fails=True)
    coordinator, _ = _coordinator(events, accounting=accounting)

    with pytest.raises(MemoryExtractionUnavailable, match="job registration is uncertain"):
        coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert "provider" not in events
    assert accounting.settlements == []


def test_provider_over_cap_charges_admitted_maximum_and_returns_no_output() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(
        events, provider=ProviderSpy(events, billed_microusd=5_001)
    )

    with pytest.raises(MemoryExtractionUnavailable, match="above admitted maximum"):
        coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert accounting.settlements == [(5_000, "failed")]


def test_uncertain_completion_never_returns_output_or_settles_separately() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(events, completion_fails=True)

    with pytest.raises(MemoryExtractionUnavailable, match="reconciliation required"):
        coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert events[-1] == "complete"
    assert accounting.settlements == []


def test_deterministically_rejected_completion_is_charged_and_discarded() -> None:
    events: list[str] = []
    coordinator, accounting = _coordinator(events, completion_rejects=True)

    result = coordinator.execute(manifest=_manifest(), dispatch=_dispatch())

    assert result.state == "discarded" and result.output is None
    assert accounting.settlements == [(2_000, "discarded")]
