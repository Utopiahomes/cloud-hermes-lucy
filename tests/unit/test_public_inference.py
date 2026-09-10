from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

import pytest

from lucy.cost_admission import ProviderAttemptAdmissionV1, ProviderAttemptRequestV1
from lucy.public_inference import (
    ProviderInferenceOutcome,
    PublicInferenceCoordinator,
    PublicInferenceRequest,
    PublicInferenceUnavailable,
)

_State = Literal[
    "PERSISTENCE_PENDING",
    "ADMITTED",
    "SUBMITTED",
    "UNKNOWN",
    "SETTLEMENT_PENDING",
    "OVER_CAP_PENDING",
    "SETTLED",
    "OVER_CAP",
]


class FakeAdmission:
    def __init__(self) -> None:
        self.attempt_id = uuid4()
        self.policy_id = uuid4()
        self.event_id = uuid4()
        self.calls: list[str] = []
        self.replay_state: _State | None = None

    def result(
        self,
        state: _State,
        replayed: bool = False,
    ) -> ProviderAttemptAdmissionV1:
        return ProviderAttemptAdmissionV1(
            attempt_id=self.attempt_id,
            policy_id=self.policy_id,
            policy_version=1,
            state=state,
            reserved_microusd=5_000,
            unresolved_microusd=0 if state in {"SETTLED", "OVER_CAP"} else 5_000,
            event_id=self.event_id,
            replayed=replayed,
        )

    def reserve(self, request: ProviderAttemptRequestV1) -> ProviderAttemptAdmissionV1:
        self.calls.append("reserve")
        self.attempt_id = request.attempt_id
        return self.result(
            self.replay_state or "PERSISTENCE_PENDING",
            replayed=self.replay_state is not None,
        )

    def claim_submission(self, _: UUID) -> ProviderAttemptAdmissionV1:
        self.calls.append("claim")
        return self.result("SUBMITTED")

    def mark_unknown(self, _: UUID) -> ProviderAttemptAdmissionV1:
        self.calls.append("unknown")
        return self.result("UNKNOWN")

    def settle(self, **_: object) -> ProviderAttemptAdmissionV1:
        self.calls.append("settle")
        self.event_id = uuid4()
        return self.result("SETTLEMENT_PENDING")



class FakeRecovery:
    def __init__(self, admission: FakeAdmission) -> None:
        self._admission = admission

    def acknowledge(self, **_: object) -> ProviderAttemptAdmissionV1:
        return self._admission.result("ADMITTED")

    def acknowledge_outcome(self, **_: object) -> ProviderAttemptAdmissionV1:
        return self._admission.result("SETTLED")


class FakeJournal:
    def __init__(self, *, fail: bool = False, fail_outcome: bool = False) -> None:
        self.fail = fail
        self.fail_outcome = fail_outcome
        self.calls = 0

    def append_reservation(self, _: ProviderAttemptAdmissionV1) -> str:
        self.calls += 1
        if self.fail:
            raise RuntimeError("synthetic journal unavailable")
        return "d" * 64

    def append_outcome(self, **_: object) -> str:
        self.calls += 1
        if self.fail_outcome:
            raise RuntimeError("synthetic outcome journal unavailable")
        return "e" * 64


class FakeProvider:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def infer(self, _: PublicInferenceRequest) -> ProviderInferenceOutcome:
        self.calls += 1
        if self.fail:
            raise TimeoutError("synthetic ambiguous timeout")
        return ProviderInferenceOutcome(
            output="synthetic answer",
            incurred_microusd=2_000,
            provider_reference="synthetic-provider-reference",
        )


def request_pair(attempt_id: UUID) -> tuple[ProviderAttemptRequestV1, PublicInferenceRequest]:
    inference = PublicInferenceRequest(
        prompt="synthetic prompt",
        maximum_microusd=5_000,
        input_tokens=100,
        output_tokens=100,
        request_bytes=500,
        timeout_seconds=20,
    )
    attempt = ProviderAttemptRequestV1(
        attempt_id=attempt_id,
        idempotency_key=f"public:{attempt_id}",
        node_id=uuid4(),
        channel_binding_id=uuid4(),
        provider="openrouter",
        model="openai/gpt-oss-20b",
        rate_version="synthetic-v1",
        request_commitment="a" * 64,
        session_commitment="b" * 64,
        ip_commitment="c" * 64,
        maximum_microusd=inference.maximum_microusd,
        input_tokens=inference.input_tokens,
        output_tokens=inference.output_tokens,
        request_bytes=inference.request_bytes,
        timeout_seconds=inference.timeout_seconds,
        requested_at=datetime.now(UTC),
    )
    return attempt, inference


def coordinator(
    admission: FakeAdmission, journal: FakeJournal, provider: FakeProvider
) -> PublicInferenceCoordinator:
    return PublicInferenceCoordinator(
        admission,
        journal,
        FakeRecovery(admission),
        provider,
        provider_reference_commitment_key=b"k" * 32,
    )


def test_provider_runs_only_after_durable_admission_and_exact_claim() -> None:
    admission, journal, provider = FakeAdmission(), FakeJournal(), FakeProvider()
    attempt, inference = request_pair(admission.attempt_id)
    result = coordinator(admission, journal, provider).execute(
        attempt=attempt, inference=inference
    )
    assert result.output == "synthetic answer"
    assert admission.calls == [
        "reserve",
        "claim",
        "settle",
    ]
    assert journal.calls == 2 and provider.calls == 1


def test_journal_failure_never_reaches_provider() -> None:
    admission, journal, provider = FakeAdmission(), FakeJournal(fail=True), FakeProvider()
    attempt, inference = request_pair(admission.attempt_id)
    with pytest.raises(RuntimeError, match="journal unavailable"):
        coordinator(admission, journal, provider).execute(attempt=attempt, inference=inference)
    assert admission.calls == ["reserve"]
    assert provider.calls == 0


def test_ambiguous_provider_failure_preserves_unknown_exposure() -> None:
    admission, journal = FakeAdmission(), FakeJournal()
    provider = FakeProvider(fail=True)
    attempt, inference = request_pair(admission.attempt_id)
    with pytest.raises(PublicInferenceUnavailable, match="outcome is unknown"):
        coordinator(admission, journal, provider).execute(attempt=attempt, inference=inference)
    assert admission.calls == ["reserve", "claim", "unknown"]


def test_outcome_journal_failure_retains_exposure_and_does_not_return_output() -> None:
    admission = FakeAdmission()
    journal = FakeJournal(fail_outcome=True)
    provider = FakeProvider()
    attempt, inference = request_pair(admission.attempt_id)
    with pytest.raises(RuntimeError, match="outcome journal unavailable"):
        coordinator(admission, journal, provider).execute(attempt=attempt, inference=inference)
    assert admission.calls == ["reserve", "claim", "settle"]
    assert provider.calls == 1 and journal.calls == 2


def test_retry_never_calls_provider_again() -> None:
    admission, journal, provider = FakeAdmission(), FakeJournal(), FakeProvider()
    admission.replay_state = "UNKNOWN"
    attempt, inference = request_pair(admission.attempt_id)
    result = coordinator(admission, journal, provider).execute(
        attempt=attempt, inference=inference
    )
    assert result.replayed and result.output is None and result.state == "UNKNOWN"
    assert admission.calls == ["reserve"]
    assert journal.calls == 0 and provider.calls == 0


def test_body_request_cannot_exceed_or_differ_from_reserved_bounds() -> None:
    admission, journal, provider = FakeAdmission(), FakeJournal(), FakeProvider()
    attempt, inference = request_pair(admission.attempt_id)
    changed = inference.model_copy(update={"output_tokens": inference.output_tokens + 1})
    with pytest.raises(ValueError, match="differs"):
        coordinator(admission, journal, provider).execute(attempt=attempt, inference=changed)
    assert admission.calls == [] and provider.calls == 0
