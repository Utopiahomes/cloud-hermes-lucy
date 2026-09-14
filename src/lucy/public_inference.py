"""Fail-closed orchestration for an R1 bounded public provider call."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from lucy.cost_admission import (
    ProviderAttemptAdmissionV1,
    ProviderAttemptRequestV1,
)


class PublicInferenceUnavailable(RuntimeError):
    """The paid route cannot safely execute or replay a provider call."""


class PublicInferenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt: str = Field(min_length=1)
    maximum_microusd: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    request_bytes: int = Field(ge=1)
    timeout_seconds: int = Field(ge=1)


class ProviderInferenceOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    output: str
    incurred_microusd: int = Field(ge=0)
    provider_reference: str = Field(min_length=1, max_length=500)


class CostAdmissionGateway(Protocol):
    def reserve(self, request: ProviderAttemptRequestV1) -> ProviderAttemptAdmissionV1: ...

    def claim_submission(self, attempt_id: UUID) -> ProviderAttemptAdmissionV1: ...

    def mark_unknown(self, attempt_id: UUID) -> ProviderAttemptAdmissionV1: ...

    def settle(
        self,
        *,
        attempt_id: UUID,
        incurred_microusd: int,
        provider_reference_commitment: str,
    ) -> ProviderAttemptAdmissionV1: ...



class CostRecoveryGateway(Protocol):
    def acknowledge(
        self, *, attempt_id: UUID, event_id: UUID, head_digest: str
    ) -> CostAcknowledgementResult: ...

    def acknowledge_outcome(
        self, *, attempt_id: UUID, event_id: UUID, head_digest: str
    ) -> CostAcknowledgementResult: ...


class CostAcknowledgementResult(Protocol):
    @property
    def state(self) -> str: ...


class CostJournalGateway(Protocol):
    def append_reservation(self, admission: ProviderAttemptAdmissionV1) -> str: ...

    def append_outcome(
        self,
        *,
        attempt: ProviderAttemptRequestV1,
        admission: ProviderAttemptAdmissionV1,
        incurred_microusd: int,
        provider_reference_commitment: str,
    ) -> str: ...


class PublicProvider(Protocol):
    def infer(self, request: PublicInferenceRequest) -> ProviderInferenceOutcome: ...


@dataclass(frozen=True)
class PublicInferenceResult:
    attempt_id: UUID
    state: str
    output: str | None
    replayed: bool


class PublicInferenceCoordinator:
    """Keep body-bearing provider execution behind content-free durable gates."""

    def __init__(
        self,
        admission: CostAdmissionGateway,
        journal: CostJournalGateway,
        recovery: CostRecoveryGateway,
        provider: PublicProvider,
        *,
        provider_reference_commitment_key: bytes,
    ) -> None:
        if len(provider_reference_commitment_key) < 32:
            raise ValueError("provider reference commitment key is too short")
        self._admission = admission
        self._journal = journal
        self._recovery = recovery
        self._provider = provider
        self._commitment_key = provider_reference_commitment_key

    def execute(
        self,
        *,
        attempt: ProviderAttemptRequestV1,
        inference: PublicInferenceRequest,
    ) -> PublicInferenceResult:
        self._require_same_bounds(attempt, inference)
        reserved = self._admission.reserve(attempt)
        if reserved.replayed and reserved.state != "PERSISTENCE_PENDING":
            return PublicInferenceResult(attempt.attempt_id, reserved.state, None, True)
        if reserved.state != "PERSISTENCE_PENDING":
            raise PublicInferenceUnavailable("provider reservation returned an invalid state")

        head_digest = self._journal.append_reservation(reserved)
        admitted = self._recovery.acknowledge(
            attempt_id=attempt.attempt_id,
            event_id=reserved.event_id,
            head_digest=head_digest,
        )
        if admitted.state != "ADMITTED":
            raise PublicInferenceUnavailable("provider reservation is not durably admitted")
        claimed = self._admission.claim_submission(attempt.attempt_id)
        if claimed.state != "SUBMITTED" or claimed.replayed:
            raise PublicInferenceUnavailable("provider submission claim is unavailable")

        try:
            outcome = self._provider.infer(inference)
        except Exception:
            self._admission.mark_unknown(attempt.attempt_id)
            raise PublicInferenceUnavailable("provider outcome is unknown") from None
        reference_commitment = hmac.new(
            self._commitment_key,
            outcome.provider_reference.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        settled = self._admission.settle(
            attempt_id=attempt.attempt_id,
            incurred_microusd=outcome.incurred_microusd,
            provider_reference_commitment=reference_commitment,
        )
        if settled.state not in {"SETTLEMENT_PENDING", "OVER_CAP_PENDING"}:
            raise PublicInferenceUnavailable("provider settlement persistence is unavailable")
        outcome_head = self._journal.append_outcome(
            attempt=attempt,
            admission=settled,
            incurred_microusd=outcome.incurred_microusd,
            provider_reference_commitment=reference_commitment,
        )
        finalized = self._recovery.acknowledge_outcome(
            attempt_id=attempt.attempt_id,
            event_id=settled.event_id,
            head_digest=outcome_head,
        )
        if finalized.state != "SETTLED":
            raise PublicInferenceUnavailable("provider settlement did not close")
        return PublicInferenceResult(attempt.attempt_id, finalized.state, outcome.output, False)

    @staticmethod
    def _require_same_bounds(
        attempt: ProviderAttemptRequestV1, inference: PublicInferenceRequest
    ) -> None:
        if (
            attempt.maximum_microusd,
            attempt.input_tokens,
            attempt.output_tokens,
            attempt.request_bytes,
            attempt.timeout_seconds,
        ) != (
            inference.maximum_microusd,
            inference.input_tokens,
            inference.output_tokens,
            inference.request_bytes,
            inference.timeout_seconds,
        ):
            raise ValueError("provider request differs from its admitted bounds")
