"""Fail-closed orchestration for bounded private-memory extraction attempts."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from lucy.governed_memory import ImportAttemptResultV1
from lucy.memory_import import ImportManifestV2
from lucy.secret_filter import MemorySecretDetected, detect_memory_secrets


class MemoryExtractionUnavailable(RuntimeError):
    """The attempt cannot proceed without weakening an import boundary."""


class MemoryExtractionCompletionRejected(ValueError):
    """The provider output failed deterministic completion validation."""


class MemoryExtractionDispatchV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    attempt_key: str = Field(min_length=1, max_length=512)
    source_record_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    prompt: str = Field(min_length=1, max_length=2_000_000)
    input_tokens: int = Field(ge=1)
    output_tokens: int = Field(ge=1)
    request_bytes: int = Field(ge=1)
    maximum_microusd: int = Field(ge=0)
    timeout_seconds: int = Field(ge=1, le=600)

    @model_validator(mode="after")
    def exact_source_set(self) -> MemoryExtractionDispatchV1:
        if len(set(self.source_record_ids)) != len(self.source_record_ids):
            raise ValueError("extraction source record IDs must be unique")
        if self.request_bytes != len(self.prompt.encode("utf-8")):
            raise ValueError("extraction request byte count is not exact")
        return self


class MemoryExtractionProviderOutcomeV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    output: str
    billed_microusd: int = Field(ge=0)
    provider_policy_id: str = Field(min_length=1, max_length=200)
    model_route: str = Field(min_length=1, max_length=200)
    provider_reference_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")


class MemoryExtractionResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reservation_id: UUID
    state: Literal["succeeded", "discarded", "reconciliation_required"]
    output: str | None
    billed_microusd: int = Field(ge=0)
    reason: str | None = None


class MemoryImportCampaignAccounting(Protocol):
    def reserve_attempt(
        self, campaign_id: UUID, *, attempt_key: str, reserved_microusd: int
    ) -> ImportAttemptResultV1: ...

    def settle_attempt(
        self, reservation_id: UUID, *, billed_microusd: int, result: str
    ) -> ImportAttemptResultV1: ...


class MemoryImportSourceEligibility(Protocol):
    def require_eligible(
        self,
        *,
        campaign_id: UUID,
        manifest_digest: str,
        source_record_ids: tuple[str, ...],
        phase: Literal["admission", "pre_dispatch", "post_dispatch"],
    ) -> None: ...


class MemoryImportProvider(Protocol):
    def infer(
        self,
        *,
        manifest: ImportManifestV2,
        dispatch: MemoryExtractionDispatchV1,
    ) -> MemoryExtractionProviderOutcomeV1: ...


class MemoryExtractionSuccessCompletion(Protocol):
    def complete_success(
        self,
        *,
        reservation_id: UUID,
        outcome: MemoryExtractionProviderOutcomeV1,
    ) -> None: ...


class MemoryExtractionCoordinator:
    """Reserve, recheck, execute, recheck, and settle one exact import attempt."""

    def __init__(
        self,
        accounting: MemoryImportCampaignAccounting,
        eligibility: MemoryImportSourceEligibility,
        provider: MemoryImportProvider,
        completion: MemoryExtractionSuccessCompletion,
        *,
        now: Callable[[], datetime],
    ) -> None:
        self._accounting = accounting
        self._eligibility = eligibility
        self._provider = provider
        self._completion = completion
        self._now = now

    def execute(
        self,
        *,
        manifest: ImportManifestV2,
        dispatch: MemoryExtractionDispatchV1,
    ) -> MemoryExtractionResultV1:
        self._validate_dispatch(manifest, dispatch)
        self._require_sources(manifest, dispatch, "admission")
        reservation = self._accounting.reserve_attempt(
            manifest.campaign_id,
            attempt_key=dispatch.attempt_key,
            reserved_microusd=dispatch.maximum_microusd,
        )
        if reservation.replayed:
            return MemoryExtractionResultV1(
                reservation_id=reservation.reservation_id,
                state="reconciliation_required",
                output=None,
                billed_microusd=0,
                reason="campaign reservation replay requires durable outcome reconciliation",
            )
        try:
            self._require_sources(manifest, dispatch, "pre_dispatch")
        except Exception:
            self._accounting.settle_attempt(
                reservation.reservation_id,
                billed_microusd=0,
                result="discarded",
            )
            raise MemoryExtractionUnavailable(
                "source eligibility changed before provider dispatch"
            ) from None
        try:
            outcome = self._provider.infer(manifest=manifest, dispatch=dispatch)
        except Exception:
            self._accounting.settle_attempt(
                reservation.reservation_id,
                billed_microusd=dispatch.maximum_microusd,
                result="failed",
            )
            raise MemoryExtractionUnavailable(
                "provider outcome is unknown; full reservation charged to campaign"
            ) from None
        if outcome.billed_microusd > dispatch.maximum_microusd:
            self._accounting.settle_attempt(
                reservation.reservation_id,
                billed_microusd=dispatch.maximum_microusd,
                result="failed",
            )
            raise MemoryExtractionUnavailable("provider reported cost above admitted maximum")
        if (
            outcome.provider_policy_id != manifest.provider_policy_id
            or outcome.model_route != manifest.model_route
        ):
            self._accounting.settle_attempt(
                reservation.reservation_id,
                billed_microusd=outcome.billed_microusd,
                result="discarded",
            )
            return MemoryExtractionResultV1(
                reservation_id=reservation.reservation_id,
                state="discarded",
                output=None,
                billed_microusd=outcome.billed_microusd,
                reason="provider policy or model route differed from manifest",
            )
        try:
            self._require_sources(manifest, dispatch, "post_dispatch")
        except Exception:
            self._accounting.settle_attempt(
                reservation.reservation_id,
                billed_microusd=outcome.billed_microusd,
                result="discarded",
            )
            return MemoryExtractionResultV1(
                reservation_id=reservation.reservation_id,
                state="discarded",
                output=None,
                billed_microusd=outcome.billed_microusd,
                reason="source became ineligible during provider execution",
            )
        try:
            self._completion.complete_success(
                reservation_id=reservation.reservation_id,
                outcome=outcome,
            )
        except MemoryExtractionCompletionRejected:
            self._accounting.settle_attempt(
                reservation.reservation_id,
                billed_microusd=outcome.billed_microusd,
                result="discarded",
            )
            return MemoryExtractionResultV1(
                reservation_id=reservation.reservation_id,
                state="discarded",
                output=None,
                billed_microusd=outcome.billed_microusd,
                reason="provider output failed deterministic completion validation",
            )
        except Exception:
            raise MemoryExtractionUnavailable(
                "provider outcome completion is uncertain; reconciliation required"
            ) from None
        return MemoryExtractionResultV1(
            reservation_id=reservation.reservation_id,
            state="succeeded",
            output=outcome.output,
            billed_microusd=outcome.billed_microusd,
        )

    def _validate_dispatch(
        self, manifest: ImportManifestV2, dispatch: MemoryExtractionDispatchV1
    ) -> None:
        if manifest.contract_version != "2":
            raise MemoryExtractionUnavailable(
                "real extraction requires an executable v2 import manifest"
            )
        now = self._now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("extraction clock must be timezone-aware")
        if now >= manifest.expires_at:
            raise MemoryExtractionUnavailable("memory import campaign has expired")
        included = {record.source_record_id for record in manifest.records if record.included}
        if not set(dispatch.source_record_ids).issubset(included):
            raise ValueError("extraction dispatch contains records outside the manifest")
        if dispatch.input_tokens > manifest.max_request_input_tokens:
            raise ValueError("extraction input exceeds the manifest token ceiling")
        if dispatch.output_tokens > manifest.max_request_output_tokens:
            raise ValueError("extraction output exceeds the manifest token ceiling")
        if dispatch.input_tokens + dispatch.output_tokens > manifest.max_request_total_tokens:
            raise ValueError("extraction request exceeds the manifest total-token ceiling")
        if dispatch.maximum_microusd > manifest.max_model_spend_microusd:
            raise ValueError("extraction reservation exceeds the campaign spend ceiling")
        findings = detect_memory_secrets(dispatch.prompt)
        if findings:
            raise MemorySecretDetected(tuple(item.category for item in findings))

    def _require_sources(
        self,
        manifest: ImportManifestV2,
        dispatch: MemoryExtractionDispatchV1,
        phase: Literal["admission", "pre_dispatch", "post_dispatch"],
    ) -> None:
        self._eligibility.require_eligible(
            campaign_id=manifest.campaign_id,
            manifest_digest=manifest.digest,
            source_record_ids=dispatch.source_record_ids,
            phase=phase,
        )
