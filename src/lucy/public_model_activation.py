"""Exact, fail-closed release contract for model-backed Public Lucy."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MODEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,79}/[A-Za-z0-9][A-Za-z0-9._:-]{0,159}\Z")
_PROVIDER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,99}\Z")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PublicModelArtifactPinsV2(StrictModel):
    cloud_source_commit: str
    cloud_rollback_commit: str
    website_source_commit: str
    website_rollback_commit: str
    image_digest: str
    base_image_digest: str
    schema_revision: Literal["0071_memory_import_job_replay"]
    aws_realm_template_sha256: str
    aws_recovery_template_sha256: str

    @model_validator(mode="after")
    def pins_are_exact(self) -> PublicModelArtifactPinsV2:
        commits = (
            self.cloud_source_commit,
            self.cloud_rollback_commit,
            self.website_source_commit,
            self.website_rollback_commit,
        )
        digests = (
            self.image_digest,
            self.base_image_digest,
            self.aws_realm_template_sha256,
            self.aws_recovery_template_sha256,
        )
        if any(_GIT_SHA.fullmatch(item) is None for item in commits):
            raise ValueError("model release commits must be full lowercase Git SHAs")
        if any(_SHA256.fullmatch(item) is None for item in digests):
            raise ValueError("model release artifacts must be lowercase SHA-256 values")
        return self


class PublicModelIngressV2(StrictModel):
    website_origin: Literal["https://www.utopiahomes.com"]
    website_api_path: Literal["/api/lucy"]
    public_service: Literal["lucy-public"]
    model_service: Literal["lucy-public-model"]
    model_service_private_only: Literal[True]
    trust_forwarded_host: Literal[False]
    max_browser_request_bytes: int = Field(ge=1_024, le=1_048_576)
    max_model_request_bytes: int = Field(ge=10_000, le=1_000_000)
    requests_per_ip_per_minute: int = Field(ge=1, le=600)
    requests_per_session_per_minute: int = Field(ge=1, le=600)


class OpenRouterRoutingV2(StrictModel):
    provider: Literal["openrouter"]
    model: str = Field(min_length=3, max_length=240)
    allowed_providers: tuple[str, ...] = Field(min_length=1, max_length=10)
    rate_version: str = Field(min_length=1, max_length=80)
    credential_scope_reference: str = Field(min_length=3, max_length=256)
    zero_data_retention: Literal[True]
    data_collection: Literal["deny"]
    allow_fallbacks: Literal[False]
    max_prompt_usd_per_million: float = Field(gt=0, le=1_000)
    max_completion_usd_per_million: float = Field(gt=0, le=1_000)

    @model_validator(mode="after")
    def route_is_exact(self) -> OpenRouterRoutingV2:
        if _MODEL.fullmatch(self.model) is None:
            raise ValueError("model identifier is not exact")
        if (
            len(set(self.allowed_providers)) != len(self.allowed_providers)
            or any(_PROVIDER.fullmatch(item) is None for item in self.allowed_providers)
        ):
            raise ValueError("provider allowlist is invalid")
        return self


class PublicModelCostPolicyV2(StrictModel):
    kill_state: Literal["disabled", "enabled"]
    platform_daily_cap_microusd: int = Field(ge=1)
    node_daily_cap_microusd: int = Field(ge=1)
    site_daily_cap_microusd: int = Field(ge=1)
    provider_daily_cap_microusd: int = Field(ge=1)
    outstanding_cap_microusd: int = Field(ge=1)
    per_attempt_cap_microusd: int = Field(ge=1)
    per_conversation_cap_microusd: int = Field(ge=1)
    concurrency_limit: int = Field(ge=1, le=100)
    requests_per_minute: int = Field(ge=1, le=600)
    session_requests_per_minute: int = Field(ge=1, le=600)
    ip_requests_per_minute: int = Field(ge=1, le=600)

    @model_validator(mode="after")
    def caps_are_nested(self) -> PublicModelCostPolicyV2:
        enclosing = (
            self.platform_daily_cap_microusd,
            self.node_daily_cap_microusd,
            self.site_daily_cap_microusd,
            self.provider_daily_cap_microusd,
            self.outstanding_cap_microusd,
        )
        if self.per_attempt_cap_microusd > min(enclosing):
            raise ValueError("per-attempt cost exceeds an enclosing cap")
        if self.per_conversation_cap_microusd > min(enclosing):
            raise ValueError("per-conversation cost exceeds an enclosing cap")
        return self


class PublicModelExecutionV2(StrictModel):
    generator_max_microusd: int = Field(ge=1)
    verifier_max_microusd: int = Field(ge=1)
    generator_max_output_tokens: int = Field(ge=64, le=4_096)
    verifier_max_output_tokens: int = Field(ge=64, le=4_096)
    max_input_tokens: int = Field(ge=1, le=1_000_000)
    provider_timeout_seconds: int = Field(ge=1, le=30)
    public_to_model_timeout_seconds: int = Field(ge=1, le=30)
    website_to_public_timeout_seconds: int = Field(ge=1, le=60)

    def validate_against(self, cost: PublicModelCostPolicyV2) -> None:
        if max(self.generator_max_microusd, self.verifier_max_microusd) > (
            cost.per_attempt_cap_microusd
        ):
            raise ValueError("model call cap exceeds the per-attempt cost policy")
        if self.generator_max_microusd + self.verifier_max_microusd > (
            cost.per_conversation_cap_microusd
        ):
            raise ValueError("model call caps exceed the per-conversation policy")
        if max(self.generator_max_output_tokens, self.verifier_max_output_tokens) > (
            self.max_input_tokens
        ):
            raise ValueError("model token bounds are incoherent")
        if not (
            self.provider_timeout_seconds * 2
            <= self.public_to_model_timeout_seconds
            < self.website_to_public_timeout_seconds
        ):
            raise ValueError("model handoff timeouts are incoherent")


class PublicModelHistoryV2(StrictModel):
    storage: Literal["browser-memory-only"]
    max_turns: Literal[6]
    max_characters: Literal[4000]
    expires_after_seconds: Literal[1800]
    clears_on_refresh: Literal[True]
    clears_on_close: Literal[True]
    prior_messages_are_evidence: Literal[False]


class PublicModelPublicationV2(StrictModel):
    active_snapshot_sha256: str
    rollback_snapshot_sha256: str | None
    model_allowed_snapshot_sha256: tuple[str, ...] = Field(min_length=1, max_length=5)
    withdrawn_snapshot_sha256: tuple[str, ...] = Field(default=(), max_length=100)
    source_lineage: tuple[str, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def snapshot_sets_are_safe(self) -> PublicModelPublicationV2:
        allowed = set(self.model_allowed_snapshot_sha256)
        withdrawn = set(self.withdrawn_snapshot_sha256)
        values = allowed | withdrawn | {self.active_snapshot_sha256}
        if self.rollback_snapshot_sha256 is not None:
            values.add(self.rollback_snapshot_sha256)
        if any(_SHA256.fullmatch(item) is None for item in values):
            raise ValueError("model release snapshots must use lowercase SHA-256 values")
        if (
            len(allowed) != len(self.model_allowed_snapshot_sha256)
            or len(withdrawn) != len(self.withdrawn_snapshot_sha256)
            or allowed & withdrawn
            or self.active_snapshot_sha256 in withdrawn
            or self.rollback_snapshot_sha256 in withdrawn
        ):
            raise ValueError("model release snapshot eligibility is inconsistent")
        return self


class UtopiaPublicModelActivationManifestV2(StrictModel):
    contract: Literal["lucy.utopia.public-model.activation-manifest.v2"]
    environment: Literal["production"]
    realm_slug: Literal["utopia"]
    release_state: Literal["staged-disabled", "staging-test", "active"]
    release_decision_id: str = Field(min_length=1, max_length=256)
    artifacts: PublicModelArtifactPinsV2
    ingress: PublicModelIngressV2
    routing: OpenRouterRoutingV2
    cost_policy: PublicModelCostPolicyV2
    execution: PublicModelExecutionV2
    history: PublicModelHistoryV2
    publication: PublicModelPublicationV2
    model_traffic_enabled: bool
    transcript_capture_enabled: Literal[False]
    permitted_data_classes: tuple[
        Literal["approved-public-knowledge", "temporary-browser-conversation-context"], ...
    ] = Field(min_length=2, max_length=2)
    permitted_actions: tuple[Literal["public-read-only-model-answer"], ...] = Field(
        min_length=1, max_length=1
    )
    operations_contact: str = Field(min_length=3, max_length=320)
    rollback_owner: str = Field(min_length=3, max_length=320)

    @model_validator(mode="after")
    def state_is_fail_closed(self) -> UtopiaPublicModelActivationManifestV2:
        if set(self.permitted_data_classes) != {
            "approved-public-knowledge",
            "temporary-browser-conversation-context",
        }:
            raise ValueError("model release data classes are incomplete")
        expected = {
            "staged-disabled": (False, "disabled"),
            "staging-test": (False, "enabled"),
            "active": (True, "enabled"),
        }[self.release_state]
        if (self.model_traffic_enabled, self.cost_policy.kill_state) != expected:
            raise ValueError("model traffic and cost state do not match the release state")
        if (
            self.release_state == "active"
            and self.publication.active_snapshot_sha256
            not in self.publication.model_allowed_snapshot_sha256
        ):
            raise ValueError("active model traffic requires an eligible active snapshot")
        self.execution.validate_against(self.cost_policy)
        return self
