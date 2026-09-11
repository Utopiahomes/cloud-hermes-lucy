"""Fail-closed contract for one bounded R1 customer activation."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ArtifactPins(StrictModel):
    source_commit: str
    rollback_commit: str
    image_digest: str
    base_image_digest: str
    schema_revision: Literal["0053_r1_telegram_authority"]
    aws_realm_template_sha256: str
    aws_recovery_template_sha256: str

    @model_validator(mode="after")
    def validate_digests(self) -> ArtifactPins:
        if not _GIT_SHA.fullmatch(self.source_commit):
            raise ValueError("source commit must be a full lowercase Git SHA")
        if not _GIT_SHA.fullmatch(self.rollback_commit):
            raise ValueError("rollback commit must be a full lowercase Git SHA")
        digests = (
            self.image_digest,
            self.base_image_digest,
            self.aws_realm_template_sha256,
            self.aws_recovery_template_sha256,
        )
        if any(_SHA256.fullmatch(value) is None for value in digests):
            raise ValueError("artifact digests must be lowercase SHA-256 values")
        return self


class CustomerIdentity(StrictModel):
    issuer: HttpUrl
    audience: str = Field(min_length=1, max_length=512)
    owner_subjects: tuple[str, ...] = Field(min_length=1, max_length=10)
    strong_auth_claim: str = Field(min_length=1, max_length=128)
    strong_auth_values: tuple[str, ...] = Field(min_length=1, max_length=10)


class IngressBoundary(StrictModel):
    public_hostnames: tuple[str, ...] = Field(min_length=1, max_length=10)
    private_hostnames: tuple[str, ...] = Field(max_length=10)
    allowed_origins: tuple[HttpUrl, ...] = Field(min_length=1, max_length=10)
    trust_forwarded_host: Literal[False]
    max_request_bytes: int = Field(ge=1024, le=1_048_576)
    requests_per_ip_per_minute: int = Field(ge=1, le=600)
    requests_per_session_per_minute: int = Field(ge=1, le=600)
    session_ttl_seconds: int = Field(ge=300, le=86_400)

    @model_validator(mode="after")
    def validate_hosts(self) -> IngressBoundary:
        hosts = self.public_hostnames + self.private_hostnames
        if len(set(hosts)) != len(hosts):
            raise ValueError("public and private hostnames must be distinct")
        if any(_HOSTNAME.fullmatch(host) is None for host in hosts):
            raise ValueError("ingress hostname is invalid")
        origin_hosts = {origin.host for origin in self.allowed_origins}
        if not origin_hosts.issubset(set(hosts)):
            raise ValueError("every allowed origin must use an exact declared hostname")
        if any(origin.scheme != "https" for origin in self.allowed_origins):
            raise ValueError("allowed origins must use HTTPS")
        return self


class PaidInferenceLimits(StrictModel):
    provider: Literal["openrouter"]
    model: str = Field(min_length=1, max_length=256)
    rate_version: str = Field(min_length=1, max_length=128)
    credential_scope_reference: str = Field(min_length=1, max_length=256)
    platform_daily_cap_microusd: int = Field(ge=1)
    realm_daily_cap_microusd: int = Field(ge=1)
    site_daily_cap_microusd: int = Field(ge=1)
    provider_daily_cap_microusd: int = Field(ge=1)
    outstanding_cap_microusd: int = Field(ge=1)
    per_request_cap_microusd: int = Field(ge=1)
    concurrency_cap: int = Field(ge=1, le=100)
    max_input_tokens: int = Field(ge=1)
    max_output_tokens: int = Field(ge=1)
    timeout_seconds: int = Field(ge=1, le=300)

    @model_validator(mode="after")
    def validate_caps(self) -> PaidInferenceLimits:
        ceilings = (
            self.platform_daily_cap_microusd,
            self.realm_daily_cap_microusd,
            self.site_daily_cap_microusd,
            self.provider_daily_cap_microusd,
            self.outstanding_cap_microusd,
        )
        if self.per_request_cap_microusd > min(ceilings):
            raise ValueError("per-request cost cap exceeds an enclosing ceiling")
        return self


class PublicationSeed(StrictModel):
    snapshot_sha256: str
    source_lineage: tuple[str, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_snapshot(self) -> PublicationSeed:
        if _SHA256.fullmatch(self.snapshot_sha256) is None:
            raise ValueError("public snapshot must use a lowercase SHA-256 digest")
        return self


class UtopiaActivationManifestV1(StrictModel):
    contract: Literal["lucy.utopia.r1.activation-manifest.v1"]
    environment: Literal["production"]
    realm_slug: Literal["utopia"]
    activation_scope: Literal["public_only", "public_and_private"] = "public_and_private"
    activation_decision_id: str = Field(min_length=1, max_length=256)
    artifacts: ArtifactPins
    customer_identity: CustomerIdentity | None
    ingress: IngressBoundary
    paid_inference_enabled: bool
    paid_inference: PaidInferenceLimits | None
    transcript_capture_enabled: Literal[False]
    public_seed: PublicationSeed
    permitted_data_classes: tuple[str, ...] = Field(min_length=1, max_length=50)
    permitted_actions: tuple[str, ...] = Field(min_length=1, max_length=50)
    operations_contact: str = Field(min_length=3, max_length=320)
    rollback_owner: str = Field(min_length=3, max_length=320)

    @model_validator(mode="after")
    def validate_paid_inference(self) -> UtopiaActivationManifestV1:
        if self.paid_inference_enabled != (self.paid_inference is not None):
            raise ValueError("paid inference configuration must exactly match its enable flag")
        if self.activation_scope == "public_only":
            if self.customer_identity is not None or self.ingress.private_hostnames:
                raise ValueError("public-only activation cannot expose private identity or ingress")
            if self.paid_inference_enabled:
                raise ValueError("public-only activation must keep paid inference disabled")
        elif self.customer_identity is None or not self.ingress.private_hostnames:
            raise ValueError("private activation requires customer identity and private ingress")
        return self
