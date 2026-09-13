"""Permit-bound, exact-job recovery contracts for encrypted memory outcomes."""

from __future__ import annotations

import base64
import secrets
from datetime import datetime, timedelta
from typing import Literal, Self
from uuid import UUID, uuid5

from pydantic import Field, model_validator

from lucy.contracts.canonical import canonical_sha256
from lucy.contracts.security_v1_2 import DeploymentEnvironment
from lucy.contracts.security_v1_3 import (
    DigestHex,
    ExecutionBindingV1,
    Nonce,
    OriginScopeV1,
    SafeIdentifier,
    SignedV13Contract,
    StrictV13Contract,
    V13SigningKeyPurpose,
)

MEMORY_OUTCOME_RECOVERY_MAX_SECONDS = 300
MEMORY_OUTCOME_PACKAGE_DIGEST_PREFIX = b"LUCY-MEMORY-OUTCOME-PACKAGE-V1\0"


class MemoryOutcomeBindingV1(StrictV13Contract):
    contract_version: Literal["1"] = "1"
    extraction_job_id: UUID
    reservation_id: UUID
    campaign_id: UUID
    destination_content_scope_id: UUID
    manifest_digest: DigestHex
    attempt_key: str = Field(min_length=1, max_length=512)
    source_record_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    request_commitment: DigestHex
    provider_policy_id: str = Field(min_length=1, max_length=200)
    model_route: str = Field(min_length=1, max_length=200)
    maximum_microusd: int = Field(ge=0)


class MemoryOutcomeEnvelopeV1(StrictV13Contract):
    contract_version: Literal["1"] = "1"
    binding: MemoryOutcomeBindingV1
    encryption_id: UUID
    registry_id: UUID
    algorithm: str = Field(min_length=1, max_length=100)
    encryption_context_version: int = Field(ge=1)
    record_version: int = Field(ge=1)
    storage_epoch: int = Field(ge=1)
    registry_epoch: int = Field(ge=1)
    key_epoch: int = Field(ge=1)
    ciphertext_b64: str = Field(min_length=1)
    content_nonce_b64: str = Field(min_length=1)
    keyed_commitment: DigestHex
    billed_microusd: int = Field(ge=0)
    provider_reference_commitment: DigestHex

    @model_validator(mode="after")
    def validate_encoded_ciphertext(self) -> Self:
        try:
            ciphertext = base64.b64decode(self.ciphertext_b64, validate=True)
            nonce = base64.b64decode(self.content_nonce_b64, validate=True)
        except ValueError as exc:
            raise ValueError("memory outcome ciphertext encoding is invalid") from exc
        if len(ciphertext) < 17 or len(nonce) != 12:
            raise ValueError("memory outcome ciphertext shape is invalid")
        return self


class MemoryOutcomeRecoveryPackageV1(StrictV13Contract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.memory-outcome-recovery-package.v1"] = (
        "lucy.memory-outcome-recovery-package.v1"
    )
    target_scope: OriginScopeV1
    envelope: MemoryOutcomeEnvelopeV1

    @model_validator(mode="after")
    def require_outcome_specific_aws_envelope(self) -> Self:
        if (
            self.envelope.algorithm != "AES-256-GCM+AWS-KMS"
            or self.envelope.encryption_context_version != 3
            or self.envelope.encryption_id
            != uuid5(
                self.envelope.binding.extraction_job_id,
                "memory-provider-outcome:v1",
            )
        ):
            raise ValueError("recovery package is not an outcome-specific AWS envelope")
        return self

    def digest_hex(self) -> str:
        return canonical_sha256(self, prefix=MEMORY_OUTCOME_PACKAGE_DIGEST_PREFIX)


class MemoryOutcomeRecoveryGrantV1(SignedV13Contract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.memory-outcome-recovery-grant.v1"] = (
        "lucy.memory-outcome-recovery-grant.v1"
    )
    signing_key_purpose: Literal[V13SigningKeyPurpose.POLICY_NOTARY] = (
        V13SigningKeyPurpose.POLICY_NOTARY
    )
    operation_id: UUID
    caller_identity: SafeIdentifier
    target_scope: OriginScopeV1
    execution_binding: ExecutionBindingV1
    campaign_id: UUID
    manifest_digest: DigestHex
    extraction_job_id: UUID
    reservation_id: UUID
    destination_content_scope_id: UUID
    encryption_id: UUID
    registry_id: UUID
    package_digest: DigestHex
    pilot_authorization_id: UUID
    policy_version: int = Field(ge=1)
    permit_claim_deadline: datetime
    execution_completion_deadline: datetime
    max_plaintext_bytes: int = Field(ge=1, le=1_048_576)
    nonce: Nonce

    @model_validator(mode="after")
    def validate_scope_and_deadlines(self) -> Self:
        for name, value in (
            ("issued_at", self.issued_at),
            ("permit_claim_deadline", self.permit_claim_deadline),
            ("execution_completion_deadline", self.execution_completion_deadline),
        ):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{name} must be timezone-aware")
        if self.execution_binding.active_realm_id != self.target_scope.security_realm_id:
            raise ValueError("recovery grant crosses its active realm")
        if self.execution_binding.active_storage_epoch != self.target_scope.storage_epoch:
            raise ValueError("recovery grant crosses its active storage epoch")
        if not self.issued_at < self.permit_claim_deadline:
            raise ValueError("recovery claim deadline must follow issuance")
        if self.permit_claim_deadline > self.issued_at + timedelta(seconds=60):
            raise ValueError("recovery claim window exceeds 60 seconds")
        if not self.permit_claim_deadline < self.execution_completion_deadline:
            raise ValueError("recovery completion deadline must follow claim deadline")
        if self.execution_completion_deadline > self.issued_at + timedelta(
            seconds=MEMORY_OUTCOME_RECOVERY_MAX_SECONDS
        ):
            raise ValueError("recovery execution window exceeds five minutes")
        return self


class MemoryOutcomeKmsContextV1(StrictV13Contract):
    contract_version: Literal["MemoryOutcomeKmsContextV1"] = "MemoryOutcomeKmsContextV1"
    tenant_account_id: UUID
    node_id: UUID
    node_tenure_id: UUID
    tenure_epoch: int = Field(ge=1)
    security_realm_id: UUID
    storage_epoch: int = Field(ge=1)
    encryption_id: UUID
    purpose: Literal["MEMORY_OUTCOME_DEK"] = "MEMORY_OUTCOME_DEK"

    @classmethod
    def from_scope(
        cls,
        scope: OriginScopeV1,
        *,
        encryption_id: UUID,
    ) -> MemoryOutcomeKmsContextV1:
        return cls(
            **scope.model_dump(mode="python"),
            encryption_id=encryption_id,
        )

    def as_aws_context(self) -> dict[str, str]:
        return {key: str(value) for key, value in self.model_dump(mode="python").items()}


class MemoryOutcomeRecoveryResultV1(StrictV13Contract):
    contract_version: Literal["1"] = "1"
    operation_id: UUID
    extraction_job_id: UUID
    package_digest: DigestHex
    released: bool
    replayed: bool
    output: str | None = None
    billed_microusd: int = Field(ge=0)
    provider_policy_id: str | None = None
    model_route: str | None = None
    provider_reference_commitment: DigestHex | None = None

    @model_validator(mode="after")
    def validate_release_shape(self) -> Self:
        content = (
            self.output,
            self.provider_policy_id,
            self.model_route,
            self.provider_reference_commitment,
        )
        if self.released and (self.replayed or any(value is None for value in content)):
            raise ValueError("released recovery result is incomplete")
        if not self.released and any(value is not None for value in content):
            raise ValueError("non-release recovery result contains provider content")
        if not self.released and self.billed_microusd != 0:
            raise ValueError("non-release recovery result contains billed cost")
        if self.replayed == self.released:
            raise ValueError("recovery result must be either released or replayed")
        return self


def recovery_grant_matches_package(
    grant: MemoryOutcomeRecoveryGrantV1,
    package: MemoryOutcomeRecoveryPackageV1,
) -> bool:
    envelope = package.envelope
    binding = envelope.binding
    values_match = (
        grant.target_scope == package.target_scope
        and grant.campaign_id == binding.campaign_id
        and secrets.compare_digest(grant.manifest_digest, binding.manifest_digest)
        and grant.extraction_job_id == binding.extraction_job_id
        and grant.reservation_id == binding.reservation_id
        and grant.destination_content_scope_id == binding.destination_content_scope_id
        and grant.encryption_id == envelope.encryption_id
        and grant.registry_id == envelope.registry_id
        and secrets.compare_digest(grant.package_digest, package.digest_hex())
        and grant.execution_binding.active_realm_id
        == package.target_scope.security_realm_id
        and grant.execution_binding.active_storage_epoch == envelope.storage_epoch
        and package.target_scope.storage_epoch == envelope.storage_epoch
    )
    return bool(values_match)


def require_environment(
    grant: MemoryOutcomeRecoveryGrantV1, environment: DeploymentEnvironment
) -> None:
    if grant.environment != environment:
        raise PermissionError("recovery grant crosses its deployment environment")
