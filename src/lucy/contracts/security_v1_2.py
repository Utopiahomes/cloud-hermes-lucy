"""Security Baseline v1.2 contracts and signature verification.

These contracts coexist with the v1.1 permit. They are intentionally new wire
types: production v1.2 executors must never reinterpret a V1 permit as V2.
"""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal, Self, TypeVar, cast
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, ConfigDict, Field, model_validator

from lucy.contracts.canonical import (
    canonical_json_bytes,
    canonical_sha256,
    canonical_signed_bytes,
    signed_contract_sha256,
)

CLOCK_SKEW_SECONDS = 30
OWNER_ASSERTION_MAX_AGE_SECONDS = 300
PERMIT_CLAIM_MAX_SECONDS = 300
EXECUTION_MAX_SECONDS = 600
MAX_PLAINTEXT_BYTES = 65_536
MAX_ENCRYPTED_PACKAGE_BYTES = 131_072
MAX_DELETION_PACKAGE_BYTES = 131_072
MAX_DELETION_MANIFEST_BYTES = 65_536
MAX_DELETION_TARGETS = 90
MAX_DELETION_CHUNKS = 1
DECRYPT_LAMBDA_TIMEOUT_SECONDS = 60
DELETION_LAMBDA_TIMEOUT_SECONDS = 120
AWS_DYNAMODB_TRANSACTION_ACTION_LIMIT = 100
AWS_DYNAMODB_TRANSACTION_BYTES_LIMIT = 4_000_000
AWS_LAMBDA_SYNCHRONOUS_PAYLOAD_LIMIT = 6_000_000

_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_SAFE_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$"
_TARGETS_PREFIX = b"LUCY-DELETION-TARGETS-V1\x00"
_LAMBDA_ALIAS_ARN = re.compile(
    r"^arn:aws(?:-us-gov|-cn)?:lambda:[a-z0-9-]+:\d{12}:"
    r"function:[A-Za-z0-9-_]{1,64}:(?!\$LATEST$)[A-Za-z0-9-_]{1,128}$"
)

SafeIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=512, pattern=_SAFE_IDENTIFIER_PATTERN),
]
OwnerSubject = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=_SAFE_IDENTIFIER_PATTERN),
]
Nonce = Annotated[
    str,
    Field(min_length=32, max_length=128, pattern=_SAFE_IDENTIFIER_PATTERN),
]
DigestHex = Annotated[str, Field(pattern=_DIGEST_PATTERN)]


class StrictSecurityContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DeploymentEnvironment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class SensitiveActionV2(StrEnum):
    EVIDENCE_RETRIEVE = "evidence.retrieve"
    EVIDENCE_DELETE = "evidence.delete"


class SensitiveReasonCode(StrEnum):
    VERIFY_EXACT_WORDING = "verify_exact_wording"
    RESOLVE_AMBIGUITY = "resolve_ambiguity"
    RECOVER_MISSING_CONTEXT = "recover_missing_context"
    OWNER_REVIEW = "owner_review"
    OWNER_REQUEST = "owner_request"
    SENSITIVE_DATA = "sensitive_data"
    RETENTION_EXPIRED = "retention_expired"


class OwnerInteractionChannel(StrEnum):
    TELEGRAM = "telegram"
    OWNER_CONSOLE = "owner_console"
    SYNTHETIC_ACCEPTANCE = "synthetic_acceptance"


class OwnerAuthenticationMethod(StrEnum):
    WEBAUTHN = "webauthn"
    TOTP = "totp"
    VERIFIED_OWNER_EVENT = "verified_owner_event"
    SYNTHETIC_ACCEPTANCE = "synthetic_acceptance"


class SignatureAlgorithm(StrEnum):
    ED25519 = "Ed25519"
    ECDSA_SHA_256 = "ECDSA_SHA_256"


class SigningKeyPurpose(StrEnum):
    OWNER_BROKER = "owner_broker"
    POLICY_NOTARY = "policy_notary"
    RETRIEVAL_RECEIPT = "retrieval_receipt"
    DELETION_RECEIPT = "deletion_receipt"


class VerificationKeyStatus(StrEnum):
    ACTIVE = "active"
    RETIRING = "retiring"
    RETIRED = "retired"
    REVOKED = "revoked"


class VerificationMode(StrEnum):
    LIVE_AUTHORIZATION = "live_authorization"
    HISTORICAL_AUDIT = "historical_audit"


class SignedSecurityContract(StrictSecurityContract):
    canonicalization_version: Literal["lucy-cjson-1"] = "lucy-cjson-1"
    signature_algorithm: SignatureAlgorithm
    key_id: SafeIdentifier
    issuer: SafeIdentifier
    environment: DeploymentEnvironment
    issued_at: datetime
    storage_epoch: int = Field(ge=1)
    registry_epoch: int = Field(ge=1)
    key_epoch: int = Field(ge=1)
    signature: str = Field(default="", max_length=1024)

    @model_validator(mode="after")
    def validate_common_envelope(self) -> Self:
        _require_aware(self.issued_at, "issued_at")
        return self

    def canonical_unsigned_bytes(self) -> bytes:
        return canonical_signed_bytes(self)

    def unsigned_digest_hex(self) -> str:
        return signed_contract_sha256(self)


class OwnerInteractionAssertionV1(SignedSecurityContract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.owner-interaction-assertion.v1"] = (
        "lucy.owner-interaction-assertion.v1"
    )
    signature_algorithm: Literal[SignatureAlgorithm.ED25519] = SignatureAlgorithm.ED25519
    assertion_id: UUID
    broker_identity: SafeIdentifier
    channel: OwnerInteractionChannel
    owner_subject: OwnerSubject
    source_interaction_id: SafeIdentifier
    source_message_id: SafeIdentifier
    requested_action: SensitiveActionV2
    evidence_id: UUID | None
    authentication_method: OwnerAuthenticationMethod
    interaction_created_at: datetime
    max_age_seconds: int = Field(ge=1, le=OWNER_ASSERTION_MAX_AGE_SECONDS)
    expires_at: datetime
    nonce: Nonce
    anti_replay_id: SafeIdentifier

    @model_validator(mode="after")
    def validate_assertion_lifetime(self) -> Self:
        _require_aware(self.interaction_created_at, "interaction_created_at")
        _require_aware(self.expires_at, "expires_at")
        skew = timedelta(seconds=CLOCK_SKEW_SECONDS)
        if self.issued_at < self.interaction_created_at - skew:
            raise ValueError("assertion predates the owner interaction")
        if self.issued_at > self.interaction_created_at + timedelta(seconds=self.max_age_seconds):
            raise ValueError("owner interaction was already too old when asserted")
        if not self.issued_at < self.expires_at:
            raise ValueError("owner assertion expiration must follow issuance")
        maximum_expiry = self.interaction_created_at + timedelta(seconds=self.max_age_seconds)
        if self.expires_at > maximum_expiry:
            raise ValueError("owner assertion exceeds its declared maximum age")
        return self


class SensitiveActionPermitV2(SignedSecurityContract):
    contract_version: Literal["2"] = "2"
    object_type: Literal["lucy.sensitive-action-permit.v2"] = (
        "lucy.sensitive-action-permit.v2"
    )
    signature_algorithm: Literal[SignatureAlgorithm.ED25519] = SignatureAlgorithm.ED25519
    permit_id: UUID
    action: SensitiveActionV2
    owner_subject: OwnerSubject
    owner_assertion_id: UUID
    owner_assertion_digest: DigestHex
    evidence_id: UUID
    reason: SensitiveReasonCode
    max_records: int = Field(ge=1, le=MAX_DELETION_TARGETS)
    max_bytes: int = Field(ge=1, le=MAX_DELETION_PACKAGE_BYTES)
    record_version: int = Field(ge=1)
    permit_claim_deadline: datetime
    nonce: Nonce

    @model_validator(mode="after")
    def validate_permit_scope(self) -> Self:
        _require_deadline(
            self.issued_at,
            self.permit_claim_deadline,
            PERMIT_CLAIM_MAX_SECONDS,
            "permit claim",
        )
        retrieval_reasons = {
            SensitiveReasonCode.VERIFY_EXACT_WORDING,
            SensitiveReasonCode.RESOLVE_AMBIGUITY,
            SensitiveReasonCode.RECOVER_MISSING_CONTEXT,
            SensitiveReasonCode.OWNER_REVIEW,
        }
        deletion_reasons = {
            SensitiveReasonCode.OWNER_REQUEST,
            SensitiveReasonCode.SENSITIVE_DATA,
            SensitiveReasonCode.RETENTION_EXPIRED,
        }
        if self.action == SensitiveActionV2.EVIDENCE_RETRIEVE:
            if self.reason not in retrieval_reasons:
                raise ValueError("retrieval permit uses a deletion reason code")
            if self.max_records != 1 or self.max_bytes > MAX_PLAINTEXT_BYTES:
                raise ValueError("retrieval permit exceeds the single-record plaintext boundary")
        elif self.reason not in deletion_reasons:
            raise ValueError("deletion permit uses a retrieval reason code")
        return self


class DeletionTargetReferenceV1(StrictSecurityContract):
    evidence_id: UUID
    key_ref: UUID
    record_version: int = Field(ge=1)
    key_epoch: int = Field(ge=1)


def deletion_targets_digest(targets: tuple[DeletionTargetReferenceV1, ...]) -> str:
    payload = [target.model_dump(mode="python") for target in targets]
    return canonical_sha256(payload, prefix=_TARGETS_PREFIX)


class DeletionTargetManifestV1(SignedSecurityContract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.deletion-target-manifest.v1"] = (
        "lucy.deletion-target-manifest.v1"
    )
    signature_algorithm: Literal[SignatureAlgorithm.ED25519] = SignatureAlgorithm.ED25519
    manifest_id: UUID
    permit_id: UUID
    permit_nonce: Nonce
    action: Literal[SensitiveActionV2.EVIDENCE_DELETE] = SensitiveActionV2.EVIDENCE_DELETE
    root_evidence_id: UUID
    owner_assertion_id: UUID
    owner_assertion_digest: DigestHex
    idempotency_key: SafeIdentifier
    scope_version: int = Field(ge=1)
    root_record_version: int = Field(ge=1)
    targets: tuple[DeletionTargetReferenceV1, ...] = Field(
        min_length=1, max_length=MAX_DELETION_TARGETS
    )
    target_count: int = Field(ge=1, le=MAX_DELETION_TARGETS)
    targets_digest: DigestHex
    permit_claim_deadline: datetime
    execution_deadline: datetime

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        _require_deadline(
            self.issued_at,
            self.permit_claim_deadline,
            PERMIT_CLAIM_MAX_SECONDS,
            "manifest claim",
        )
        _require_deadline(
            self.issued_at,
            self.execution_deadline,
            EXECUTION_MAX_SECONDS,
            "manifest execution",
        )
        if self.permit_claim_deadline > self.execution_deadline:
            raise ValueError("manifest claim deadline exceeds execution deadline")
        order = tuple((str(target.evidence_id), str(target.key_ref)) for target in self.targets)
        if order != tuple(sorted(order)):
            raise ValueError("deletion targets must use canonical evidence/key order")
        if len({target.evidence_id for target in self.targets}) != len(self.targets):
            raise ValueError("deletion manifest contains duplicate evidence IDs")
        if len({target.key_ref for target in self.targets}) != len(self.targets):
            raise ValueError("deletion manifest contains duplicate key references")
        if self.root_evidence_id not in {target.evidence_id for target in self.targets}:
            raise ValueError("deletion manifest does not include its root evidence")
        if self.target_count != len(self.targets):
            raise ValueError("deletion target count does not match the manifest")
        if self.targets_digest != deletion_targets_digest(self.targets):
            raise ValueError("deletion target digest does not match the manifest")
        if len(self.canonical_unsigned_bytes()) > MAX_DELETION_MANIFEST_BYTES:
            raise ValueError("canonical deletion manifest exceeds the Phase 1 boundary")
        return self


class KmsEncryptionContextV1(StrictSecurityContract):
    application: Literal["cloud-hermes-lucy"] = "cloud-hermes-lucy"
    environment: DeploymentEnvironment
    evidence_id: UUID
    storage_epoch: int = Field(ge=1)
    registry_epoch: int = Field(ge=1)
    key_epoch: int = Field(ge=1)
    record_version: int = Field(ge=1)

    def as_aws_context(self) -> dict[str, str]:
        return {
            "application": self.application,
            "environment": self.environment.value,
            "evidence-id": str(self.evidence_id),
            "storage-epoch": str(self.storage_epoch),
            "registry-epoch": str(self.registry_epoch),
            "key-epoch": str(self.key_epoch),
            "record-version": str(self.record_version),
        }


class EncryptedEvidencePackageV1(StrictSecurityContract):
    """One bounded ciphertext package returned by the PostgreSQL claim gate."""

    contract_version: Literal["1"] = "1"
    canonicalization_version: Literal["lucy-cjson-1"] = "lucy-cjson-1"
    object_type: Literal["lucy.encrypted-evidence-package.v1"] = (
        "lucy.encrypted-evidence-package.v1"
    )
    operation_id: UUID
    permit_id: UUID
    action: Literal[SensitiveActionV2.EVIDENCE_RETRIEVE] = (
        SensitiveActionV2.EVIDENCE_RETRIEVE
    )
    evidence_id: UUID
    key_ref: UUID
    algorithm: Literal["AES-256-GCM+AWS-KMS"] = "AES-256-GCM+AWS-KMS"
    ciphertext_b64: str = Field(min_length=1, max_length=100_000)
    content_nonce_b64: str = Field(min_length=1, max_length=64)
    aad_b64: str = Field(min_length=1, max_length=32_768)
    encryption_context: KmsEncryptionContextV1
    record_version: int = Field(ge=1)
    storage_epoch: int = Field(ge=1)
    registry_epoch: int = Field(ge=1)
    key_epoch: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_package(self) -> Self:
        ciphertext = _decode_b64(self.ciphertext_b64, "ciphertext_b64")
        nonce = _decode_b64(self.content_nonce_b64, "content_nonce_b64")
        _decode_b64(self.aad_b64, "aad_b64")
        if len(ciphertext) > MAX_PLAINTEXT_BYTES + 16:
            raise ValueError("encrypted evidence exceeds the bounded plaintext plus GCM tag")
        if len(nonce) != 12:
            raise ValueError("AES-GCM content nonce must contain exactly 12 bytes")
        bindings = (
            self.evidence_id,
            self.record_version,
            self.storage_epoch,
            self.registry_epoch,
            self.key_epoch,
        )
        context_bindings = (
            self.encryption_context.evidence_id,
            self.encryption_context.record_version,
            self.encryption_context.storage_epoch,
            self.encryption_context.registry_epoch,
            self.encryption_context.key_epoch,
        )
        if bindings != context_bindings:
            raise ValueError("KMS encryption context does not match the evidence package")
        if len(canonical_json_bytes(self)) > MAX_ENCRYPTED_PACKAGE_BYTES:
            raise ValueError("encrypted evidence package exceeds the Phase 1 boundary")
        return self

    def package_digest_hex(self) -> str:
        return canonical_sha256(self, prefix=b"LUCY-ENCRYPTED-EVIDENCE-PACKAGE-V1\x00")


class SensitiveExecutionGrantV1(SignedSecurityContract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.sensitive-execution-grant.v1"] = (
        "lucy.sensitive-execution-grant.v1"
    )
    signature_algorithm: Literal[SignatureAlgorithm.ED25519] = SignatureAlgorithm.ED25519
    grant_id: UUID
    action: SensitiveActionV2
    permit_id: UUID
    permit_nonce: Nonce
    operation_id: UUID
    database_session_user: SafeIdentifier
    evidence_id: UUID
    deletion_manifest_id: UUID | None = None
    deletion_manifest_digest: DigestHex | None = None
    encrypted_package_digest: DigestHex
    package_size_bytes: int = Field(ge=1, le=MAX_DELETION_PACKAGE_BYTES)
    idempotency_key: SafeIdentifier
    record_version: int = Field(ge=1)
    executor_identity: SafeIdentifier
    executor_alias_arn: str = Field(min_length=1, max_length=300)
    executor_version: int = Field(ge=1)
    permit_claim_deadline: datetime
    execution_deadline: datetime

    @model_validator(mode="after")
    def validate_execution_grant(self) -> Self:
        _require_aware(self.permit_claim_deadline, "permit_claim_deadline")
        _require_deadline(
            self.issued_at,
            self.execution_deadline,
            EXECUTION_MAX_SECONDS,
            "execution grant",
        )
        if _LAMBDA_ALIAS_ARN.fullmatch(self.executor_alias_arn) is None:
            raise ValueError("executor_alias_arn must be an exact qualified Lambda alias ARN")
        if self.action == SensitiveActionV2.EVIDENCE_RETRIEVE:
            if self.deletion_manifest_id is not None or self.deletion_manifest_digest is not None:
                raise ValueError("retrieval grant must not bind a deletion manifest")
            if self.package_size_bytes > MAX_ENCRYPTED_PACKAGE_BYTES:
                raise ValueError("retrieval package exceeds the Phase 1 boundary")
        elif self.deletion_manifest_id is None or self.deletion_manifest_digest is None:
            raise ValueError("deletion grant must bind the exact deletion manifest")
        return self


class ExecutorResult(StrEnum):
    RETRIEVAL_SUCCEEDED = "retrieval_succeeded"
    DELETION_SUCCEEDED = "deletion_succeeded"
    IDEMPOTENT_REPLAY = "idempotent_replay"
    REJECTED = "rejected"


class ExecutorReceiptV1(SignedSecurityContract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.executor-receipt.v1"] = "lucy.executor-receipt.v1"
    signature_algorithm: Literal[SignatureAlgorithm.ECDSA_SHA_256] = (
        SignatureAlgorithm.ECDSA_SHA_256
    )
    receipt_id: UUID
    action: SensitiveActionV2
    executor_identity: SafeIdentifier
    executor_alias_arn: str = Field(min_length=1, max_length=300)
    executor_version: int = Field(ge=1)
    operation_id: UUID
    permit_id: UUID
    execution_grant_id: UUID
    deletion_manifest_id: UUID | None = None
    package_digest: DigestHex
    result: ExecutorResult
    lambda_request_id: SafeIdentifier
    kms_request_id: SafeIdentifier | None = None
    transaction_client_token: SafeIdentifier | None = None
    execution_deadline: datetime
    completed_at: datetime
    record_version: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        _require_aware(self.execution_deadline, "execution_deadline")
        _require_aware(self.completed_at, "completed_at")
        if _LAMBDA_ALIAS_ARN.fullmatch(self.executor_alias_arn) is None:
            raise ValueError("executor_alias_arn must be an exact qualified Lambda alias ARN")
        skew = timedelta(seconds=CLOCK_SKEW_SECONDS)
        if self.completed_at > self.execution_deadline + skew:
            raise ValueError("executor completed after the accepted execution deadline")
        if self.issued_at < self.completed_at - skew or self.issued_at > self.completed_at + skew:
            raise ValueError("receipt issuance is not contemporaneous with completion")
        if self.action == SensitiveActionV2.EVIDENCE_RETRIEVE:
            if self.deletion_manifest_id is not None or self.transaction_client_token is not None:
                raise ValueError("retrieval receipt contains deletion-only fields")
            if self.kms_request_id is None:
                raise ValueError("retrieval receipt must bind the KMS request ID")
            if self.result not in {
                ExecutorResult.RETRIEVAL_SUCCEEDED,
                ExecutorResult.IDEMPOTENT_REPLAY,
                ExecutorResult.REJECTED,
            }:
                raise ValueError("retrieval receipt uses a deletion result")
        else:
            if self.deletion_manifest_id is None or self.transaction_client_token is None:
                raise ValueError("deletion receipt must bind manifest and transaction token")
            if self.kms_request_id is not None:
                raise ValueError("deletion receipt must not contain an evidence KMS request ID")
            if self.result not in {
                ExecutorResult.DELETION_SUCCEEDED,
                ExecutorResult.IDEMPOTENT_REPLAY,
                ExecutorResult.REJECTED,
            }:
                raise ValueError("deletion receipt uses a retrieval result")
        return self


class ExecutorQuotaV1(StrictSecurityContract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.executor-quota.v1"] = "lucy.executor-quota.v1"
    action: SensitiveActionV2
    max_plaintext_bytes: int = Field(ge=0, le=MAX_PLAINTEXT_BYTES)
    max_invocation_package_bytes: int = Field(ge=1, le=MAX_DELETION_PACKAGE_BYTES)
    max_targets: int = Field(ge=1, le=MAX_DELETION_TARGETS)
    max_chunks: int = Field(ge=0, le=MAX_DELETION_CHUNKS)
    configured_timeout_seconds: int = Field(ge=1, le=DELETION_LAMBDA_TIMEOUT_SECONDS)
    aws_transaction_action_limit: Literal[100] = 100
    aws_transaction_bytes_limit: Literal[4_000_000] = 4_000_000
    aws_lambda_sync_payload_limit: Literal[6_000_000] = 6_000_000

    @classmethod
    def phase1(cls, action: SensitiveActionV2) -> ExecutorQuotaV1:
        if action == SensitiveActionV2.EVIDENCE_RETRIEVE:
            return cls(
                action=action,
                max_plaintext_bytes=MAX_PLAINTEXT_BYTES,
                max_invocation_package_bytes=MAX_ENCRYPTED_PACKAGE_BYTES,
                max_targets=1,
                max_chunks=0,
                configured_timeout_seconds=DECRYPT_LAMBDA_TIMEOUT_SECONDS,
            )
        return cls(
            action=action,
            max_plaintext_bytes=0,
            max_invocation_package_bytes=MAX_DELETION_PACKAGE_BYTES,
            max_targets=MAX_DELETION_TARGETS,
            max_chunks=MAX_DELETION_CHUNKS,
            configured_timeout_seconds=DELETION_LAMBDA_TIMEOUT_SECONDS,
        )

    @model_validator(mode="after")
    def validate_action_quota(self) -> Self:
        if self.action == SensitiveActionV2.EVIDENCE_RETRIEVE:
            if self.max_targets != 1 or self.max_chunks != 0:
                raise ValueError("retrieval quota must describe one target and no deletion chunks")
            if self.configured_timeout_seconds > DECRYPT_LAMBDA_TIMEOUT_SECONDS:
                raise ValueError("decrypt timeout exceeds the Phase 1 boundary")
        elif self.max_plaintext_bytes != 0 or self.max_chunks != 1:
            raise ValueError("deletion quota must not authorize plaintext or multiple chunks")
        return self


class RetrievalOperationState(StrEnum):
    ISSUED = "ISSUED"
    CLAIMED = "CLAIMED"
    EXECUTING = "EXECUTING"
    EXECUTOR_RECEIPTED = "EXECUTOR_RECEIPTED"
    DELIVERY_CONFIRMED = "DELIVERY_CONFIRMED"
    DELIVERY_UNKNOWN = "DELIVERY_UNKNOWN"
    EXPIRED = "EXPIRED"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_FINAL = "FAILED_FINAL"


class DeletionOperationState(StrEnum):
    ISSUED = "ISSUED"
    CLAIMED = "CLAIMED"
    EXECUTING = "EXECUTING"
    EXECUTOR_RECEIPTED = "EXECUTOR_RECEIPTED"
    EFFECTIVE = "EFFECTIVE"
    FINALITY_PENDING = "FINALITY_PENDING"
    FINALITY_EXTENDED = "FINALITY_EXTENDED"
    FINALITY_VERIFIED = "FINALITY_VERIFIED"
    EXPIRED = "EXPIRED"
    BULK_REQUIRED = "BULK_REQUIRED"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_FINAL = "FAILED_FINAL"


_RETRIEVAL_TRANSITIONS: dict[RetrievalOperationState, frozenset[RetrievalOperationState]] = {
    RetrievalOperationState.ISSUED: frozenset(
        {RetrievalOperationState.CLAIMED, RetrievalOperationState.EXPIRED}
    ),
    RetrievalOperationState.CLAIMED: frozenset(
        {
            RetrievalOperationState.EXECUTING,
            RetrievalOperationState.EXPIRED,
            RetrievalOperationState.FAILED_RETRYABLE,
            RetrievalOperationState.FAILED_FINAL,
        }
    ),
    RetrievalOperationState.EXECUTING: frozenset(
        {
            RetrievalOperationState.EXECUTOR_RECEIPTED,
            RetrievalOperationState.FAILED_RETRYABLE,
            RetrievalOperationState.FAILED_FINAL,
        }
    ),
    RetrievalOperationState.FAILED_RETRYABLE: frozenset(
        {
            RetrievalOperationState.EXECUTING,
            RetrievalOperationState.EXPIRED,
            RetrievalOperationState.FAILED_FINAL,
        }
    ),
    RetrievalOperationState.EXECUTOR_RECEIPTED: frozenset(
        {RetrievalOperationState.DELIVERY_CONFIRMED, RetrievalOperationState.DELIVERY_UNKNOWN}
    ),
}

_DELETION_TRANSITIONS: dict[DeletionOperationState, frozenset[DeletionOperationState]] = {
    DeletionOperationState.ISSUED: frozenset(
        {DeletionOperationState.CLAIMED, DeletionOperationState.EXPIRED}
    ),
    DeletionOperationState.CLAIMED: frozenset(
        {
            DeletionOperationState.EXECUTING,
            DeletionOperationState.BULK_REQUIRED,
            DeletionOperationState.EXPIRED,
            DeletionOperationState.FAILED_RETRYABLE,
            DeletionOperationState.FAILED_FINAL,
        }
    ),
    DeletionOperationState.EXECUTING: frozenset(
        {
            DeletionOperationState.EXECUTOR_RECEIPTED,
            DeletionOperationState.FAILED_RETRYABLE,
            DeletionOperationState.FAILED_FINAL,
        }
    ),
    DeletionOperationState.FAILED_RETRYABLE: frozenset(
        {
            DeletionOperationState.EXECUTING,
            DeletionOperationState.EXPIRED,
            DeletionOperationState.FAILED_FINAL,
        }
    ),
    DeletionOperationState.EXECUTOR_RECEIPTED: frozenset({DeletionOperationState.EFFECTIVE}),
    DeletionOperationState.EFFECTIVE: frozenset({DeletionOperationState.FINALITY_PENDING}),
    DeletionOperationState.FINALITY_PENDING: frozenset(
        {DeletionOperationState.FINALITY_EXTENDED, DeletionOperationState.FINALITY_VERIFIED}
    ),
    DeletionOperationState.FINALITY_EXTENDED: frozenset(
        {DeletionOperationState.FINALITY_EXTENDED, DeletionOperationState.FINALITY_VERIFIED}
    ),
}


def require_retrieval_transition(
    current: RetrievalOperationState, target: RetrievalOperationState
) -> None:
    if target not in _RETRIEVAL_TRANSITIONS.get(current, frozenset()):
        raise ValueError(f"invalid retrieval state transition: {current} -> {target}")


def require_deletion_transition(
    current: DeletionOperationState, target: DeletionOperationState
) -> None:
    if target not in _DELETION_TRANSITIONS.get(current, frozenset()):
        raise ValueError(f"invalid deletion state transition: {current} -> {target}")


class FinalityStatus(StrEnum):
    PENDING = "PENDING"
    EXTENDED = "EXTENDED"
    VERIFIED = "VERIFIED"


class DeletionRecoveryInventoryV1(StrictSecurityContract):
    """Content-free AWS recovery facts; PostgreSQL derives the finality verdict."""

    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.deletion-recovery-inventory.v1"] = (
        "lucy.deletion-recovery-inventory.v1"
    )
    operation_id: UUID
    metadata_observed_at: datetime
    pitr_status: Literal["ENABLED", "DISABLED"]
    pitr_recovery_period_days: int | None = Field(default=None, ge=1, le=35)
    pitr_earliest_restorable_at: datetime | None = None
    pitr_latest_restorable_at: datetime | None = None
    on_demand_backup_count: int = Field(ge=0)
    aws_backup_recovery_point_count: int = Field(ge=0)
    export_count: int = Field(ge=0)
    import_count: int = Field(ge=0)
    global_replica_count: int = Field(ge=0)
    quarantine_table_count: int = Field(ge=0)
    stream_enabled: bool
    exceptional_earliest_restorable_at: datetime | None = None
    exceptional_latest_restorable_at: datetime | None = None
    metadata_inventory_digest: DigestHex

    @model_validator(mode="after")
    def validate_recovery_inventory(self) -> Self:
        _require_aware(self.metadata_observed_at, "metadata_observed_at")
        for name in (
            "pitr_earliest_restorable_at",
            "pitr_latest_restorable_at",
            "exceptional_earliest_restorable_at",
            "exceptional_latest_restorable_at",
        ):
            value = cast(datetime | None, getattr(self, name))
            if value is not None:
                _require_aware(value, name)
        if self.pitr_status == "ENABLED":
            if (
                self.pitr_recovery_period_days is None
                or self.pitr_earliest_restorable_at is None
                or self.pitr_latest_restorable_at is None
            ):
                raise ValueError("enabled PITR requires its actual recovery interval")
            if self.pitr_earliest_restorable_at > self.pitr_latest_restorable_at:
                raise ValueError("PITR recovery interval is inverted")
        elif any(
            value is not None
            for value in (
                self.pitr_recovery_period_days,
                self.pitr_earliest_restorable_at,
                self.pitr_latest_restorable_at,
            )
        ):
            raise ValueError("disabled PITR must not report a recovery interval")
        if (
            self.exceptional_earliest_restorable_at is not None
            and self.exceptional_latest_restorable_at is not None
            and self.exceptional_earliest_restorable_at
            > self.exceptional_latest_restorable_at
        ):
            raise ValueError("exceptional recovery interval is inverted")
        exceptional_count = sum(
            (
                self.on_demand_backup_count,
                self.aws_backup_recovery_point_count,
                self.export_count,
                self.import_count,
                self.global_replica_count,
                self.quarantine_table_count,
            )
        ) + int(self.stream_enabled)
        if exceptional_count == 0 and any(
            value is not None
            for value in (
                self.exceptional_earliest_restorable_at,
                self.exceptional_latest_restorable_at,
            )
        ):
            raise ValueError("empty exceptional inventory must not report an interval")
        return self


class DeletionFinalityRecordV1(StrictSecurityContract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.deletion-finality-record.v1"] = (
        "lucy.deletion-finality-record.v1"
    )
    operation_id: UUID
    deletion_effective_at: datetime
    finality_not_before: datetime
    finality_verified_at: datetime | None = None
    finality_status: FinalityStatus
    metadata_observed_at: datetime
    earliest_restorable_at: datetime | None = None
    latest_restorable_at: datetime | None = None
    recoverable_copy_count: int = Field(ge=0)
    metadata_inventory_digest: DigestHex

    @model_validator(mode="after")
    def validate_finality(self) -> Self:
        for name in (
            "deletion_effective_at",
            "finality_not_before",
            "metadata_observed_at",
        ):
            _require_aware(cast(datetime, getattr(self, name)), name)
        if self.finality_verified_at is not None:
            _require_aware(self.finality_verified_at, "finality_verified_at")
        if self.earliest_restorable_at is not None:
            _require_aware(self.earliest_restorable_at, "earliest_restorable_at")
        if self.latest_restorable_at is not None:
            _require_aware(self.latest_restorable_at, "latest_restorable_at")
        if self.finality_not_before < self.deletion_effective_at:
            raise ValueError("finality lower bound predates effective deletion")
        if (
            self.earliest_restorable_at is not None
            and self.latest_restorable_at is not None
            and self.earliest_restorable_at > self.latest_restorable_at
        ):
            raise ValueError("restorable metadata interval is inverted")
        if self.finality_status == FinalityStatus.VERIFIED:
            if self.finality_verified_at is None:
                raise ValueError("verified finality requires a verification timestamp")
            if self.finality_verified_at < self.finality_not_before:
                raise ValueError("finality cannot be verified before its lower bound")
            if self.recoverable_copy_count != 0:
                raise ValueError("finality cannot be verified while a recoverable copy exists")
            if self.earliest_restorable_at is not None or self.latest_restorable_at is not None:
                raise ValueError("verified finality cannot report a restorable registry interval")
        elif self.finality_verified_at is not None:
            raise ValueError("unverified finality must not have a verification timestamp")
        if self.finality_status == FinalityStatus.EXTENDED and self.recoverable_copy_count == 0:
            raise ValueError("extended finality requires a recoverable copy")
        return self


class VerificationKeyV1(StrictSecurityContract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.verification-key.v1"] = "lucy.verification-key.v1"
    key_id: SafeIdentifier
    issuer: SafeIdentifier
    purpose: SigningKeyPurpose
    algorithm: SignatureAlgorithm
    environment: DeploymentEnvironment
    public_key_b64: str = Field(min_length=1, max_length=4096)
    valid_from: datetime
    issuance_not_after: datetime
    verify_not_after: datetime
    status: VerificationKeyStatus
    compromise_suspected_from: datetime | None = None

    @model_validator(mode="after")
    def validate_key_window(self) -> Self:
        _require_aware(self.valid_from, "valid_from")
        _require_aware(self.issuance_not_after, "issuance_not_after")
        _require_aware(self.verify_not_after, "verify_not_after")
        if not self.valid_from < self.issuance_not_after <= self.verify_not_after:
            raise ValueError("verification-key validity interval is invalid")
        if self.compromise_suspected_from is not None:
            _require_aware(self.compromise_suspected_from, "compromise_suspected_from")
        return self


class ContractTrustStore:
    """Pinned public-key inventory with explicit live/historical semantics."""

    def __init__(self, keys: tuple[VerificationKeyV1, ...]) -> None:
        by_id = {key.key_id: key for key in keys}
        if len(by_id) != len(keys):
            raise ValueError("verification-key inventory contains duplicate key IDs")
        self._keys = by_id

    def verify(
        self,
        contract: SignedSecurityContract,
        *,
        purpose: SigningKeyPurpose,
        environment: DeploymentEnvironment,
        now: datetime | None = None,
        mode: VerificationMode = VerificationMode.LIVE_AUTHORIZATION,
    ) -> None:
        checked_at = now or datetime.now(UTC)
        _require_aware(checked_at, "verification time")
        key = self._keys.get(contract.key_id)
        if key is None:
            raise PermissionError("signed contract uses an unknown key ID")
        if key.purpose != purpose or key.environment != environment:
            raise PermissionError("verification key has the wrong purpose or environment")
        if purpose != _required_signing_purpose(contract):
            raise PermissionError("contract type is not valid for the requested signing purpose")
        if contract.issuer != key.issuer:
            raise PermissionError("signed contract issuer does not match the pinned key")
        if contract.environment != environment or contract.signature_algorithm != key.algorithm:
            raise PermissionError("signed contract environment or algorithm is not trusted")
        if key.status == VerificationKeyStatus.REVOKED:
            raise PermissionError("verification key is revoked")
        if (
            key.compromise_suspected_from is not None
            and contract.issued_at >= key.compromise_suspected_from
        ):
            raise PermissionError("signed contract falls in a suspected compromise interval")
        skew = timedelta(seconds=CLOCK_SKEW_SECONDS)
        if not key.valid_from - skew <= contract.issued_at <= key.issuance_not_after + skew:
            raise PermissionError("signed contract falls outside the key issuance interval")
        if mode == VerificationMode.LIVE_AUTHORIZATION:
            if key.status == VerificationKeyStatus.RETIRED:
                raise PermissionError("retired keys cannot authorize live operations")
            if checked_at > key.verify_not_after + skew:
                raise PermissionError("verification key is outside its live acceptance window")
            _verify_live_contract_time(contract, checked_at)
        self._verify_signature(contract, key)

    @staticmethod
    def _verify_signature(contract: SignedSecurityContract, key: VerificationKeyV1) -> None:
        try:
            public_bytes = base64.b64decode(key.public_key_b64, validate=True)
            signature = base64.b64decode(contract.signature, validate=True)
            if key.algorithm == SignatureAlgorithm.ED25519:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
                public_key.verify(signature, contract.canonical_unsigned_bytes())
                return
            candidate = serialization.load_der_public_key(public_bytes)
            if not isinstance(candidate, ec.EllipticCurvePublicKey) or not isinstance(
                candidate.curve, ec.SECP256R1
            ):
                raise ValueError("receipt public key is not an ECDSA P-256 key")
            digest = bytes.fromhex(contract.unsigned_digest_hex())
            candidate.verify(
                signature,
                digest,
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise PermissionError("signed contract signature is invalid") from exc


SignedContractT = TypeVar("SignedContractT", bound=SignedSecurityContract)


class Ed25519ContractSigner:
    """Local signer used by the owner broker and policy notary."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey, *, key_id: str) -> None:
        if re.fullmatch(_SAFE_IDENTIFIER_PATTERN, key_id) is None:
            raise ValueError("signing key ID is invalid")
        self._private_key = private_key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_b64(self) -> str:
        raw = self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def sign(self, contract: SignedContractT) -> SignedContractT:
        if contract.signature_algorithm != SignatureAlgorithm.ED25519:
            raise ValueError("Ed25519 signer cannot sign this contract algorithm")
        if contract.key_id != self._key_id:
            raise ValueError("contract key ID does not match the signer")
        if contract.signature:
            raise ValueError("unsigned contract unexpectedly contains a signature")
        signature = self._private_key.sign(contract.canonical_unsigned_bytes())
        return contract.model_copy(
            update={"signature": base64.b64encode(signature).decode("ascii")}
        )


def ecdsa_public_key_der_b64(public_key: ec.EllipticCurvePublicKey) -> str:
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("receipt public key must use P-256")
    raw = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(raw).decode("ascii")


def _verify_live_contract_time(contract: SignedSecurityContract, now: datetime) -> None:
    skew = timedelta(seconds=CLOCK_SKEW_SECONDS)
    if contract.issued_at > now + skew:
        raise PermissionError("signed contract was issued in the future")
    deadline: datetime | None = None
    if isinstance(contract, OwnerInteractionAssertionV1):
        deadline = contract.expires_at
    elif isinstance(contract, SensitiveActionPermitV2):
        deadline = contract.permit_claim_deadline
    elif isinstance(contract, (DeletionTargetManifestV1, SensitiveExecutionGrantV1)):
        deadline = contract.execution_deadline
    if deadline is not None and now > deadline + skew:
        raise PermissionError("signed contract is outside its live acceptance deadline")


def _required_signing_purpose(contract: SignedSecurityContract) -> SigningKeyPurpose:
    if isinstance(contract, OwnerInteractionAssertionV1):
        return SigningKeyPurpose.OWNER_BROKER
    if isinstance(
        contract,
        (SensitiveActionPermitV2, DeletionTargetManifestV1, SensitiveExecutionGrantV1),
    ):
        return SigningKeyPurpose.POLICY_NOTARY
    if isinstance(contract, ExecutorReceiptV1):
        if contract.action == SensitiveActionV2.EVIDENCE_RETRIEVE:
            return SigningKeyPurpose.RETRIEVAL_RECEIPT
        return SigningKeyPurpose.DELETION_RECEIPT
    raise PermissionError("signed contract type has no trusted signing purpose")


def _require_aware(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _require_deadline(start: datetime, end: datetime, maximum_seconds: int, label: str) -> None:
    _require_aware(start, "issued_at")
    _require_aware(end, f"{label} deadline")
    lifetime = end - start
    if lifetime <= timedelta(0) or lifetime > timedelta(seconds=maximum_seconds):
        raise ValueError(f"{label} deadline exceeds the Phase 1 maximum")


def _decode_b64(value: str, name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError(f"{name} must be canonical base64") from exc
