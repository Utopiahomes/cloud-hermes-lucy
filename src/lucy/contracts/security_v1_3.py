"""Additive Security Baseline v1.3 scope and authorization contracts.

These models never reinterpret v1.2 wire objects. New contract names, versions,
domain separators, and key purposes are distinct while retaining the repository's
reviewed ``lucy-cjson-1`` canonicalizer.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from collections.abc import Mapping
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Literal, Self, TypeVar, cast
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from pydantic import BaseModel, ConfigDict, Field, model_validator

from lucy.contracts.canonical import (
    canonical_json_bytes,
    canonical_sha256,
    canonical_signed_bytes,
    signed_contract_sha256,
)
from lucy.contracts.security_v1_2 import (
    DeploymentEnvironment,
    ExecutorResult,
    SensitiveActionV2,
    SensitiveReasonCode,
    SignatureAlgorithm,
)

V1_3_CLOCK_SKEW_SECONDS = 5
V1_3_CONTEXT_MAX_SECONDS = 300
V1_3_PERMIT_CLAIM_MAX_SECONDS = 60
V1_3_EXECUTION_MAX_SECONDS = 600
V1_3_OWNER_ASSERTION_MAX_SECONDS = 300
RESOLVED_CONTEXT_DIGEST_PREFIX = b"LUCY-RESOLVED-EXECUTION-CONTEXT-V1\0"
_QUALIFIED_LAMBDA_ALIAS_ARN = re.compile(
    r"^arn:aws(?:-us-gov|-cn)?:lambda:[a-z0-9-]+:\d{12}:"
    r"function:[A-Za-z0-9-_]{1,64}:(?!\$LATEST$)[A-Za-z0-9-_]{1,128}$"
)

_SAFE_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$"
_DIGEST = r"^[0-9a-f]{64}$"

SafeIdentifier = Annotated[str, Field(min_length=1, max_length=512, pattern=_SAFE_IDENTIFIER)]
DigestHex = Annotated[str, Field(pattern=_DIGEST)]
Nonce = Annotated[str, Field(min_length=32, max_length=128, pattern=_SAFE_IDENTIFIER)]


class StrictV13Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PrincipalType(StrEnum):
    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"
    RUNTIME = "runtime"


class AuthenticationStrength(StrEnum):
    SINGLE_FACTOR = "single_factor"
    MFA = "mfa"
    PHISHING_RESISTANT = "phishing_resistant"
    WORKLOAD_IDENTITY = "workload_identity"
    SYNTHETIC_ACCEPTANCE = "synthetic_acceptance"


class AudienceClass(StrEnum):
    PUBLIC_WEBSITE = "public_website"
    AUTHENTICATED_INTERNAL = "authenticated_internal"
    REALM_SERVICE = "realm_service"


class V13SigningKeyPurpose(StrEnum):
    OWNER_BROKER = "owner_broker_v13"
    POLICY_NOTARY = "policy_notary_v13"
    RETRIEVAL_RECEIPT = "retrieval_receipt_v13"
    DELETION_RECEIPT = "deletion_receipt_v13"


class V13VerificationKeyStatus(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class OriginScopeV1(StrictV13Contract):
    tenant_account_id: UUID
    node_id: UUID
    node_tenure_id: UUID
    tenure_epoch: int = Field(ge=1)
    security_realm_id: UUID
    storage_epoch: int = Field(ge=1)


class ExecutionBindingV1(StrictV13Contract):
    deployment_id: UUID
    active_realm_id: UUID
    active_storage_epoch: int = Field(ge=1)
    realm_binding_generation: int = Field(ge=1)
    node_authz_epoch: int = Field(ge=1)


class ExactObjectSelectorV1(StrictV13Contract):
    selector_type: Literal["exact_object"] = "exact_object"
    object_id: UUID
    object_version: int = Field(ge=1)


class ResolvedExecutionContextV1(StrictV13Contract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.resolved-execution-context.v1"] = (
        "lucy.resolved-execution-context.v1"
    )
    context_id: UUID
    request_id: UUID
    issued_at: datetime
    expires_at: datetime
    principal_id: UUID
    principal_type: PrincipalType
    identity_issuer: SafeIdentifier
    identity_subject: SafeIdentifier
    authn_strength: AuthenticationStrength
    auth_time: datetime
    initiator_principal_id: UUID | None = None
    target_scope: OriginScopeV1
    workspace_id: UUID
    service_principal_id: UUID
    service_binding_id: UUID
    execution_binding: ExecutionBindingV1
    lucy_instance_id: UUID | None = None
    runtime_id: UUID | None = None
    channel_binding_id: UUID
    channel_generation: int = Field(ge=1)
    audience_class: AudienceClass
    session_id: UUID | None = None
    action: SafeIdentifier
    resource_selector: ExactObjectSelectorV1
    policy_version: int = Field(ge=1)
    membership_generations: tuple[int, ...] = Field(min_length=1)
    grant_id: UUID | None = None
    grant_generation: int | None = Field(default=None, ge=1)
    approval_ref: UUID | None = None
    context_issuer: SafeIdentifier
    context_digest: DigestHex

    @model_validator(mode="after")
    def validate_context(self) -> Self:
        _aware(self.issued_at, "issued_at")
        _aware(self.expires_at, "expires_at")
        _aware(self.auth_time, "auth_time")
        if not self.issued_at < self.expires_at:
            raise ValueError("context expiration must follow issuance")
        if self.expires_at > self.issued_at + timedelta(seconds=V1_3_CONTEXT_MAX_SECONDS):
            raise ValueError("resolved context exceeds five minutes")
        if self.execution_binding.active_realm_id != self.target_scope.security_realm_id:
            raise ValueError("ordinary context target and active realm must match")
        if (self.grant_id is None) != (self.grant_generation is None):
            raise ValueError("grant ID and generation must appear together")
        expected_digest = resolved_execution_context_digest(self)
        if not secrets.compare_digest(self.context_digest, expected_digest):
            raise ValueError("resolved context digest is invalid")
        return self


class SignedV13Contract(StrictV13Contract):
    canonicalization_version: Literal["lucy-cjson-1"] = "lucy-cjson-1"
    signature_algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519
    signing_key_purpose: V13SigningKeyPurpose
    key_id: SafeIdentifier
    issuer: SafeIdentifier
    environment: DeploymentEnvironment
    issued_at: datetime
    signature: str = Field(default="", max_length=1024)

    def canonical_unsigned_bytes(self) -> bytes:
        return canonical_signed_bytes(self)

    def unsigned_digest_hex(self) -> str:
        return signed_contract_sha256(self)


class V13VerificationKeyV1(StrictV13Contract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.v13-verification-key.v1"] = "lucy.v13-verification-key.v1"
    key_id: SafeIdentifier
    issuer: SafeIdentifier
    environment: DeploymentEnvironment
    purpose: V13SigningKeyPurpose
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519
    public_key_b64: str = Field(min_length=40, max_length=4096)
    status: V13VerificationKeyStatus
    valid_from: datetime
    issuance_not_after: datetime
    verify_not_after: datetime

    @model_validator(mode="after")
    def validate_key_window(self) -> Self:
        _aware(self.valid_from, "valid_from")
        _aware(self.issuance_not_after, "issuance_not_after")
        _aware(self.verify_not_after, "verify_not_after")
        if not self.valid_from < self.issuance_not_after <= self.verify_not_after:
            raise ValueError("verification-key validity window is invalid")
        try:
            raw = base64.b64decode(self.public_key_b64, validate=True)
            if self.algorithm == SignatureAlgorithm.ED25519:
                ed25519.Ed25519PublicKey.from_public_bytes(raw)
            else:
                candidate = serialization.load_der_public_key(raw)
                if not isinstance(candidate, ec.EllipticCurvePublicKey) or not isinstance(
                    candidate.curve, ec.SECP256R1
                ):
                    raise ValueError("receipt key must use ECDSA P-256")
        except (ValueError, TypeError) as exc:
            raise ValueError("v1.3 verification key material is invalid") from exc
        return self


SignedV13T = TypeVar("SignedV13T", bound=SignedV13Contract)


class Ed25519V13Signer:
    def __init__(
        self,
        private_key: ed25519.Ed25519PrivateKey,
        *,
        key_id: str,
        purpose: V13SigningKeyPurpose,
    ) -> None:
        self._private_key = private_key
        self._key_id = key_id
        self._purpose = purpose

    @property
    def public_key_b64(self) -> str:
        raw = self._private_key.public_key().public_bytes_raw()
        return base64.b64encode(raw).decode("ascii")

    def sign(self, contract: SignedV13T) -> SignedV13T:
        if contract.signature_algorithm != SignatureAlgorithm.ED25519:
            raise ValueError("Ed25519 signer cannot sign this contract algorithm")
        if contract.key_id != self._key_id or contract.signing_key_purpose != self._purpose:
            raise ValueError("contract does not match the v1.3 signing key")
        if contract.signature:
            raise ValueError("unsigned contract unexpectedly contains a signature")
        value = base64.b64encode(
            self._private_key.sign(contract.canonical_unsigned_bytes())
        ).decode("ascii")
        return contract.model_copy(update={"signature": value})


class V13ContractVerifier:
    def __init__(self, keys: tuple[V13VerificationKeyV1, ...]) -> None:
        if not keys or len({key.key_id for key in keys}) != len(keys):
            raise ValueError("v1.3 trust store must contain distinct keys")
        self._keys = {key.key_id: key for key in keys}

    def verify(
        self,
        contract: SignedV13Contract,
        *,
        expected_purpose: V13SigningKeyPurpose,
        checked_at: datetime,
    ) -> None:
        _aware(checked_at, "checked_at")
        key = self._keys.get(contract.key_id)
        if key is None:
            raise PermissionError("v1.3 signing key is not trusted")
        if contract.signing_key_purpose != expected_purpose or key.purpose != expected_purpose:
            raise PermissionError("v1.3 signing-key purpose is not trusted")
        if contract.issuer != key.issuer or contract.environment != key.environment:
            raise PermissionError("v1.3 contract issuer or environment is not trusted")
        if contract.signature_algorithm != key.algorithm:
            raise PermissionError("v1.3 signature algorithm is not trusted")
        if key.status != V13VerificationKeyStatus.ACTIVE:
            raise PermissionError("v1.3 signing key cannot authorize live operations")
        skew = timedelta(seconds=V1_3_CLOCK_SKEW_SECONDS)
        if not key.valid_from - skew <= contract.issued_at <= key.issuance_not_after + skew:
            raise PermissionError("v1.3 contract falls outside the key issuance window")
        if checked_at > key.verify_not_after + skew or contract.issued_at > checked_at + skew:
            raise PermissionError("v1.3 contract is outside the live verification window")
        deadline = _live_deadline(contract)
        if deadline is not None and checked_at > deadline + skew:
            raise PermissionError("v1.3 contract authorization has expired")
        try:
            signature = base64.b64decode(contract.signature, validate=True)
            raw_key = base64.b64decode(key.public_key_b64, validate=True)
            if key.algorithm == SignatureAlgorithm.ED25519:
                ed25519.Ed25519PublicKey.from_public_bytes(raw_key).verify(
                    signature, contract.canonical_unsigned_bytes()
                )
            else:
                candidate = serialization.load_der_public_key(raw_key)
                if not isinstance(candidate, ec.EllipticCurvePublicKey) or not isinstance(
                    candidate.curve, ec.SECP256R1
                ):
                    raise ValueError("receipt key must use ECDSA P-256")
                candidate.verify(
                    signature,
                    bytes.fromhex(contract.unsigned_digest_hex()),
                    ec.ECDSA(utils.Prehashed(hashes.SHA256())),
                )
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise PermissionError("v1.3 contract signature is invalid") from exc


class OwnerInteractionAssertionV2(SignedV13Contract):
    contract_version: Literal["2"] = "2"
    object_type: Literal["lucy.owner-interaction-assertion.v2"] = (
        "lucy.owner-interaction-assertion.v2"
    )
    signing_key_purpose: Literal[V13SigningKeyPurpose.OWNER_BROKER] = (
        V13SigningKeyPurpose.OWNER_BROKER
    )
    assertion_id: UUID
    principal_id: UUID
    identity_issuer: SafeIdentifier
    identity_subject: SafeIdentifier
    authn_strength: AuthenticationStrength
    auth_time: datetime
    target_scope: OriginScopeV1
    workspace_id: UUID
    requested_action: SensitiveActionV2
    resource_selector: ExactObjectSelectorV1
    displayed_action_digest: DigestHex
    channel_binding_id: UUID
    challenge_id: UUID
    node_authz_epoch: int = Field(ge=1)
    expires_at: datetime
    nonce: Nonce

    @model_validator(mode="after")
    def validate_assertion(self) -> Self:
        _aware(self.issued_at, "issued_at")
        _aware(self.auth_time, "auth_time")
        _aware(self.expires_at, "expires_at")
        if self.signing_key_purpose != V13SigningKeyPurpose.OWNER_BROKER:
            raise ValueError("owner assertion uses the wrong signing-key purpose")
        if self.issued_at < self.auth_time - timedelta(seconds=V1_3_CLOCK_SKEW_SECONDS):
            raise ValueError("owner assertion predates authentication")
        if self.issued_at > self.auth_time + timedelta(seconds=V1_3_OWNER_ASSERTION_MAX_SECONDS):
            raise ValueError("strong owner authentication is stale")
        if not self.issued_at < self.expires_at:
            raise ValueError("owner assertion expiration must follow issuance")
        if self.expires_at > self.issued_at + timedelta(seconds=V1_3_PERMIT_CLAIM_MAX_SECONDS):
            raise ValueError("owner assertion exceeds the v1.3 admission window")
        return self


class SensitiveActionPermitV3(SignedV13Contract):
    contract_version: Literal["3"] = "3"
    object_type: Literal["lucy.sensitive-action-permit.v3"] = "lucy.sensitive-action-permit.v3"
    signing_key_purpose: Literal[V13SigningKeyPurpose.POLICY_NOTARY] = (
        V13SigningKeyPurpose.POLICY_NOTARY
    )
    permit_id: UUID
    action: SensitiveActionV2
    reason: SensitiveReasonCode
    principal_id: UUID
    service_principal_id: UUID
    service_binding_id: UUID
    operation_id: UUID
    target_scope: OriginScopeV1
    workspace_id: UUID
    resource_selector: ExactObjectSelectorV1
    execution_binding: ExecutionBindingV1
    restore_mapping_id: UUID | None = None
    owner_assertion_id: UUID
    owner_assertion_digest: DigestHex
    approval_digest: DigestHex
    policy_version: int = Field(ge=1)
    membership_generation: int = Field(ge=1)
    channel_generation: int = Field(ge=1)
    grant_generation: int | None = Field(default=None, ge=1)
    permit_claim_deadline: datetime
    execution_completion_deadline: datetime
    max_records: int = Field(ge=1, le=90)
    max_bytes: int = Field(ge=1, le=131_072)
    nonce: Nonce

    @model_validator(mode="after")
    def validate_scope_and_deadlines(self) -> Self:
        _aware(self.issued_at, "issued_at")
        _aware(self.permit_claim_deadline, "permit_claim_deadline")
        _aware(self.execution_completion_deadline, "execution_completion_deadline")
        if not self.issued_at < self.permit_claim_deadline:
            raise ValueError("permit claim deadline must follow issuance")
        if self.permit_claim_deadline > self.issued_at + timedelta(
            seconds=V1_3_PERMIT_CLAIM_MAX_SECONDS
        ):
            raise ValueError("permit claim window exceeds 60 seconds")
        if not self.permit_claim_deadline < self.execution_completion_deadline:
            raise ValueError("execution deadline must follow admission deadline")
        if self.execution_completion_deadline > self.issued_at + timedelta(
            seconds=V1_3_EXECUTION_MAX_SECONDS
        ):
            raise ValueError("execution completion window exceeds ten minutes")
        realms_match = (
            self.execution_binding.active_realm_id == self.target_scope.security_realm_id
            and self.execution_binding.active_storage_epoch == self.target_scope.storage_epoch
        )
        if not realms_match and self.restore_mapping_id is None:
            raise ValueError("historical scope mismatch requires an exact restore mapping")
        if self.action == SensitiveActionV2.EVIDENCE_RETRIEVE and (
            self.max_records != 1 or self.max_bytes > 65_536
        ):
            raise ValueError("retrieval remains a bounded single-record operation")
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
        elif self.reason not in deletion_reasons:
            raise ValueError("deletion permit uses a retrieval reason code")
        return self


class EvidencePayloadBindingV2(StrictV13Contract):
    """Immutable ciphertext and original-scope binding for one evidence record."""

    evidence_id: UUID
    original_scope: OriginScopeV1
    record_version: int = Field(ge=1)
    cipher_suite: Literal["AES-256-GCM"] = "AES-256-GCM"
    ciphertext_b64: str = Field(min_length=1, max_length=100_000)
    content_nonce_b64: str = Field(min_length=1, max_length=64)
    authenticated_header_b64: str = Field(min_length=1, max_length=32_768)
    payload_ciphertext_digest: DigestHex

    @model_validator(mode="after")
    def validate_payload(self) -> Self:
        ciphertext = _decode_b64(self.ciphertext_b64, "ciphertext_b64")
        nonce = _decode_b64(self.content_nonce_b64, "content_nonce_b64")
        _decode_b64(self.authenticated_header_b64, "authenticated_header_b64")
        if len(ciphertext) > 65_552:
            raise ValueError("encrypted evidence exceeds the bounded plaintext plus GCM tag")
        if len(nonce) != 12:
            raise ValueError("AES-GCM content nonce must contain exactly 12 bytes")
        if not secrets.compare_digest(
            self.payload_ciphertext_digest,
            hashlib.sha256(ciphertext).hexdigest(),
        ):
            raise ValueError("payload ciphertext digest does not match ciphertext")
        return self


class EvidenceWrapperBindingV2(StrictV13Contract):
    """Replaceable key-wrapper binding around an unchanged payload."""

    representation_id: UUID
    wrapping_scope: OriginScopeV1
    wrapped_key_ref: UUID
    encryption_context: KmsEncryptionContextV2
    encryption_context_version: Literal["KmsEncryptionContextV2"] = "KmsEncryptionContextV2"
    payload_ciphertext_digest: DigestHex
    migration_receipt_id: UUID | None = None

    @model_validator(mode="after")
    def validate_wrapper(self) -> Self:
        context = self.encryption_context
        scope = self.wrapping_scope
        if (
            context.tenant_account_id != scope.tenant_account_id
            or context.node_id != scope.node_id
            or context.node_tenure_id != scope.node_tenure_id
            or context.tenure_epoch != scope.tenure_epoch
            or context.security_realm_id != scope.security_realm_id
            or context.storage_epoch != scope.storage_epoch
        ):
            raise ValueError("KMS context does not match wrapping scope")
        return self


class EncryptedEvidencePackageV2(StrictV13Contract):
    """Bounded two-layer package for one exact retrieval operation."""

    contract_version: Literal["2"] = "2"
    canonicalization_version: Literal["lucy-cjson-1"] = "lucy-cjson-1"
    object_type: Literal["lucy.encrypted-evidence-package.v2"] = (
        "lucy.encrypted-evidence-package.v2"
    )
    operation_id: UUID
    permit_id: UUID
    action: Literal[SensitiveActionV2.EVIDENCE_RETRIEVE] = (
        SensitiveActionV2.EVIDENCE_RETRIEVE
    )
    payload_binding: EvidencePayloadBindingV2
    wrapper_binding: EvidenceWrapperBindingV2
    content_classification: SafeIdentifier
    lineage_refs: tuple[UUID, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def validate_package(self) -> Self:
        payload = self.payload_binding
        wrapper = self.wrapper_binding
        if wrapper.encryption_context.evidence_id != payload.evidence_id:
            raise ValueError("KMS context evidence ID does not match payload")
        if wrapper.payload_ciphertext_digest != payload.payload_ciphertext_digest:
            raise ValueError("wrapper does not bind the exact payload ciphertext")
        if (
            payload.original_scope != wrapper.wrapping_scope
            and wrapper.migration_receipt_id is None
        ):
            raise ValueError("rehosted wrapper requires an exact migration receipt")
        if len(set(self.lineage_refs)) != len(self.lineage_refs):
            raise ValueError("evidence lineage contains duplicate references")
        if len(canonical_json_bytes(self)) > 131_072:
            raise ValueError("encrypted evidence package exceeds the R1 boundary")
        return self

    def package_digest_hex(self) -> str:
        return canonical_sha256(self, prefix=b"LUCY-ENCRYPTED-EVIDENCE-PACKAGE-V2\0")


class DeletionArtifactClass(StrEnum):
    ENCRYPTED_ARCHIVE = "encrypted_archive"
    MEMORY_CLAIM = "memory_claim"
    EMBEDDING = "embedding"
    RESULT_BODY = "result_body"
    PUBLIC_PROJECTION = "public_projection"


class DeletionDisposition(StrEnum):
    DESTROY_WRAPPED_KEY = "destroy_wrapped_key"
    DELETE = "delete"
    INVALIDATE = "invalidate"
    RECOMPUTE = "recompute"


class DeletionTargetReferenceV2(StrictV13Contract):
    artifact_class: DeletionArtifactClass
    artifact_id: UUID
    artifact_version: int = Field(ge=1)
    root_evidence_id: UUID
    disposition: DeletionDisposition
    representation_id: UUID | None = None
    wrapped_key_ref: UUID | None = None

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        archive = self.artifact_class == DeletionArtifactClass.ENCRYPTED_ARCHIVE
        if archive and (
            self.representation_id is None
            or self.wrapped_key_ref is None
            or self.disposition != DeletionDisposition.DESTROY_WRAPPED_KEY
        ):
            raise ValueError("archive deletion target requires exact representation and key")
        if not archive and (
            self.representation_id is not None
            or self.wrapped_key_ref is not None
            or self.disposition == DeletionDisposition.DESTROY_WRAPPED_KEY
        ):
            raise ValueError("derived deletion target must not carry archive key authority")
        return self


def deletion_targets_digest_v2(targets: tuple[DeletionTargetReferenceV2, ...]) -> str:
    return canonical_sha256(
        [target.model_dump(mode="python") for target in targets],
        prefix=b"LUCY-DELETION-TARGETS-V2\0",
    )


class DeletionTargetManifestV2(SignedV13Contract):
    """Frozen, scoped closure for archive and derived-data deletion."""

    contract_version: Literal["2"] = "2"
    object_type: Literal["lucy.deletion-target-manifest.v2"] = (
        "lucy.deletion-target-manifest.v2"
    )
    signing_key_purpose: Literal[V13SigningKeyPurpose.POLICY_NOTARY] = (
        V13SigningKeyPurpose.POLICY_NOTARY
    )
    manifest_id: UUID
    permit_id: UUID
    permit_digest: DigestHex
    operation_id: UUID
    action: Literal[SensitiveActionV2.EVIDENCE_DELETE] = SensitiveActionV2.EVIDENCE_DELETE
    target_scope: OriginScopeV1
    workspace_id: UUID
    root_evidence_id: UUID
    root_representation_id: UUID
    owner_assertion_id: UUID
    owner_assertion_digest: DigestHex
    idempotency_key: SafeIdentifier
    closure_version: int = Field(ge=1)
    targets: tuple[DeletionTargetReferenceV2, ...] = Field(min_length=1, max_length=90)
    target_count: int = Field(ge=1, le=90)
    targets_digest: DigestHex
    tombstone_policy_version: int = Field(ge=1)
    finality_policy_version: int = Field(ge=1)
    permit_claim_deadline: datetime
    execution_completion_deadline: datetime
    nonce: Nonce

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        _aware(self.issued_at, "issued_at")
        _aware(self.permit_claim_deadline, "permit_claim_deadline")
        _aware(self.execution_completion_deadline, "execution_completion_deadline")
        if not self.issued_at < self.permit_claim_deadline <= self.execution_completion_deadline:
            raise ValueError("deletion manifest deadlines are invalid")
        if self.permit_claim_deadline > self.issued_at + timedelta(
            seconds=V1_3_PERMIT_CLAIM_MAX_SECONDS
        ):
            raise ValueError("deletion manifest claim window exceeds 60 seconds")
        if self.execution_completion_deadline > self.issued_at + timedelta(
            seconds=V1_3_EXECUTION_MAX_SECONDS
        ):
            raise ValueError("deletion manifest execution window exceeds ten minutes")
        order = tuple(
            (
                target.artifact_class.value,
                str(target.artifact_id),
                str(target.representation_id or UUID(int=0)),
            )
            for target in self.targets
        )
        if order != tuple(sorted(order)):
            raise ValueError("deletion targets are not in canonical order")
        identities = {(target.artifact_class, target.artifact_id) for target in self.targets}
        if len(identities) != len(self.targets):
            raise ValueError("deletion manifest contains duplicate artifact targets")
        if any(target.root_evidence_id != self.root_evidence_id for target in self.targets):
            raise ValueError("deletion target is outside the root evidence closure")
        root_matches = [
            target
            for target in self.targets
            if target.artifact_class == DeletionArtifactClass.ENCRYPTED_ARCHIVE
            and target.artifact_id == self.root_evidence_id
            and target.representation_id == self.root_representation_id
        ]
        if len(root_matches) != 1:
            raise ValueError("deletion manifest lacks its exact root representation")
        if self.target_count != len(self.targets):
            raise ValueError("deletion target count does not match the manifest")
        if not secrets.compare_digest(
            self.targets_digest,
            deletion_targets_digest_v2(self.targets),
        ):
            raise ValueError("deletion target digest does not match the manifest")
        if len(self.canonical_unsigned_bytes()) > 65_536:
            raise ValueError("canonical deletion manifest exceeds the R1 boundary")
        return self


class SensitiveExecutionGrantV2(SignedV13Contract):
    """Policy-signed, post-claim delegation to one qualified realm executor."""

    contract_version: Literal["2"] = "2"
    object_type: Literal["lucy.sensitive-execution-grant.v2"] = (
        "lucy.sensitive-execution-grant.v2"
    )
    signing_key_purpose: Literal[V13SigningKeyPurpose.POLICY_NOTARY] = (
        V13SigningKeyPurpose.POLICY_NOTARY
    )
    grant_id: UUID
    action: SensitiveActionV2
    permit_id: UUID
    permit_digest: DigestHex
    operation_id: UUID
    caller_identity: SafeIdentifier
    target_scope: OriginScopeV1
    workspace_id: UUID
    resource_selector: ExactObjectSelectorV1
    execution_binding: ExecutionBindingV1
    restore_mapping_id: UUID | None = None
    deletion_manifest_id: UUID | None = None
    deletion_manifest_digest: DigestHex | None = None
    encrypted_package_digest: DigestHex
    package_size_bytes: int = Field(ge=1, le=131_072)
    idempotency_key: SafeIdentifier
    executor_identity: SafeIdentifier
    executor_alias_arn: str = Field(min_length=1, max_length=300)
    executor_version: int = Field(ge=1)
    permit_claimed_at: datetime
    permit_claim_deadline: datetime
    execution_completion_deadline: datetime
    max_records: int = Field(ge=1, le=90)
    max_bytes: int = Field(ge=1, le=131_072)
    nonce: Nonce

    @model_validator(mode="after")
    def validate_grant(self) -> Self:
        _aware(self.issued_at, "issued_at")
        _aware(self.permit_claimed_at, "permit_claimed_at")
        _aware(self.permit_claim_deadline, "permit_claim_deadline")
        _aware(self.execution_completion_deadline, "execution_completion_deadline")
        if self.permit_claimed_at > self.issued_at + timedelta(
            seconds=V1_3_CLOCK_SKEW_SECONDS
        ):
            raise ValueError("execution grant predates permit claim")
        if self.permit_claimed_at > self.permit_claim_deadline + timedelta(
            seconds=V1_3_CLOCK_SKEW_SECONDS
        ):
            raise ValueError("execution grant binds a late permit claim")
        if self.issued_at > self.permit_claim_deadline + timedelta(
            seconds=V1_3_CLOCK_SKEW_SECONDS
        ):
            raise ValueError("execution grant was issued after permit admission closed")
        if not self.issued_at < self.execution_completion_deadline:
            raise ValueError("execution completion deadline must follow grant issuance")
        if self.execution_completion_deadline > self.issued_at + timedelta(
            seconds=V1_3_EXECUTION_MAX_SECONDS
        ):
            raise ValueError("execution completion window exceeds ten minutes")
        if _QUALIFIED_LAMBDA_ALIAS_ARN.fullmatch(self.executor_alias_arn) is None:
            raise ValueError("executor alias must be an exact qualified Lambda alias ARN")
        if self.package_size_bytes > self.max_bytes:
            raise ValueError("execution package exceeds the grant byte ceiling")
        realms_match = (
            self.execution_binding.active_realm_id == self.target_scope.security_realm_id
            and self.execution_binding.active_storage_epoch == self.target_scope.storage_epoch
        )
        if not realms_match and self.restore_mapping_id is None:
            raise ValueError("historical scope mismatch requires an exact restore mapping")
        if self.action == SensitiveActionV2.EVIDENCE_RETRIEVE:
            if self.deletion_manifest_id is not None or self.deletion_manifest_digest is not None:
                raise ValueError("retrieval grant must not bind a deletion manifest")
            if self.max_records != 1 or self.max_bytes > 65_536:
                raise ValueError("retrieval remains a bounded single-record operation")
        elif self.deletion_manifest_id is None or self.deletion_manifest_digest is None:
            raise ValueError("deletion grant must bind the exact deletion manifest")
        return self


class ExecutorReceiptV2(SignedV13Contract):
    """Content-free, realm-scoped outcome from one exact executor invocation."""

    contract_version: Literal["2"] = "2"
    object_type: Literal["lucy.executor-receipt.v2"] = "lucy.executor-receipt.v2"
    signature_algorithm: Literal[SignatureAlgorithm.ECDSA_SHA_256] = (
        SignatureAlgorithm.ECDSA_SHA_256
    )
    signing_key_purpose: V13SigningKeyPurpose
    receipt_id: UUID
    action: SensitiveActionV2
    executor_identity: SafeIdentifier
    executor_alias_arn: str = Field(min_length=1, max_length=300)
    executor_version: int = Field(ge=1)
    caller_identity: SafeIdentifier
    target_scope: OriginScopeV1
    execution_binding: ExecutionBindingV1
    operation_id: UUID
    permit_id: UUID
    permit_digest: DigestHex
    execution_grant_id: UUID
    execution_grant_digest: DigestHex
    deletion_manifest_id: UUID | None = None
    deletion_manifest_digest: DigestHex | None = None
    package_digest: DigestHex
    result: ExecutorResult
    lambda_request_id: SafeIdentifier
    kms_request_id: SafeIdentifier | None = None
    transaction_client_token: SafeIdentifier | None = None
    execution_completion_deadline: datetime
    completed_at: datetime
    record_version: int = Field(ge=1)
    journal_ref: SafeIdentifier
    finality_state: Literal["not_applicable", "operationally_deleted"]

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        _aware(self.issued_at, "issued_at")
        _aware(self.execution_completion_deadline, "execution_completion_deadline")
        _aware(self.completed_at, "completed_at")
        if _QUALIFIED_LAMBDA_ALIAS_ARN.fullmatch(self.executor_alias_arn) is None:
            raise ValueError("executor alias must be an exact qualified Lambda alias ARN")
        skew = timedelta(seconds=V1_3_CLOCK_SKEW_SECONDS)
        if self.completed_at > self.execution_completion_deadline + skew:
            raise ValueError("executor completed after the accepted execution deadline")
        if not self.completed_at - skew <= self.issued_at <= self.completed_at + skew:
            raise ValueError("receipt issuance is not contemporaneous with completion")
        if (
            self.execution_binding.active_realm_id != self.target_scope.security_realm_id
            or self.execution_binding.active_storage_epoch != self.target_scope.storage_epoch
        ):
            raise ValueError("receipt target and execution scope do not match")
        if self.action == SensitiveActionV2.EVIDENCE_RETRIEVE:
            if self.signing_key_purpose != V13SigningKeyPurpose.RETRIEVAL_RECEIPT:
                raise ValueError("retrieval receipt uses the wrong signing-key purpose")
            if (
                self.deletion_manifest_id is not None
                or self.deletion_manifest_digest is not None
                or self.transaction_client_token is not None
                or self.kms_request_id is None
                or self.finality_state != "not_applicable"
            ):
                raise ValueError("retrieval receipt contains invalid action-specific fields")
            if self.result not in {
                ExecutorResult.RETRIEVAL_SUCCEEDED,
                ExecutorResult.IDEMPOTENT_REPLAY,
                ExecutorResult.REJECTED,
            }:
                raise ValueError("retrieval receipt uses a deletion result")
        else:
            if self.signing_key_purpose != V13SigningKeyPurpose.DELETION_RECEIPT:
                raise ValueError("deletion receipt uses the wrong signing-key purpose")
            if (
                self.deletion_manifest_id is None
                or self.deletion_manifest_digest is None
                or self.transaction_client_token is None
                or self.kms_request_id is not None
            ):
                raise ValueError("deletion receipt contains invalid action-specific fields")
            if self.result not in {
                ExecutorResult.DELETION_SUCCEEDED,
                ExecutorResult.IDEMPOTENT_REPLAY,
                ExecutorResult.REJECTED,
            }:
                raise ValueError("deletion receipt uses a retrieval result")
            expected_finality = (
                "not_applicable"
                if self.result == ExecutorResult.REJECTED
                else "operationally_deleted"
            )
            if self.finality_state != expected_finality:
                raise ValueError("deletion receipt finality state contradicts its result")
        return self


class KmsEncryptionContextV2(StrictV13Contract):
    contract_version: Literal["KmsEncryptionContextV2"] = "KmsEncryptionContextV2"
    tenant_account_id: UUID
    node_id: UUID
    node_tenure_id: UUID
    tenure_epoch: int = Field(ge=1)
    security_realm_id: UUID
    storage_epoch: int = Field(ge=1)
    evidence_id: UUID
    purpose: Literal["EVIDENCE_DEK"] = "EVIDENCE_DEK"

    def as_aws_context(self) -> dict[str, str]:
        return {
            "contract_version": self.contract_version,
            "tenant_account_id": str(self.tenant_account_id),
            "node_id": str(self.node_id),
            "node_tenure_id": str(self.node_tenure_id),
            "tenure_epoch": str(self.tenure_epoch),
            "security_realm_id": str(self.security_realm_id),
            "storage_epoch": str(self.storage_epoch),
            "evidence_id": str(self.evidence_id),
            "purpose": self.purpose,
        }


def resolved_execution_context_digest(
    value: Mapping[str, object] | ResolvedExecutionContextV1,
) -> str:
    """Commit to every context field except the digest itself."""

    if isinstance(value, ResolvedExecutionContextV1):
        payload = value.model_dump(mode="python", exclude={"context_digest"})
    else:
        payload = dict(value)
        payload.pop("context_digest", None)
    return canonical_sha256(payload, prefix=RESOLVED_CONTEXT_DIGEST_PREFIX)


def build_resolved_execution_context_v1(
    payload: Mapping[str, object],
) -> ResolvedExecutionContextV1:
    """Build a context with a verified, non-self-referential digest."""

    values = dict(payload)
    values.pop("context_digest", None)
    unknown = set(values).difference(ResolvedExecutionContextV1.model_fields)
    if unknown:
        raise ValueError("resolved context contains unknown fields")
    complete = ResolvedExecutionContextV1.model_construct(
        **cast(dict[str, Any], values),
        context_digest="0" * 64,
    ).model_dump(mode="python")
    complete["context_digest"] = resolved_execution_context_digest(complete)
    return ResolvedExecutionContextV1.model_validate(complete)


def _aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")


def _decode_b64(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{field} is not valid base64") from exc


def _live_deadline(contract: SignedV13Contract) -> datetime | None:
    if isinstance(contract, OwnerInteractionAssertionV2):
        return contract.expires_at
    if isinstance(contract, SensitiveActionPermitV3):
        return contract.permit_claim_deadline
    if isinstance(contract, SensitiveExecutionGrantV2):
        return contract.execution_completion_deadline
    if isinstance(contract, DeletionTargetManifestV2):
        return contract.execution_completion_deadline
    return None


def security_v1_3_json_schemas() -> dict[str, dict[str, object]]:
    """Return the strict schemas owned by this first R1-2 contract increment."""
    models: tuple[type[BaseModel], ...] = (
        OriginScopeV1,
        ExecutionBindingV1,
        ExactObjectSelectorV1,
        ResolvedExecutionContextV1,
        V13VerificationKeyV1,
        OwnerInteractionAssertionV2,
        SensitiveActionPermitV3,
        EvidencePayloadBindingV2,
        EvidenceWrapperBindingV2,
        EncryptedEvidencePackageV2,
        DeletionTargetReferenceV2,
        DeletionTargetManifestV2,
        SensitiveExecutionGrantV2,
        ExecutorReceiptV2,
        KmsEncryptionContextV2,
    )
    return {model.__name__: model.model_json_schema() for model in models}
