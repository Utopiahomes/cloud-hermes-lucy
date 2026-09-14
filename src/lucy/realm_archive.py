"""Encryption-only archive boundary for one V1.3 security realm."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from typing import Literal, Protocol
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field, model_validator

from lucy.contracts.security_v1_3 import (
    EvidencePayloadBindingV2,
    EvidenceWrapperBindingV2,
    KmsEncryptionContextV2,
    OriginScopeV1,
)

_KMS_KEY_ARN = re.compile(
    r"arn:aws:kms:(?P<region>[a-z0-9-]+):(?P<account>[0-9]{12}):"
    r"key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)


@dataclass(frozen=True)
class GeneratedDataKeyV1:
    plaintext: bytes
    ciphertext: bytes
    key_id: str
    request_id: str


class RealmArchiveBackend(Protocol):
    def generate_data_key(
        self, *, key_arn: str, encryption_context: dict[str, str]
    ) -> GeneratedDataKeyV1: ...

    def load_archive_envelope(self, key_ref: UUID) -> RealmArchiveEnvelopeV1 | None: ...

    def put_archive_envelope(
        self,
        *,
        envelope: RealmArchiveEnvelopeV1,
        wrapped_key: bytes,
        key_arn: str,
    ) -> None: ...


@dataclass(frozen=True)
class RealmArchiveIdentityV1:
    target_scope: OriginScopeV1
    evidence_key_arn: str
    record_version: int

    def __post_init__(self) -> None:
        match = _KMS_KEY_ARN.fullmatch(self.evidence_key_arn)
        if match is None:
            raise ValueError("realm archive requires an exact KMS key ARN")
        if self.record_version < 1:
            raise ValueError("realm archive record version must be positive")


class RealmArchiveEnvelopeV1(BaseModel):
    """Encrypted, content-bearing outcome durably recoverable from DynamoDB."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.realm-archive-envelope.v1"] = (
        "lucy.realm-archive-envelope.v1"
    )
    payload_binding: EvidencePayloadBindingV2
    wrapper_binding: EvidenceWrapperBindingV2
    keyed_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    kms_request_id: str = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def validate_bindings(self) -> RealmArchiveEnvelopeV1:
        if (
            self.payload_binding.evidence_id
            != self.wrapper_binding.encryption_context.evidence_id
            or self.payload_binding.payload_ciphertext_digest
            != self.wrapper_binding.payload_ciphertext_digest
        ):
            raise ValueError("realm archive envelope bindings differ")
        return self


class RealmArchiveEncryptor:
    """Generate and register a DEK without holding decrypt or delete authority."""

    def __init__(
        self,
        backend: RealmArchiveBackend,
        identity: RealmArchiveIdentityV1,
        *,
        commitment_key: bytes,
    ) -> None:
        if len(commitment_key) != 32:
            raise ValueError("realm archive commitment key must contain 32 bytes")
        self._backend = backend
        self._identity = identity
        self._commitment_key = commitment_key

    def recover(
        self,
        *,
        evidence_id: UUID,
        representation_id: UUID,
        key_ref: UUID,
        request_commitment: str,
    ) -> RealmArchiveEnvelopeV1 | None:
        """Load only the exact durable envelope allocated by PostgreSQL."""

        envelope = self._backend.load_archive_envelope(key_ref)
        if envelope is None:
            return None
        if (
            envelope.payload_binding.evidence_id != evidence_id
            or envelope.payload_binding.original_scope != self._identity.target_scope
            or envelope.wrapper_binding.representation_id != representation_id
            or envelope.wrapper_binding.wrapped_key_ref != key_ref
            or envelope.wrapper_binding.wrapping_scope != self._identity.target_scope
            or envelope.request_commitment != request_commitment
        ):
            raise RuntimeError("durable realm archive envelope differs from its intent")
        return envelope

    def encrypt(
        self,
        *,
        evidence_id: UUID,
        representation_id: UUID,
        key_ref: UUID,
        plaintext: bytes,
        authenticated_header: bytes,
        request_commitment: str,
    ) -> RealmArchiveEnvelopeV1:
        if not plaintext or len(plaintext) > 65_536:
            raise ValueError("realm archive plaintext must contain 1 through 65536 bytes")
        if len(authenticated_header) > 24_576:
            raise ValueError("realm archive authenticated header is too large")
        context = KmsEncryptionContextV2(
            tenant_account_id=self._identity.target_scope.tenant_account_id,
            node_id=self._identity.target_scope.node_id,
            node_tenure_id=self._identity.target_scope.node_tenure_id,
            tenure_epoch=self._identity.target_scope.tenure_epoch,
            security_realm_id=self._identity.target_scope.security_realm_id,
            storage_epoch=self._identity.target_scope.storage_epoch,
            evidence_id=evidence_id,
        )
        generated = self._backend.generate_data_key(
            key_arn=self._identity.evidence_key_arn,
            encryption_context=context.as_aws_context(),
        )
        if (
            len(generated.plaintext) != 32
            or generated.key_id != self._identity.evidence_key_arn
            or not generated.ciphertext
            or not generated.request_id
        ):
            raise RuntimeError("KMS returned an invalid realm archive data key")
        nonce = os.urandom(12)
        ciphertext = AESGCM(generated.plaintext).encrypt(
            nonce, plaintext, authenticated_header
        )
        ciphertext_digest = hashlib.sha256(ciphertext).hexdigest()
        payload = EvidencePayloadBindingV2(
            evidence_id=evidence_id,
            original_scope=self._identity.target_scope,
            record_version=self._identity.record_version,
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            content_nonce_b64=base64.b64encode(nonce).decode("ascii"),
            authenticated_header_b64=base64.b64encode(authenticated_header).decode("ascii"),
            payload_ciphertext_digest=ciphertext_digest,
        )
        wrapper = EvidenceWrapperBindingV2(
            representation_id=representation_id,
            wrapping_scope=self._identity.target_scope,
            wrapped_key_ref=key_ref,
            encryption_context=context,
            payload_ciphertext_digest=ciphertext_digest,
        )
        envelope = RealmArchiveEnvelopeV1(
            payload_binding=payload,
            wrapper_binding=wrapper,
            keyed_commitment=hmac.new(
                self._commitment_key, plaintext, hashlib.sha256
            ).hexdigest(),
            request_commitment=request_commitment,
            kms_request_id=generated.request_id,
        )
        self._backend.put_archive_envelope(
            envelope=envelope,
            wrapped_key=generated.ciphertext,
            key_arn=generated.key_id,
        )
        return envelope
