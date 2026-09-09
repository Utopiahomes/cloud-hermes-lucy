"""Encryption-only archive boundary for one V1.3 security realm."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

    def put_wrapped_key(
        self,
        *,
        key_ref: UUID,
        wrapped_key: bytes,
        key_arn: str,
        encryption_context: KmsEncryptionContextV2,
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


@dataclass(frozen=True)
class RealmArchiveEncryptionV1:
    payload_binding: EvidencePayloadBindingV2
    wrapper_binding: EvidenceWrapperBindingV2
    keyed_commitment: str
    kms_request_id: str


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

    def encrypt(
        self,
        *,
        evidence_id: UUID,
        representation_id: UUID,
        key_ref: UUID,
        plaintext: bytes,
        authenticated_header: bytes,
    ) -> RealmArchiveEncryptionV1:
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
        self._backend.put_wrapped_key(
            key_ref=key_ref,
            wrapped_key=generated.ciphertext,
            key_arn=generated.key_id,
            encryption_context=context,
        )
        return RealmArchiveEncryptionV1(
            payload_binding=payload,
            wrapper_binding=wrapper,
            keyed_commitment=hmac.new(
                self._commitment_key, plaintext, hashlib.sha256
            ).hexdigest(),
            kms_request_id=generated.request_id,
        )
