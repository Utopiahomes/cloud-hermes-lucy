from __future__ import annotations

import base64
from typing import Any
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lucy.contracts.security_v1_3 import KmsEncryptionContextV2, OriginScopeV1
from lucy.realm_archive import (
    GeneratedDataKeyV1,
    RealmArchiveEncryptor,
    RealmArchiveIdentityV1,
)

ACCOUNT = "123456789012"
KEY_ARN = (
    f"arn:aws:kms:us-east-1:{ACCOUNT}:key/11111111-1111-4111-8111-111111111111"
)


def _scope(realm: int = 5) -> OriginScopeV1:
    return OriginScopeV1(
        tenant_account_id=UUID(int=1),
        node_id=UUID(int=2),
        node_tenure_id=UUID(int=3),
        tenure_epoch=1,
        security_realm_id=UUID(int=realm),
        storage_epoch=2,
    )


class FakeBackend:
    def __init__(self, *, key_id: str = KEY_ARN, plaintext: bytes = b"d" * 32) -> None:
        self.key_id = key_id
        self.plaintext = plaintext
        self.generated: list[dict[str, Any]] = []
        self.stored: list[dict[str, Any]] = []

    def generate_data_key(
        self, *, key_arn: str, encryption_context: dict[str, str]
    ) -> GeneratedDataKeyV1:
        self.generated.append(
            {"key_arn": key_arn, "encryption_context": encryption_context}
        )
        return GeneratedDataKeyV1(
            plaintext=self.plaintext,
            ciphertext=b"wrapped-dek",
            key_id=self.key_id,
            request_id="kms-request-1",
        )

    def put_wrapped_key(
        self,
        *,
        key_ref: UUID,
        wrapped_key: bytes,
        key_arn: str,
        encryption_context: KmsEncryptionContextV2,
    ) -> None:
        self.stored.append(
            {
                "key_ref": key_ref,
                "wrapped_key": wrapped_key,
                "key_arn": key_arn,
                "encryption_context": encryption_context,
            }
        )


def _encryptor(backend: FakeBackend) -> RealmArchiveEncryptor:
    return RealmArchiveEncryptor(
        backend,
        RealmArchiveIdentityV1(
            target_scope=_scope(), evidence_key_arn=KEY_ARN, record_version=1
        ),
        commitment_key=b"c" * 32,
    )


def test_archive_encrypts_and_registers_one_exact_realm_wrapper() -> None:
    backend = FakeBackend()
    evidence_id, representation_id, key_ref = UUID(int=6), UUID(int=7), UUID(int=8)
    plaintext, header = b"synthetic evidence", b'{"classification":"private"}'

    result = _encryptor(backend).encrypt(
        evidence_id=evidence_id,
        representation_id=representation_id,
        key_ref=key_ref,
        plaintext=plaintext,
        authenticated_header=header,
    )

    assert backend.generated == [
        {
            "key_arn": KEY_ARN,
            "encryption_context": (
                result.wrapper_binding.encryption_context.as_aws_context()
            ),
        }
    ]
    assert backend.stored[0] == {
        "key_ref": key_ref,
        "wrapped_key": b"wrapped-dek",
        "key_arn": KEY_ARN,
        "encryption_context": result.wrapper_binding.encryption_context,
    }
    assert result.payload_binding.original_scope == _scope()
    assert result.wrapper_binding.wrapping_scope == _scope()
    assert result.wrapper_binding.wrapped_key_ref == key_ref
    assert AESGCM(b"d" * 32).decrypt(
        base64.b64decode(result.payload_binding.content_nonce_b64),
        base64.b64decode(result.payload_binding.ciphertext_b64),
        header,
    ) == plaintext
    assert len(result.keyed_commitment) == 64
    assert result.kms_request_id == "kms-request-1"


@pytest.mark.parametrize(
    "plaintext", (b"", b"x" * 65_537), ids=("empty", "too-large")
)
def test_archive_rejects_plaintext_outside_the_contract_before_aws(
    plaintext: bytes,
) -> None:
    backend = FakeBackend()
    with pytest.raises(ValueError, match="1 through 65536"):
        _encryptor(backend).encrypt(
            evidence_id=UUID(int=6),
            representation_id=UUID(int=7),
            key_ref=UUID(int=8),
            plaintext=plaintext,
            authenticated_header=b"header",
        )
    assert backend.generated == []
    assert backend.stored == []


def test_archive_rejects_wrong_kms_key_before_registry_write() -> None:
    backend = FakeBackend(
        key_id=(
            f"arn:aws:kms:us-east-1:{ACCOUNT}:"
            "key/99999999-9999-4999-8999-999999999999"
        )
    )
    with pytest.raises(RuntimeError, match="invalid realm archive data key"):
        _encryptor(backend).encrypt(
            evidence_id=UUID(int=6),
            representation_id=UUID(int=7),
            key_ref=UUID(int=8),
            plaintext=b"synthetic evidence",
            authenticated_header=b"header",
        )
    assert len(backend.generated) == 1
    assert backend.stored == []


def test_archive_identity_rejects_non_key_arn_and_bad_commitment_key() -> None:
    with pytest.raises(ValueError, match="exact KMS key ARN"):
        RealmArchiveIdentityV1(
            target_scope=_scope(), evidence_key_arn="alias/lucy", record_version=1
        )
    with pytest.raises(ValueError, match="32 bytes"):
        RealmArchiveEncryptor(
            FakeBackend(),
            RealmArchiveIdentityV1(
                target_scope=_scope(), evidence_key_arn=KEY_ARN, record_version=1
            ),
            commitment_key=b"short",
        )
