from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidTag

from lucy.archive_crypto import (
    AWS_KMS_ALGORITHM,
    AwsDynamoArchiveKeyStore,
    AwsKmsEnvelopeCipher,
    EnvelopeCipher,
    MemoryArchiveKeyStore,
    SqliteArchiveKeyStore,
    WrappedDataKey,
    verify_archive_dependencies,
)

KMS_KEY_ARN = (
    "arn:aws:kms:us-east-1:123456789012:"
    "key/12345678-1234-1234-1234-123456789012"
)


class FakeKmsClient:
    def __init__(self) -> None:
        self.records: dict[bytes, tuple[bytes, dict[str, str]]] = {}
        self.generate_calls: list[dict[str, Any]] = []
        self.decrypt_calls: list[dict[str, Any]] = []

    def generate_data_key(self, **kwargs: Any) -> dict[str, Any]:
        self.generate_calls.append(kwargs)
        plaintext = b"d" * 32
        ciphertext = f"wrapped-{len(self.records)}".encode()
        self.records[ciphertext] = (plaintext, kwargs["EncryptionContext"])
        return {
            "Plaintext": plaintext,
            "CiphertextBlob": ciphertext,
            "KeyId": KMS_KEY_ARN,
        }

    def decrypt(self, **kwargs: Any) -> dict[str, Any]:
        self.decrypt_calls.append(kwargs)
        plaintext, context = self.records[kwargs["CiphertextBlob"]]
        if kwargs["EncryptionContext"] != context:
            raise ValueError("encryption context mismatch")
        return {"Plaintext": plaintext, "KeyId": KMS_KEY_ARN}


class FakeDynamoClient:
    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        key = kwargs["Item"]["key_ref"]["S"]
        if key in self.items:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException"}},
                "PutItem",
            )
        self.items[key] = kwargs["Item"]
        return {}

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        key = kwargs["Key"]["key_ref"]["S"]
        item = self.items.get(key)
        return {} if item is None else {"Item": item}

    def delete_item(self, **kwargs: Any) -> dict[str, Any]:
        key = kwargs["Key"]["key_ref"]["S"]
        item = self.items.pop(key, None)
        return {} if item is None else {"Attributes": item}


def _cipher() -> EnvelopeCipher:
    return EnvelopeCipher(b"k" * 32, b"c" * 32, kek_version="test-v1")


def test_envelope_round_trip_uses_keyed_commitment() -> None:
    evidence_id = uuid4()
    plaintext = b'super secret phrase: "rosebud"'
    aad = b'{"evidence":"metadata"}'
    encrypted = _cipher().encrypt(evidence_id, plaintext, aad)

    assert plaintext not in encrypted.ciphertext
    assert encrypted.keyed_commitment != hashlib.sha256(plaintext).hexdigest()
    assert _cipher().decrypt(evidence_id, encrypted, aad) == plaintext
    with pytest.raises(InvalidTag):
        _cipher().decrypt(evidence_id, encrypted, b"wrong metadata")


def test_external_key_store_deletion_is_irreversible_for_database_payload() -> None:
    evidence_id = uuid4()
    encrypted = _cipher().encrypt(evidence_id, b"private", b"metadata")
    keys = MemoryArchiveKeyStore()
    keys.put(evidence_id, encrypted.wrapped_key)
    assert keys.get(evidence_id) == encrypted.wrapped_key
    assert keys.delete(evidence_id) is True
    assert keys.get(evidence_id) is None
    assert keys.delete(evidence_id) is False


def test_sqlite_key_store_requires_external_absolute_directory(tmp_path: Path) -> None:
    store = SqliteArchiveKeyStore(tmp_path / "archive-keys.sqlite3")
    key_ref = uuid4()
    wrapped = _cipher().encrypt(uuid4(), b"private", b"metadata").wrapped_key
    store.put(key_ref, wrapped)
    assert store.get(key_ref) == wrapped
    assert store.delete(key_ref) is True
    assert store.get(key_ref) is None

    with pytest.raises(ValueError, match="absolute"):
        SqliteArchiveKeyStore(Path("relative.sqlite3"))


def test_aws_kms_envelope_uses_bound_encryption_context() -> None:
    client = FakeKmsClient()
    cipher = AwsKmsEnvelopeCipher(
        client,
        key_arn=KMS_KEY_ARN,
        commitment_key=b"c" * 32,
    )
    evidence_id = uuid4()
    plaintext = b"private conversation"
    encrypted = cipher.encrypt(evidence_id, plaintext, b"metadata")

    assert cipher.algorithm == AWS_KMS_ALGORITHM
    assert plaintext not in encrypted.ciphertext
    assert encrypted.wrapped_key.ciphertext != plaintext
    assert client.generate_calls == [
        {
            "KeyId": KMS_KEY_ARN,
            "KeySpec": "AES_256",
            "EncryptionContext": {
                "application": "cloud-hermes-lucy",
                "evidence-id": str(evidence_id),
            },
        }
    ]
    assert cipher.decrypt(evidence_id, encrypted, b"metadata") == plaintext
    assert client.decrypt_calls[0]["KeyId"] == KMS_KEY_ARN
    with pytest.raises(ValueError, match="context mismatch"):
        cipher.decrypt(uuid4(), encrypted, b"metadata")


def test_dynamodb_key_store_is_conditional_idempotent_and_deletable() -> None:
    client = FakeDynamoClient()
    store = AwsDynamoArchiveKeyStore(client, table_name="lucy-wrapped-keys-prod")
    key_ref = uuid4()
    wrapped = WrappedDataKey(
        ciphertext=b"kms-ciphertext",
        nonce=b"kms",
        kek_version=KMS_KEY_ARN,
    )

    store.put(key_ref, wrapped)
    store.put(key_ref, wrapped)
    assert store.get(key_ref) == wrapped
    with pytest.raises(ValueError, match="collision"):
        store.put(
            key_ref,
            WrappedDataKey(
                ciphertext=b"different",
                nonce=b"kms",
                kek_version=KMS_KEY_ARN,
            ),
        )
    assert store.delete(key_ref) is True
    assert store.get(key_ref) is None
    assert store.delete(key_ref) is False


def test_startup_check_exercises_kms_and_registry_without_leaving_a_key() -> None:
    kms = FakeKmsClient()
    dynamo = FakeDynamoClient()
    cipher = AwsKmsEnvelopeCipher(
        kms,
        key_arn=KMS_KEY_ARN,
        commitment_key=b"c" * 32,
    )
    store = AwsDynamoArchiveKeyStore(dynamo, table_name="lucy-wrapped-keys-prod")

    verify_archive_dependencies(cipher, store)

    assert len(kms.generate_calls) == 1
    assert len(kms.decrypt_calls) == 1
    assert dynamo.items == {}
