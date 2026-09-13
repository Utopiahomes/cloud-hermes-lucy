"""Write-only AWS encryption adapters for durable memory-provider outcomes."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any, Protocol
from uuid import UUID

from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lucy.archive_crypto import AWS_KMS_ALGORITHM, EncryptedPayload, WrappedDataKey
from lucy.contracts.memory_outcome_recovery_v1 import MemoryOutcomeKmsContextV1
from lucy.contracts.security_v1_3 import OriginScopeV1


class OutcomeKmsClient(Protocol):
    def generate_data_key(self, **kwargs: Any) -> dict[str, Any]: ...


class OutcomeDynamoClient(Protocol):
    def put_item(self, **kwargs: Any) -> dict[str, Any]: ...


class AwsKmsMemoryOutcomeEncryptor:
    """Generate outcome DEKs without exposing any decrypt capability."""

    def __init__(
        self,
        client: OutcomeKmsClient,
        *,
        key_arn: str,
        commitment_key: bytes,
        target_scope: OriginScopeV1,
        registry_epoch: int,
        key_epoch: int,
        record_version: int = 1,
    ) -> None:
        if not re.fullmatch(
            r"arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:\d{12}:key/[A-Za-z0-9-]+",
            key_arn,
        ):
            raise ValueError("outcome KMS key must be a full key ARN")
        if len(commitment_key) != 32:
            raise ValueError("outcome commitment key must contain 32 bytes")
        if min(registry_epoch, key_epoch, record_version) < 1:
            raise ValueError("outcome security epochs must be positive")
        self._client = client
        self._key_arn = key_arn
        self._commitment_key = commitment_key
        self._scope = target_scope
        self._registry_epoch = registry_epoch
        self._key_epoch = key_epoch
        self._record_version = record_version

    @property
    def algorithm(self) -> str:
        return AWS_KMS_ALGORITHM

    @property
    def encryption_context_version(self) -> int:
        return 3

    @property
    def record_version(self) -> int:
        return self._record_version

    @property
    def storage_epoch(self) -> int:
        return self._scope.storage_epoch

    @property
    def registry_epoch(self) -> int:
        return self._registry_epoch

    @property
    def key_epoch(self) -> int:
        return self._key_epoch

    def encrypt(self, evidence_id: UUID, plaintext: bytes, aad: bytes) -> EncryptedPayload:
        context = MemoryOutcomeKmsContextV1.from_scope(
            self._scope, encryption_id=evidence_id
        ).as_aws_context()
        response = self._client.generate_data_key(
            KeyId=self._key_arn,
            KeySpec="AES_256",
            EncryptionContext=context,
        )
        dek = _required_bytes(response, "Plaintext")
        wrapped = _required_bytes(response, "CiphertextBlob")
        if len(dek) != 32 or str(response.get("KeyId", "")) != self._key_arn:
            raise ValueError("AWS KMS returned an unexpected outcome data key")
        nonce = os.urandom(12)
        return EncryptedPayload(
            ciphertext=AESGCM(dek).encrypt(nonce, plaintext, aad),
            content_nonce=nonce,
            wrapped_key=WrappedDataKey(
                ciphertext=wrapped,
                nonce=b"kms",
                kek_version=self._key_arn,
            ),
            keyed_commitment=hmac.new(
                self._commitment_key, plaintext, hashlib.sha256
            ).hexdigest(),
        )


class DynamoMemoryOutcomeKeyWriter:
    """Create one exact wrapped-key record; intentionally has no read method."""

    def __init__(
        self,
        client: OutcomeDynamoClient,
        *,
        table_name: str,
        registry_id: UUID,
    ) -> None:
        if re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", table_name) is None:
            raise ValueError("invalid outcome key table name")
        self._client = client
        self._table_name = table_name
        self._registry_id = registry_id

    @property
    def registry_identity(self) -> UUID:
        return self._registry_id

    def put_new(self, key_ref: UUID, wrapped_key: WrappedDataKey) -> None:
        try:
            self._client.put_item(
                TableName=self._table_name,
                Item={
                    "key_ref": {"S": str(key_ref)},
                    "registry_id": {"S": str(self._registry_id)},
                    "ciphertext": {"B": wrapped_key.ciphertext},
                    "kek_version": {"S": wrapped_key.kek_version},
                },
                ConditionExpression="attribute_not_exists(key_ref)",
            )
        except ClientError as exc:
            if _aws_error_code(exc) == "ConditionalCheckFailedException":
                raise ValueError("outcome key already exists; recovery required") from exc
            raise


def _required_bytes(response: dict[str, Any], name: str) -> bytes:
    value = response.get(name)
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError(f"AWS KMS response is missing {name}")
    return bytes(value)


def _aws_error_code(exc: ClientError) -> str:
    value = exc.response.get("Error", {}).get("Code", "")
    return value if isinstance(value, str) else ""
