"""Envelope encryption and an external wrapped-key registry for archives."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import UUID, uuid4

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lucy.contracts.security_v1_2 import DeploymentEnvironment, KmsEncryptionContextV1

LOCAL_ALGORITHM = "AES-256-GCM+AES-KW-GCM"
AWS_KMS_ALGORITHM = "AES-256-GCM+AWS-KMS"
ALGORITHM = LOCAL_ALGORITHM
AWS_KMS_CONTEXT_APPLICATION = "cloud-hermes-lucy"
STARTUP_CHECK_ID = UUID("00000000-0000-0000-0000-000000000001")


@dataclass(frozen=True)
class WrappedDataKey:
    ciphertext: bytes
    nonce: bytes
    kek_version: str


@dataclass(frozen=True)
class EncryptedPayload:
    ciphertext: bytes
    content_nonce: bytes
    wrapped_key: WrappedDataKey
    keyed_commitment: str


class ArchiveKeyStore(Protocol):
    @property
    def registry_identity(self) -> UUID: ...

    def put(self, key_ref: UUID, wrapped_key: WrappedDataKey) -> None: ...

    def get(self, key_ref: UUID) -> WrappedDataKey | None: ...

    def delete(self, key_ref: UUID) -> bool: ...


class ArchiveCipher(Protocol):
    @property
    def algorithm(self) -> str: ...

    @property
    def encryption_context_version(self) -> int: ...

    @property
    def record_version(self) -> int: ...

    @property
    def storage_epoch(self) -> int: ...

    @property
    def registry_epoch(self) -> int: ...

    @property
    def key_epoch(self) -> int: ...

    def commitment(self, plaintext: bytes) -> str: ...

    def encrypt(self, evidence_id: UUID, plaintext: bytes, aad: bytes) -> EncryptedPayload: ...

    def decrypt(self, evidence_id: UUID, payload: EncryptedPayload, aad: bytes) -> bytes: ...


class KmsClient(Protocol):
    def generate_data_key(self, **kwargs: Any) -> dict[str, Any]: ...

    def decrypt(self, **kwargs: Any) -> dict[str, Any]: ...


class DynamoClient(Protocol):
    def put_item(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_item(self, **kwargs: Any) -> dict[str, Any]: ...

    def delete_item(self, **kwargs: Any) -> dict[str, Any]: ...


class MemoryArchiveKeyStore:
    """Test-only key registry with the same delete semantics as production."""

    def __init__(self, *, registry_id: UUID | None = None) -> None:
        self._records: dict[UUID, WrappedDataKey] = {}
        self._registry_id = registry_id or uuid4()

    @property
    def registry_identity(self) -> UUID:
        return self._registry_id

    def put(self, key_ref: UUID, wrapped_key: WrappedDataKey) -> None:
        existing = self._records.get(key_ref)
        if existing is not None and existing != wrapped_key:
            raise ValueError("key reference collision")
        self._records[key_ref] = wrapped_key

    def get(self, key_ref: UUID) -> WrappedDataKey | None:
        return self._records.get(key_ref)

    def delete(self, key_ref: UUID) -> bool:
        return self._records.pop(key_ref, None) is not None


class SqliteArchiveKeyStore:
    """Local acceptance key registry, intentionally outside PostgreSQL backups.

    Production must use a managed, deletion-aware external key service whose
    recovery process cannot resurrect a destroyed wrapped key.
    """

    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise ValueError("archive key-store path must be absolute")
        if not path.parent.is_dir():
            raise ValueError("archive key-store directory must already exist")
        self._path = path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=5)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS registry_identity ("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1), registry_id TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO registry_identity VALUES (1,?)", (str(uuid4()),)
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS wrapped_keys ("
                "key_ref TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, "
                "nonce BLOB NOT NULL, kek_version TEXT NOT NULL)"
            )

    @property
    def registry_identity(self) -> UUID:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT registry_id FROM registry_identity WHERE singleton=1"
            ).fetchone()
        if row is None:
            raise RuntimeError("archive registry identity is unavailable")
        return UUID(row[0])

    def put(self, key_ref: UUID, wrapped_key: WrappedDataKey) -> None:
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT ciphertext, nonce, kek_version FROM wrapped_keys WHERE key_ref = ?",
                (str(key_ref),),
            ).fetchone()
            candidate = (
                wrapped_key.ciphertext,
                wrapped_key.nonce,
                wrapped_key.kek_version,
            )
            if existing is not None and existing != candidate:
                raise ValueError("key reference collision")
            connection.execute(
                "INSERT OR IGNORE INTO wrapped_keys "
                "(key_ref, ciphertext, nonce, kek_version) VALUES (?, ?, ?, ?)",
                (str(key_ref), *candidate),
            )

    def get(self, key_ref: UUID) -> WrappedDataKey | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT ciphertext, nonce, kek_version FROM wrapped_keys WHERE key_ref = ?",
                (str(key_ref),),
            ).fetchone()
        if row is None:
            return None
        return WrappedDataKey(ciphertext=row[0], nonce=row[1], kek_version=row[2])

    def delete(self, key_ref: UUID) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM wrapped_keys WHERE key_ref = ?", (str(key_ref),)
            )
            return cursor.rowcount == 1


class AwsDynamoArchiveKeyStore:
    """Production wrapped-DEK registry isolated from PostgreSQL backups."""

    def __init__(
        self,
        client: DynamoClient,
        *,
        table_name: str,
        registry_id: UUID | None = None,
    ) -> None:
        if re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", table_name) is None:
            raise ValueError("invalid DynamoDB archive key table name")
        self._client = client
        self._table_name = table_name
        self._registry_id = registry_id

    @property
    def registry_identity(self) -> UUID:
        if self._registry_id is None:
            raise RuntimeError("production registry identity is not configured")
        return self._registry_id

    @classmethod
    def from_environment(cls) -> AwsDynamoArchiveKeyStore:
        table_name = os.environ.get("LUCY_AWS_DYNAMODB_KEY_TABLE", "").strip()
        try:
            registry_id = UUID(os.environ["LUCY_ARCHIVE_REGISTRY_ID"])
        except (KeyError, ValueError):
            raise ValueError("LUCY_ARCHIVE_REGISTRY_ID must be a UUID") from None
        region = _aws_region()
        client = cast(DynamoClient, boto3.client("dynamodb", region_name=region))
        return cls(client, table_name=table_name, registry_id=registry_id)

    def put(self, key_ref: UUID, wrapped_key: WrappedDataKey) -> None:
        item = {
            "key_ref": {"S": str(key_ref)},
            "ciphertext": {"B": wrapped_key.ciphertext},
            "nonce": {"B": wrapped_key.nonce},
            "kek_version": {"S": wrapped_key.kek_version},
        }
        try:
            self._client.put_item(
                TableName=self._table_name,
                Item=item,
                ConditionExpression="attribute_not_exists(key_ref)",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != ("ConditionalCheckFailedException"):
                raise
            if self.get(key_ref) != wrapped_key:
                raise ValueError("key reference collision") from exc

    def get(self, key_ref: UUID) -> WrappedDataKey | None:
        response = self._client.get_item(
            TableName=self._table_name,
            Key={"key_ref": {"S": str(key_ref)}},
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not isinstance(item, dict):
            return None
        try:
            return WrappedDataKey(
                ciphertext=bytes(item["ciphertext"]["B"]),
                nonce=bytes(item["nonce"]["B"]),
                kek_version=str(item["kek_version"]["S"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid wrapped key record in DynamoDB") from exc

    def delete(self, key_ref: UUID) -> bool:
        response = self._client.delete_item(
            TableName=self._table_name,
            Key={"key_ref": {"S": str(key_ref)}},
            ReturnValues="ALL_OLD",
        )
        return bool(response.get("Attributes"))


class EnvelopeCipher:
    def __init__(self, kek: bytes, commitment_key: bytes, *, kek_version: str) -> None:
        if len(kek) != 32 or len(commitment_key) != 32:
            raise ValueError("archive encryption keys must each contain 32 bytes")
        if not kek_version.strip():
            raise ValueError("KEK version must not be blank")
        self._kek = kek
        self._commitment_key = commitment_key
        self._kek_version = kek_version

    @property
    def algorithm(self) -> str:
        return LOCAL_ALGORITHM

    @property
    def encryption_context_version(self) -> int:
        return 1

    @property
    def record_version(self) -> int:
        return 1

    @property
    def storage_epoch(self) -> int:
        return 1

    @property
    def registry_epoch(self) -> int:
        return 1

    @property
    def key_epoch(self) -> int:
        return 1

    @classmethod
    def from_environment(cls) -> EnvelopeCipher:
        return cls(
            _decode_key("LUCY_ARCHIVE_KEK_B64"),
            _decode_key("LUCY_ARCHIVE_COMMITMENT_KEY_B64"),
            kek_version=os.environ.get("LUCY_ARCHIVE_KEK_VERSION", "").strip(),
        )

    def commitment(self, plaintext: bytes) -> str:
        return hmac.new(self._commitment_key, plaintext, hashlib.sha256).hexdigest()

    def encrypt(self, evidence_id: UUID, plaintext: bytes, aad: bytes) -> EncryptedPayload:
        dek = AESGCM.generate_key(bit_length=256)
        content_nonce = os.urandom(12)
        ciphertext = AESGCM(dek).encrypt(content_nonce, plaintext, aad)
        wrap_nonce = os.urandom(12)
        wrapped = AESGCM(self._kek).encrypt(wrap_nonce, dek, self._key_aad(evidence_id))
        return EncryptedPayload(
            ciphertext=ciphertext,
            content_nonce=content_nonce,
            wrapped_key=WrappedDataKey(
                ciphertext=wrapped,
                nonce=wrap_nonce,
                kek_version=self._kek_version,
            ),
            keyed_commitment=self.commitment(plaintext),
        )

    def decrypt(
        self,
        evidence_id: UUID,
        payload: EncryptedPayload,
        aad: bytes,
    ) -> bytes:
        if payload.wrapped_key.kek_version != self._kek_version:
            raise ValueError("archive KEK version is unavailable")
        dek = AESGCM(self._kek).decrypt(
            payload.wrapped_key.nonce,
            payload.wrapped_key.ciphertext,
            self._key_aad(evidence_id),
        )
        plaintext = AESGCM(dek).decrypt(payload.content_nonce, payload.ciphertext, aad)
        if not hmac.compare_digest(payload.keyed_commitment, self.commitment(plaintext)):
            raise ValueError("archive commitment mismatch")
        return plaintext

    def _key_aad(self, evidence_id: UUID) -> bytes:
        return f"lucy-archive-key:v1:{evidence_id}".encode()


class AwsKmsEnvelopeCipher:
    """AWS KMS data-key envelope encryption using Render OIDC credentials."""

    def __init__(
        self,
        client: KmsClient,
        *,
        key_arn: str,
        commitment_key: bytes,
        environment: DeploymentEnvironment,
        storage_epoch: int,
        registry_epoch: int,
        key_epoch: int,
        record_version: int = 1,
    ) -> None:
        if not _valid_kms_key_arn(key_arn):
            raise ValueError("LUCY_AWS_KMS_KEY_ARN must be a full KMS key ARN")
        if len(commitment_key) != 32:
            raise ValueError("archive commitment key must contain 32 bytes")
        if min(storage_epoch, registry_epoch, key_epoch, record_version) < 1:
            raise ValueError("archive security epochs and record version must be positive")
        self._client = client
        self._key_arn = key_arn
        self._commitment_key = commitment_key
        self._environment = environment
        self._storage_epoch = storage_epoch
        self._registry_epoch = registry_epoch
        self._key_epoch = key_epoch
        self._record_version = record_version

    @classmethod
    def from_environment(cls) -> AwsKmsEnvelopeCipher:
        region = _aws_region()
        client = cast(KmsClient, boto3.client("kms", region_name=region))
        return cls(
            client,
            key_arn=os.environ.get("LUCY_AWS_KMS_KEY_ARN", "").strip(),
            commitment_key=_decode_key("LUCY_ARCHIVE_COMMITMENT_KEY_B64"),
            environment=DeploymentEnvironment(
                os.environ.get("LUCY_SECURITY_ENVIRONMENT", "").strip()
            ),
            storage_epoch=_positive_environment_int("LUCY_SECURITY_STORAGE_EPOCH"),
            registry_epoch=_positive_environment_int("LUCY_SECURITY_REGISTRY_EPOCH"),
            key_epoch=_positive_environment_int("LUCY_SECURITY_KEY_EPOCH"),
            record_version=_positive_environment_int("LUCY_ARCHIVE_RECORD_VERSION"),
        )

    @property
    def algorithm(self) -> str:
        return AWS_KMS_ALGORITHM

    @property
    def encryption_context_version(self) -> int:
        return 2

    @property
    def record_version(self) -> int:
        return self._record_version

    @property
    def storage_epoch(self) -> int:
        return self._storage_epoch

    @property
    def registry_epoch(self) -> int:
        return self._registry_epoch

    @property
    def key_epoch(self) -> int:
        return self._key_epoch

    def commitment(self, plaintext: bytes) -> str:
        return hmac.new(self._commitment_key, plaintext, hashlib.sha256).hexdigest()

    def encrypt(self, evidence_id: UUID, plaintext: bytes, aad: bytes) -> EncryptedPayload:
        response = self._client.generate_data_key(
            KeyId=self._key_arn,
            KeySpec="AES_256",
            EncryptionContext=self._encryption_context(evidence_id),
        )
        dek = _required_bytes(response, "Plaintext")
        wrapped = _required_bytes(response, "CiphertextBlob")
        response_key_id = str(response.get("KeyId", ""))
        if len(dek) != 32 or response_key_id != self._key_arn:
            raise ValueError("AWS KMS returned an unexpected data key")
        content_nonce = os.urandom(12)
        ciphertext = AESGCM(dek).encrypt(content_nonce, plaintext, aad)
        return EncryptedPayload(
            ciphertext=ciphertext,
            content_nonce=content_nonce,
            wrapped_key=WrappedDataKey(
                ciphertext=wrapped,
                nonce=b"kms",
                kek_version=self._key_arn,
            ),
            keyed_commitment=self.commitment(plaintext),
        )

    def decrypt(
        self,
        evidence_id: UUID,
        payload: EncryptedPayload,
        aad: bytes,
    ) -> bytes:
        if payload.wrapped_key.kek_version != self._key_arn:
            raise ValueError("archive KMS key is unavailable")
        response = self._client.decrypt(
            CiphertextBlob=payload.wrapped_key.ciphertext,
            KeyId=self._key_arn,
            EncryptionContext=self._encryption_context(evidence_id),
        )
        dek = _required_bytes(response, "Plaintext")
        if len(dek) != 32 or str(response.get("KeyId", "")) != self._key_arn:
            raise ValueError("AWS KMS returned an unexpected plaintext key")
        plaintext = AESGCM(dek).decrypt(
            payload.content_nonce,
            payload.ciphertext,
            aad,
        )
        if not hmac.compare_digest(
            payload.keyed_commitment,
            self.commitment(plaintext),
        ):
            raise ValueError("archive commitment mismatch")
        return plaintext

    def _encryption_context(self, evidence_id: UUID) -> dict[str, str]:
        return KmsEncryptionContextV1(
            environment=self._environment,
            evidence_id=evidence_id,
            storage_epoch=self._storage_epoch,
            registry_epoch=self._registry_epoch,
            key_epoch=self._key_epoch,
            record_version=self._record_version,
        ).as_aws_context()


def archive_dependencies_from_environment() -> tuple[ArchiveCipher, ArchiveKeyStore]:
    backend = os.environ.get("LUCY_ARCHIVE_BACKEND", "local-sqlite").strip()
    if backend == "local-sqlite":
        path = os.environ.get("LUCY_ARCHIVE_KEYSTORE_PATH", "").strip()
        if not path:
            raise ValueError("LUCY_ARCHIVE_KEYSTORE_PATH is required")
        return EnvelopeCipher.from_environment(), SqliteArchiveKeyStore(Path(path))
    if backend == "aws-kms-dynamodb":
        return (
            AwsKmsEnvelopeCipher.from_environment(),
            AwsDynamoArchiveKeyStore.from_environment(),
        )
    raise ValueError("unsupported LUCY_ARCHIVE_BACKEND")


def archive_key_store_from_environment() -> ArchiveKeyStore:
    """Build only the wrapped-key registry; deletion needs no KMS authority."""

    backend = os.environ.get("LUCY_ARCHIVE_BACKEND", "local-sqlite").strip()
    if backend == "local-sqlite":
        path = os.environ.get("LUCY_ARCHIVE_KEYSTORE_PATH", "").strip()
        if not path:
            raise ValueError("LUCY_ARCHIVE_KEYSTORE_PATH is required")
        return SqliteArchiveKeyStore(Path(path))
    if backend == "aws-kms-dynamodb":
        return AwsDynamoArchiveKeyStore.from_environment()
    raise ValueError("unsupported LUCY_ARCHIVE_BACKEND")


def verify_archive_dependencies(
    cipher: ArchiveCipher,
    key_store: ArchiveKeyStore,
) -> None:
    """Exercise wrap, registry, unwrap, and deletion before entering ready state."""

    existing = key_store.get(STARTUP_CHECK_ID)
    if existing is not None and not key_store.delete(STARTUP_CHECK_ID):
        raise RuntimeError("stale archive startup-check key could not be deleted")
    plaintext = b"lucy-archive-startup-check"
    aad = b'{"purpose":"startup-check"}'
    encrypted = cipher.encrypt(STARTUP_CHECK_ID, plaintext, aad)
    key_store.put(STARTUP_CHECK_ID, encrypted.wrapped_key)
    try:
        stored = key_store.get(STARTUP_CHECK_ID)
        if stored != encrypted.wrapped_key:
            raise RuntimeError("archive key registry failed its startup check")
        candidate = EncryptedPayload(
            ciphertext=encrypted.ciphertext,
            content_nonce=encrypted.content_nonce,
            wrapped_key=stored,
            keyed_commitment=encrypted.keyed_commitment,
        )
        if cipher.decrypt(STARTUP_CHECK_ID, candidate, aad) != plaintext:
            raise RuntimeError("archive cipher failed its startup check")
    finally:
        if not key_store.delete(STARTUP_CHECK_ID):
            raise RuntimeError("archive startup-check key was not destroyed")


def _decode_key(name: str) -> bytes:
    encoded = os.environ.get(name, "")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ValueError(f"{name} must be valid base64") from exc
    if len(decoded) != 32:
        raise ValueError(f"{name} must decode to exactly 32 bytes")
    return decoded


def _aws_region() -> str:
    region = (
        os.environ.get("AWS_REGION", "").strip() or os.environ.get("AWS_DEFAULT_REGION", "").strip()
    )
    if re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", region) is None:
        raise ValueError("AWS_REGION must name an explicit AWS region")
    return region


def _valid_kms_key_arn(value: str) -> bool:
    return (
        re.fullmatch(
            r"arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:\d{12}:"
            r"key/[0-9a-f-]{36}",
            value,
        )
        is not None
    )


def _required_bytes(response: dict[str, Any], name: str) -> bytes:
    value = response.get(name)
    if not isinstance(value, bytes):
        raise ValueError(f"AWS response did not include {name}")
    return value


def _positive_environment_int(name: str) -> int:
    try:
        value = int(os.environ.get(name, ""))
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value
