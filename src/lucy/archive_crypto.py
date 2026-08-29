"""Envelope encryption and an external wrapped-key registry for archives."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGORITHM = "AES-256-GCM+AES-KW-GCM"


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
    def put(self, key_ref: UUID, wrapped_key: WrappedDataKey) -> None: ...

    def get(self, key_ref: UUID) -> WrappedDataKey | None: ...

    def delete(self, key_ref: UUID) -> bool: ...


class MemoryArchiveKeyStore:
    """Test-only key registry with the same delete semantics as production."""

    def __init__(self) -> None:
        self._records: dict[UUID, WrappedDataKey] = {}

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
                "CREATE TABLE IF NOT EXISTS wrapped_keys ("
                "key_ref TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, "
                "nonce BLOB NOT NULL, kek_version TEXT NOT NULL)"
            )

    def put(self, key_ref: UUID, wrapped_key: WrappedDataKey) -> None:
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT ciphertext, nonce, kek_version FROM wrapped_keys "
                "WHERE key_ref = ?",
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
                "SELECT ciphertext, nonce, kek_version FROM wrapped_keys "
                "WHERE key_ref = ?",
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


class EnvelopeCipher:
    def __init__(self, kek: bytes, commitment_key: bytes, *, kek_version: str) -> None:
        if len(kek) != 32 or len(commitment_key) != 32:
            raise ValueError("archive encryption keys must each contain 32 bytes")
        if not kek_version.strip():
            raise ValueError("KEK version must not be blank")
        self._kek = kek
        self._commitment_key = commitment_key
        self._kek_version = kek_version

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
        wrapped = AESGCM(self._kek).encrypt(
            wrap_nonce, dek, self._key_aad(evidence_id)
        )
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
        if not hmac.compare_digest(
            payload.keyed_commitment, self.commitment(plaintext)
        ):
            raise ValueError("archive commitment mismatch")
        return plaintext

    def _key_aad(self, evidence_id: UUID) -> bytes:
        return f"lucy-archive-key:v1:{evidence_id}".encode()


def _decode_key(name: str) -> bytes:
    encoded = os.environ.get(name, "")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ValueError(f"{name} must be valid base64") from exc
    if len(decoded) != 32:
        raise ValueError(f"{name} must decode to exactly 32 bytes")
    return decoded
