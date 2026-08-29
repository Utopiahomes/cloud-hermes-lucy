from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag

from lucy.archive_crypto import (
    EnvelopeCipher,
    MemoryArchiveKeyStore,
    SqliteArchiveKeyStore,
)


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
