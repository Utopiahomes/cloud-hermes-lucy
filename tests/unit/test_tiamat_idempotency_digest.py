from __future__ import annotations

import hashlib
import hmac

import pytest

from lucy.shared_execution.idempotency import DigestKey, IdempotencyDigestRing


def test_digest_ring_emits_current_then_live_predecessor() -> None:
    current = DigestKey("digest-v2", b"n" * 32)
    previous = DigestKey("digest-v1", b"o" * 32)
    candidates = IdempotencyDigestRing(current, (previous,)).candidates(
        "018f4f77-7b1f-7ad2-bb8d-1bc001f34f45"
    )
    assert tuple(item.version for item in candidates) == ("digest-v2", "digest-v1")
    assert (
        candidates[0].digest
        == hmac.new(
            current.key,
            b"018f4f77-7b1f-7ad2-bb8d-1bc001f34f45",
            hashlib.sha256,
        ).hexdigest()
    )
    assert candidates[0].digest != candidates[1].digest


def test_digest_ring_rejects_weak_or_duplicate_key_versions() -> None:
    with pytest.raises(ValueError, match="digest key is invalid"):
        DigestKey("digest-v1", b"short")
    with pytest.raises(ValueError, match="versions must be unique"):
        IdempotencyDigestRing(
            DigestKey("digest-v1", b"a" * 32),
            (DigestKey("digest-v1", b"b" * 32),),
        )
