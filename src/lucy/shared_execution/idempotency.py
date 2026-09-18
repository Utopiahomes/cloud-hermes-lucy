"""Keyed idempotency digests with bounded overlap for safe key rotation."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


@dataclass(frozen=True)
class DigestKey:
    version: str
    key: bytes

    def __post_init__(self) -> None:
        if not 1 <= len(self.version) <= 128 or len(self.key) < 32:
            raise ValueError("digest key is invalid")


@dataclass(frozen=True)
class KeyedDigest:
    version: str
    digest: str


class IdempotencyDigestRing:
    """Compute the current digest plus every still-live predecessor candidate."""

    def __init__(self, current: DigestKey, predecessors: tuple[DigestKey, ...] = ()) -> None:
        versions = (current.version, *(item.version for item in predecessors))
        if len(set(versions)) != len(versions):
            raise ValueError("digest key versions must be unique")
        self._keys = (current, *predecessors)

    def candidates(self, raw_idempotency_key: str) -> tuple[KeyedDigest, ...]:
        if not raw_idempotency_key:
            raise ValueError("idempotency key is required")
        encoded = raw_idempotency_key.encode("utf-8")
        return tuple(
            KeyedDigest(item.version, hmac.new(item.key, encoded, hashlib.sha256).hexdigest())
            for item in self._keys
        )
