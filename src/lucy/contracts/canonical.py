"""Deterministic encoding for security-sensitive Lucy contracts.

Lucy Canonical JSON v1 deliberately accepts a small JSON subset. Security
contracts contain no floating-point values, and timestamps always use UTC with
six fractional digits. Keeping those rules here makes signing behavior
independent of Pydantic's or a platform's default JSON formatting.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel

CANONICALIZATION_VERSION = "lucy-cjson-1"
SIGNED_CONTRACT_PREFIX = b"LUCY-SIGNED-CONTRACT\x00"


def canonical_json_bytes(value: object) -> bytes:
    """Encode the supported JSON subset deterministically as UTF-8."""

    normalized = _normalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_signed_bytes(value: BaseModel) -> bytes:
    """Return domain-prefixed canonical bytes, excluding the signature field."""

    payload = value.model_dump(mode="python", exclude={"signature"})
    return SIGNED_CONTRACT_PREFIX + canonical_json_bytes(payload)


def canonical_sha256(value: object, *, prefix: bytes = b"") -> str:
    """Hash canonical JSON with an optional, explicit domain prefix."""

    return hashlib.sha256(prefix + canonical_json_bytes(value)).hexdigest()


def signed_contract_sha256(value: BaseModel) -> str:
    return hashlib.sha256(canonical_signed_bytes(value)).hexdigest()


def _normalize(value: object) -> Any:
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical timestamps must be timezone-aware")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return _normalize(value.value)
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        raise TypeError("floating-point values are prohibited in Lucy Canonical JSON v1")
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical JSON object keys must be strings")
            normalized[key] = _normalize(item)
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(item) for item in value]
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")
