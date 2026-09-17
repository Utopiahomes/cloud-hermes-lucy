"""RFC 8785 canonicalization for Shared Execution identities and schema bounds."""

from __future__ import annotations

from typing import Any

import rfc8785


def canonical_json_bytes(value: Any) -> bytes:
    """Canonicalize an I-JSON value, failing closed on unsupported numbers or scalars."""

    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, UnicodeError, TypeError, ValueError) as exc:
        raise ValueError("value is outside the RFC 8785 canonical domain") from exc
