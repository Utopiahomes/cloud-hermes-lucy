"""A from-scratch, independent RFC 8785 (JCS) implementation, used ONLY to cross-check the
`rfc8785` third-party library that check_invariants_impl.py actually relies on for I-B10 and
the canonicalization vectors — never to replace it. Two implementations that agree are much
stronger evidence than one implementation checked against itself.

Deliberately scoped: no float support. RFC 8785's number-formatting rule (ES6 Number.toString
semantics) is the fiddliest part of the spec and genuinely easy to get wrong — proven directly
by fixtures/canonicalization/official-rfc8785-test-vectors/ in this bundle, where a first,
naive attempt at this same file (`json.dumps(obj, sort_keys=True, ...)`) silently mis-serialized
integer-valued floats (56 -> "56.0") against the official 'structures' vector. No document this
bundle canonicalizes (guest.answer requests) contains a float, so rather than risk a second,
subtler float-formatting bug, this implementation raises NotImplementedError if it ever meets
one. This is the same judgment RC2 §11.2 itself makes normative: 'Hand-rolled number formatting,
string escaping, or Unicode canonicalization is not accepted' for a REAL implementation's
runtime path — here it's fine, because the scope is narrow and the gap is loud, not silent.

Key ordering compares UTF-16BE-encoded bytes, not Python's native codepoint string comparison —
RFC 8785 orders object members by their UTF-16 code unit sequence, which differs from codepoint
order for astral-plane characters (surrogate pairs). This was the second bug the naive attempt
had, caught by the official 'weird' vector (an emoji, U+1F602, needs to sort before a BMP
character above U+E000 under UTF-16-code-unit order, but after it under codepoint order).
"""

from __future__ import annotations

import json
from typing import Any


def canonicalize(obj: Any) -> bytes:
    return _serialize(obj).encode("utf-8")


def _serialize(obj: Any) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        raise NotImplementedError(
            "jcs_reference.py intentionally does not implement RFC 8785 float formatting "
            "(ES6 Number.toString semantics) — no guest.answer document needs it. See module "
            "docstring."
        )
    if isinstance(obj, list):
        return "[" + ",".join(_serialize(item) for item in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(f"{json.dumps(k, ensure_ascii=False)}:{_serialize(v)}" for k, v in items) + "}"
    raise TypeError(f"not JSON-representable: {type(obj)!r}")
