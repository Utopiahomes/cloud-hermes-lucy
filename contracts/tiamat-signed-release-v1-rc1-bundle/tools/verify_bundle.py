#!/usr/bin/env python3
"""Independent RC1 verifier. It imports no generator code."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent.parent
MAX_JWS = 131_072
checks = 0
failures: list[str] = []


class DuplicateMember(ValueError):
    pass


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateMember(key)
        result[key] = value
    return result


def decode_json(segment: str) -> dict[str, Any]:
    if "=" in segment:
        raise ValueError("padded_base64url")
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    value = json.loads(raw, object_pairs_hook=strict_object)
    if not isinstance(value, dict):
        raise ValueError("not_object")
    return value


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)


def public_key(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(value))


schemas = {
    "release": load(ROOT / "schemas" / "release-payload.schema.json"),
    "inventory": load(ROOT / "schemas" / "trust-inventory.schema.json"),
}
validators = {
    kind: Draft202012Validator(schema, format_checker=FormatChecker())
    for kind, schema in schemas.items()
}
for schema in schemas.values():
    Draft202012Validator.check_schema(schema)

key_data = load(ROOT / "test-keys.json")
release_key = public_key(key_data["release_public_key_b64"])
root_key = public_key(key_data["root_public_key_b64"])
inventory = load(ROOT / "examples" / "trust-inventory.json")
scopes = {
    (item["caller_id"], item["realm"], item["release_type"], item["subject_id"])
    for item in inventory["keys"][0]["authorized_scopes"]
}


def release_invariants(payload: dict[str, Any]) -> str:
    content = payload["content"]
    binding = {
        "execution_profile": "profile_id",
        "privacy_policy": "policy_id",
        "spending_grant": "partition_id",
    }
    field = binding.get(payload["release_type"])
    if field is not None and payload["subject_id"] != content[field]:
        return "subject_binding_invalid"
    if payload["release_type"] == "spending_grant":
        required = 2 * content["maximum_concurrency"] * content["largest_per_call_microusd"]
        if content["contingency_reserve_microusd"] < required:
            return "contingency_invalid"
    return "valid"


def state_holds(rule: str, conditions: list[bool]) -> bool:
    if rule not in {
        "trust",
        "time",
        "chain",
        "grant",
        "revocation",
        "restore",
        "rotation",
        "inflight",
        "offline",
        "compact",
    }:
        raise ValueError(f"unknown state rule: {rule}")
    return all(conditions)


def verify_token(token: str, kind: str) -> str:
    if len(token.encode("ascii", errors="ignore")) > MAX_JWS:
        return "jws_too_large"
    parts = token.split(".")
    if len(parts) != 3:
        return "compact_invalid"
    try:
        header = decode_json(parts[0])
        payload = decode_json(parts[1])
        signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    except (ValueError, json.JSONDecodeError, DuplicateMember):
        return "compact_invalid"
    expected_typ = (
        "stoin-signed-release+jws" if kind == "release" else "stoin-release-trust-inventory+jws"
    )
    if (
        set(header) != {"alg", "kid", "typ"}
        or header["alg"] != "EdDSA"
        or header["typ"] != expected_typ
    ):
        return "header_invalid"
    expected_kid = "release-key-staging-1" if kind == "release" else "tiamat-trust-root-staging-1"
    if header["kid"] != expected_kid:
        return "header_invalid"
    key = release_key if kind == "release" else root_key
    try:
        key.verify(signature, f"{parts[0]}.{parts[1]}".encode("ascii"))
    except (InvalidSignature, ValueError):
        return "signature_invalid" if kind == "release" else "root_signature_invalid"
    errors = list(validators[kind].iter_errors(payload))
    if errors:
        return "schema_invalid"
    if kind == "inventory":
        return "valid"
    calculated = hashlib.sha256(rfc8785.dumps(payload["content"])).hexdigest()
    if calculated != payload["content_digest"]:
        return "content_digest_mismatch"
    scope = (payload["caller_id"], payload["realm"], payload["release_type"], payload["subject_id"])
    if scope not in scopes:
        return "scope_unauthorized"
    return release_invariants(payload)


for path in sorted((ROOT / "examples").glob("*.json")):
    kind = "inventory" if path.name == "trust-inventory.json" else "release"
    checks += 1
    if list(validators[kind].iter_errors(load(path))):
        failures.append(f"{path.name}: schema invalid")

for path in sorted((ROOT / "vectors").rglob("*.json")):
    vector = load(path)
    if "rule" in vector:
        actual_holds = state_holds(vector["rule"], vector["conditions"])
        checks += 1
        if actual_holds != vector["holds"]:
            failures.append(f"{vector['id']}: state result disagrees")
        continue
    actual = verify_token(vector["compact_jws"], vector["kind"])
    checks += 1
    if actual != vector["expected"]:
        failures.append(f"{vector['id']}: expected {vector['expected']}, got {actual}")
    checks += 1
    if (actual == "valid") != vector["valid"]:
        failures.append(f"{vector['id']}: validity declaration disagrees")

coverage = load(ROOT / "COVERAGE.json")["normative_rules"]
vector_ids = {load(path)["id"] for path in (ROOT / "vectors").rglob("*.json")}
for rule, ids in coverage.items():
    checks += 1
    missing = set(ids) - vector_ids
    if missing:
        failures.append(f"coverage {rule}: missing {sorted(missing)}")

left = {"b": 2, "a": [3, {"d": 4, "c": 5}]}
right = {"a": [3, {"c": 5, "d": 4}], "b": 2}
checks += 1
if hashlib.sha256(rfc8785.dumps(left)).digest() != hashlib.sha256(rfc8785.dumps(right)).digest():
    failures.append("RFC 8785 semantic-order stability")

if failures:
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    print(f"{len(failures)} failures across {checks} checks", file=sys.stderr)
    raise SystemExit(1)
print(f"RC1 signed-release bundle verified: {checks} independent checks, all passing")
