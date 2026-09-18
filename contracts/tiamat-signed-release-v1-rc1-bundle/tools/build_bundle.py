#!/usr/bin/env python3
"""Build deterministic synthetic JWS vectors. Never use these keys outside tests."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors"
RELEASE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ROOT_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(31, -1, -1)))


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def compact(
    payload: bytes, key: Ed25519PrivateKey, kid: str, typ: str, *, alg: str = "EdDSA"
) -> str:
    header = json.dumps({"alg": alg, "kid": kid, "typ": typ}, separators=(",", ":")).encode()
    signing = f"{b64(header)}.{b64(payload)}".encode("ascii")
    return f"{signing.decode()}.{b64(key.sign(signing))}"


def compact_raw(header: bytes, payload: bytes, key: Ed25519PrivateKey) -> str:
    signing = f"{b64(header)}.{b64(payload)}".encode("ascii")
    return f"{signing.decode()}.{b64(key.sign(signing))}"


def raw_public(key: Ed25519PrivateKey) -> str:
    value = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(value).decode("ascii")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def write_vector(
    vector_id: str, valid: bool, expected: str, token: str, kind: str = "release"
) -> None:
    write_json(
        VECTORS / ("positive" if valid else "negative") / f"{vector_id}.json",
        {
            "id": vector_id,
            "kind": kind,
            "valid": valid,
            "expected": expected,
            "compact_jws": token,
        },
    )


def signed_release(doc: dict[str, Any], *, alg: str = "EdDSA") -> str:
    payload = json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode()
    return compact(
        payload, RELEASE_KEY, "release-key-staging-1", "stoin-signed-release+jws", alg=alg
    )


def main() -> None:
    for directory in (VECTORS / "positive", VECTORS / "negative", VECTORS / "state"):
        directory.mkdir(parents=True, exist_ok=True)
        for path in directory.glob("*.json"):
            path.unlink()

    docs: dict[str, dict[str, Any]] = {}
    for path in sorted((ROOT / "examples").glob("*.json")):
        if path.name != "trust-inventory.json":
            docs[path.stem] = json.loads(path.read_text(encoding="utf-8"))

    inventory_path = ROOT / "examples" / "trust-inventory.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory["keys"][0]["public_key_b64"] = raw_public(RELEASE_KEY)
    inventory["keys"][0]["authorized_scopes"] = [
        {
            "caller_id": doc["caller_id"],
            "realm": doc["realm"],
            "release_type": doc["release_type"],
            "subject_id": doc["subject_id"],
        }
        for doc in docs.values()
    ]
    write_json(inventory_path, inventory)

    for name, doc in docs.items():
        write_vector(f"release.pos.{name}", True, "valid", signed_release(doc))

    inventory_payload = json.dumps(inventory, separators=(",", ":")).encode()
    inventory_token = compact(
        inventory_payload, ROOT_KEY, inventory["root_key_id"], "stoin-release-trust-inventory+jws"
    )
    write_vector("inventory.pos.bootstrap", True, "valid", inventory_token, "inventory")

    base = docs["execution-profile"]
    bad_signature = signed_release(base)[:-1] + ("A" if signed_release(base)[-1] != "A" else "B")
    write_vector("release.neg.bad-signature", False, "signature_invalid", bad_signature)
    write_vector(
        "release.neg.wrong-alg", False, "header_invalid", signed_release(base, alg="HS256")
    )
    payload = json.dumps(base, separators=(",", ":")).encode()
    valid_header = {
        "alg": "EdDSA",
        "kid": "release-key-staging-1",
        "typ": "stoin-signed-release+jws",
    }
    for name, header in (
        ("unknown-kid", dict(valid_header, kid="unknown-key")),
        ("unknown-header", dict(valid_header, crit=["x-test"])),
    ):
        token = compact_raw(
            json.dumps(header, separators=(",", ":")).encode(), payload, RELEASE_KEY
        )
        write_vector(f"release.neg.{name}", False, "header_invalid", token)
    duplicate_header = (
        b'{"alg":"EdDSA","kid":"release-key-staging-1",'
        b'"typ":"stoin-signed-release+jws","kid":"duplicate"}'
    )
    write_vector(
        "release.neg.duplicate-header",
        False,
        "compact_invalid",
        compact_raw(duplicate_header, payload, RELEASE_KEY),
    )
    duplicate_payload = payload[:-1] + b',"format_version":"1"}'
    encoded_header = json.dumps(valid_header, separators=(",", ":")).encode()
    write_vector(
        "release.neg.duplicate-json-member",
        False,
        "compact_invalid",
        compact_raw(encoded_header, duplicate_payload, RELEASE_KEY),
    )
    write_vector(
        "release.neg.invalid-utf8",
        False,
        "compact_invalid",
        compact_raw(encoded_header, b"\xff", RELEASE_KEY),
    )
    padded_signing = f"{b64(encoded_header)}=.{b64(payload)}".encode("ascii")
    padded_token = f"{padded_signing.decode()}.{b64(RELEASE_KEY.sign(padded_signing))}"
    write_vector("release.neg.padding", False, "compact_invalid", padded_token)
    write_vector("release.neg.malformed", False, "compact_invalid", "not.a-jws")

    mutations: list[tuple[str, str, Any]] = []
    unknown = copy.deepcopy(base)
    unknown["format_version"] = "2"
    mutations.append(("unknown-version", "schema_invalid", unknown))
    unknown_type = copy.deepcopy(base)
    unknown_type["release_type"] = "future_release"
    mutations.append(("unknown-release-type", "schema_invalid", unknown_type))
    float_value = copy.deepcopy(base)
    float_value["sequence"] = 1.5
    mutations.append(("float", "schema_invalid", float_value))
    extra = copy.deepcopy(base)
    extra["unexpected"] = True
    mutations.append(("unknown-member", "schema_invalid", extra))
    digest = copy.deepcopy(base)
    digest["content_digest"] = "0" * 64
    mutations.append(("content-digest", "content_digest_mismatch", digest))
    scope = copy.deepcopy(base)
    scope["caller_id"] = "stoin:synth:other"
    mutations.append(("scope", "scope_unauthorized", scope))
    subject = copy.deepcopy(base)
    subject["content"]["profile_id"] = "wrong-profile"
    subject["content_digest"] = hashlib.sha256(rfc8785.dumps(subject["content"])).hexdigest()
    mutations.append(("subject-binding", "subject_binding_invalid", subject))
    contingency = copy.deepcopy(docs["spending-grant"])
    contingency["content"]["contingency_reserve_microusd"] = 7999
    contingency["content_digest"] = hashlib.sha256(
        rfc8785.dumps(contingency["content"])
    ).hexdigest()
    mutations.append(("contingency", "contingency_invalid", contingency))
    key_revoke = copy.deepcopy(docs["release-revocation"])
    key_revoke["content"] = {"target_type": "key", "target_key_id": "release-key-staging-1"}
    key_revoke["content_digest"] = hashlib.sha256(rfc8785.dumps(key_revoke["content"])).hexdigest()
    mutations.append(("key-revocation", "schema_invalid", key_revoke))
    for name, expected, doc in mutations:
        write_vector(f"release.neg.{name}", False, expected, signed_release(doc))

    wrong_inventory = compact(
        inventory_payload,
        RELEASE_KEY,
        inventory["root_key_id"],
        "stoin-release-trust-inventory+jws",
    )
    write_vector(
        "inventory.neg.release-key-signed",
        False,
        "root_signature_invalid",
        wrong_inventory,
        "inventory",
    )

    token = signed_release(base)
    parts = token.split(".")
    payload = base64.urlsafe_b64decode(parts[1] + "==")
    reparsed = json.dumps(json.loads(payload), indent=2).encode()
    reserialized = f"{parts[0]}.{b64(reparsed)}.{parts[2]}"
    write_vector("release.neg.payload-reserialized", False, "signature_invalid", reserialized)
    write_vector("release.neg.oversized", False, "jws_too_large", "A" * 131073)

    state_vectors = [
        ("trust-key-active", "trust", True, [True, True, True, True, True]),
        ("trust-wrong-issuer", "trust", False, [False, True, True, True, True]),
        ("trust-wrong-environment", "trust", False, [True, False, True, True, True]),
        ("trust-wrong-use", "trust", False, [True, True, False, True, True]),
        ("trust-wrong-purpose", "trust", False, [True, True, True, False, True]),
        ("trust-revoked", "trust", False, [True, True, True, True, False]),
        ("time-current", "time", True, [True, True]),
        ("time-expired", "time", False, [False, True]),
        ("time-key-window", "time", False, [True, False]),
        ("chain-successor", "chain", True, [True, True, True, True]),
        ("chain-missing-predecessor", "chain", False, [False, True, True, True]),
        ("chain-nonincreasing", "chain", False, [True, False, True, True]),
        ("chain-competing-successor", "chain", False, [True, True, False, True]),
        ("chain-resurrection", "chain", False, [True, True, True, False]),
        ("grant-current", "grant", True, [True, True]),
        ("grant-outside-period", "grant", False, [False, True]),
        ("grant-insufficient-authority", "grant", False, [True, False]),
        ("revocation-current", "revocation", True, [True, True]),
        ("revocation-generation-rollback", "revocation", False, [False, True]),
        ("revocation-race", "revocation", False, [True, False]),
        ("restore-reconciled", "restore", True, [True, True, True, True]),
        ("restore-no-witness", "restore", False, [False, True, True, True]),
        ("restore-generation-mismatch", "restore", False, [True, False, True, True]),
        ("restore-unreconciled-settlement", "restore", False, [True, True, False, True]),
        ("restore-same-generation-stale", "restore", False, [True, True, True, False]),
        ("rotation-overlap", "rotation", True, [True, True, True]),
        ("profile-inflight-replacement", "inflight", True, [True, True, True]),
        ("next-period-offline", "offline", True, [True, True]),
        ("unprotected-header", "compact", False, [False]),
    ]
    for name, rule, holds, conditions in state_vectors:
        write_json(
            VECTORS / "state" / f"state.{name}.json",
            {"id": f"state.{name}", "rule": rule, "holds": holds, "conditions": conditions},
        )

    write_json(
        ROOT / "test-keys.json",
        {
            "warning": "Synthetic keys only; test seeds are in build_bundle.py.",
            "release_public_key_b64": raw_public(RELEASE_KEY),
            "root_public_key_b64": raw_public(ROOT_KEY),
        },
    )
    print(f"built {len(list(VECTORS.rglob('*.json')))} deterministic vectors")


if __name__ == "__main__":
    main()
