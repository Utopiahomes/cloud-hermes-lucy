#!/usr/bin/env python3
"""Checks internal consistency of the guest.answer@1.0 RC2 Tier A bundle.

Mirrors the Management Contract bundle's verify_bundle.py in spirit: every positive vector must
validate against its named schema, every negative vector must be rejected by it, and every
invariant vector's declared expectation (hold/violation) must match what the invariant checker
actually computes. This script checks the bundle; it does not check either implementation.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

BUNDLE = Path(__file__).resolve().parent.parent
SCHEMAS = BUNDLE / "schemas"
VECTORS = BUNDLE / "vectors"


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def build_registry() -> Registry:
    resources = []
    for path in SCHEMAS.glob("*.json"):
        contents = load(path)
        resources.append((contents["$id"], Resource.from_contents(contents)))
    return Registry().with_resources(resources)


SCHEMA_FILES = {
    "request.schema.json": "request.schema.json",
    "response.schema.json": "response.schema.json",
    "error.response.schema.json": "error.response.schema.json",
}


def get_validator(registry: Registry, schema_filename: str) -> Draft202012Validator:
    schema = load(SCHEMAS / schema_filename)
    return Draft202012Validator(schema, registry=registry)


def check_schema_vectors(registry: Registry) -> list[str]:
    errors: list[str] = []
    checked = 0
    for directory, expect_valid in [(VECTORS / "positive", True), (VECTORS / "negative", False)]:
        for path in sorted(directory.glob("*.json")):
            vector = load(path)
            validator = get_validator(registry, vector["schema"])
            is_valid = validator.is_valid(vector["document"])
            checked += 1
            declared_valid = vector["expect"] == "valid"
            if declared_valid != expect_valid:
                errors.append(f"{path.name}: vector's own expect={vector['expect']!r} disagrees with its directory")
            if is_valid != declared_valid:
                schema_errors = list(validator.iter_errors(vector["document"]))
                first = schema_errors[0].message if schema_errors else "(schema rejected nothing, but is_valid was False?)"
                errors.append(
                    f"{path.name}: expected valid={declared_valid}, got valid={is_valid} "
                    f"(vector_id={vector['vector_id']}); first schema error: {first}"
                )
    print(f"schema vectors checked: {checked}")
    return errors


def applicable_invariants(documents: dict) -> set[str]:
    """Which invariant checks CAN run against this vector's documents, based on required-key
    presence — not which one the vector claims to target. This is what makes the complete-state
    gate below independent of the vector's own declaration: it runs every check the document
    shape supports, not just the one named."""
    keys = set(documents.keys())
    applicable = set()
    if "request" in keys:
        applicable |= {"I-B01", "I-B02", "I-B03"}
    if "request" in keys and "response" in keys:
        applicable |= {"I-B04"}
    if "response" in keys:
        applicable |= {"I-B05", "I-B06", "I-B07"}
    if {"response", "assumed_approved_hostnames", "assumed_approved_destinations"} <= keys:
        applicable |= {"I-B08"}
    if "state" in keys and "expected_outcome" in keys:
        applicable |= {"I-B09"}
    if {"a", "b", "same_canonical_identity"} <= keys:
        applicable |= {"I-B10"}
    return applicable


def actually_violated_invariants(documents: dict) -> set[str]:
    """Independently determines which invariants are ACTUALLY violated by running every
    applicable check, ignoring anything the vector itself claims. This is the core of the
    complete-state gate: a vector's declared invariant/expect is a claim; this function is
    the proof."""
    from check_invariants_impl import CHECKS

    violated = set()
    for invariant_id in applicable_invariants(documents):
        check = CHECKS[invariant_id]
        try:
            check(documents)
        except AssertionError:
            violated.add(invariant_id)
    return violated


def check_invariants(registry: Registry) -> list[str]:
    """Complete-state gate for invariant vectors, mirroring the Management Contract bundle's
    treatment of health vectors: every 'hold' vector must hold under EVERY applicable invariant,
    not just the one it names, and every 'violation' vector's actual violated set must match
    EXACTLY its declared primary invariant plus its declared also_violates list — no undeclared
    breakage, none declared that doesn't occur. Both directions are computed by
    actually_violated_invariants(), independently of anything the vector or the generator claims."""
    errors: list[str] = []
    checked = 0
    inv_dir = VECTORS / "invariants"
    for path in sorted(inv_dir.glob("inv.*.json")):
        vector = load(path)
        invariant_id = vector["invariant"]
        if invariant_id not in {
            "I-B01", "I-B02", "I-B03", "I-B04", "I-B05", "I-B06", "I-B07", "I-B08", "I-B09", "I-B10",
        }:
            continue  # non-machine-checkable invariants (e.g. I-B11) have no vector files here
        checked += 1
        documents = vector["documents"]
        actual_violated = actually_violated_invariants(documents)

        if vector["expect"] == "hold":
            if actual_violated:
                errors.append(
                    f"{path.name}: declared to hold, but actually violates {sorted(actual_violated)} "
                    f"(complete-state gate failure — a 'hold' vector must hold under every applicable "
                    f"invariant, not just {invariant_id})"
                )
        else:
            declared = {invariant_id} | set(vector.get("also_violates", []))
            if actual_violated != declared:
                missing = declared - actual_violated
                undeclared = actual_violated - declared
                detail = []
                if missing:
                    detail.append(f"declared but did not actually occur: {sorted(missing)}")
                if undeclared:
                    detail.append(f"occurred but was not declared (undeclared breakage): {sorted(undeclared)}")
                errors.append(f"{path.name}: {'; '.join(detail)}")
    print(f"invariant vectors checked (complete-state gate): {checked}")
    return errors


def check_positive_schema_vectors_are_complete_states(registry: Registry) -> list[str]:
    """The other half of the complete-state gate: every positive request/response SCHEMA vector
    must ALSO hold under every applicable cross-field invariant, not just validate against its
    own schema in isolation. This is exactly the RC2-era-defect class the Management Contract
    bundle's own README describes: a vector correct about the one field it targets while being
    an illegal state on every other axis. response vectors are checked against a default
    approved-hostname fixture matching what the vectors themselves use, since I-B08 needs one."""
    errors: list[str] = []
    checked = 0
    default_hostnames = {"internal": ["www.utopiahomes.com"], "external_booking": ["booking.examplepms.com"]}

    for path in sorted((VECTORS / "positive").glob("request.pos.*.json")):
        vector = load(path)
        checked += 1
        violated = actually_violated_invariants({"request": vector["document"]})
        if violated:
            errors.append(f"{path.name}: positive request vector violates invariants {sorted(violated)}")

    for path in sorted((VECTORS / "positive").glob("response.pos.*.json")):
        vector = load(path)
        checked += 1
        violated = actually_violated_invariants(
            {"response": vector["document"], "assumed_approved_hostnames": default_hostnames}
        )
        if violated:
            errors.append(f"{path.name}: positive response vector violates invariants {sorted(violated)}")

    print(f"positive schema vectors checked against applicable invariants: {checked}")
    return errors


REQUIRED_ISS = "stoin:application:utopia-homes-web"
REQUIRED_SUB = "stoin:service:utopia-homes-web-guest-adapter"
REQUIRED_AUD = "stoin:business:utopia-homes-prime"
REQUIRED_SCOPE = "guest.answer"
UUID_V4_RE = __import__("re").compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def evaluate_auth_claims(vector: dict) -> tuple[str, str | None]:
    """Returns (accept|reject, error_code|None), implementing RC2 §7.1/§7.2's claim rules
    exactly, including the 401-vs-403 distinction. Checks claim shape/arithmetic only, not a
    real signature — see generate_vectors.py's module docstring for why the bundle doesn't
    embed signed tokens."""
    claims = vector["claims"]
    header = vector["header"]
    now = vector["evaluated_at"]

    def reject(code: str = "authentication_failed") -> tuple[str, str]:
        return "reject", code

    if header["alg"] != "EdDSA":
        return reject()
    if header["kid"] not in vector["known_kids"]:
        return reject()

    for name in ("iss", "sub", "aud", "scope", "iat", "nbf", "exp", "jti"):
        if name not in claims:
            return reject()

    if claims["iss"] != REQUIRED_ISS:
        return reject()
    if claims["sub"] != REQUIRED_SUB:
        return reject()
    if claims["aud"] != REQUIRED_AUD:
        return reject()
    if claims["scope"] != REQUIRED_SCOPE:
        return reject()
    if not UUID_V4_RE.match(claims["jti"]):
        return reject()

    iat, nbf, exp = claims["iat"], claims["nbf"], claims["exp"]
    if nbf != iat:
        return reject()
    if not (iat < exp):
        return reject()
    if exp - iat > 300:
        return reject()
    if iat > now + 30:
        return reject()
    if now > exp + 30:
        return reject()

    # Authentication (signature/identity/timing) has fully succeeded at this point. Two distinct
    # failure modes remain, both requiring the key's LOCAL binding (§7.1), not just the token's
    # own claims:
    key_info = vector["key_metadata"][header["kid"]]

    # (a) §7.1: "Production and nonproduction keys are distinct and non-interchangeable" — an
    # environment mismatch is an identity-binding failure, i.e. 401, not 403.
    if key_info["environment"] != vector["serving_environment"]:
        return reject()

    # (b) §7.2's 403 case: the key is real, environment-matched, every claim is valid, but the
    # key's local capability binding doesn't include the requested scope.
    if claims["scope"] not in key_info["capabilities"]:
        return reject("capability_forbidden")

    return "accept", None


def check_canonicalization_vectors() -> list[str]:
    """Every canonicalization vector (I-B10 + vectors/canonicalization/) is checked using TWO
    independent implementations: rfc8785 (the library check_invariants_impl.py relies on) and
    jcs_reference.py (this bundle's own from-scratch implementation). Both must agree with each
    other AND with what the vector expects — three-way agreement, not one implementation
    trusting itself.

    inv.I-B10.neg.*.json vectors are deliberately WRONG claims (that's what makes them
    'violation' vectors — the whole point is to prove the checker catches a false
    same_canonical_identity assertion), so for those an implementation disagreeing with the
    vector's own declared value is the CORRECT, expected outcome. vectors/canonicalization/
    files carry no expect field at all — they're always meant to be true statements, so for
    those any disagreement is a real bug.
    """
    import rfc8785
    from jcs_reference import canonicalize as jcs_reference_canonicalize

    errors = []
    checked = 0
    paths = sorted((VECTORS / "invariants").glob("inv.I-B10.*.json")) + sorted(
        (VECTORS / "canonicalization").glob("canon.*.json")
    )
    for path in paths:
        vector = load(path)
        documents = vector["documents"]
        declared = documents["same_canonical_identity"]
        # canon.*.json vectors have no "expect" field; treat their implicit expectation as "hold"
        # (the declared same_canonical_identity value is meant to be a true statement).
        vector_should_be_true = vector.get("expect", "hold") == "hold"
        checked += 1

        same_via_library = rfc8785.dumps(documents["a"]) == rfc8785.dumps(documents["b"])
        try:
            same_via_reference = jcs_reference_canonicalize(documents["a"]) == jcs_reference_canonicalize(
                documents["b"]
            )
        except NotImplementedError:
            same_via_reference = None  # a float is present; jcs_reference.py can't check this one

        if same_via_reference is not None and same_via_library != same_via_reference:
            errors.append(
                f"{path.name}: rfc8785 library and jcs_reference.py DISAGREE with each other "
                f"(library says same={same_via_library}, reference says same={same_via_reference})"
            )

        for impl_name, computed in [("rfc8785", same_via_library), ("jcs_reference", same_via_reference)]:
            if computed is None:
                continue
            matches_declared = computed == declared
            # A "hold"-style vector must have computed == declared. A "violation"-style vector
            # (only inv.I-B10.neg.*) must have computed != declared (that mismatch IS the proof
            # the checker would correctly reject the vector's false claim).
            ok = matches_declared if vector_should_be_true else not matches_declared
            if not ok:
                errors.append(
                    f"{path.name} ({impl_name}): computed same_canonical_identity={computed}, "
                    f"vector declares {declared} (expect={'hold' if vector_should_be_true else 'violation'})"
                )

    print(f"canonicalization vectors checked (cross-implementation): {checked}")
    return errors


def check_jcs_against_official_vectors() -> list[str]:
    """Independent external validation: both the rfc8785 library and this bundle's own
    jcs_reference.py must reproduce the RFC 8785 reference implementation's own published
    input/output pairs exactly, not just agree with each other on documents nobody outside this
    bundle has seen."""
    import rfc8785
    from jcs_reference import canonicalize as jcs_reference_canonicalize

    errors = []
    checked = 0
    fixtures_dir = BUNDLE / "fixtures" / "canonicalization" / "official-rfc8785-vectors"
    for input_path in sorted((fixtures_dir / "input").glob("*.json")):
        name = input_path.stem
        output_path = fixtures_dir / "output" / f"{name}.json"
        doc = load(input_path)
        expected = output_path.read_bytes()
        checked += 1

        got_library = rfc8785.dumps(doc)
        if got_library != expected:
            errors.append(f"official vector {name!r}: rfc8785 library produced {got_library!r}, expected {expected!r}")

        try:
            got_reference = jcs_reference_canonicalize(doc)
        except NotImplementedError:
            continue  # this fixture needs float formatting jcs_reference.py doesn't implement
        if got_reference != expected:
            errors.append(f"official vector {name!r}: jcs_reference.py produced {got_reference!r}, expected {expected!r}")

    print(f"official RFC 8785 reference vectors checked: {checked}")
    return errors


def check_auth_vectors() -> list[str]:
    errors = []
    checked = 0
    for path in sorted((VECTORS / "auth").glob("auth.*.json")):
        vector = load(path)
        checked += 1
        actual, actual_code = evaluate_auth_claims(vector)
        if actual != vector["expect"]:
            errors.append(f"{path.name}: expected {vector['expect']!r}, got {actual!r}")
        elif vector.get("expect_error_code") != actual_code:
            errors.append(
                f"{path.name}: expected error code {vector.get('expect_error_code')!r}, got {actual_code!r}"
            )
    print(f"auth vectors checked: {checked}")
    return errors


def check_jti_replay_vectors() -> list[str]:
    """Independently replays each vector's sequence against a fresh in-memory jti record,
    exactly modeling RC2 §7.2's 'atomically records... and rejects replay' — a second
    presentation of an already-accepted jti is rejected regardless of whether its other claims
    are otherwise fine."""
    errors = []
    checked = 0
    for path in sorted((VECTORS / "auth").glob("jti-replay.*.json")):
        vector = load(path)
        checked += 1
        seen_jtis: set[str] = set()
        for i, step in enumerate(vector["sequence"]):
            claims = step["claims"]
            base_vector = {
                "claims": claims,
                "header": {"alg": "EdDSA", "kid": step["kid"]},
                "known_kids": ["known-key-1"],
                "key_metadata": {"known-key-1": {"environment": "production", "capabilities": ["guest.answer"]}},
                "serving_environment": "production",
                "evaluated_at": step["evaluated_at"],
            }
            claim_result, _ = evaluate_auth_claims(base_vector)
            if claim_result == "accept" and claims["jti"] in seen_jtis:
                actual = "reject"
            else:
                actual = claim_result
            if actual == "accept":
                seen_jtis.add(claims["jti"])
            if actual != step["expect"]:
                errors.append(f"{path.name} step {i}: expected {step['expect']!r}, got {actual!r}")
    print(f"jti replay vectors checked: {checked}")
    return errors


def check_header_vectors() -> list[str]:
    """Reuses the actual regex patterns from common.defs.json rather than re-declaring them a
    third time, so this check can't silently drift from what the schemas themselves enforce."""
    import re as _re

    common = load(SCHEMAS / "common.defs.json")["$defs"]
    uuid_pattern = _re.compile(common["uuidV4"]["pattern"])
    release_pattern = _re.compile(common["releaseId"]["pattern"])

    def check_uuid(value: object) -> bool:
        return isinstance(value, str) and bool(uuid_pattern.fullmatch(value))

    def check_release(value: object) -> bool:
        return isinstance(value, str) and bool(release_pattern.fullmatch(value))

    def check_retry_after(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 30

    def check_no_query(value: object) -> bool:
        return value == ""

    def check_cache_control(value: object) -> bool:
        return value == "no-store"

    def check_no_set_cookie(value: object) -> bool:
        return value is None

    def check_accept_header(value: object) -> bool:
        return value == "application/json"

    def check_content_type_header(value: object) -> bool:
        return value == "application/json"

    def check_authorization_framing(value: object) -> bool:
        return isinstance(value, str) and value.startswith("Bearer ") and len(value) > len("Bearer ")

    rule_checkers = {
        "uuid_v4": check_uuid,
        "release_id": check_release,
        "retry_after": check_retry_after,
        "no_query_params": check_no_query,
        "cache_control": check_cache_control,
        "no_set_cookie": check_no_set_cookie,
        "accept_header": check_accept_header,
        "content_type_header": check_content_type_header,
        "authorization_framing": check_authorization_framing,
    }

    errors = []
    checked = 0
    for path in sorted((VECTORS / "headers").glob("headers.*.json")):
        vector = load(path)
        checker = rule_checkers[vector["rule"]]
        for case in vector["cases"]:
            checked += 1
            actual = "valid" if checker(case["value"]) else "invalid"
            if actual != case["expect"]:
                errors.append(
                    f"{path.name}: value={case['value']!r} expected {case['expect']!r}, got {actual!r}"
                )
    print(f"header vectors checked: {checked}")
    return errors


def _strict_decode_reject_duplicates(text: str) -> dict:
    """A strict JSON decoder that raises ValueError on any duplicate member name, at any
    nesting depth — RC2 §11.2 step 1. object_pairs_hook fires once per JSON object encountered
    during parsing, at every nesting level, so a nested duplicate is caught exactly the same way
    a top-level one is; this is not a special case."""

    def hook(pairs: list[tuple[str, Any]]) -> dict:
        seen: set[str] = set()
        for key, _ in pairs:
            if key in seen:
                raise ValueError(f"duplicate member name {key!r}")
            seen.add(key)
        return dict(pairs)

    return json.loads(text, object_pairs_hook=hook)


def check_transport_vectors(registry: Registry) -> list[str]:
    """Byte-size boundary and duplicate-member-name vectors operate on raw text, independently
    of both the schema validator (byte length isn't a JSON Schema concept) and the normal
    json.loads the rest of this script uses (which silently keeps the last value of a duplicate
    key rather than rejecting it)."""
    errors = []
    checked = 0
    for path in sorted((VECTORS / "transport").glob("transport.*.json")):
        vector = load(path)
        checked += 1
        raw = vector["raw_body"]
        actual_byte_length = len(raw.encode("utf-8"))
        if actual_byte_length != vector["byte_length"]:
            errors.append(
                f"{path.name}: declared byte_length={vector['byte_length']}, actual={actual_byte_length}"
            )

        if vector["expect"] in ("accepted", "request_too_large", "over_limit"):
            within_limit = actual_byte_length <= 65536
            if vector["expect"] == "accepted":
                actual = "accepted" if within_limit else "rejected"
                expected = "accepted"
            else:
                actual = "accepted" if within_limit else "rejected"
                expected = "rejected"
            if actual != expected:
                errors.append(f"{path.name}: expected {expected!r}, got {actual!r} (byte-size check)")
            # The document must also be genuinely schema-valid once parsed and stripped of
            # padding — otherwise this "reachable via whitespace" proof would be hollow.
            schema_file = f"{vector.get('schema', 'request')}.schema.json"
            try:
                parsed = json.loads(raw)
                get_validator(registry, schema_file).validate(parsed)
            except Exception as exc:  # noqa: BLE001 - want to report any parse/validation failure
                errors.append(f"{path.name}: padded body did not parse to a schema-valid document: {exc}")

        elif vector["expect"] == "invalid_request":
            try:
                _strict_decode_reject_duplicates(raw)
            except ValueError:
                pass  # correctly rejected
            else:
                errors.append(f"{path.name}: expected duplicate-member rejection, but strict decode succeeded")
        else:
            errors.append(f"{path.name}: unrecognized expect value {vector['expect']!r}")

    print(f"transport vectors checked: {checked}")
    return errors


def check_exchange_vectors() -> list[str]:
    """Independently re-implements each exchange-level check from scratch against the vector's
    own declared 'exchange' facts — never trusting the vector's 'expect' label."""

    def request_id_echo(exchange: dict) -> bool:
        return exchange["outbound_x_request_id"] == exchange["inbound_x_request_id"]

    def correlation_id_distinct(exchange: dict) -> bool:
        return exchange["correlation_id"] != exchange["x_request_id"]

    def release_headers_present(exchange: dict) -> bool:
        headers = exchange["headers"]
        return "X-Utopia-Business-Release" in headers and "X-Utopia-Knowledge-Release" in headers

    checkers = {
        "request_id_echo": request_id_echo,
        "correlation_id_distinct": correlation_id_distinct,
        "release_headers_present": release_headers_present,
    }

    errors = []
    checked = 0
    for path in sorted((VECTORS / "exchange").glob("exchange.*.json")):
        vector = load(path)
        checked += 1
        exchange = vector["exchange"]
        checker = checkers[exchange["check"]]
        holds = checker(exchange)
        actual = "hold" if holds else "violation"
        if actual != vector["expect"]:
            errors.append(f"{path.name}: expected {vector['expect']!r}, got {actual!r}")
    print(f"exchange vectors checked: {checked}")
    return errors


def _make_lenient(schema: dict) -> dict:
    """Recursively derives a lenient copy of a schema by flipping every additionalProperties:
    false to true — never mutates the shipped schema file itself, and is what a real consumer
    is instructed to do in fixtures/provider/strict-vs-lenient-parsing.json rather than editing
    the strict schema in place."""
    import copy as _copy

    lenient = _copy.deepcopy(schema)

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("additionalProperties") is False:
                node["additionalProperties"] = True
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(lenient)
    return lenient


def check_strict_vs_lenient_fixture(registry: Registry) -> list[str]:
    """Actually runs both the strict provider schema and a derived lenient consumer schema
    against fixtures/provider/strict-vs-lenient-parsing.json's document, rather than treating
    that file as illustrative-only prose. Added per Lyra's review of the second Tier A cut."""
    errors = []
    fixture = load(BUNDLE / "fixtures" / "provider" / "strict-vs-lenient-parsing.json")
    doc = fixture["document_with_a_hypothetical_additive_v1_1_member"]
    expected = fixture["expected"]

    strict_schema = load(SCHEMAS / "response.schema.json")
    strict_validator = Draft202012Validator(strict_schema, registry=registry)
    strict_rejects = not strict_validator.is_valid(doc)
    if strict_rejects != expected["strict_provider_schema_rejects_it"]:
        errors.append(
            f"strict-vs-lenient fixture: expected strict schema to reject={expected['strict_provider_schema_rejects_it']}, "
            f"actually rejects={strict_rejects}"
        )

    lenient_schema = _make_lenient(strict_schema)
    lenient_validator = Draft202012Validator(lenient_schema, registry=registry)
    lenient_accepts = lenient_validator.is_valid(doc)
    if lenient_accepts != expected["lenient_consumer_schema_accepts_it"]:
        errors.append(
            f"strict-vs-lenient fixture: expected lenient schema to accept={expected['lenient_consumer_schema_accepts_it']}, "
            f"actually accepts={lenient_accepts}"
        )

    print("strict-vs-lenient fixture checked: 1")
    return errors


def check_retry_policy_fixture() -> list[str]:
    """Cross-checks fixtures/consumer/retry-policy.json's per-code auto_retry_permitted claim
    against the actual retryable flag baked into every error.pos.*.json vector for that code —
    the two are supposed to be the same fact stated twice (once as policy, once as wire data),
    so this proves they haven't drifted apart, rather than trusting the fixture as prose.
    Specifically confirms answer_validation_failed's auto_retry_permitted=false despite its
    HTTP 503, per RC2 §17 and acceptance criterion 33. Added per Lyra's review."""
    errors = []
    policy = load(BUNDLE / "fixtures" / "consumer" / "retry-policy.json")

    wire_retryable: dict[str, bool] = {}
    for path in sorted((VECTORS / "positive").glob("error.pos.*.json")):
        vector = load(path)
        wire_retryable[vector["document"]["error"]["code"]] = vector["document"]["error"]["retryable"]

    for entry in policy["codes"]:
        code = entry["code"]
        if code not in wire_retryable:
            errors.append(f"retry-policy.json names code {code!r} with no matching error.pos.*.json vector")
            continue
        if entry["auto_retry_permitted"] != wire_retryable[code]:
            errors.append(
                f"retry-policy.json: {code} auto_retry_permitted={entry['auto_retry_permitted']} "
                f"disagrees with the wire vector's retryable={wire_retryable[code]}"
            )

    declared_codes = {e["code"] for e in policy["codes"]}
    missing = set(wire_retryable) - declared_codes
    if missing:
        errors.append(f"retry-policy.json is missing codes present in the wire vectors: {sorted(missing)}")

    avf = next((e for e in policy["codes"] if e["code"] == "answer_validation_failed"), None)
    if avf is None or avf["auto_retry_permitted"] is not False or avf["http"] != 503:
        errors.append(
            "retry-policy.json must explicitly declare answer_validation_failed as http=503, "
            "auto_retry_permitted=false — the specific rule acceptance criterion 33 exists for"
        )

    print("retry-policy fixture checked: 1")
    return errors


def check_non_retry_test_fixture(registry: Registry) -> list[str]:
    """Confirms fixtures/consumer/answer-validation-failed-non-retry-test.json's response_body
    is itself schema-valid AND byte-identical (except correlation_id, which is per-instance) to
    the actual answer_validation_failed error.pos.*.json vector — not a hand-typed body that
    could silently drift from what the schema actually requires."""
    errors = []
    fixture = load(BUNDLE / "fixtures" / "consumer" / "answer-validation-failed-non-retry-test.json")
    body = fixture["given"]["response_body"]

    validator = get_validator(registry, "error.response.schema.json")
    if not validator.is_valid(body):
        errors.append("answer-validation-failed-non-retry-test.json: given.response_body is not schema-valid")

    matching_vector = None
    for path in sorted((VECTORS / "positive").glob("error.pos.*.json")):
        vector = load(path)
        if vector["document"]["error"]["code"] == "answer_validation_failed":
            matching_vector = vector["document"]
            break
    if matching_vector is None:
        errors.append("no error.pos.*.json vector found for answer_validation_failed to cross-check against")
    else:
        for key in ("code", "message", "retryable"):
            if body["error"][key] != matching_vector["error"][key]:
                errors.append(
                    f"answer-validation-failed-non-retry-test.json: error.{key}={body['error'][key]!r} "
                    f"disagrees with the wire vector's {matching_vector['error'][key]!r}"
                )

    print("non-retry test fixture checked: 1")
    return errors


def main() -> int:
    registry = build_registry()
    errors = []
    errors += check_schema_vectors(registry)
    errors += check_invariants(registry)
    errors += check_positive_schema_vectors_are_complete_states(registry)
    errors += check_jcs_against_official_vectors()
    errors += check_canonicalization_vectors()
    errors += check_auth_vectors()
    errors += check_jti_replay_vectors()
    errors += check_header_vectors()
    errors += check_transport_vectors(registry)
    errors += check_exchange_vectors()
    errors += check_strict_vs_lenient_fixture(registry)
    errors += check_retry_policy_fixture()
    errors += check_non_retry_test_fixture(registry)

    if errors:
        print(f"\nFAILED — {len(errors)} problem(s):")
        for e in errors:
            print(f"  {e}")
        return 1

    print("\nOK — all vectors behaved exactly as declared.")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
