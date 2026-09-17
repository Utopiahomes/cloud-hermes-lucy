#!/usr/bin/env python3
# ruff: noqa: E501, E701, E702
"""Generate the deterministic RC1 wire bundle from contract constants.

This generator is intentionally not imported by verify_bundle.py.  Generation makes fixtures;
the verifier separately evaluates the resulting schemas, vectors, invariants, and coverage map.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
VECTORS = ROOT / "vectors"
SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
UUID4 = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
STABLE_ID = "^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$"

ERRORS: dict[str, tuple[int, str, bool]] = {
    "invalid_request": (400, "The execution request is invalid.", False),
    "authentication_failed": (401, "Service authentication failed.", False),
    "capability_forbidden": (403, "This execution capability is not permitted.", False),
    "route_not_found": (404, "The requested execution route was not found.", False),
    "method_not_allowed": (405, "The execution method is not allowed.", False),
    "response_media_not_acceptable": (406, "The requested response media type is not supported.", False),
    "execution_aborted": (409, "The execution ended before model dispatch.", False),
    "idempotency_conflict": (409, "The idempotency key conflicts with an earlier request.", False),
    "request_in_progress": (409, "The execution request is already in progress.", True),
    "idempotency_recovery_unavailable": (409, "The earlier execution result is no longer available.", False),
    "execution_outcome_unknown": (409, "The execution outcome could not be determined.", False),
    "execution_invalidated": (409, "The earlier execution result is no longer eligible.", False),
    "request_too_large": (413, "The execution request is too large.", False),
    "unsupported_media_type": (415, "The execution request media type is not supported.", False),
    "output_contract_unsupported": (422, "The requested output contract is not supported.", False),
    "cost_ceiling_insufficient": (422, "The execution cost ceiling is insufficient.", False),
    "rate_limited": (429, "Execution capacity is temporarily limited.", True),
    "provider_response_invalid": (502, "The model returned an unusable result.", False),
    "provider_response_too_large": (502, "The model response is too large.", False),
    "output_limit_reached": (502, "The model reached its output limit.", False),
    "content_filtered": (502, "The model response was filtered.", False),
    "provider_execution_failed": (502, "The model execution failed.", False),
    "cost_settlement_violation": (502, "The provider charge exceeded its reservation.", False),
    "privacy_route_unavailable": (503, "No approved private execution route is available.", False),
    "authentication_state_unavailable": (503, "Service authentication state is temporarily unavailable.", True),
    "state_store_unavailable": (503, "Execution state is temporarily unavailable.", True),
    "spending_authority_exhausted": (503, "Execution spending authority is unavailable.", False),
    "temporarily_unavailable": (503, "Model execution is temporarily unavailable.", True),
    "deadline_exceeded": (504, "Model execution exceeded its deadline.", False),
}


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def common_schema() -> dict[str, Any]:
    return {
        "$schema": SCHEMA_DIALECT,
        "$id": "https://contracts.stoin.local/shared-execution/v1/common.defs.json",
        "$defs": {
            "uuid4": {"type": "string", "pattern": UUID4},
            "stableId": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": STABLE_ID},
            "releaseId": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[\\x20-\\x7E]+$"},
            "nonnegative": {"type": "integer", "minimum": 0},
            "cost": {
                "type": "object",
                "additionalProperties": False,
                "required": ["reserved_microusd", "settled_microusd", "settlement_status"],
                "properties": {
                    "reserved_microusd": {"type": "integer", "minimum": 1, "maximum": 1000000},
                    "settled_microusd": {"type": ["integer", "null"], "minimum": 0},
                    "settlement_status": {"enum": ["settled", "pending_reconciliation", "reservation_forfeited", "settlement_overrun"]},
                },
            },
        },
    }


def request_schema() -> dict[str, Any]:
    message = {
        "type": "object", "additionalProperties": False, "required": ["role", "content"],
        "properties": {"role": {"enum": ["system", "user", "assistant"]}, "content": {"type": "string", "minLength": 1, "maxLength": 65536}},
    }
    output = {
        "oneOf": [
            {"type": "object", "additionalProperties": False, "required": ["mode"], "properties": {"mode": {"const": "text"}}},
            {"type": "object", "additionalProperties": False, "required": ["mode", "name", "schema"], "properties": {"mode": {"const": "json_schema"}, "name": {"$ref": "common.defs.json#/$defs/stableId"}, "schema": {"type": "object"}}},
        ]
    }
    return {
        "$schema": SCHEMA_DIALECT, "$id": "https://contracts.stoin.local/shared-execution/v1/request.schema.json",
        "type": "object", "additionalProperties": False,
        "required": ["contract", "execution_profile_id", "messages", "output", "limits"],
        "properties": {
            "contract": {"const": "stoin.inference.execute.request.v1"},
            "execution_profile_id": {"$ref": "common.defs.json#/$defs/stableId"},
            "messages": {"type": "array", "minItems": 2, "maxItems": 32, "items": message},
            "output": output,
            "limits": {"type": "object", "additionalProperties": False, "required": ["max_output_tokens", "max_cost_microusd"], "properties": {"max_output_tokens": {"type": "integer", "minimum": 1, "maximum": 4096}, "max_cost_microusd": {"type": "integer", "minimum": 1, "maximum": 1000000}}},
        },
    }


def response_schema() -> dict[str, Any]:
    output = {"oneOf": [
        {"type": "object", "additionalProperties": False, "required": ["mode", "content"], "properties": {"mode": {"const": "text"}, "content": {"type": "string", "maxLength": 65536}}},
        {"type": "object", "additionalProperties": False, "required": ["mode", "content"], "properties": {"mode": {"const": "json_schema"}, "content": {"type": "object"}}},
    ]}
    return {
        "$schema": SCHEMA_DIALECT, "$id": "https://contracts.stoin.local/shared-execution/v1/response.schema.json",
        "type": "object", "additionalProperties": False,
        "required": ["contract", "request_id", "execution_id", "replayed", "execution_profile_id", "profile_release_id", "output", "finish_reason", "usage", "cost"],
        "properties": {
            "contract": {"const": "stoin.inference.execute.response.v1"}, "request_id": {"$ref": "common.defs.json#/$defs/uuid4"}, "execution_id": {"$ref": "common.defs.json#/$defs/uuid4"}, "replayed": {"type": "boolean"}, "execution_profile_id": {"$ref": "common.defs.json#/$defs/stableId"}, "profile_release_id": {"$ref": "common.defs.json#/$defs/releaseId"}, "output": output, "finish_reason": {"const": "stop"},
            "usage": {"type": "object", "additionalProperties": False, "required": ["input_tokens", "generated_tokens", "output_tokens", "reasoning_tokens"], "properties": {"input_tokens": {"$ref": "common.defs.json#/$defs/nonnegative"}, "generated_tokens": {"$ref": "common.defs.json#/$defs/nonnegative"}, "output_tokens": {"type": ["integer", "null"], "minimum": 0}, "reasoning_tokens": {"type": ["integer", "null"], "minimum": 0}}},
            "cost": {"$ref": "common.defs.json#/$defs/cost"},
        },
    }


def error_schema() -> dict[str, Any]:
    codes = list(ERRORS)
    details = []
    for code, (_, message, retryable) in ERRORS.items():
        details.append({"if": {"properties": {"code": {"const": code}}, "required": ["code"]}, "then": {"properties": {"message": {"const": message}, "retryable": {"const": retryable}}}})
    return {
        "$schema": SCHEMA_DIALECT, "$id": "https://contracts.stoin.local/shared-execution/v1/error.schema.json",
        "type": "object", "additionalProperties": False, "required": ["contract", "correlation_id", "error"],
        "properties": {
            "contract": {"const": "stoin.inference.execute.error.v1"}, "correlation_id": {"$ref": "common.defs.json#/$defs/uuid4"}, "request_id": {"$ref": "common.defs.json#/$defs/uuid4"},
            "execution": {"type": "object", "additionalProperties": False, "required": ["execution_id", "state"], "properties": {"execution_id": {"$ref": "common.defs.json#/$defs/uuid4"}, "state": {"enum": ["admitted", "dispatched", "completed", "failed", "outcome_unknown"]}}},
            "cost": {"$ref": "common.defs.json#/$defs/cost"},
            "error": {"type": "object", "additionalProperties": False, "required": ["code", "message", "retryable"], "properties": {"code": {"enum": codes}, "message": {"type": "string"}, "retryable": {"type": "boolean"}}, "allOf": details},
        },
    }


def request(mode: str = "text") -> dict[str, Any]:
    output: dict[str, Any] = {"mode": "text"}
    if mode == "json_schema":
        output = {"mode": "json_schema", "name": "guest-answer-candidate", "schema": {"type": "object", "properties": {"answer": {"type": "string", "minLength": 1, "maxLength": 4000}}, "required": ["answer"], "additionalProperties": False}}
    return {"contract": "stoin.inference.execute.request.v1", "execution_profile_id": "utopia-homes.public-answer.generate.v1", "messages": [{"role": "system", "content": "Use approved Utopia context only."}, {"role": "user", "content": "Tell me about Buttercup."}], "output": output, "limits": {"max_output_tokens": 900, "max_cost_microusd": 2000}}


def response(mode: str = "text") -> dict[str, Any]:
    content: Any = "Buttercup is a Utopia home."
    if mode == "json_schema": content = {"answer": "Buttercup is a Utopia home."}
    return {"contract": "stoin.inference.execute.response.v1", "request_id": "7c606a49-357b-4d76-8678-b0f754c65016", "execution_id": "59eeddf3-35a1-4d22-a51e-08acf5d5f34d", "replayed": False, "execution_profile_id": "utopia-homes.public-answer.generate.v1", "profile_release_id": "profiles-2026-09-16.1", "output": {"mode": mode, "content": content}, "finish_reason": "stop", "usage": {"input_tokens": 120, "generated_tokens": 12, "output_tokens": 12, "reasoning_tokens": 0}, "cost": {"reserved_microusd": 2000, "settled_microusd": 42, "settlement_status": "settled"}}


def error(code: str) -> dict[str, Any]:
    _, message, retryable = ERRORS[code]
    return {"contract": "stoin.inference.execute.error.v1", "correlation_id": "34a5eef4-b1f4-4aaa-b05d-19c3b31cb293", "request_id": "7c606a49-357b-4d76-8678-b0f754c65016", "error": {"code": code, "message": message, "retryable": retryable}}


def vector(vector_id: str, schema: str, valid: bool, document: dict[str, Any], rule: str) -> dict[str, Any]:
    return {"id": vector_id, "schema": schema, "valid": valid, "rule": rule, "document": document}


def build() -> None:
    for folder in (SCHEMAS, VECTORS / "positive", VECTORS / "negative", VECTORS / "invariants", VECTORS / "headers", VECTORS / "auth", VECTORS / "state"):
        folder.mkdir(parents=True, exist_ok=True)
    write(SCHEMAS / "common.defs.json", common_schema())
    write(SCHEMAS / "request.schema.json", request_schema())
    write(SCHEMAS / "response.schema.json", response_schema())
    write(SCHEMAS / "error.schema.json", error_schema())

    positives = [
        vector("request.pos.text", "request.schema.json", True, request("text"), "§9 text request"),
        vector("request.pos.json", "request.schema.json", True, request("json_schema"), "§9 JSON Schema request"),
        vector("response.pos.text", "response.schema.json", True, response("text"), "§10 text response"),
        vector("response.pos.json", "response.schema.json", True, response("json_schema"), "§10 JSON response"),
    ]
    for code in ERRORS:
        positives.append(vector(f"error.pos.{code}", "error.schema.json", True, error(code), "§16 exact error tuple"))
    for item in positives: write(VECTORS / "positive" / f"{item['id']}.json", item)

    negatives: list[dict[str, Any]] = []
    mutations = [
        ("request.unknown", "request.schema.json", request(), lambda d: d.update(extra=True), "§9 rejects unknown members"),
        ("request.bad-contract", "request.schema.json", request(), lambda d: d.update(contract="v2"), "§9 exact contract"),
        ("request.messages-short", "request.schema.json", request(), lambda d: d.update(messages=d["messages"][:1]), "§9.1 2–32 messages"),
        ("request.output-limit", "request.schema.json", request(), lambda d: d["limits"].update(max_output_tokens=4097), "§9.5 output bound"),
        ("request.cost-limit", "request.schema.json", request(), lambda d: d["limits"].update(max_cost_microusd=1000001), "§9.5 cost bound"),
        ("request.output-extra", "request.schema.json", request(), lambda d: d["output"].update(seed=1), "§9.4 no provider parameters"),
        ("response.unknown", "response.schema.json", response(), lambda d: d.update(model="secret"), "§10 provider-neutral strict output"),
        ("response.bad-finish", "response.schema.json", response(), lambda d: d.update(finish_reason="length"), "§10 success is stop only"),
        ("response.bad-uuid", "response.schema.json", response(), lambda d: d.update(execution_id="not-a-uuid"), "§10 UUID v4"),
        ("response.mode-shape", "response.schema.json", response(), lambda d: d["output"].update(mode="json_schema"), "§10 output mode/content shape"),
    ]
    for vid, schema, base, mutate, rule in mutations:
        doc = copy.deepcopy(base); mutate(doc); negatives.append(vector(vid, schema, False, doc, rule))
    for code, (_, message, retryable) in ERRORS.items():
        wrong = error(code); wrong["error"]["message"] = message + "!"
        negatives.append(vector(f"error.neg.message.{code}", "error.schema.json", False, wrong, "§16 exact message"))
        wrong_retry = error(code); wrong_retry["error"]["retryable"] = not retryable
        negatives.append(vector(f"error.neg.retry.{code}", "error.schema.json", False, wrong_retry, "§16 exact retryability"))
    for item in negatives: write(VECTORS / "negative" / f"{item['id']}.json", item)

    invariants = [
        {"id": "I-01", "rule": "messages", "section": "§9.2", "description": "one first system message; alternating user/assistant thereafter; final role user"},
        {"id": "I-02", "rule": "usage", "section": "§9.5", "description": "breakdown is paired and, when present, sums to generated_tokens"},
        {"id": "I-03", "rule": "cost", "section": "§13", "description": "settlement status and settled amount agree with reservation semantics"},
        {"id": "I-04", "rule": "error_receipts", "section": "§16", "description": "state-store and conflict errors omit receipts; paid post-dispatch errors include authoritative receipts"},
        {"id": "I-05", "rule": "restricted_schema", "section": "§9.3.2", "description": "restricted JSON Schema subset, depth, properties, enum, required, and numeric rules"},
        {"id": "I-06", "rule": "headers", "section": "§6", "description": "required request/response headers and disclosure rules"},
        {"id": "I-07", "rule": "jwt", "section": "§7", "description": "EdDSA claims, time bounds, request binding, and replay namespace"},
        {"id": "I-08", "rule": "idempotency", "section": "§11", "description": "canonical identity, stable execution id, single dispatch, replay and conflict"},
        {"id": "I-09", "rule": "exposure", "section": "§13", "description": "unique obligations and active/pending exposure bounds"},
        {"id": "I-10", "rule": "grant", "section": "§13.1", "description": "period applicability, successor selection, revocation, and no replenishment"},
    ]
    write(VECTORS / "invariants" / "invariants.json", {"invariants": invariants})
    inv_vectors = [
        {"id": "inv.messages.pos", "rule": "I-01", "holds": True, "document": request()},
        {"id": "inv.messages.neg.adjacent", "rule": "I-01", "holds": False, "document": {**request(), "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}, {"role": "user", "content": "u2"}]}},
        {"id": "inv.messages.neg.final", "rule": "I-01", "holds": False, "document": {**request(), "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}, {"role": "assistant", "content": "a"}]}},
        {"id": "inv.usage.pos", "rule": "I-02", "holds": True, "document": response()},
        {"id": "inv.usage.pos.combined", "rule": "I-02", "holds": True, "document": {**response(), "usage": {"input_tokens": 1, "generated_tokens": 4, "output_tokens": None, "reasoning_tokens": None}}},
        {"id": "inv.usage.neg.partial-null", "rule": "I-02", "holds": False, "document": {**response(), "usage": {"input_tokens": 1, "generated_tokens": 4, "output_tokens": 4, "reasoning_tokens": None}}},
        {"id": "inv.usage.neg.sum", "rule": "I-02", "holds": False, "document": {**response(), "usage": {"input_tokens": 1, "generated_tokens": 4, "output_tokens": 3, "reasoning_tokens": 2}}},
        {"id": "inv.cost.pos.settled", "rule": "I-03", "holds": True, "document": response()},
        {"id": "inv.cost.neg.over", "rule": "I-03", "holds": False, "document": {**response(), "cost": {"reserved_microusd": 10, "settled_microusd": 11, "settlement_status": "settled"}}},
        {"id": "inv.cost.pos.pending", "rule": "I-03", "holds": True, "document": {**response(), "cost": {"reserved_microusd": 10, "settled_microusd": None, "settlement_status": "pending_reconciliation"}}},
    ]
    for item in inv_vectors: write(VECTORS / "invariants" / f"{item['id']}.json", item)

    headers = [
        {"id": "headers.pos.request", "valid": True, "kind": "request", "headers": {"Authorization": "Bearer opaque", "X-Request-ID": "7c606a49-357b-4d76-8678-b0f754c65016", "Idempotency-Key": "75f612d7-55ef-4e36-8fe3-c3ce550553b9", "X-Execution-Timeout-Ms": "15000", "X-Content-SHA256": "A" * 43, "Content-Type": "application/json", "Accept": "application/json"}},
        {"id": "headers.neg.timeout", "valid": False, "kind": "request", "headers": {"Authorization": "Bearer opaque", "X-Request-ID": "7c606a49-357b-4d76-8678-b0f754c65016", "Idempotency-Key": "75f612d7-55ef-4e36-8fe3-c3ce550553b9", "X-Execution-Timeout-Ms": "18001", "X-Content-SHA256": "A" * 43, "Content-Type": "application/json", "Accept": "application/json"}},
        {"id": "headers.pos.success", "valid": True, "kind": "authenticated_response", "headers": {"Content-Type": "application/json", "Cache-Control": "no-store", "X-Request-ID": "7c606a49-357b-4d76-8678-b0f754c65016", "X-Stoin-Execution-Release": "tiamat-local.1", "X-Stoin-Execution-Policy-Release": "profiles-local.1"}},
        {"id": "headers.neg.cookie", "valid": False, "kind": "authenticated_response", "headers": {"Content-Type": "application/json", "Cache-Control": "no-store", "X-Request-ID": "7c606a49-357b-4d76-8678-b0f754c65016", "X-Stoin-Execution-Release": "tiamat-local.1", "X-Stoin-Execution-Policy-Release": "profiles-local.1", "Set-Cookie": "x=y"}},
    ]
    for item in headers: write(VECTORS / "headers" / f"{item['id']}.json", item)

    auth = [
        {"id": "auth.pos.claims", "valid": True, "claims": {"iss": "https://homes.internal", "sub": "stoin:synth:utopia-homes-prime", "aud": "stoin:shared-model-execution", "scope": "inference.execute", "iat": 1000, "nbf": 1000, "exp": 1300, "jti": "75f612d7-55ef-4e36-8fe3-c3ce550553b9", "req": "A" * 43}, "now": 1010},
        {"id": "auth.neg.long-life", "valid": False, "claims": {"iss": "https://homes.internal", "sub": "stoin:synth:utopia-homes-prime", "aud": "stoin:shared-model-execution", "scope": "inference.execute", "iat": 1000, "nbf": 1000, "exp": 1301, "jti": "75f612d7-55ef-4e36-8fe3-c3ce550553b9", "req": "A" * 43}, "now": 1010},
        {"id": "auth.neg.scope", "valid": False, "claims": {"iss": "https://homes.internal", "sub": "stoin:synth:utopia-homes-prime", "aud": "stoin:shared-model-execution", "scope": "admin", "iat": 1000, "nbf": 1000, "exp": 1300, "jti": "75f612d7-55ef-4e36-8fe3-c3ce550553b9", "req": "A" * 43}, "now": 1010},
    ]
    for item in auth: write(VECTORS / "auth" / f"{item['id']}.json", item)

    states = [
        {"id": "state.pos.single-dispatch", "valid": True, "events": ["create_reserved", "lease_acquired", "dispatched_commit", "provider_send", "completed_commit"]},
        {"id": "state.neg.send-before-commit", "valid": False, "events": ["create_reserved", "lease_acquired", "provider_send", "dispatched_commit"]},
        {"id": "state.pos.timeout-pending-slot", "valid": True, "events": ["create_reserved", "dispatched_commit", "provider_send", "deadline", "outcome_unknown", "pending_reconciliation_slot_retained"]},
        {"id": "state.neg.timeout-frees-slot", "valid": False, "events": ["create_reserved", "dispatched_commit", "provider_send", "deadline", "outcome_unknown", "exposure_slot_released"]},
    ]
    for item in states: write(VECTORS / "state" / f"{item['id']}.json", item)

    coverage = {
        "contract": "Stoin Shared Model Execution Contract v1.0 RC1",
        "scope": "Tier A deterministic wire and state-model artifact",
        "acceptance_criteria": {str(i): {"status": "covered" if i in {1,2,3,4,5,6,7,8,9,10,11,12,15,16,17,18,19,20,21,22,25,27,28,29,30,31,32,35,36,39,40,41,42,45,46,47,48,49,50,51,55,56,57,58,62,63,64,65,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85} else "executor-proof-required"} for i in range(1, 86)},
        "notes": "Covered means represented by a schema, deterministic vector, or invariant. Executor-proof-required means the behavior needs a running stateful implementation, failure injection, timing observation, or external provider evidence; the bundle does not claim that proof.",
    }
    write(ROOT / "COVERAGE.json", coverage)


if __name__ == "__main__":
    build()
