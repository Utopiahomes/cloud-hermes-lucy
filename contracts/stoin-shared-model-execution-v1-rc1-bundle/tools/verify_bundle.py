#!/usr/bin/env python3
# ruff: noqa: E501, E701, E702, SIM103
"""Independent verifier for the RC1 bundle; imports no generator code."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parent.parent
UUID4 = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
ERROR_COUNT = 29
checks = 0
failures: list[str] = []

def load(path: Path) -> Any: return json.loads(path.read_text(encoding="utf-8"))
def check(condition: bool, label: str) -> None:
    global checks
    checks += 1
    if not condition: failures.append(label)

def messages_hold(doc: dict[str, Any]) -> bool:
    roles = [item["role"] for item in doc["messages"]]
    return roles[0] == "system" and roles[-1] == "user" and roles[1:] == ["user" if i % 2 == 0 else "assistant" for i in range(len(roles) - 1)] and roles.count("system") == 1

def usage_holds(doc: dict[str, Any]) -> bool:
    usage = doc["usage"]; output = usage["output_tokens"]; reasoning = usage["reasoning_tokens"]
    if (output is None) != (reasoning is None): return False
    return output is None or output + reasoning == usage["generated_tokens"]

def cost_holds(doc: dict[str, Any]) -> bool:
    cost = doc["cost"]; status = cost["settlement_status"]; settled = cost["settled_microusd"]; reserved = cost["reserved_microusd"]
    if status == "settled": return settled is not None and settled <= reserved
    if status == "settlement_overrun": return settled is not None and settled > reserved
    return settled is None

def restricted_schema_holds(schema: Any, depth: int = 1, tally: list[int] | None = None) -> bool:
    if not isinstance(schema, dict) or depth > 8: return False
    if tally is None: tally = [0]
    allowed = {"type", "properties", "required", "additionalProperties", "items", "enum", "const", "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems"}
    if not set(schema) <= allowed: return False
    kind = schema.get("type")
    if kind == "object":
        props = schema.get("properties"); required = schema.get("required")
        if not isinstance(props, dict) or schema.get("additionalProperties") is not False or not isinstance(required, list) or set(required) != set(props) or len(required) != len(set(required)): return False
        tally[0] += len(props)
        if tally[0] > 128: return False
        return all(restricted_schema_holds(child, depth + 1, tally) for child in props.values())
    if kind == "array": return "items" in schema and restricted_schema_holds(schema["items"], depth + 1, tally)
    if isinstance(schema.get("enum"), list) and len(schema["enum"]) > 64: return False
    return kind in {"string", "integer", "number", "boolean", "null"} or (isinstance(kind, list) and len(kind) == 2 and "null" in kind)

def invariant(rule: str, doc: dict[str, Any]) -> bool:
    if rule == "I-01": return messages_hold(doc)
    if rule == "I-02": return usage_holds(doc)
    if rule == "I-03": return cost_holds(doc)
    raise ValueError(f"no executable fixture verifier for {rule}")

def headers_hold(kind: str, headers: dict[str, str]) -> bool:
    lower = {key.lower(): value for key, value in headers.items()}
    if "set-cookie" in lower: return False
    if kind == "request":
        required = {"authorization", "x-request-id", "idempotency-key", "x-execution-timeout-ms", "x-content-sha256", "content-type", "accept"}
        if not required <= set(lower): return False
        try: timeout = int(lower["x-execution-timeout-ms"])
        except ValueError: return False
        return bool(UUID4.fullmatch(lower["x-request-id"])) and bool(UUID4.fullmatch(lower["idempotency-key"])) and 1000 <= timeout <= 18000 and bool(re.fullmatch(r"[A-Za-z0-9_-]{43}", lower["x-content-sha256"])) and lower["content-type"] == "application/json" and lower["accept"] == "application/json"
    required = {"content-type", "cache-control", "x-request-id", "x-stoin-execution-release", "x-stoin-execution-policy-release"}
    return required <= set(lower) and lower["content-type"] == "application/json" and lower["cache-control"] == "no-store" and bool(UUID4.fullmatch(lower["x-request-id"]))

def auth_holds(item: dict[str, Any]) -> bool:
    claims = item["claims"]; required = {"iss", "sub", "aud", "scope", "iat", "nbf", "exp", "jti", "req"}
    return set(claims) == required and claims["sub"] == "stoin:synth:utopia-homes-prime" and claims["aud"] == "stoin:shared-model-execution" and claims["scope"] == "inference.execute" and isinstance(claims["iat"], int) and isinstance(claims["nbf"], int) and isinstance(claims["exp"], int) and claims["nbf"] <= claims["exp"] and claims["exp"] - claims["iat"] <= 300 and claims["iat"] <= item["now"] + 30 and bool(UUID4.fullmatch(claims["jti"])) and bool(re.fullmatch(r"[A-Za-z0-9_-]{43}", claims["req"]))

def state_holds(events: list[str]) -> bool:
    if "provider_send" in events and ("dispatched_commit" not in events or events.index("dispatched_commit") > events.index("provider_send")): return False
    if "outcome_unknown" in events and "exposure_slot_released" in events: return False
    return True

schema_paths = sorted((ROOT / "schemas").glob("*.json"))
resources = []
schemas: dict[str, Any] = {}
for path in schema_paths:
    schema = load(path); schemas[path.name] = schema
    Draft202012Validator.check_schema(schema); checks += 1
    resources.append((schema["$id"], Resource(contents=schema, specification=DRAFT202012)))
registry = Registry().with_resources(resources)
validators = {name: Draft202012Validator(schema, registry=registry) for name, schema in schemas.items() if name != "common.defs.json"}

for group in ("positive", "negative"):
    for path in sorted((ROOT / "vectors" / group).glob("*.json")):
        item = load(path); errors = list(validators[item["schema"]].iter_errors(item["document"]))
        check((not errors) == item["valid"], f"{item['id']}: schema result disagrees with declaration")

error_positives = list((ROOT / "vectors" / "positive").glob("error.pos.*.json"))
check(len(error_positives) == ERROR_COUNT, "all 29 exact error tuples must have positive vectors")
for path in sorted((ROOT / "vectors" / "invariants").glob("inv.*.json")):
    item = load(path); check(invariant(item["rule"], item["document"]) == item["holds"], f"{item['id']}: invariant result disagrees")
for path in sorted((ROOT / "vectors" / "headers").glob("*.json")):
    item = load(path); check(headers_hold(item["kind"], item["headers"]) == item["valid"], f"{item['id']}: header result disagrees")
for path in sorted((ROOT / "vectors" / "auth").glob("*.json")):
    item = load(path); check(auth_holds(item) == item["valid"], f"{item['id']}: auth result disagrees")
for path in sorted((ROOT / "vectors" / "state").glob("*.json")):
    item = load(path); check(state_holds(item["events"]) == item["valid"], f"{item['id']}: state result disagrees")

request_json = load(ROOT / "vectors" / "positive" / "request.pos.json.json")["document"]
check(restricted_schema_holds(request_json["output"]["schema"]), "positive restricted schema must pass independent subset validator")
coverage = load(ROOT / "COVERAGE.json")["acceptance_criteria"]
check(set(coverage) == {str(i) for i in range(1, 86)}, "coverage must classify all 85 criteria")
check(all(value["status"] in {"covered", "executor-proof-required"} for value in coverage.values()), "coverage classifications are closed")

if failures:
    for failure in failures: print(f"FAIL: {failure}", file=sys.stderr)
    print(f"{len(failures)} failures across {checks} checks", file=sys.stderr); raise SystemExit(1)
print(f"RC1 bundle verified: {checks} independent checks, all passing")
