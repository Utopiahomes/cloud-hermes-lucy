#!/usr/bin/env python3
"""
Reference verifier for the Stoin Management Contract v1.0 (RC3) conformance bundle.

WHAT THIS IS: a check that the BUNDLE is internally consistent -- that every schema is a
valid 2020-12 schema, that every vector behaves exactly as it declares, and that the
invariant rules are implementable as written. Run it after any edit to the bundle and
before pinning a new digest.

WHAT THIS IS NOT: a shared runtime library, and not either side's conformance suite.
Contract §14 makes the bundle a contract artifact that neither implementation imports.
Each side SHOULD write its own validation, in its own language, against its own DEPLOYED
endpoint over HTTP (acceptance criterion 16). If both sides ran this one script against
each other, the seam would be proven by shared code rather than by an agreed contract,
which is the thing the whole exercise is avoiding.

It enforces four things:

  1. Every schema is a valid JSON Schema 2020-12 document.
  2. Every schema vector validates, or fails, exactly as it declares.
  3. Every invariant vector holds, or is violated, exactly as it declares -- and a
     violation vector's `also_violates` list must name every OTHER invariant it breaks,
     no more and no less. That keeps a fixture from silently drifting into breaking a
     rule it was never meant to exercise.
  4. THE COMPLETE-STATE GATE (§14). Every positive vector must satisfy every applicable
     structural invariant as a complete legal state before it counts as evidence for the
     narrower field behaviour it targets. This exists because the RC2 bundle shipped six
     positive fixtures that were each correct about the field they tested and wrong about
     the state they sat in. A vector that probes a retry_after_seconds bound while
     asserting an illegal health state is not evidence of anything.

Where a health vector has no paired /capabilities document, the gate synthesises one from
the vector's `assumed_enabled_set`, defaulting to the single v1.0 capability guest.answer.

Usage: verify_bundle.py [--verbose]
Exit code 0 means every vector behaved as declared and every positive state is legal.
"""
import json
import pathlib
import sys

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012
except ImportError:
    print("needs: pip install jsonschema", file=sys.stderr)
    raise

BUNDLE = pathlib.Path(__file__).resolve().parent.parent
SCHEMAS = BUNDLE / "schemas"
VECTORS = BUNDLE / "vectors"
VERBOSE = "--verbose" in sys.argv
DEFAULT_ENABLED = ["guest.answer"]

failures = []
checks = 0


def fail(vector_id, detail):
    failures.append(f"{vector_id}: {detail}")


def ok(vector_id, detail=""):
    if VERBOSE:
        print(f"  pass  {vector_id}  {detail}")


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def pointer(doc, ptr):
    """RFC 6901 JSON pointer. Empty string is the whole document."""
    if ptr in ("", None):
        return doc
    cur = doc
    for raw in ptr.lstrip("/").split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        cur = cur[int(token)] if isinstance(cur, list) else cur[token]
    return cur


def doc_key(schema_filename):
    return schema_filename.split(".")[0]


def enabled_set(caps_doc):
    return {c["capability_id"] for c in caps_doc["capabilities"] if c["state"] == "enabled"}


def synth_caps(ids):
    return {"contract_version": "1.0", "observed_at": "2026-09-15T20:15:30Z",
            "capabilities": [{"capability_id": c, "contract_version": "1.0",
                              "state": "enabled"} for c in sorted(ids)]}


# ---------------------------------------------------------------- schemas
schema_paths = sorted(SCHEMAS.glob("*.json"))
resources, schemas_by_name = [], {}
for p in schema_paths:
    contents = load(p)
    schemas_by_name[p.name] = contents
    resources.append((contents["$id"], Resource(contents=contents, specification=DRAFT202012)))
registry = Registry().with_resources(resources)

print(f"schemas: {len(schema_paths)}")
for name, contents in schemas_by_name.items():
    checks += 1
    try:
        Draft202012Validator.check_schema(contents)
        ok(name, "valid 2020-12 schema")
    except Exception as exc:
        fail(name, f"is not a valid 2020-12 schema: {exc}")

validators = {
    name: Draft202012Validator(contents, registry=registry)
    for name, contents in schemas_by_name.items()
    if name != "common.defs.json"
}

# ---------------------------------------------------------------- invariant rules
INV = load(VECTORS / "invariants" / "invariants.json")
rules = {i["id"]: i for i in INV["invariants"]}


def check_sorted(spec, docs):
    target = docs.get(doc_key(spec["schema"]))
    if target is None:
        return None
    seq = pointer(target, spec["pointer"])
    key = spec.get("key")
    values = [item[key] for item in seq] if key else list(seq)
    return values == sorted(values)


def check_unique(spec, docs):
    target = docs.get(doc_key(spec["schema"]))
    if target is None:
        return None
    values = [item[spec["key"]] for item in pointer(target, spec["pointer"])]
    return len(values) == len(set(values))


def check_equality(rule, docs):
    left = docs.get(doc_key(rule["left"]["schema"]))
    right = docs.get(doc_key(rule["right"]["schema"]))
    if left is None or right is None:
        return None
    return pointer(left, rule["left"]["pointer"]) == pointer(right, rule["right"]["pointer"])


def check_status_sets(docs):
    """I-04. RC3 §10 status rules over E and I."""
    health, caps = docs.get("health"), docs.get("capabilities")
    if health is None or caps is None:
        return None
    E = enabled_set(caps)
    I = set(health.get("degraded_capabilities", []))
    if not I <= E:
        return True          # not this rule's job; invariant I-06 owns I ⊆ E
    status = health["status"]
    reasons = health.get("reason_codes", [])
    if status == "healthy":
        return bool(E) and not I
    if status == "degraded":
        return bool(I) and I < E
    if status == "unavailable":
        if E:
            return I == E
        return not I and "no_enabled_capabilities" in reasons
    if status == "unknown":
        return bool(E) and (not I or I < E)
    return False


def check_impaired_subset(docs):
    """I-06. Every impaired capability is advertised and enabled."""
    health, caps = docs.get("health"), docs.get("capabilities")
    if health is None or caps is None:
        return None
    return set(health.get("degraded_capabilities", [])) <= enabled_set(caps)


def check_no_enabled_biconditional(docs):
    """I-07. no_enabled_capabilities present exactly when E is empty."""
    health, caps = docs.get("health"), docs.get("capabilities")
    if health is None or caps is None:
        return None
    present = "no_enabled_capabilities" in health.get("reason_codes", [])
    return present == (len(enabled_set(caps)) == 0)


def check_transitional(docs, mode):
    """I-05. Provider-mode obligation, not a wire-format rule."""
    health = docs.get("health")
    if health is None or mode != "transitional":
        return None
    if health.get("status") != "unknown":
        return False
    if health.get("degraded_capabilities"):
        return False
    return "health_coverage_limited" in health.get("reason_codes", [])


def run_invariant(inv_id, docs, mode=None):
    """True (holds), False (violated), or None (not applicable to these documents)."""
    rule = rules[inv_id]
    kind = rule["rule"]
    if kind == "sorted_ascending":
        results = [check_sorted(s, docs) for s in rule["applies_to"]]
    elif kind == "unique_by_key":
        results = [check_unique(s, docs) for s in rule["applies_to"]]
    elif kind == "cross_endpoint_equality":
        results = [check_equality(rule, docs)]
    elif kind == "status_set_semantics":
        results = [check_status_sets(docs)]
    elif kind == "impaired_subset_of_enabled":
        results = [check_impaired_subset(docs)]
    elif kind == "no_enabled_capabilities_biconditional":
        results = [check_no_enabled_biconditional(docs)]
    elif kind == "transitional_adapter_health":
        results = [check_transitional(docs, mode)]
    else:
        raise SystemExit(f"unimplemented invariant rule {kind!r} for {inv_id}")
    applicable = [r for r in results if r is not None]
    return all(applicable) if applicable else None


def violated_invariants(docs, mode=None):
    return {i for i in rules if run_invariant(i, docs, mode) is False}


def complete_state_gate(vector_id, docs, mode=None):
    """RC3 §14: a positive vector must be a complete legal state first."""
    global checks
    checks += 1
    broken = violated_invariants(docs, mode)
    if broken:
        fail(vector_id, "declared positive but is not a complete legal state — violates "
                        + ", ".join(sorted(broken)))
        return False
    return True


# ---------------------------------------------------------------- schema vectors
schema_vectors = sorted(
    list((VECTORS / "positive").glob("*.json")) + list((VECTORS / "negative").glob("*.json")))
print(f"schema vectors: {len(schema_vectors)}")

for p in schema_vectors:
    v = load(p)
    vid = v["vector_id"]
    checks += 1
    if v["schema"] not in validators:
        fail(vid, f"names unknown schema {v['schema']}")
        continue
    errors = sorted(validators[v["schema"]].iter_errors(v["document"]), key=lambda e: e.json_path)
    if v["expect"] == "valid":
        if errors:
            fail(vid, "declared valid but failed schema: " +
                 "; ".join(f"{e.json_path}: {e.message}" for e in errors[:3]))
            continue
        docs = {doc_key(v["schema"]): v["document"]}
        if "health" in docs and "capabilities" not in docs:
            docs["capabilities"] = synth_caps(v.get("assumed_enabled_set", DEFAULT_ENABLED))
        if complete_state_gate(vid, docs):
            ok(vid, v["contract_reference"])
    elif v["expect"] == "invalid":
        if not errors:
            fail(vid, "declared invalid but the schema accepted it — this rule is NOT being "
                      f"enforced ({v['contract_reference']})")
        else:
            ok(vid, f"rejected: {errors[0].message[:70]}")
    else:
        fail(vid, f"unknown expect value {v['expect']!r}")

# ---------------------------------------------------------------- invariant vectors
inv_vectors = sorted(p for p in (VECTORS / "invariants").glob("inv.*.json"))
print(f"invariant vectors: {len(inv_vectors)}")

for p in inv_vectors:
    v = load(p)
    vid, inv_id, mode = v["vector_id"], v["invariant"], v.get("provider_mode")
    docs = v["documents"]
    checks += 1
    result = run_invariant(inv_id, docs, mode)
    if result is None:
        fail(vid, f"invariant {inv_id} was not applicable to the supplied documents")
        continue
    if v["expect"] == "hold":
        if result is not True:
            fail(vid, f"{inv_id} should hold but was violated")
            continue
        if complete_state_gate(vid, docs, mode):
            ok(vid, f"{inv_id} holds")
    elif v["expect"] == "violation":
        if result is not False:
            fail(vid, f"{inv_id} should be violated but passed — the rule is NOT being "
                      f"enforced ({v['contract_reference']})")
            continue
        checks += 1
        declared = set(v.get("also_violates", []))
        actual = violated_invariants(docs, mode) - {inv_id}
        if actual != declared:
            missing = ", ".join(sorted(actual - declared)) or "none"
            spurious = ", ".join(sorted(declared - actual)) or "none"
            fail(vid, f"also_violates is inaccurate — undeclared: {missing}; "
                      f"declared but not violated: {spurious}")
        else:
            ok(vid, f"{inv_id} violated" + (f" (also {', '.join(sorted(actual))})" if actual else ""))
    else:
        fail(vid, f"unknown expect value {v['expect']!r}")

# ---------------------------------------------------------------- report
print()
if failures:
    print(f"FAILED — {len(failures)} of {checks} checks did not behave as declared:")
    for f in failures:
        print(f"  {f}")
    sys.exit(1)
print(f"OK — {checks} checks, every vector behaved exactly as declared.")
