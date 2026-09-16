#!/usr/bin/env python3
"""Generates the Tier A vector files for guest.answer@1.0 RC2 from first principles.

Kept in the bundle deliberately (unlike the Management Contract bundle, whose generator
scripts were not carried forward — a choice later regretted when RC4-style revisions would
have benefited from them). Re-running this script reproduces the same vector files.

Auth vectors describe claim sets and the specific rule under test rather than embedding
pre-signed JWTs: a fixed embedded signing key would make every vector's validity a function of
wall-clock time relative to a frozen iat/exp, and signature verification itself is already
proven, separately, by each side's actual JWT library. What Tier A needs to pin deterministically
is the claim *shape and arithmetic* RC2 requires, encoded here as data, not as a signed token.

Run: python tools/generate_vectors.py
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

BUNDLE = Path(__file__).resolve().parent.parent
VECTORS = BUNDLE / "vectors"

UUIDS = [
    "27b20c7b-777e-4af3-8db1-5fe1fc2f3b7e",
    "056d5f10-ed13-44fa-b8bc-1af90d43dceb",
    "f938d01b-0125-48ed-962b-9c739e43a24f",
    "12682577-2c4b-4889-8391-47dca4b38ad4",
    "a9ec2c26-cf3d-4a58-9939-cd421db25d71",
    "ed1f1cfa-125c-4178-ae7d-dbc527a14863",
    "b139a2b0-61f2-4523-99ad-aa4c67db2cdc",
    "5a6a3c4e-1b2c-4d5e-89ab-1234567890ab",
    "c1a2b3d4-e5f6-4789-9abc-def012345678",
    "9f86d081-884c-4d65-9861-5c4111111111",
    "3f8a1c2d-4b5e-4f60-8a1b-2c3d4e5f6a7b",
    "7d6c5b4a-3f2e-4d1c-9b8a-7f6e5d4c3b2a",
    "1a2b3c4d-5e6f-4789-8a9b-0c1d2e3f4a5b",
    "2b3c4d5e-6f70-4819-9a0b-1c2d3e4f5a6b",
]


def uid(i: int) -> str:
    return UUIDS[i % len(UUIDS)]


def write(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # newline="" disables Path.write_text's platform newline translation (which would otherwise
    # silently turn every "\n" into "\r\n" on Windows) — the bundle digest is taken over raw
    # bytes, so this is not cosmetic; without it every generated vector has the wrong bytes.
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="")


def base_request() -> dict:
    return {
        "contract_version": "1.0",
        "session_id": uid(0),
        "message": {
            "turn_id": uid(1),
            "content": "Which home is best for 20 people, four cars, and a pool?",
        },
        "history": [
            {"turn_id": uid(2), "role": "user", "content": "Tell me about the homes with pools."},
            {
                "turn_id": uid(3),
                "role": "assistant",
                "content": "Buttercup Beauty and Central Ave Socialization have verified pool information.",
            },
        ],
        "page_context": {
            "path": "/stays/buttercup-beauty",
            "subject_type": "property",
            "subject_id": "buttercup-beauty",
        },
        "locale": "en-US",
    }


def base_response() -> dict:
    return {
        "contract_version": "1.0",
        "response_id": uid(4),
        "session_id": uid(0),
        "assistant_turn_id": uid(5),
        "outcome": "answered",
        "answer": "Our public collection currently includes three homes. Buttercup Beauty is a verified match.",
        "sources": [
            {
                "source_id": "public-property:buttercup-beauty",
                "title": "Buttercup Beauty",
                "url": "https://www.utopiahomes.com/stays/buttercup-beauty",
            }
        ],
        "actions": [
            {
                "action_id": "view-property:buttercup-beauty",
                "kind": "open_internal_link",
                "label": "Explore Buttercup Beauty",
                "url": "https://www.utopiahomes.com/stays/buttercup-beauty",
            }
        ],
        "limitations": [],
    }


ERROR_TABLE = [
    ("invalid_request", 400, "The request is invalid.", False),
    ("unsupported_version", 400, "This request version is not supported.", False),
    ("authentication_failed", 401, "Authentication failed.", False),
    ("capability_forbidden", 403, "This capability is not permitted.", False),
    ("idempotency_conflict", 409, "This request conflicts with an earlier request.", False),
    ("request_in_progress", 409, "This request is still in progress.", True),
    ("idempotency_recovery_unavailable", 409, "The earlier response is no longer available.", False),
    ("response_invalidated", 409, "The earlier response is no longer valid.", False),
    ("request_too_large", 413, "The request is too large.", False),
    ("rate_limited", 429, "Too many requests. Please try again shortly.", True),
    ("temporarily_unavailable", 503, "Lucy is temporarily unavailable. Please try again shortly.", True),
    ("answer_validation_failed", 503, "Lucy could not produce a supported answer for this request.", False),
    ("deadline_exceeded", 504, "Lucy could not respond within the allowed time.", True),
]


def base_error(code: str, message: str, retryable: bool) -> dict:
    return {
        "contract_version": "1.0",
        "error": {"code": code, "message": message, "correlation_id": uid(6), "retryable": retryable},
    }


def vec(vector_id: str, schema: str, expect: str, ref: str, desc: str, document: dict) -> dict:
    return {
        "vector_id": vector_id,
        "schema": schema,
        "expect": expect,
        "contract_reference": ref,
        "description": desc,
        "document": document,
    }


# --------------------------------------------------------------------------------------
# Request vectors
# --------------------------------------------------------------------------------------


def generate_request_vectors() -> None:
    n_pos = 0
    n_neg = 0

    def pos(name: str, ref: str, desc: str, doc: dict) -> None:
        nonlocal n_pos
        n_pos += 1
        write(
            VECTORS / "positive" / f"request.pos.{n_pos:03d}.json",
            vec(f"request.pos.{n_pos:03d}", "request.schema.json", "valid", ref, desc, doc),
        )

    def neg(name: str, ref: str, desc: str, doc: dict) -> None:
        nonlocal n_neg
        n_neg += 1
        write(
            VECTORS / "negative" / f"request.neg.{n_neg:03d}.json",
            vec(f"request.neg.{n_neg:03d}", "request.schema.json", "invalid", ref, desc, doc),
        )

    # Positive: full worked example straight from RC2 §9.
    pos("full", "§9", "Canonical worked example from the contract text.", base_request())

    # Positive: minimal — no history, no page_context.
    minimal = base_request()
    del minimal["history"]
    del minimal["page_context"]
    pos("minimal", "§9.1", "Minimal valid request: history and page_context both omitted.", minimal)

    # Positive: empty history array (present but empty, as distinct from omitted).
    empty_hist = base_request()
    empty_hist["history"] = []
    pos("empty-history-array", "§9.1", "history present as an empty array rather than omitted.", empty_hist)

    # Positive: page_context with subject_type=none and subject_id=null.
    none_subject = base_request()
    none_subject["page_context"] = {"path": "/about", "subject_type": "none", "subject_id": None}
    pos("subject-type-none", "§9.1", "subject_type=none paired with subject_id=null.", none_subject)

    # Positive: history at the 12-entry boundary (all alternating, ending in assistant).
    boundary_hist = base_request()
    hist = []
    for i in range(12):
        role = "user" if i % 2 == 0 else "assistant"
        hist.append({"turn_id": f"{i:08x}-0000-4000-8000-000000000000", "role": role, "content": f"turn {i}"})
    boundary_hist["history"] = hist
    pos("history-12-boundary", "§9.1", "history at the maximum 12 entries, correctly alternating.", boundary_hist)

    # Positive: message.content at min length (1 char) and max length (2000 chars).
    min_content = base_request()
    min_content["message"]["content"] = "x"
    pos("message-content-min", "§9.1", "message.content at the 1-character minimum.", min_content)

    max_content = base_request()
    max_content["message"]["content"] = "x" * 2000
    pos("message-content-max", "§9.1", "message.content at the 2000-character maximum.", max_content)

    # Positive: subject_id at 1 char and 64 chars.
    subj_min = base_request()
    subj_min["page_context"]["subject_id"] = "a"
    pos("subject-id-min", "§9.1", "subject_id at the 1-character minimum.", subj_min)

    subj_max = base_request()
    subj_max["page_context"]["subject_id"] = "a" * 64
    pos("subject-id-max", "§9.1", "subject_id at the 64-character maximum.", subj_max)

    # --- Negative vectors ---

    neg("missing-contract-version", "§9.1", "contract_version omitted.", _without(base_request(), "contract_version"))
    neg("wrong-contract-version", "§9.1", "contract_version is not exactly '1.0'.", _with(base_request(), "contract_version", "1.1"))
    neg("missing-session-id", "§9.1", "session_id omitted.", _without(base_request(), "session_id"))
    neg("session-id-not-uuid", "§9.1", "session_id is not a UUID v4.", _with(base_request(), "session_id", "not-a-uuid"))
    neg("session-id-uppercase", "§3", "session_id uses uppercase hex, which RC2's canonical form rejects.", _with(base_request(), "session_id", uid(0).upper()))
    neg("session-id-v1", "§3", "session_id has a UUID version nibble other than 4.", _with(base_request(), "session_id", "27b20c7b-777e-1af3-8db1-5fe1fc2f3b7e"))

    missing_msg = base_request()
    del missing_msg["message"]
    neg("missing-message", "§9.1", "message omitted entirely.", missing_msg)

    empty_content = base_request()
    empty_content["message"]["content"] = ""
    neg("message-content-empty", "§9.1", "message.content is empty (below the 1-character minimum).", empty_content)

    over_content = base_request()
    over_content["message"]["content"] = "x" * 2001
    neg("message-content-too-long", "§9.1", "message.content exceeds the 2000-character maximum.", over_content)

    over_hist = base_request()
    over_hist["history"] = [
        {"turn_id": f"{i:08x}-0000-4000-8000-000000000000", "role": "user" if i % 2 == 0 else "assistant", "content": "x"}
        for i in range(13)
    ]
    neg("history-13-entries", "§9.1", "history exceeds the 12-entry maximum.", over_hist)

    bad_role = base_request()
    bad_role["history"][0]["role"] = "system"
    neg("history-system-role", "§9.1", "history entry uses the rejected role 'system'.", bad_role)

    bad_role2 = base_request()
    bad_role2["history"][0]["role"] = "tool"
    neg("history-tool-role", "§9.1", "history entry uses the rejected role 'tool'.", bad_role2)

    unknown_member = base_request()
    unknown_member["extra_field"] = "not allowed"
    neg("unknown-top-level-member", "§9.1", "Unknown top-level member must be rejected.", unknown_member)

    unknown_msg_member = base_request()
    unknown_msg_member["message"]["metadata"] = "not allowed"
    neg("unknown-message-member", "§9.1", "Unknown member inside message must be rejected.", unknown_msg_member)

    query_path = base_request()
    query_path["page_context"]["path"] = "/stays/buttercup-beauty?ref=ad"
    neg("page-context-query-string", "§9.1", "page_context.path contains a literal query string.", query_path)

    frag_path = base_request()
    frag_path["page_context"]["path"] = "/stays/buttercup-beauty#reviews"
    neg("page-context-fragment", "§9.1", "page_context.path contains a literal fragment.", frag_path)

    encoded_q_path = base_request()
    encoded_q_path["page_context"]["path"] = "/stays/buttercup-beauty%3Fref=ad"
    neg("page-context-encoded-query", "§9.1", "page_context.path contains a percent-encoded query delimiter.", encoded_q_path)

    encoded_frag_path = base_request()
    encoded_frag_path["page_context"]["path"] = "/stays/buttercup-beauty%23reviews"
    neg("page-context-encoded-fragment", "§9.1", "page_context.path contains a percent-encoded fragment delimiter.", encoded_frag_path)

    scheme_path = base_request()
    scheme_path["page_context"]["path"] = "https://evil.example.com/x"
    neg("page-context-external-scheme", "§9.1", "page_context.path contains an external scheme and host.", scheme_path)

    protocol_relative_path = base_request()
    protocol_relative_path["page_context"]["path"] = "//evil.example.com/x"
    neg("page-context-protocol-relative", "§9.1", "page_context.path is protocol-relative.", protocol_relative_path)

    over_path = base_request()
    over_path["page_context"]["path"] = "/" + ("a" * 512)
    neg("page-context-path-too-long", "§9.1", "page_context.path exceeds the 512-character maximum.", over_path)

    bad_subject_type = base_request()
    bad_subject_type["page_context"]["subject_type"] = "owner"
    neg("subject-type-unapproved", "§9.1", "subject_type is not one of the five approved values.", bad_subject_type)

    none_with_id = base_request()
    none_with_id["page_context"] = {"path": "/about", "subject_type": "none", "subject_id": "buttercup-beauty"}
    neg("subject-type-none-with-id", "§9.1", "subject_type=none paired with a non-null subject_id.", none_with_id)

    nonnull_missing = base_request()
    nonnull_missing["page_context"] = {"path": "/stays/x", "subject_type": "property", "subject_id": None}
    neg("subject-type-property-null-id", "§9.1", "subject_type=property paired with a null subject_id.", nonnull_missing)

    empty_subject_id = base_request()
    empty_subject_id["page_context"]["subject_id"] = ""
    neg("subject-id-empty-string", "§9.1", "subject_id is an empty string (below the 1-character minimum) rather than null.", empty_subject_id)

    bad_subject_id_case = base_request()
    bad_subject_id_case["page_context"]["subject_id"] = "Buttercup-Beauty"
    neg("subject-id-uppercase", "§9.1", "subject_id is not lowercase kebab-case.", bad_subject_id_case)

    bad_subject_id_double_hyphen = base_request()
    bad_subject_id_double_hyphen["page_context"]["subject_id"] = "buttercup--beauty"
    neg("subject-id-consecutive-hyphen", "§9.1", "subject_id has a consecutive hyphen.", bad_subject_id_double_hyphen)

    over_subject_id = base_request()
    over_subject_id["page_context"]["subject_id"] = "a" * 65
    neg("subject-id-too-long", "§9.1", "subject_id exceeds the 64-character maximum.", over_subject_id)

    bad_locale = base_request()
    bad_locale["locale"] = "fr-FR"
    neg("locale-not-en-us", "§9.1", "locale is a well-formed BCP-47 tag other than the only accepted value en-US.", bad_locale)

    missing_locale = base_request()
    del missing_locale["locale"]
    neg("missing-locale", "§9.1", "locale omitted; it is a required member.", missing_locale)

    # Note: turn_id uniqueness/non-collision (§9.1) is a cross-array-item comparison no single
    # JSON Schema field constraint can express; it's covered as invariant I-B03 instead, not as
    # a request.neg.* schema vector.

    print(f"request vectors: {n_pos} positive, {n_neg} negative")


def _without(doc: dict, key: str) -> dict:
    d = copy.deepcopy(doc)
    del d[key]
    return d


def _with(doc: dict, key: str, value) -> dict:
    d = copy.deepcopy(doc)
    d[key] = value
    return d


# --------------------------------------------------------------------------------------
# Response vectors
# --------------------------------------------------------------------------------------


def generate_response_vectors() -> None:
    n_pos = 0
    n_neg = 0

    def pos(name: str, ref: str, desc: str, doc: dict) -> None:
        nonlocal n_pos
        n_pos += 1
        write(
            VECTORS / "positive" / f"response.pos.{n_pos:03d}.json",
            vec(f"response.pos.{n_pos:03d}", "response.schema.json", "valid", ref, desc, doc),
        )

    def neg(name: str, ref: str, desc: str, doc: dict) -> None:
        nonlocal n_neg
        n_neg += 1
        write(
            VECTORS / "negative" / f"response.neg.{n_neg:03d}.json",
            vec(f"response.neg.{n_neg:03d}", "response.schema.json", "invalid", ref, desc, doc),
        )

    pos("full", "§12", "Canonical worked example from the contract text.", base_response())

    empty_arrays = base_response()
    empty_arrays["sources"] = []
    empty_arrays["actions"] = []
    pos("empty-sources-actions", "§12.2", "sources and actions both present as empty arrays.", empty_arrays)

    for outcome in ["answered", "partial", "clarification_needed", "out_of_scope", "refused"]:
        doc = base_response()
        doc["outcome"] = outcome
        pos(f"outcome-{outcome}", "§12.1", f"Valid response with outcome={outcome}.", doc)

    shared_url = base_response()
    shared_url["actions"][0]["url"] = shared_url["sources"][0]["url"]
    pos("source-action-shared-url", "§12.2", "A source and an action share the same URL — explicitly permitted (I-B07).", shared_url)

    max_sources = base_response()
    max_sources["sources"] = [
        {"source_id": f"public-property:home-{i:02d}", "title": f"Home {i}", "url": f"https://www.utopiahomes.com/stays/home-{i:02d}"}
        for i in range(8)
    ]
    pos("sources-max-8", "§12.2", "sources at the maximum of 8 entries, all unique.", max_sources)

    max_actions = base_response()
    max_actions["actions"] = [
        {"action_id": f"view-property:home-{i:02d}", "kind": "open_internal_link", "label": f"View home {i}", "url": f"https://www.utopiahomes.com/stays/home-{i:02d}"}
        for i in range(4)
    ]
    pos("actions-max-4", "§12.2", "actions at the maximum of 4 entries, all unique.", max_actions)

    max_limitations = base_response()
    max_limitations["limitations"] = ["Live pricing is not available." for _ in range(1)] + [
        f"Limitation {i}." for i in range(3)
    ]
    pos("limitations-max-4", "§12.2", "limitations at the maximum of 4 entries.", max_limitations)

    booking_action = base_response()
    booking_action["actions"] = [
        {
            "action_id": "book-property:buttercup-beauty",
            "kind": "open_external_booking_link",
            "label": "Check availability",
            "url": "https://booking.examplepms.com/buttercup-beauty?nights=3",
        }
    ]
    pos("external-booking-action-with-query", "§12.2", "open_external_booking_link URL may carry a query string (unlike request page_context.path).", booking_action)

    # --- Negative vectors ---

    for field in ["contract_version", "response_id", "session_id", "assistant_turn_id", "outcome", "answer", "sources", "actions", "limitations"]:
        neg(f"missing-{field}", "§12.2", f"{field} omitted; it is required.", _without(base_response(), field))

    bad_outcome = base_response()
    bad_outcome["outcome"] = "answered_maybe"
    neg("outcome-not-enum", "§12.1", "outcome is not one of the five approved values.", bad_outcome)

    empty_answer = base_response()
    empty_answer["answer"] = ""
    neg("answer-empty", "§12.2", "answer is empty (below the 1-character minimum).", empty_answer)

    long_answer = base_response()
    long_answer["answer"] = "x" * 4001
    neg("answer-too-long", "§12.2", "answer exceeds the 4000-character maximum.", long_answer)

    unknown_top = base_response()
    unknown_top["debug_info"] = "leak"
    neg("unknown-top-level-member", "§12.2", "Unknown top-level member must be rejected.", unknown_top)

    too_many_sources = base_response()
    too_many_sources["sources"] = [
        {"source_id": f"public-property:home-{i:02d}", "title": f"Home {i}", "url": f"https://www.utopiahomes.com/stays/home-{i:02d}"}
        for i in range(9)
    ]
    neg("sources-too-many", "§12.2", "sources exceeds the 8-entry maximum.", too_many_sources)

    too_many_actions = base_response()
    too_many_actions["actions"] = [
        {"action_id": f"view-property:home-{i:02d}", "kind": "open_internal_link", "label": f"View home {i}", "url": f"https://www.utopiahomes.com/stays/home-{i:02d}"}
        for i in range(5)
    ]
    neg("actions-too-many", "§12.2", "actions exceeds the 4-entry maximum.", too_many_actions)

    too_many_limitations = base_response()
    too_many_limitations["limitations"] = [f"Limitation {i}." for i in range(5)]
    neg("limitations-too-many", "§12.2", "limitations exceeds the 4-entry maximum.", too_many_limitations)

    bad_source_id_no_colon = base_response()
    bad_source_id_no_colon["sources"][0]["source_id"] = "publicpropertybuttercupbeauty"
    neg("source-id-no-colon", "§12.2", "source_id has no namespace-separating colon.", bad_source_id_no_colon)

    bad_source_id_two_colons = base_response()
    bad_source_id_two_colons["sources"][0]["source_id"] = "public:property:buttercup-beauty"
    neg("source-id-two-colons", "§12.2", "source_id has more than one colon.", bad_source_id_two_colons)

    bad_source_id_upper = base_response()
    bad_source_id_upper["sources"][0]["source_id"] = "Public-Property:Buttercup-Beauty"
    neg("source-id-uppercase", "§12.2", "source_id is not lowercase kebab-case.", bad_source_id_upper)

    bad_source_id_long_ns = base_response()
    bad_source_id_long_ns["sources"][0]["source_id"] = ("a" * 33) + ":buttercup-beauty"
    neg("source-id-namespace-too-long", "§12.2", "source_id's namespace segment exceeds the 32-character maximum.", bad_source_id_long_ns)

    bad_source_id_long_local = base_response()
    bad_source_id_long_local["sources"][0]["source_id"] = "public-property:" + ("b" * 96)
    neg("source-id-local-too-long", "§12.2", "source_id's local-identifier segment exceeds the 95-character maximum.", bad_source_id_long_local)

    long_title = base_response()
    long_title["sources"][0]["title"] = "x" * 121
    neg("source-title-too-long", "§12.2", "source title exceeds the 120-character maximum.", long_title)

    empty_title = base_response()
    empty_title["sources"][0]["title"] = ""
    neg("source-title-empty", "§12.2", "source title is empty.", empty_title)

    bad_action_kind = base_response()
    bad_action_kind["actions"][0]["kind"] = "open_modal"
    neg("action-kind-not-enum", "§12.2", "action kind is not one of the three approved values.", bad_action_kind)

    long_label = base_response()
    long_label["actions"][0]["label"] = "x" * 81
    neg("action-label-too-long", "§12.2", "action label exceeds the 80-character maximum.", long_label)

    long_limitation = base_response()
    long_limitation["limitations"] = ["x" * 241]
    neg("limitation-too-long", "§12.2", "limitation text exceeds the 240-character maximum.", long_limitation)

    http_url = base_response()
    http_url["sources"][0]["url"] = "http://www.utopiahomes.com/stays/buttercup-beauty"
    neg("source-url-not-https", "§12.2", "source URL uses http, not https.", http_url)

    fragment_url = base_response()
    fragment_url["sources"][0]["url"] = "https://www.utopiahomes.com/stays/buttercup-beauty#reviews"
    neg("source-url-has-fragment", "§12.2", "source URL contains a fragment, which RC2 prohibits.", fragment_url)

    userinfo_url = base_response()
    userinfo_url["actions"][0]["url"] = "https://user:pass@www.utopiahomes.com/x"
    neg("action-url-has-userinfo", "§12.2", "action URL contains user-info, which RC2 prohibits.", userinfo_url)

    long_url = base_response()
    long_url["sources"][0]["url"] = "https://www.utopiahomes.com/" + ("a" * 2040)
    neg("source-url-too-long", "§12.2", "source URL exceeds the 2048-character maximum.", long_url)

    print(f"response vectors: {n_pos} positive, {n_neg} negative")


# --------------------------------------------------------------------------------------
# Error vectors
# --------------------------------------------------------------------------------------


def generate_error_vectors() -> None:
    n_pos = 0
    n_neg = 0

    def pos(name: str, ref: str, desc: str, doc: dict) -> None:
        nonlocal n_pos
        n_pos += 1
        write(
            VECTORS / "positive" / f"error.pos.{n_pos:03d}.json",
            vec(f"error.pos.{n_pos:03d}", "error.response.schema.json", "valid", ref, desc, doc),
        )

    def neg(name: str, ref: str, desc: str, doc: dict) -> None:
        nonlocal n_neg
        n_neg += 1
        write(
            VECTORS / "negative" / f"error.neg.{n_neg:03d}.json",
            vec(f"error.neg.{n_neg:03d}", "error.response.schema.json", "invalid", ref, desc, doc),
        )

    for code, status, message, retryable in ERROR_TABLE:
        pos(code, "§17", f"Exact required message/retryable pairing for {code} ({status}).", base_error(code, message, retryable))

    ok_code, ok_message, ok_retryable = ERROR_TABLE[0][0], ERROR_TABLE[0][2], ERROR_TABLE[0][3]
    wrong_message = base_error(ok_code, "The request could not be processed.", ok_retryable)
    neg("wrong-message-for-code", "§17", "message does not match the exact required string for this code.", wrong_message)

    wrong_retryable = base_error(ok_code, ok_message, True)
    neg("wrong-retryable-for-code", "§17", "retryable does not match the required value for this code (invalid_request is never retryable).", wrong_retryable)

    # An answer_validation_failed marked retryable=true — the specific case criterion 33 exists for.
    avf_retryable = base_error("answer_validation_failed", "Lucy could not produce a supported answer for this request.", True)
    neg("answer-validation-failed-marked-retryable", "§17", "answer_validation_failed is 503 but must never be retryable=true (criterion 33).", avf_retryable)

    bad_code = base_error("not_a_real_code", ok_message, False)
    neg("unknown-error-code", "§17", "error.code is not one of the 13 defined codes.", bad_code)

    missing_correlation = base_error(ok_code, ok_message, ok_retryable)
    del missing_correlation["error"]["correlation_id"]
    neg("missing-correlation-id", "§17", "correlation_id omitted.", missing_correlation)

    bad_correlation = base_error(ok_code, ok_message, ok_retryable)
    bad_correlation["error"]["correlation_id"] = "not-a-uuid"
    neg("correlation-id-not-uuid", "§17", "correlation_id is not a valid UUID v4.", bad_correlation)

    extra_field = base_error(ok_code, ok_message, ok_retryable)
    extra_field["error"]["stack_trace"] = "leaked internal detail"
    neg("unknown-error-member", "§17", "Unknown member inside error (e.g. a stack trace) must be rejected.", extra_field)

    empty_message = base_error(ok_code, "", ok_retryable)
    neg("empty-message", "§17", "message is empty (and also does not match the required exact string).", empty_message)

    print(f"error vectors: {n_pos} positive, {n_neg} negative")


# --------------------------------------------------------------------------------------
# Invariant vectors
# --------------------------------------------------------------------------------------


def _invvec(vector_id: str, invariant: str, expect: str, ref: str, desc: str, documents: dict, also_violates: list[str]) -> dict:
    return {
        "vector_id": vector_id,
        "invariant": invariant,
        "expect": expect,
        "contract_reference": ref,
        "description": desc,
        "documents": documents,
        "also_violates": also_violates,
    }


def generate_invariant_vectors() -> None:
    n = 0
    per_invariant_counts: dict[str, int] = {}

    def emit(invariant: str, expect: str, ref: str, desc: str, documents: dict, also_violates: list[str] | None = None) -> None:
        nonlocal n
        n += 1
        suffix = "pos" if expect == "hold" else "neg"
        key = f"{invariant}.{suffix}"
        per_invariant_counts[key] = per_invariant_counts.get(key, 0) + 1
        vid = f"inv.{invariant}.{suffix}.{per_invariant_counts[key]:03d}"
        write(
            VECTORS / "invariants" / f"{vid}.json",
            _invvec(vid, invariant, expect, ref, desc, documents, also_violates or []),
        )

    # I-B01: history aggregate character bound
    ok_hist_req = base_request()
    emit("I-B01", "hold", "§9.1", "History content well under the 10,000-character total.", {"request": ok_hist_req})

    over_hist_req = base_request()
    over_hist_req["history"] = [
        {"turn_id": f"{i:08x}-0000-4000-8000-000000000000", "role": "user" if i % 2 == 0 else "assistant", "content": "x" * 900}
        for i in range(12)
    ]
    emit("I-B01", "violation", "§9.1", "History content totals 10,800 characters, over the 10,000 limit.", {"request": over_hist_req})

    # I-B02: history role shape
    emit("I-B02", "hold", "§9.1", "History alternates correctly, starts user, ends assistant.", {"request": base_request()})

    bad_alt_req = base_request()
    bad_alt_req["history"][1]["role"] = "user"
    emit("I-B02", "violation", "§9.1", "Two consecutive history entries are both 'user'.", {"request": bad_alt_req})

    # I-B03: turn_id uniqueness/non-collision
    emit("I-B03", "hold", "§9.1", "All turn_id values across message and history are distinct.", {"request": base_request()})

    collide_req = base_request()
    collide_req["message"]["turn_id"] = collide_req["history"][0]["turn_id"]
    emit("I-B03", "violation", "§9.1", "message.turn_id collides with a history entry's turn_id.", {"request": collide_req})

    # I-B04: response.session_id matches request
    emit("I-B04", "hold", "§12.2", "response.session_id equals request.session_id.", {"request": base_request(), "response": base_response()})

    mismatched_resp = base_response()
    mismatched_resp["session_id"] = uid(9)
    emit("I-B04", "violation", "§12.2", "response.session_id does not match request.session_id.", {"request": base_request(), "response": mismatched_resp})

    # I-B05: source id/url uniqueness
    emit("I-B05", "hold", "§12.2", "All source_id and url values are unique within sources.", {"response": base_response()})

    dup_source_id = base_response()
    dup_source_id["sources"].append(dict(dup_source_id["sources"][0], url="https://www.utopiahomes.com/stays/other"))
    emit("I-B05", "violation", "§12.2", "Two sources share the same source_id.", {"response": dup_source_id})

    dup_source_url = base_response()
    dup_source_url["sources"].append(dict(dup_source_url["sources"][0], source_id="public-property:other-home"))
    emit("I-B05", "violation", "§12.2", "Two sources share the same url.", {"response": dup_source_url})

    # I-B06: action id/url uniqueness
    emit("I-B06", "hold", "§12.2", "All action_id and url values are unique within actions.", {"response": base_response()})

    dup_action_id = base_response()
    dup_action_id["actions"].append(dict(dup_action_id["actions"][0], url="https://www.utopiahomes.com/stays/other"))
    emit("I-B06", "violation", "§12.2", "Two actions share the same action_id.", {"response": dup_action_id})

    # I-B07: no cross-array uniqueness
    shared = base_response()
    shared["actions"][0]["url"] = shared["sources"][0]["url"]
    emit("I-B07", "hold", "§12.2", "A source and an action legitimately share the same URL.", {"response": shared})

    # I-B08: URL host / action-kind approval, AND exact approved-destination membership (§12.2:
    # "A source URL must exactly match an approved public-source destination"; an internal/
    # contact action "must use an approved Utopia-owned hostname and match an approved
    # destination"; an external-booking action must use the approved hostname "and match the
    # property's configured destination"). Extended with the destination-matching half per
    # Lyra's review — an approved HOST serving an unapproved PATH must still be caught.
    approved = {"internal": ["www.utopiahomes.com"], "external_booking": ["booking.examplepms.com"]}
    buttercup_url = "https://www.utopiahomes.com/stays/buttercup-beauty"
    booking_url = "https://booking.examplepms.com/buttercup-beauty"
    approved_destinations = [buttercup_url, booking_url]

    good_hosts = base_response()
    emit(
        "I-B08",
        "hold",
        "§12.2",
        "Internal-link action uses an approved Homes hostname AND an approved exact destination.",
        {"response": good_hosts, "assumed_approved_hostnames": approved, "assumed_approved_destinations": approved_destinations},
    )

    booking_ok = base_response()
    booking_ok["actions"] = [
        {
            "action_id": "book-property:buttercup-beauty",
            "kind": "open_external_booking_link",
            "label": "Check availability",
            "url": booking_url,
        }
    ]
    emit(
        "I-B08",
        "hold",
        "§12.2",
        "External-booking action uses the approved external-booking hostname and destination.",
        {"response": booking_ok, "assumed_approved_hostnames": approved, "assumed_approved_destinations": approved_destinations},
    )

    wrong_host = base_response()
    wrong_host["actions"][0]["url"] = booking_url  # internal-link kind, external host
    emit(
        "I-B08",
        "violation",
        "§12.2",
        "open_internal_link action points at the external-booking hostname instead of an approved internal one.",
        {"response": wrong_host, "assumed_approved_hostnames": approved, "assumed_approved_destinations": approved_destinations},
    )

    wrong_booking_host = base_response()
    wrong_booking_host["actions"] = [
        {
            "action_id": "book-property:buttercup-beauty",
            "kind": "open_external_booking_link",
            "label": "Check availability",
            "url": buttercup_url,
        }
    ]
    emit(
        "I-B08",
        "violation",
        "§12.2",
        "open_external_booking_link action points at the internal Homes hostname instead of an approved external one.",
        {"response": wrong_booking_host, "assumed_approved_hostnames": approved, "assumed_approved_destinations": approved_destinations},
    )

    unapproved_path_action = base_response()
    unapproved_path_action["actions"][0]["url"] = "https://www.utopiahomes.com/stays/some-other-property"
    emit(
        "I-B08",
        "violation",
        "§12.2",
        "The action's hostname IS approved for open_internal_link, but this exact path was never configured as an approved destination — hostname approval alone is not sufficient.",
        {"response": unapproved_path_action, "assumed_approved_hostnames": approved, "assumed_approved_destinations": approved_destinations},
    )

    unapproved_path_source = base_response()
    unapproved_path_source["sources"][0]["url"] = "https://www.utopiahomes.com/stays/some-other-property"
    emit(
        "I-B08",
        "violation",
        "§12.2",
        "A source URL that was never checked against destination approval at all in the original I-B08 — sources are covered by RC2's own text ('A source URL must exactly match an approved public-source destination') as explicitly as actions are.",
        {"response": unapproved_path_source, "assumed_approved_hostnames": approved, "assumed_approved_destinations": approved_destinations},
    )

    # I-B09: idempotency status selection — one vector per branch.
    branches = [
        ("hold", {"durable_status": "none", "volatile_content_present": False, "canonical_request_matches": True, "still_eligible": True}, "new_execution", "No prior admission under this key: a fresh execution is admitted."),
        ("hold", {"durable_status": "completed", "volatile_content_present": True, "canonical_request_matches": True, "still_eligible": True}, "replay", "Same key, same canonical request, content still volatile, still eligible: replay."),
        ("hold", {"durable_status": "completed", "volatile_content_present": True, "canonical_request_matches": False, "still_eligible": True}, "idempotency_conflict", "Same key, different canonical request: conflict regardless of completion state."),
        ("hold", {"durable_status": "in_progress", "volatile_content_present": False, "canonical_request_matches": True, "still_eligible": True}, "request_in_progress", "Same key, original still executing: in-progress duplicate."),
        ("hold", {"durable_status": "completed", "volatile_content_present": False, "canonical_request_matches": True, "still_eligible": True}, "idempotency_recovery_unavailable", "Durable status shows completion but volatile content is gone (e.g. coordinator restart)."),
        ("hold", {"durable_status": "unresolved", "volatile_content_present": False, "canonical_request_matches": True, "still_eligible": True}, "idempotency_recovery_unavailable", "Durable status is unresolved and volatile content is unavailable."),
        ("hold", {"durable_status": "completed", "volatile_content_present": True, "canonical_request_matches": True, "still_eligible": False}, "response_invalidated", "Content is still volatile but the underlying public state has changed."),
        ("violation", {"durable_status": "completed", "volatile_content_present": False, "canonical_request_matches": True, "still_eligible": True}, "replay", "WRONG: claims replay is possible despite volatile content being unavailable."),
    ]
    for expect, state, expected_outcome, desc in branches:
        emit("I-B09", expect, "§11", desc, {"state": state, "expected_outcome": expected_outcome})

    # I-B10: canonical request identity determinism
    a = base_request()
    b = {k: a[k] for k in reversed(list(a.keys()))}  # same content, reordered top-level keys
    emit("I-B10", "hold", "§11.2", "Reordering top-level members does not change canonical identity.", {"a": a, "b": b, "same_canonical_identity": True})

    c = base_request()
    d = base_request()
    d["message"]["content"] = d["message"]["content"] + " please"
    emit("I-B10", "hold", "§11.2", "Changed content correctly produces a different canonical identity (declaring same=False and confirming it).", {"a": c, "b": d, "same_canonical_identity": False})

    e = base_request()
    f = base_request()
    f["message"]["content"] = f["message"]["content"] + " please"
    emit("I-B10", "violation", "§11.2", "WRONG: claims two requests with different content canonicalize identically.", {"a": e, "b": f, "same_canonical_identity": True})

    print(f"invariant vectors: {n}")


# --------------------------------------------------------------------------------------
# Auth claim vectors (§7.2)
# --------------------------------------------------------------------------------------

REQUIRED_ISS = "stoin:application:utopia-homes-web"
REQUIRED_SUB = "stoin:service:utopia-homes-web-guest-adapter"
REQUIRED_AUD = "stoin:business:utopia-homes-prime"
REQUIRED_SCOPE = "guest.answer"


def base_claims(now: int = 1_000_000) -> dict:
    return {
        "iss": REQUIRED_ISS,
        "sub": REQUIRED_SUB,
        "aud": REQUIRED_AUD,
        "scope": REQUIRED_SCOPE,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": uid(7),
    }


def generate_auth_vectors() -> None:
    n = 0
    # kid -> {environment, capabilities}. RC2 §7.1: "For each accepted key, Prime locally binds
    # the exact issuer, subject, audience, deployment environment, and permitted capabilities."
    # known-key-1 is the normal production guest-adapter key; restricted-key-1 models a
    # cryptographically valid, known key that was never granted guest.answer (the 403
    # capability_forbidden case); preview-key-1 models a valid, known, guest.answer-granted key
    # whose bound environment is "preview", not "production" — RC2 §7.1's "Production and
    # nonproduction keys are distinct and non-interchangeable" and acceptance criterion 9's
    # "a preview token fails against production" (added per Lyra's review of the first cut).
    default_key_metadata = {
        "known-key-1": {"environment": "production", "capabilities": ["guest.answer"]},
        "restricted-key-1": {"environment": "production", "capabilities": ["some.other.capability"]},
        "preview-key-1": {"environment": "preview", "capabilities": ["guest.answer"]},
    }

    def emit(
        name: str,
        expect: str,
        ref: str,
        desc: str,
        claims: dict,
        *,
        alg: str = "EdDSA",
        kid: str = "known-key-1",
        evaluated_at: int = 1_000_000,
        violated_rule: str | None = None,
        expect_error_code: str | None = None,
        key_metadata: dict | None = None,
        serving_environment: str = "production",
    ) -> None:
        nonlocal n
        n += 1
        if expect_error_code is None and expect == "reject":
            expect_error_code = "authentication_failed"
        metadata = key_metadata or default_key_metadata
        write(
            VECTORS / "auth" / f"auth.{n:03d}.json",
            {
                "vector_id": f"auth.{n:03d}",
                "kind": "auth-claims",
                "expect": expect,
                "expect_error_code": expect_error_code,
                "contract_reference": ref,
                "description": desc,
                "header": {"alg": alg, "kid": kid},
                "claims": claims,
                "known_kids": list(metadata.keys()),
                "key_metadata": metadata,
                "serving_environment": serving_environment,
                "evaluated_at": evaluated_at,
                "violated_rule": violated_rule,
            },
        )

    emit("valid", "accept", "§7.2", "A fully valid claim set.", base_claims())

    emit("wrong-iss", "reject", "§7.2", "iss does not match the required issuer.", {**base_claims(), "iss": "stoin:application:someone-else"}, violated_rule="iss")
    emit("wrong-sub", "reject", "§7.2", "sub does not match the required subject.", {**base_claims(), "sub": "stoin:service:impersonator"}, violated_rule="sub")
    emit("wrong-aud", "reject", "§7.2", "aud does not match the required audience.", {**base_claims(), "aud": "stoin:business:someone-else"}, violated_rule="aud")
    emit("wrong-scope", "reject", "§7.2", "scope is not the exact string guest.answer.", {**base_claims(), "scope": "guest.answer.extended"}, violated_rule="scope")

    for claim in ["iss", "sub", "aud", "scope", "iat", "nbf", "exp", "jti"]:
        c = base_claims()
        del c[claim]
        emit(f"missing-{claim}", "reject", "§7.2", f"{claim} is absent from the claim set.", c, violated_rule=claim)

    nbf_ne_iat = base_claims()
    nbf_ne_iat["nbf"] = nbf_ne_iat["iat"] + 5
    emit("nbf-not-equal-iat", "reject", "§7.2", "nbf != iat, which RC2 requires to hold exactly.", nbf_ne_iat, violated_rule="nbf==iat")

    iat_after_exp = base_claims()
    iat_after_exp["iat"] = iat_after_exp["exp"]
    emit("iat-not-before-exp", "reject", "§7.2", "iat is not strictly before exp.", iat_after_exp, violated_rule="iat<exp")

    lifetime_over = base_claims()
    lifetime_over["exp"] = lifetime_over["iat"] + 301
    emit("lifetime-exceeds-300s", "reject", "§7.2", "exp - iat exceeds the 300-second maximum.", lifetime_over, violated_rule="exp-iat<=300")

    iat_future = base_claims()
    iat_future["iat"] = 1_000_031
    iat_future["nbf"] = 1_000_031
    emit("iat-too-far-future", "reject", "§7.2", "iat is more than 30 seconds ahead of the evaluation instant.", iat_future, evaluated_at=1_000_000, violated_rule="iat-futurity")

    bad_jti = base_claims()
    bad_jti["jti"] = "not-a-uuid"
    emit("jti-not-uuid", "reject", "§7.2", "jti is not a UUID v4.", bad_jti, violated_rule="jti")

    emit("unknown-kid", "reject", "§7.1", "The JWT header's kid is not in the provider's allowlist.", base_claims(), kid="unrecognized-key", violated_rule="kid")
    emit("wrong-algorithm", "reject", "§7.1", "The JWT header declares an algorithm other than EdDSA (classic algorithm-confusion attempt).", base_claims(), alg="HS256", violated_rule="alg")

    at_boundary = base_claims()
    emit("accepted-at-exp-plus-30", "accept", "§7.2", "Evaluated exactly at exp+30 — the latest accepted instant.", at_boundary, evaluated_at=at_boundary["exp"] + 30)

    past_boundary = base_claims()
    emit("rejected-after-exp-plus-30", "reject", "§7.2", "Evaluated one second past exp+30.", past_boundary, evaluated_at=past_boundary["exp"] + 31, violated_rule="exp+30")

    # The 401-vs-403 distinction (§7.2): a fully valid, authentic token — correct signature/kid,
    # correct scope claim value, correct timing — whose KEY is simply not permitted for
    # guest.answer. Every prior "reject" vector above is a 401 case (bad/missing/malformed
    # claims); this is the only 403 case v1.0's single-capability design can exercise.
    restricted = base_claims()
    emit(
        "authenticated-but-capability-not-permitted",
        "reject",
        "§7.2",
        "Signature, kid, and every claim value are valid, but the key's local capability binding does not include guest.answer — 403 capability_forbidden, not 401.",
        restricted,
        kid="restricted-key-1",
        violated_rule="key-capability-binding",
        expect_error_code="capability_forbidden",
    )

    # Preview-vs-production key non-interchangeability (§7.1, acceptance criterion 9). Both
    # directions: a preview key presented while serving production traffic, and a production
    # key presented while serving preview traffic. Both are 401, not 403 — this is an identity/
    # environment-binding mismatch, not a valid identity lacking a capability grant.
    preview_in_prod = base_claims()
    emit(
        "preview-key-against-production",
        "reject",
        "§7.1",
        "A fully valid, known, guest.answer-granted key — but bound to the preview environment — presented while serving production traffic.",
        preview_in_prod,
        kid="preview-key-1",
        serving_environment="production",
        violated_rule="key-environment-binding",
        expect_error_code="authentication_failed",
    )

    production_in_preview = base_claims()
    emit(
        "production-key-against-preview",
        "reject",
        "§7.1",
        "The reverse: a valid production key presented while serving preview traffic.",
        production_in_preview,
        kid="known-key-1",
        serving_environment="preview",
        violated_rule="key-environment-binding",
        expect_error_code="authentication_failed",
    )

    print(f"auth vectors: {n}")


def generate_jti_replay_vectors() -> None:
    """RC2 §7.2: 'The provider atomically records a content-free digest of each accepted jti...
    and rejects replay.' The claim-shape vectors above only prove jti is a well-formed UUID v4;
    they cannot prove replay-rejection, which is a property of two requests sharing the same
    provider-side state, not of one token in isolation."""
    n = 0

    def emit(name: str, ref: str, desc: str, sequence: list[dict]) -> None:
        nonlocal n
        n += 1
        write(
            VECTORS / "auth" / f"jti-replay.{n:03d}.json",
            {
                "vector_id": f"jti-replay.{n:03d}",
                "kind": "jti-replay",
                "contract_reference": ref,
                "description": desc,
                "sequence": sequence,
            },
        )

    shared_jti = uid(8)
    first = base_claims()
    first["jti"] = shared_jti
    second = base_claims()
    second["jti"] = shared_jti
    second["iat"] += 1
    second["nbf"] += 1
    second["exp"] += 1

    emit(
        "same-jti-twice-rejected",
        "§7.2",
        "Two otherwise-independently-valid tokens sharing one jti: the first is accepted and recorded; the second, still within the recorded jti's acceptance window, is rejected as a replay.",
        [
            {"claims": first, "kid": "known-key-1", "evaluated_at": first["iat"], "expect": "accept"},
            {"claims": second, "kid": "known-key-1", "evaluated_at": second["iat"], "expect": "reject", "reason": "jti-replay"},
        ],
    )

    distinct_jti = base_claims()
    distinct_jti["jti"] = uid(9)
    distinct_second = base_claims()
    distinct_second["jti"] = uid(10)
    distinct_second["iat"] += 1
    distinct_second["nbf"] += 1
    distinct_second["exp"] += 1
    emit(
        "distinct-jti-both-accepted",
        "§7.2",
        "Two independently-valid tokens with DIFFERENT jti values: both are accepted — confirms the checker isn't just rejecting every second request.",
        [
            {"claims": distinct_jti, "kid": "known-key-1", "evaluated_at": distinct_jti["iat"], "expect": "accept"},
            {"claims": distinct_second, "kid": "known-key-1", "evaluated_at": distinct_second["iat"], "expect": "accept"},
        ],
    )

    print(f"jti replay vectors: {n}")


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------
# Canonicalization vectors (§11.2) — dedicated, beyond the general I-B10 invariant vectors
# --------------------------------------------------------------------------------------


def generate_canonicalization_vectors() -> None:
    n = 0

    def emit(name: str, ref: str, desc: str, a: dict, b: dict, same: bool) -> None:
        nonlocal n
        n += 1
        write(
            VECTORS / "canonicalization" / f"canon.{n:03d}.json",
            {
                "vector_id": f"canon.{n:03d}",
                "kind": "canonicalization",
                "contract_reference": ref,
                "description": desc,
                "documents": {"a": a, "b": b, "same_canonical_identity": same},
            },
        )

    a = base_request()
    b = json.loads(json.dumps({k: a[k] for k in reversed(list(a.keys()))}))
    emit("reordered-top-level-members", "§11.2", "Top-level member order differs; canonical identity is unchanged.", a, b, True)

    c = base_request()
    d = copy.deepcopy(c)
    d["message"] = json.loads(json.dumps({k: d["message"][k] for k in reversed(list(d["message"].keys()))}))
    emit("reordered-nested-members", "§11.2", "Nested (message) member order differs; canonical identity is unchanged.", c, d, True)

    e = base_request()
    f = copy.deepcopy(e)
    del f["history"]
    emit("omitted-vs-present-empty-history", "§11.2", "history omitted (e) vs. history present as [] is not shown here — this instead pairs the full worked example against the same request with history OMITTED, which RC2 §11.2 rule 4 says is preserved as omitted rather than normalized: they are different canonical requests.", e, f, False)

    g = base_request()
    h = copy.deepcopy(g)
    h["history"] = list(reversed(h["history"]))
    emit("reordered-history-array", "§11.2", "history array order changed (still schema-valid on its own axis); array ordering is significant per §11.2.", g, h, False)

    i_doc = base_request()
    j_doc = copy.deepcopy(i_doc)
    j_doc["message"]["content"] = j_doc["message"]["content"].replace("home", "property")
    emit("changed-content", "§11.2", "message.content changed; canonical identity changes.", i_doc, j_doc, False)

    print(f"canonicalization vectors: {n}")


# --------------------------------------------------------------------------------------
# Header-level vectors (§6, §8, §12.2, §17) — a class of RC2 rule the body schemas cannot
# express at all, since headers aren't part of the JSON body. Covers exactly the gaps the
# coverage map identified: §8's header UUID-v4 format/required-presence, §9.1's prohibition on
# query parameters, §12.2's release-header format, and §17's Retry-After bounds.
# --------------------------------------------------------------------------------------


def generate_header_vectors() -> None:
    n = 0

    def emit(name: str, ref: str, desc: str, rule: str, cases: list[dict]) -> None:
        nonlocal n
        n += 1
        write(
            VECTORS / "headers" / f"headers.{n:03d}.json",
            {
                "vector_id": f"headers.{n:03d}",
                "kind": "header-format",
                "contract_reference": ref,
                "description": desc,
                "rule": rule,
                "cases": cases,
            },
        )

    emit(
        "request-id-format",
        "§8",
        "X-Request-ID must be a canonical lowercase UUID v4; RC2 §8 explicitly types it the same as the body's UUID v4 fields.",
        "uuid_v4",
        [
            {"value": "5a6a3c4e-1b2c-4d5e-89ab-1234567890ab", "expect": "valid"},
            {"value": None, "expect": "invalid", "reason": "missing"},
            {"value": "not-a-uuid", "expect": "invalid", "reason": "malformed"},
            {"value": "5A6A3C4E-1B2C-4D5E-89AB-1234567890AB", "expect": "invalid", "reason": "uppercase (RC2 §3 requires canonical lowercase)"},
        ],
    )

    emit(
        "idempotency-key-format",
        "§8",
        "Idempotency-Key must be a canonical lowercase UUID v4, identical treatment to X-Request-ID.",
        "uuid_v4",
        [
            {"value": "5a6a3c4e-1b2c-4d5e-89ab-1234567890ab", "expect": "valid"},
            {"value": None, "expect": "invalid", "reason": "missing"},
            {"value": "not-a-uuid", "expect": "invalid", "reason": "malformed"},
        ],
    )

    emit(
        "release-header-format",
        "§12.2",
        "X-Utopia-Business-Release and X-Utopia-Knowledge-Release must be 1-128 visible ASCII characters, no whitespace.",
        "release_id",
        [
            {"value": "homes-business:release:2026-09-16.1", "expect": "valid"},
            {"value": "x" * 128, "expect": "valid"},
            {"value": "x" * 129, "expect": "invalid", "reason": "exceeds 128 characters"},
            {"value": "", "expect": "invalid", "reason": "below 1 character"},
            {"value": "has a space", "expect": "invalid", "reason": "contains whitespace"},
            {"value": "has\ttab", "expect": "invalid", "reason": "contains a non-visible control character"},
        ],
    )

    emit(
        "retry-after-bounds",
        "§17",
        "Retryable error responses include integer Retry-After seconds between 1 and 30.",
        "retry_after",
        [
            {"value": 1, "expect": "valid"},
            {"value": 30, "expect": "valid"},
            {"value": 0, "expect": "invalid", "reason": "below minimum"},
            {"value": 31, "expect": "invalid", "reason": "above maximum"},
            {"value": 15.5, "expect": "invalid", "reason": "not an integer"},
        ],
    )

    emit(
        "query-parameters-prohibited",
        "§8",
        "Query parameters are prohibited in v1.0; a request with any query string must be rejected as invalid_request before body parsing.",
        "no_query_params",
        [
            {"value": "", "expect": "valid"},
            {"value": "foo=bar", "expect": "invalid", "reason": "query parameters are prohibited"},
            {"value": "contract_version=1.0", "expect": "invalid", "reason": "query parameters are prohibited, even ones naming a real body field"},
        ],
    )

    emit(
        "cache-control-no-store",
        "§6",
        "Every response — success or error — MUST include Cache-Control: no-store.",
        "cache_control",
        [
            {"value": "no-store", "expect": "valid"},
            {"value": None, "expect": "invalid", "reason": "header absent"},
            {"value": "no-cache", "expect": "invalid", "reason": "wrong directive"},
            {"value": "no-store, max-age=0", "expect": "invalid", "reason": "RC2 requires exactly no-store, not a superset directive list"},
        ],
    )

    emit(
        "no-set-cookie",
        "§6",
        "Responses MUST NOT set cookies.",
        "no_set_cookie",
        [
            {"value": None, "expect": "valid"},
            {"value": "session=abc123; Path=/", "expect": "invalid", "reason": "Set-Cookie present"},
        ],
    )

    emit(
        "accept-header-required",
        "§8",
        "Every request MUST include Accept: application/json.",
        "accept_header",
        [
            {"value": "application/json", "expect": "valid"},
            {"value": None, "expect": "invalid", "reason": "header absent"},
            {"value": "text/html", "expect": "invalid", "reason": "wrong media type"},
            {"value": "application/xml", "expect": "invalid", "reason": "wrong media type"},
        ],
    )

    emit(
        "content-type-header-required",
        "§8",
        "Every request MUST include Content-Type: application/json.",
        "content_type_header",
        [
            {"value": "application/json", "expect": "valid"},
            {"value": None, "expect": "invalid", "reason": "header absent"},
            {"value": "application/x-www-form-urlencoded", "expect": "invalid", "reason": "wrong media type"},
            {"value": "text/plain", "expect": "invalid", "reason": "wrong media type"},
        ],
    )

    emit(
        "authorization-bearer-framing",
        "§8",
        "Authorization must be exactly 'Bearer <token>' framing — no other scheme, no missing token.",
        "authorization_framing",
        [
            {"value": "Bearer eyJhbGciOiJFZERTQSJ9.abc.def", "expect": "valid"},
            {"value": None, "expect": "invalid", "reason": "header absent"},
            {"value": "Basic dXNlcjpwYXNz", "expect": "invalid", "reason": "wrong auth scheme"},
            {"value": "Bearer", "expect": "invalid", "reason": "scheme with no token"},
            {"value": "bearer eyJ...", "expect": "invalid", "reason": "scheme must be exactly 'Bearer' (case-sensitive per RFC 7235's usual convention and RC2's own literal header example)"},
        ],
    )

    print(f"header vectors: {n}")


# --------------------------------------------------------------------------------------
# Transport-level, pre-parse raw-body vectors (§6, §11.2) — operate on literal request-body
# TEXT rather than a parsed Python dict, which is what makes both of these rules reachable at
# all: a dict cannot represent two keys with the same name, and inserting legal insignificant
# whitespace to hit an exact byte count is a text-level operation with no dict equivalent.
# Added after Lyra's review of the first Tier A cut identified both as reachable, normative
# gaps rather than the acceptable exclusions the original coverage map had called them.
# --------------------------------------------------------------------------------------


def _compact(doc: dict) -> str:
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False)


def _pad_to_byte_length(doc: dict, target_bytes: int) -> str:
    """Inserts legal insignificant whitespace immediately after the opening '{' so the padded
    text is exactly target_bytes long and still parses to the identical document — proving the
    64 KiB limit is reachable by a schema-valid request, not just by malformed oversized input."""
    compact = _compact(doc)
    base_len = len(compact.encode("utf-8"))
    pad_needed = target_bytes - base_len
    if pad_needed < 0:
        raise ValueError(f"base document is already {base_len} bytes; cannot pad down to {target_bytes}")
    padded = "{" + (" " * pad_needed) + compact[1:]
    actual = len(padded.encode("utf-8"))
    assert actual == target_bytes, (actual, target_bytes)
    assert json.loads(padded) == doc, "padding changed the parsed document"
    return padded


def generate_transport_vectors() -> None:
    n = 0

    def emit(
        name: str, ref: str, desc: str, raw_body: str, expect: str, note: str, *, schema: str = "request"
    ) -> None:
        nonlocal n
        n += 1
        write(
            VECTORS / "transport" / f"transport.{n:03d}.json",
            {
                "vector_id": f"transport.{n:03d}",
                "kind": "raw-body",
                "schema": schema,
                "contract_reference": ref,
                "description": desc,
                "raw_body": raw_body,
                "byte_length": len(raw_body.encode("utf-8")),
                "expect": expect,
                "note": note,
            },
        )

    # --- §6: request body MUST NOT exceed 64 KiB (65536 bytes) ---
    small_valid_request = base_request()
    del small_valid_request["history"]
    del small_valid_request["page_context"]

    at_limit = _pad_to_byte_length(small_valid_request, 65536)
    emit(
        "body-exactly-65536-bytes",
        "§6",
        "A schema-valid request padded with insignificant whitespace to exactly the 64 KiB limit — accepted.",
        at_limit,
        "accepted",
        "Proves the limit is reachable by whitespace padding alone, per Lyra's review: JSON permits arbitrary insignificant whitespace between tokens, so a request can be schema-valid and still be exactly at (or past) the byte ceiling.",
    )

    over_limit = _pad_to_byte_length(small_valid_request, 65537)
    emit(
        "body-65537-bytes-rejected",
        "§6",
        "One byte past the 64 KiB limit, otherwise identical to the accepted case above — rejected as request_too_large (413) before the (otherwise schema-valid) body is even evaluated.",
        over_limit,
        "request_too_large",
        "The parsed document is schema-valid; only its raw byte length triggers rejection.",
    )

    # --- §11.2: 'decodes strict UTF-8 JSON and rejects duplicate member names' ---
    top_level_dup = (
        '{"contract_version":"1.0","contract_version":"1.1","session_id":"27b20c7b-777e-4af3-8db1-5fe1fc2f3b7e",'
        '"message":{"turn_id":"056d5f10-ed13-44fa-b8bc-1af90d43dceb","content":"Hello"},"locale":"en-US"}'
    )
    emit(
        "duplicate-member-top-level",
        "§11.2",
        "contract_version appears twice at the top level of the request object.",
        top_level_dup,
        "invalid_request",
        "Most JSON decoders silently keep the last value and never surface the duplication — RC2 requires explicit rejection during decoding, before validation or model execution.",
    )

    nested_dup = (
        '{"contract_version":"1.0","session_id":"27b20c7b-777e-4af3-8db1-5fe1fc2f3b7e",'
        '"message":{"turn_id":"056d5f10-ed13-44fa-b8bc-1af90d43dceb","content":"Hello","content":"Goodbye"},'
        '"locale":"en-US"}'
    )
    emit(
        "duplicate-member-nested",
        "§11.2",
        "message.content appears twice inside the nested message object.",
        nested_dup,
        "invalid_request",
        "The duplication is nested, not top-level — confirms rejection isn't just a top-level-only check.",
    )

    # --- §6: response body MUST NOT exceed 64 KiB — a SEPARATE boundary from the request side.
    # Added per Lyra's review: request admission and response emission are different code paths
    # (consumer-side body-size enforcement vs. provider-side), so proving one doesn't prove the
    # other even though the numeric limit and mechanism (whitespace padding) are identical. ---
    small_valid_response = base_response()
    small_valid_response["sources"] = []
    small_valid_response["actions"] = []

    resp_at_limit = _pad_to_byte_length(small_valid_response, 65536)
    emit(
        "response-body-exactly-65536-bytes",
        "§6",
        "A schema-valid SUCCESS RESPONSE padded to exactly the 64 KiB limit — accepted.",
        resp_at_limit,
        "accepted",
        "Separate boundary from the request-side transport.001/002: response emission is a different code path (Prime constructing its own output) from request admission (the consumer's body validated on the way in).",
        schema="response",
    )

    resp_over_limit = _pad_to_byte_length(small_valid_response, 65537)
    emit(
        "response-body-65537-bytes-rejected",
        "§6",
        "One byte past the 64 KiB limit for a response body — this is a provider-side internal-consistency check (§6's limit applies to both directions), surfaced as answer_validation_failed or temporarily_unavailable rather than request_too_large, since request_too_large is specifically the REQUEST-side code (§17).",
        resp_over_limit,
        "over_limit",
        "The parsed document is schema-valid as a response; only its raw byte length exceeds the ceiling. Unlike the request side, RC2's error table has no response-body-specific code — this vector proves the SIZE fact only, not which of Prime's own internal failure codes it should surface as.",
        schema="response",
    )

    print(f"transport vectors: {n}")


# --------------------------------------------------------------------------------------
# Exchange-level vectors (§7-8, §12.2, §17) — relationships between a request's headers and its
# response's headers/body that no single-document header-format or body-schema vector can
# express: the ECHOED value must equal the SENT value, and two independently-generated
# identifiers must be genuinely distinct, not just individually well-formed. Added per Lyra's
# review of the second Tier A cut.
# --------------------------------------------------------------------------------------


def generate_exchange_vectors() -> None:
    n = 0

    def emit(name: str, ref: str, desc: str, expect: str, exchange: dict) -> None:
        nonlocal n
        n += 1
        write(
            VECTORS / "exchange" / f"exchange.{n:03d}.json",
            {
                "vector_id": f"exchange.{n:03d}",
                "kind": "exchange",
                "expect": expect,
                "contract_reference": ref,
                "description": desc,
                "exchange": exchange,
            },
        )

    inbound_id = "5a6a3c4e-1b2c-4d5e-89ab-1234567890ab"
    emit(
        "request-id-echoed-unchanged",
        "§8",
        "The provider returns X-Request-ID unchanged from what the consumer sent.",
        "hold",
        {"check": "request_id_echo", "inbound_x_request_id": inbound_id, "outbound_x_request_id": inbound_id},
    )
    emit(
        "request-id-not-echoed-unchanged",
        "§8",
        "WRONG: the outbound X-Request-ID differs from the inbound one (e.g. a provider that normalizes case, or substitutes its own value).",
        "violation",
        {
            "check": "request_id_echo",
            "inbound_x_request_id": inbound_id,
            "outbound_x_request_id": inbound_id.upper(),
        },
    )

    emit(
        "correlation-id-distinct-from-request-id",
        "§17",
        "An error response's body correlation_id is a freshly-generated value, distinct from the caller's X-Request-ID — never a copy of it.",
        "hold",
        {
            "check": "correlation_id_distinct",
            "x_request_id": inbound_id,
            "correlation_id": "b139a2b0-61f2-4523-99ad-aa4c67db2cdc",
        },
    )
    emit(
        "correlation-id-equals-request-id",
        "§17",
        "WRONG: correlation_id happens to equal X-Request-ID — the exact bug this check exists to catch (e.g. a naive implementation that copies the request ID instead of minting a fresh correlation ID).",
        "violation",
        {"check": "correlation_id_distinct", "x_request_id": inbound_id, "correlation_id": inbound_id},
    )

    emit(
        "release-headers-required-on-success",
        "§12.2",
        "A successful response MUST include both X-Utopia-Business-Release and X-Utopia-Knowledge-Release — presence, not just format (format is separately covered by headers.003).",
        "hold",
        {
            "check": "release_headers_present",
            "headers": {
                "X-Utopia-Business-Release": "homes-business:release:2026-09-16.1",
                "X-Utopia-Knowledge-Release": "homes-knowledge:projection:2026-09-16.1",
            },
        },
    )
    emit(
        "release-headers-missing-business",
        "§12.2",
        "WRONG: X-Utopia-Business-Release is absent from an otherwise-successful response.",
        "violation",
        {
            "check": "release_headers_present",
            "headers": {"X-Utopia-Knowledge-Release": "homes-knowledge:projection:2026-09-16.1"},
        },
    )
    emit(
        "release-headers-missing-knowledge",
        "§12.2",
        "WRONG: X-Utopia-Knowledge-Release is absent from an otherwise-successful response.",
        "violation",
        {
            "check": "release_headers_present",
            "headers": {"X-Utopia-Business-Release": "homes-business:release:2026-09-16.1"},
        },
    )

    print(f"exchange vectors: {n}")


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    generate_request_vectors()
    generate_response_vectors()
    generate_error_vectors()
    generate_invariant_vectors()
    generate_auth_vectors()
    generate_jti_replay_vectors()
    generate_canonicalization_vectors()
    generate_header_vectors()
    generate_transport_vectors()
    generate_exchange_vectors()
