"""Machine-checkable invariant logic for guest.answer@1.0 RC2 (see vectors/invariants/invariants.json
for the normative definition of each). Each function raises AssertionError on violation and returns
normally when the invariant holds. `documents` is the vector's own `documents` object — the exact
shape depends on the invariant (see the docstring of each check).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

try:
    import rfc8785
except ImportError:  # pragma: no cover
    rfc8785 = None


def check_i_b01(documents: dict[str, Any]) -> None:
    """documents = {"request": <request body>}"""
    total = sum(len(entry["content"]) for entry in documents["request"].get("history", []))
    if total > 10000:
        raise AssertionError(f"I-B01 violated: history content totals {total} characters (> 10000)")


def check_i_b02(documents: dict[str, Any]) -> None:
    """documents = {"request": <request body>}"""
    history = documents["request"].get("history", [])
    if not history:
        return
    if history[0]["role"] != "user":
        raise AssertionError("I-B02 violated: history does not begin with 'user'")
    if history[-1]["role"] != "assistant":
        raise AssertionError("I-B02 violated: history does not end with 'assistant'")
    for prev, cur in zip(history, history[1:]):
        if prev["role"] == cur["role"]:
            raise AssertionError("I-B02 violated: two consecutive history entries share a role")


def check_i_b03(documents: dict[str, Any]) -> None:
    """documents = {"request": <request body>}"""
    request = documents["request"]
    history = request.get("history", [])
    turn_ids = [request["message"]["turn_id"]] + [e["turn_id"] for e in history]
    if len(set(turn_ids)) != len(turn_ids):
        raise AssertionError("I-B03 violated: turn_id collision between message and/or history entries")


def check_i_b04(documents: dict[str, Any]) -> None:
    """documents = {"request": <request body>, "response": <response body>}"""
    if documents["request"]["session_id"] != documents["response"]["session_id"]:
        raise AssertionError("I-B04 violated: response.session_id does not match request.session_id")


def check_i_b05(documents: dict[str, Any]) -> None:
    """documents = {"response": <response body>}"""
    sources = documents["response"]["sources"]
    ids = [s["source_id"] for s in sources]
    urls = [s["url"] for s in sources]
    if len(set(ids)) != len(ids):
        raise AssertionError("I-B05 violated: duplicate source_id within sources")
    if len(set(urls)) != len(urls):
        raise AssertionError("I-B05 violated: duplicate url within sources")


def check_i_b06(documents: dict[str, Any]) -> None:
    """documents = {"response": <response body>}"""
    actions = documents["response"]["actions"]
    ids = [a["action_id"] for a in actions]
    urls = [a["url"] for a in actions]
    if len(set(ids)) != len(ids):
        raise AssertionError("I-B06 violated: duplicate action_id within actions")
    if len(set(urls)) != len(urls):
        raise AssertionError("I-B06 violated: duplicate url within actions")


def check_i_b07(documents: dict[str, Any]) -> None:
    """documents = {"response": <response body>}. This invariant is a NON-constraint: a shared
    URL between sources and actions must NOT be flagged. The 'violation' side of this invariant's
    vectors therefore doesn't exist as a distinct check — I-B05/I-B06 already prove within-array
    uniqueness is independently enforced without accidentally pooling the two arrays together.
    This function exists so a vector can assert the cross-array sharing case explicitly holds."""
    source_urls = {s["url"] for s in documents["response"]["sources"]}
    action_urls = {a["url"] for a in documents["response"]["actions"]}
    # No assertion: overlap between source_urls and action_urls is legal. This check always
    # "holds" by construction; the vector exists to document and pin the expectation, not to
    # reject anything.
    del source_urls, action_urls


def check_i_b08(documents: dict[str, Any]) -> None:
    """documents = {"response": <response body>,
    "assumed_approved_hostnames": {"internal": [...], "external_booking": [...]},
    "assumed_approved_destinations": [<exact URLs>]}

    RC2 §12.2 states two distinct, both-normative rules this checks separately: (1) hostname
    approval keyed by action kind (the original I-B08 scope), and (2) "A source URL must exactly
    match an approved public-source destination" / actions "match an approved destination" —
    exact-URL membership in a configured allowlist, not merely a matching host. A URL can pass
    (1) while failing (2), e.g. an approved hostname serving an unapproved path. Extended per
    Lyra's review of the second Tier A cut; the original version only checked actions, not
    sources, despite RC2's source-URL rule being the more explicitly worded of the two."""
    approved_hosts = documents["assumed_approved_hostnames"]
    approved_destinations = set(documents.get("assumed_approved_destinations", []))

    for source in documents["response"]["sources"]:
        if source["url"] not in approved_destinations:
            raise AssertionError(f"I-B08 violated: source url {source['url']!r} is not an approved destination")

    for action in documents["response"]["actions"]:
        host = urlsplit(action["url"]).hostname
        if action["kind"] in ("open_internal_link", "contact_utopia"):
            if host not in approved_hosts["internal"]:
                raise AssertionError(f"I-B08 violated: {action['kind']} action uses non-approved internal host {host!r}")
        elif action["kind"] == "open_external_booking_link":
            if host not in approved_hosts["external_booking"]:
                raise AssertionError(f"I-B08 violated: open_external_booking_link uses non-approved host {host!r}")
        if action["url"] not in approved_destinations:
            raise AssertionError(f"I-B08 violated: action url {action['url']!r} is not an approved destination")


def check_i_b09(documents: dict[str, Any]) -> None:
    """documents = {"state": {"durable_status": "in_progress"|"completed"|"unresolved"|"none",
    "volatile_content_present": bool, "canonical_request_matches": bool, "still_eligible": bool},
    "expected_outcome": "replay"|"idempotency_conflict"|"request_in_progress"|
    "idempotency_recovery_unavailable"|"response_invalidated"|"new_execution"}
    Implements the §11 decision table and asserts the vector's expected_outcome matches it."""
    state = documents["state"]
    expected = documents["expected_outcome"]

    if state["durable_status"] == "none":
        computed = "new_execution"
    elif not state["canonical_request_matches"]:
        computed = "idempotency_conflict"
    elif state["durable_status"] == "in_progress":
        computed = "request_in_progress"
    elif not state["volatile_content_present"]:
        computed = "idempotency_recovery_unavailable"
    elif not state["still_eligible"]:
        computed = "response_invalidated"
    else:
        computed = "replay"

    if computed != expected:
        raise AssertionError(f"I-B09 violated: state implies {computed!r}, vector declares {expected!r}")


def check_i_b10(documents: dict[str, Any]) -> None:
    """documents = {"a": <request body>, "b": <request body>, "same_canonical_identity": bool}"""
    if rfc8785 is None:
        raise RuntimeError("rfc8785 is required to check I-B10")
    digest_a = rfc8785.dumps(documents["a"])
    digest_b = rfc8785.dumps(documents["b"])
    actually_same = digest_a == digest_b
    if actually_same != documents["same_canonical_identity"]:
        raise AssertionError(
            f"I-B10 violated: canonicalized bytes equal={actually_same}, "
            f"vector declares same_canonical_identity={documents['same_canonical_identity']}"
        )


CHECKS = {
    "I-B01": check_i_b01,
    "I-B02": check_i_b02,
    "I-B03": check_i_b03,
    "I-B04": check_i_b04,
    "I-B05": check_i_b05,
    "I-B06": check_i_b06,
    "I-B07": check_i_b07,
    "I-B08": check_i_b08,
    "I-B09": check_i_b09,
    "I-B10": check_i_b10,
}
