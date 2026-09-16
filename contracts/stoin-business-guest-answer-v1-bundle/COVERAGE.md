# RC2 wire-rule coverage map

Built by walking RC2 §§3, 6, 7, 8, 9, 11, 12, 16, 17 section by section and cross-referencing
every normative (MUST/MUST NOT) wire-level rule against the vector(s) that exercise it. Built
*after* the bundle, specifically to find what the bundle was silently missing. Three rounds of
real gaps were found this way, each surfaced by an external, independent review rather than by
this document's own first pass being complete: three gaps while first writing this map
(header-format vectors, jti-replay vectors, the 401-vs-403 distinction); three more when Lyra
rejected the first version's "acknowledged gap" excuses (the byte limit is reachable via
insignificant-whitespace padding, and two others were things this bundle hadn't built rather
than things it couldn't); and a further eight when Lyra's second review found this document
itself had stopped one layer too shallow — separate response-body byte bounds, response-header
presence checks, request-header presence checks, exact-destination matching (not just hostname
approval), and mechanically verifying two fixtures that had only ever been prose. All are now
closed; see "Gaps found, then closed" near the bottom for the full history.

## §3 — global rules

| Rule | Covered by |
| --- | --- |
| Character bounds count Unicode scalar values after UTF-8/JSON decoding | Implicit in every length-bounded field's vectors (e.g. `request.pos.006`/`007` at the 1/2000-char message.content boundary) |
| UUID v4 = canonical lowercase RFC 4122 form | `request.neg.005` (uppercase), `request.neg.006` (version nibble), `headers.001` case 4 (uppercase X-Request-ID), all `common.defs.json` `uuidV4` users |

## §6 — endpoint and transport

| Rule | Covered by |
| --- | --- |
| HTTPS/TLS 1.2+ | **Not covered** — infrastructure-level, outside what a JSON vector can represent (same exclusion RC3's Management Contract bundle made for its own transport rules) |
| Accept/return UTF-8 JSON | Implicit (every vector is UTF-8 JSON) |
| Server-side call only / no browser credentials | **Not covered** — architectural/deployment concern, not a wire shape |
| No redirect to another host | **Not covered** — infrastructure-level |
| 15s provider attempt / 22s consumer total deadline | Documented as data in `fixtures/consumer/retry-policy.json`; not independently checkable without a running server (this is exactly the boundary Tier A vs. a live conformance run draws) |
| Request body ≤ 64 KiB | `transport.001` (65,536 bytes, accepted), `transport.002` (65,537 bytes, rejected) — both built from a schema-valid document padded with legal insignificant whitespace, proving the limit is reachable by an otherwise-valid request, not just malformed oversized input |
| Response body ≤ 64 KiB | `transport.005`/`.006` — the identical boundary and mechanism, proven separately on the response schema per Lyra's review (request admission and response emission are different code paths, so one proof doesn't stand in for the other) |
| `Cache-Control: no-store` on every response | `headers.006` |
| No `Set-Cookie` on responses | `headers.007` |

## §7 — service authentication

| Rule | Covered by |
| --- | --- |
| `alg=EdDSA` | `auth.017` (wrong-algorithm / HS256 confusion) |
| `kid` from allowlist | `auth.016` (unknown-kid) |
| Locally verified, no Control/introspection call | Architectural — not a wire shape |
| Dedicated key, not reused across contracts | Architectural/deployment — not vector-testable |
| Max 300s lifetime, ≤30s skew | `auth.010`–`auth.015`, `auth.021`, `auth.022` (boundary at exp+30/exp+31) |
| Per-key local binding of iss/sub/aud/env/capabilities | `auth.023` (`authenticated-but-capability-not-permitted` — the 403 case) |
| Production/nonproduction keys distinct | `auth.024` (`preview-key-against-production`), `auth.025` (`production-key-against-preview`) — both 401 `authentication_failed`, distinguishing this identity-binding failure from the capability-grant failure `auth.023` tests |
| `iss`/`sub`/`aud`/`scope` exact match | `auth.002`–`auth.005` |
| `iat`/`nbf`/`exp` arithmetic (`nbf==iat`, `iat<exp`, `exp-iat<=300`, futurity) | `auth.006`–`auth.009`, `auth.018` |
| `jti` UUID v4 shape | `auth.013` |
| `jti` replay rejected | `jti-replay.001`, `jti-replay.002` |
| Auth established before body interpretation | Architectural ordering — not vector-testable statically |
| 401 vs. 403 distinction | `auth.023` closes this; every other `reject` auth vector asserts `authentication_failed` explicitly via `expect_error_code` |
| Browser adapter's own same-origin/rate/session limits | Consumer-side (website), out of Homes-provider Tier A scope by design (§5 ownership) |

## §8 — required headers

| Rule | Covered by |
| --- | --- |
| `X-Request-ID` UUID v4 format | `headers.001` |
| `X-Request-ID` echoed unchanged (the relational half, not just format) | `exchange.001` (holds), `exchange.002` (a wrong-case echo is caught as a violation) |
| `Idempotency-Key` UUID v4 | `headers.002` |
| `Accept: application/json` required | `headers.008` |
| `Content-Type: application/json` required | `headers.009` |
| `Authorization: Bearer <token>` framing | `headers.010` |
| Query parameters prohibited | `headers.005` |
| Unknown/malformed required header → 400 (except auth → 401) | Implicit in `headers.001`/`.002`'s invalid cases; the specific HTTP-code mapping is documented, not independently re-derived, since Tier A vectors don't model a live HTTP exchange |

## §9 — request body

Comprehensively covered — `request.pos.*` (9), `request.neg.*` (30), and invariants I-B01/I-B02/I-B03
cover contract_version, session_id/turn_id shape, message.content bounds, history bounds/roles/
alternation/uniqueness, page_context path/subject_type/subject_id (including the empty-string
and none↔null edge cases), locale, and the unknown-member rejection rule.

## §11 — idempotency, retry, canonicalization

| Rule | Covered by |
| --- | --- |
| Idempotency-Key scoping (identity+env+operation+version) | Architectural; partially implicit in I-B09's state model |
| Atomic admission before paid execution | Architectural — not a wire shape |
| Five-branch status decision table | `I-B09` — all five branches plus the zero-prior-admission case, plus one deliberate violation |
| Consumer retry rules (one retry, fresh JWT/X-Request-ID, backoff, shrinking budget, non-retry codes) | `fixtures/consumer/retry-policy.json`, `fixtures/consumer/answer-validation-failed-non-retry-test.json` |
| Single-coordinator v1.0 replica profile | Architectural — not a wire shape |
| Canonicalization algorithm (strict UTF-8, validate-then-canonicalize, trim only `content`, preserve omitted-vs-null, RFC 8785 + SHA-256) | `I-B10`, `vectors/canonicalization/canon.*`, cross-checked against the official RFC 8785 reference vectors and an independent from-scratch implementation (`tools/jcs_reference.py`) |
| Reject duplicate JSON member names during decoding | `transport.003` (top-level duplicate), `transport.004` (nested duplicate) — raw request-body text, checked with a strict decoder that rejects any repeated key at any nesting depth |
| "Maintained, reviewed RFC 8785 library... hand-rolled not accepted" | This is a requirement on implementers; the bundle's own compliance is documented in the README and demonstrated by `check_jcs_against_official_vectors()` |

## §12 — response body

Comprehensively covered — `response.pos.*` (12), `response.neg.*` (30), and invariants
I-B04/I-B05/I-B06/I-B07/I-B08 cover the envelope, outcome enum, answer bounds, source/action
identifier grammar (including both the namespace and local-identifier length sub-bounds),
title/label/limitation bounds, URL rules (https-only, no userinfo, no fragment, ≤2048 chars),
within-array uniqueness (independent for ID and URL, with the explicit cross-array non-constraint),
hostname/action-kind approval, and session_id matching the request.

| Rule | Covered by |
| --- | --- |
| Release headers 1–128 visible ASCII (format) | `headers.003` |
| Release headers required present on every success response (presence, not just format) | `exchange.005` (both present, holds), `exchange.006`/`.007` (either one missing is a violation) |
| URL hostname approval matching action kind | `I-B08` |
| URL exact approved-destination matching (sources AND actions — the original I-B08 only checked action hostnames, not the source-URL rule RC2 states just as explicitly) | `I-B08` (extended), including two vectors specifically proving an *approved hostname serving an unapproved path* is still caught |
| "No markdown/HTML in answer" | Deliberately excluded — content-level, not schema-checkable (documented in `response.schema.json`'s own `$comment`, same boundary RC3 drew around evidentiary requirements) |

## §16 — privacy and logging

| Rule | Covered by |
| --- | --- |
| Allowed/forbidden durable telemetry fields | `fixtures/logs/privacy-safe-telemetry.json` |
| `session_id` digest: 24h max TTL, env-scoped key, no identity join | Same fixture |

Not "vector-checked" in the pass/fail sense, since this is reference documentation of an
allowlist rather than a validator-testable shape — the same treatment RC3 gave its own
log/error fixtures.

## §17 — error contract

| Rule | Covered by |
| --- | --- |
| Exact `code`/`message`/`retryable` per the 13-row table | `error.pos.*` (13, one per code) |
| `correlation_id` UUID v4 format | `error.neg.005`/`.006` |
| `correlation_id` distinct from `X-Request-ID` (the relational half) | `exchange.003` (holds), `exchange.004` (a coincidentally-equal value is caught as a violation — the exact bug class this rule guards against) |
| No internal detail leakage | `error.neg.007` (unknown member rejected) |
| `Retry-After` 1–30 integer seconds | `headers.004` |
| `answer_validation_failed` non-retryable despite 503 | `error.neg.002`, acceptance-criterion-33 fixtures, `I-B11`, and now mechanically: `fixtures/consumer/retry-policy.json` and `fixtures/consumer/answer-validation-failed-non-retry-test.json` are cross-checked by `check_retry_policy_fixture()`/`check_non_retry_test_fixture()` against the actual wire vector, not just read as prose |

## Gaps found, then closed

**Round one** (this map's first version) disclosed three gaps as acknowledged-but-open, reasoning
that all three were either out of a dict-based bundle's reach or structurally unreachable.
Lyra's review rejected all three: the byte limit is reachable (JSON permits arbitrary
insignificant whitespace between tokens, so a schema-valid document can be padded to any size),
and the other two were things Tier A hadn't built rather than things it couldn't. Closed via
`vectors/transport/` (`transport.001`–`.004`) and `auth.024`/`auth.025`.

**Round two**, after round one's fix, disclosed one remaining gap (response body's 64 KiB
limit) as acceptable-to-skip, reasoning that the request-side proof exercised "the identical
rule and mechanism." Lyra's second review rejected that too — request admission and response
emission are different code paths — and separately found this map had never actually looked at
headers as their own testable category beyond format (`X-Request-ID`/`Idempotency-Key` shape),
missing presence checks (`Accept`, `Content-Type`, `Authorization` framing, `Cache-Control`,
`Set-Cookie` absence, release-header presence), the *relational* half of two rules this map had
only checked the format half of (`X-Request-ID` echo, `correlation_id` distinctness), I-B08's
narrower-than-stated scope (hostname approval only, not RC2's separately-worded exact-destination
rule, and only for actions, not the sources RC2 names just as explicitly), and two fixtures
(`retry-policy.json`, `strict-vs-lenient-parsing.json`) that had only ever been asserted in
prose, never actually run against anything. All closed this round — see `vectors/exchange/`,
the extended `headers.006`–`.010`, the extended `I-B08`, and
`check_strict_vs_lenient_fixture()`/`check_retry_policy_fixture()`/`check_non_retry_test_fixture()`
in `tools/verify_bundle.py`.

Recorded in this much detail deliberately: the pattern across all three rounds is the same one —
this bundle's own coverage-map exercise finds real things, but each round has still needed an
external pass to find what the map itself missed. That's worth being explicit about rather than
implying the third round is the one that finally got it complete.

## Remaining acknowledged gaps

None currently disclosed. This section exists so a future revision that finds something has an
obvious place to record it, rather than letting a gap go unmentioned because there was nowhere
designated to put it.
