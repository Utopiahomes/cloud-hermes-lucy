# Utopia Homes Business Contract `guest.answer@1.0` — Tier A conformance bundle

The deterministic protocol bundle required by RC2 §22.1: JSON Schemas, positive/negative
vectors, authentication claim vectors, canonicalization vectors, cross-field invariants
(including the idempotency state machine), paired provider/consumer fixtures, and a
reproducible canonical content digest.

- **Contract revision this bundle encodes:** `guest.answer@1.0`, Release Candidate 2, frozen
  2026-09-16, Control commit `daf99943abf177f2209a6efb00e03c087bc542c6` on
  `codex/management-contract-v1` in `Utopiahomes/cloud-hermes-lucy`.
- **Schema dialect:** JSON Schema draft 2020-12, pinned exactly.
- **Built by:** Claude, Homes-side implementation steward (RC2 §22).
- **Scope:** Tier A only. RC2 explicitly splits protocol conformance (this bundle) from
  semantic/grounding evaluation (Tier B, §22.2), which requires live or recorded model
  execution and cannot be digest-pinned the same way. This bundle does not implement the
  Homes provider, the website consumer, or Shared Model Execution, and does not authorize
  deployment — see RC2 §25.

Every rule encoded here traces to an RC2 section, cited in each schema/vector's `$comment` or
`contract_reference`. If a vector and RC2 disagree, RC2 wins and the bundle is wrong.

## What is in it

```
schemas/      common.defs.json and the request/response/error schemas
vectors/
  positive/   34 responses that MUST validate — request/response/error
  negative/   68 responses that MUST be rejected, each naming the rule it violates
  invariants/ invariants.json plus 29 paired vectors for rules JSON Schema cannot express
  auth/       25 claim-shape vectors + 2 jti-replay sequences over stoin-business-jwt-v1
  canonicalization/  5 vectors over RFC 8785 canonical request identity
  headers/    10 vectors over request/response HEADER rules §6/§8/§12/§17 define (X-Request-ID
              and Idempotency-Key format, Accept/Content-Type/Authorization framing,
              Cache-Control, no-Set-Cookie, release-header format, Retry-After, query-param
              prohibition) — a wire-rule class the JSON body schemas cannot represent at all
  transport/  6 raw-text vectors: the 64 KiB body limit at exactly 65,536/65,537 bytes, checked
              separately on BOTH the request and response schema (reached via legal insignificant
              whitespace padding around an otherwise schema-valid document), and top-level/nested
              duplicate-JSON-member-name rejection
  exchange/   7 vectors over request↔response HEADER RELATIONSHIPS no single-document vector can
              express: X-Request-ID echoed exactly (not just individually well-formed on each
              side), error correlation_id genuinely distinct from X-Request-ID (not coincidentally
              equal), and both release headers actually present on a success response
tools/        compute_digest.py, verify_bundle.py, check_invariants_impl.py, generate_vectors.py,
              jcs_reference.py (an independent, from-scratch RFC 8785 implementation used only
              to cross-check the rfc8785 library, never to replace it), requirements.txt (pinned
              versions of every verifier dependency)
fixtures/
  provider/   the strict-provider-schema vs. lenient-consumer-parsing split — mechanically run
              by check_strict_vs_lenient_fixture(), not just documented
  consumer/   the retry policy per error code and the answer_validation_failed non-retry test —
              both mechanically cross-checked against the actual wire vectors
  logs/       a privacy-safe telemetry example plus the explicit forbidden-content list
  canonicalization/official-rfc8785-vectors/  the RFC 8785 reference implementation's own
              published test vectors, vendored verbatim, for external validation
COVERAGE.md   every normative RC2 wire rule mapped to the vector(s) that exercise it, including
              the three rounds of gaps found (two by external review) and how each was closed
MANIFEST.json per-file digests and the bundle digest
DIGEST.txt    the bundle digest alone, for pinning
```

Run `pip install -r tools/requirements.txt` once, then `python tools/verify_bundle.py` to
confirm the bundle is internally consistent, and `python tools/compute_digest.py --check` to
confirm it still matches its recorded digest.

Unlike the Management Contract bundle, `tools/generate_vectors.py` (and its helpers
`check_invariants_impl.py`/`jcs_reference.py`) **are** part of this bundle, kept deliberately: an
RC3 revision of the Management Contract bundle showed that leaving the generator behind cost
real time on the next revision. Re-running `generate_vectors.py` reproduces every file under
`vectors/` byte-for-byte; it is not a build step a consumer needs to run.

**The generator is not the conformance oracle.** `tools/verify_bundle.py` is a genuinely
separate program: it re-derives every vector's correctness from the schemas, from
`check_invariants_impl.py`'s own independent re-implementation of each invariant's rule, from a
second from-scratch RFC 8785 implementation cross-checked against the official RFC 8785 test
suite, and from `evaluate_auth_claims()`'s own re-implementation of §7's claim arithmetic — none
of which the generator consults when deciding what to write. Specifically:

- **Complete-state gate, both directions.** Every "hold"/positive vector (request/response
  schema positives *and* invariant-hold vectors) is checked against *every* applicable
  invariant, not just the one it names — `check_positive_schema_vectors_are_complete_states()`
  and the hold-branch of `check_invariants()`. Every "violation" invariant vector's actual
  violated set (computed independently, from scratch, per vector) must match its declared
  primary invariant plus its declared `also_violates` list *exactly* — no undeclared breakage,
  none declared that doesn't occur. This is the same discipline the Management Contract bundle
  used for its own health vectors, extended here to schema vectors too.
- **Cross-implementation canonicalization proof.** Every I-B10 and `canonicalization/` vector is
  checked by both `rfc8785` and `jcs_reference.py` independently; both must agree with each
  other and with the vector. Both implementations are additionally checked against the RFC
  8785 reference implementation's own published input/output pairs
  (`fixtures/canonicalization/official-rfc8785-vectors/`) — external validation, not just
  internal self-consistency. This caught two real bugs in a first, naive from-scratch
  implementation attempt (integer-valued floats mis-formatted, astral-plane characters sorted
  by codepoint instead of UTF-16 code unit) before `jcs_reference.py` reached its current form —
  direct, concrete evidence for why RC2 §11.2 itself prohibits hand-rolled canonicalization.
- See `COVERAGE.md` for the rule-by-rule map this bundle's vectors were checked against, and the
  handful of gaps found and left open rather than silently dropped.

## Strict provider mode versus lenient consumer mode

Every response/error schema sets `additionalProperties: false`. That is correct for
**provider conformance** and **wrong for a consumer's runtime path** — RC2 §19 requires
consumers to ignore unknown response members within v1. See
`fixtures/provider/strict-vs-lenient-parsing.json` for a worked example, identical in spirit
to the Management Contract bundle's own warning about this.

## Why there are no signed-JWT vectors

`vectors/auth/` describes claim **sets** (the header's `alg`/`kid` and the token's claims) and
the specific RC2 §7.1/§7.2 rule each vector exercises, evaluated against a declared
`evaluated_at` instant — not actual signed tokens. A bundle-embedded signing key would make
every vector's validity a function of wall-clock time relative to a frozen `iat`/`exp`, and
Ed25519 signature verification itself is a separately, already-proven concern (each side's own
JWT library). What Tier A needs to pin deterministically is the claim shape and arithmetic RC2
requires — which this file does directly, the same way `tools/verify_bundle.py`'s
`evaluate_auth_claims()` implements §7.1/§7.2 as pure claim-dict logic.

## Hostname/destination approval is a declared-fixture invariant, not a bundle constant

RC2 §12.2 makes both URL-host/action-kind approval AND exact-destination matching (I-B08) a
cross-field **business** invariant, explicitly deferred from the protocol freeze (RC2 §23 item 5:
real hostnames and destinations are a Homes content/deployment decision). Each I-B08 vector
therefore declares its own `assumed_approved_hostnames` and `assumed_approved_destinations`
fixtures (clearly-labeled synthetic values like `booking.examplepms.com`) rather than hardcoding
production values the bundle has no authority over. I-B08 checks both a source or action's URL
*host* against the per-kind allowlist AND its *exact URL* against the approved-destination set —
an approved hostname serving an unapproved path is still caught, and (since RC2 states the
source-URL rule at least as explicitly as the action rule) sources are checked, not only actions.

## The canonical digest

```
sha256 over the canonical listing of "<file sha256><two spaces><relative path><LF>" lines,
files sorted ascending by UTF-8 byte order, MANIFEST.json and DIGEST.txt excluded,
each file hashed over its raw bytes.
```

Reproducible from the bundle root with coreutils alone:

```sh
find . -type f ! -path './.git/*' ! -name MANIFEST.json ! -name DIGEST.txt ! -path '*/__pycache__/*' -printf '%P\n' \
  | LC_ALL=C sort | xargs -d'\n' sha256sum --text | sha256sum
```

`--text` matters on Windows: Git Bash's `sha256sum` defaults to a binary-mode `*` marker that
Linux/macOS coreutils do not use by default, which would otherwise produce a different digest
for the same logical bundle (a real gap found and documented while verifying the Management
Contract bundle in this same environment).

The `__pycache__` exclusion matters if you've ever run `generate_vectors.py` or
`verify_bundle.py` locally: `.gitignore` keeps `__pycache__/*.pyc` files out of the repository,
but `find` doesn't consult `.gitignore` — a leftover `.pyc` from an earlier local run will make
this command's digest disagree with `compute_digest.py`'s (which does exclude it) even though
the committed bundle is unaffected. A fresh `git worktree` checkout or `git archive` extraction
never has this problem, since neither ever had the local run in the first place.

**Line endings are part of the artifact.** Files are hashed as raw bytes; the shipped
`.gitattributes` pins LF.

**Do not pin an archive hash.** A `.tar.gz`/`.zip` of this directory identifies one transferred
file, not the bundle — re-archiving the byte-identical tree yields a different hash because
`gzip` embeds a modification timestamp. The content digest above is the only reproducible pin.

## Invariants, and why they are separate

Ten machine-checkable invariants (I-B01 through I-B10) live in `vectors/invariants/`, each
enforcing an RC2 rule that spans multiple fields, multiple array entries, or two paired
documents (request+response) — none of which a single JSON Schema document can express alone:

- **I-B01/I-B02/I-B03** — history's aggregate character bound, role-alternation shape, and
  turn_id uniqueness/non-collision (§9.1). Schema can bound one field; it cannot sum an array
  or compare one field's value against another array's contents.
- **I-B04** — response.session_id equals request.session_id (§12.2) — a two-document check.
- **I-B05/I-B06** — independent source_id/url and action_id/url uniqueness within their own
  arrays (§12.2) — array-item-pairwise comparisons.
- **I-B07** — the explicit non-constraint that a source and an action may share a URL (§12.2)
  — recorded so I-B05/I-B06 are never accidentally over-implemented as one shared pool.
- **I-B08** — URL hostname approval matching action kind, AND exact approved-destination
  matching for both sources and actions (§12.2), against per-vector declared fixtures (see
  above).
- **I-B09** — the full five-branch idempotency status decision table (§11).
- **I-B10** — RFC 8785 canonical request identity determinism (§11.2): reordering and
  insignificant differences preserve identity; content, array-order, and omitted-vs-null
  changes do not.

**I-B11** (answer_validation_failed is never auto-retried) is recorded but marked
`machine_checkable: false` — the wire-level half (the error schema's `retryable: false` const)
is checked; whether a specific consumer/proxy implementation actually honors it is a two-request
process assertion, not a single-document fact. This mirrors the Management Contract bundle's own
treatment of evidentiary requirements no wire-level artifact can fully prove.

## Genuinely non-normative implementation notes

RC2 closed every wire-format gap raised during Tier A preflight (RC1 review) — there is no
"Interpretations taken" section of open contract questions here. The following are pure
schema-encoding choices, not contract ambiguities, recorded for transparency:

- **`history` is treated as an omittable top-level request member**, same as `page_context`.
  RC2 §9.1 explicitly calls `page_context` optional; `history`'s "zero to 12" phrasing plus
  §11.2's general omitted-member-preservation rule are read here as `history` also being
  omittable, not only presentable-as-`[]`. Both are schema-valid regardless; only the
  canonicalization *identity* differs between omitted and empty (see
  `vectors/canonicalization/canon.003.json`).
- **Response `sources`/`actions`/`limitations` are treated as always-present (possibly-empty)
  arrays**, not omittable, based on the worked example's explicit `"limitations": []`.
- **`page_context.path` and `sources[].url`/`actions[].url` patterns** (`common.defs.json`'s
  `normalizedPath` and `httpsUrl`) are this bundle's regex encodings of RC2's prose rules —
  every individual constraint they enforce is explicit RC2 text (no scheme/host/credentials/
  query/fragment/encoded-delimiter for paths; https-only/no-userinfo/no-fragment/2048-char-max
  for URLs), but the exact regex is mine, tested against the edge cases each rule names before
  being used in any vector.
