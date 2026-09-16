# Stoin Management Contract v1.0 — conformance bundle

The machine-readable artifact required by Management Contract v1.0 §14: the four response
schemas, the error schema, and positive and negative conformance vectors, under one canonical
SHA-256 digest that both repositories pin independently.

- **Contract revision this bundle encodes:** v1.0 Release Candidate 3, frozen 2026-09-16.
- **Schema dialect:** JSON Schema draft 2020-12, pinned exactly.
- **Built by:** Claude, implementation steward, Homes side (§4, §22).
- **Status:** artifact only. Nothing here deploys, provisions, or authorizes anything, and the
  bundle does not by itself authorize implementation of either side.

Every rule encoded here traces to a section of the contract, and every vector names the section
it enforces. If a vector and the contract disagree, the contract wins and the bundle is wrong.

---

## What is in it

```
schemas/      common.defs.json and the five response schemas
vectors/
  positive/   24 responses that MUST validate AND be complete legal states
  negative/   60 responses that MUST be rejected, each naming the rule it violates
  invariants/ invariants.json plus 28 paired vectors for rules JSON Schema cannot express
tools/        compute_digest.py, verify_bundle.py
MANIFEST.json per-file digests and the bundle digest
DIGEST.txt    the bundle digest alone, for pinning
```

Run `python3 tools/verify_bundle.py` to confirm the bundle is internally consistent, and
`python3 tools/compute_digest.py --check` to confirm it still matches its recorded digest.

## Strict provider mode versus lenient consumer mode

**This is the one thing in the bundle that can break a conforming implementation if it is
misused, so it comes before everything else.**

Every response schema sets `additionalProperties: false`. That is correct for **provider
conformance**: a v1.0 provider that ships members the contract does not define is exposing
undeclared surface, and several negative vectors exist to catch exactly that.

It is **wrong for a consumer's runtime path**. §14 requires that "Consumers MUST ignore unknown
response members within major version 1," precisely so a later v1.1 can add an optional field
without breaking a deployed Control client. A Control client that wires these strict schemas into
its live request handling would reject the first v1.1 response it ever saw — turning an additive,
explicitly-permitted change into an outage.

So: validate the provider strictly in conformance tests; validate leniently, or not at all, at
runtime. If it helps, derive a lenient copy by setting `additionalProperties` to `true` — but
derive it, do not edit these files, because editing changes the digest.

## The complete-state gate

§14 requires that every positive conformance vector "first satisfy every applicable structural
schema and cross-resource invariant as a complete legal state before it may count as evidence for
the particular field behavior it targets."

That rule exists because of a specific failure in the previous version of this bundle. Six
positive fixtures were each written to exercise one field — a `retry_after_seconds` bound, a
reason code, an array ordering — and each treated the rest of the response as scenery. All six
were correct about the thing they tested and asserted an illegal health state while doing it. A
positive vector that blesses an illegal state is worse than a missing vector: it certifies the
broken behaviour it was supposed to catch.

`verify_bundle.py` enforces the rule mechanically rather than documenting it as an intention.
Every positive vector, and every invariant vector declared to hold, must pass **all** applicable
invariants before its own assertion counts. Where a health vector has no paired `/capabilities`
document, the gate synthesises one from the vector's `assumed_enabled_set`, defaulting to the
single v1.0 capability `guest.answer`.

Violation vectors carry the mirror-image check. Each declares the invariant it targets, and an
`also_violates` list naming every *other* invariant it breaks. The verifier requires that list to
be exact — no undeclared breakage, no declared breakage that does not occur — so a fixture cannot
quietly drift into failing a rule it was never meant to exercise.

**Authoring rule for anyone extending this bundle:** write the complete legal state first, then
vary the one field under test. Never the reverse.

## How each side is expected to use it

Both repositories pin `DIGEST.txt` and verify it before a conformance run. Beyond that the two
sides deliberately do **not** share code. §14 makes this a contract artifact, "not a shared
runtime library; neither implementation imports the other repository," and acceptance criterion 16
requires contract tests to run over network HTTP between two processes rather than importing both
implementations into one test process.

- **Homes (provider).** Assert that live responses from the deployed adapter validate against the
  schemas, that the invariants hold across a paired observation, and that the negative vectors are
  rejected by whatever validation the adapter applies to its own output.
- **Control (consumer).** Assert that the client parses every positive vector, tolerates unknown
  members per §14, applies the invariant checks it depends on — I-03, I-05 and I-07 in particular
  — and never persists anything outside the §20 allowlist.

`tools/verify_bundle.py` checks the **bundle**, not either implementation. It exists so that a
change to a schema or a vector gets caught here rather than during a live proof. Each side should
write its own validation in its own language.

## The canonical digest

```
sha256 over the canonical listing of "<file sha256><two spaces><relative path><LF>" lines,
files sorted ascending by UTF-8 byte order, MANIFEST.json and DIGEST.txt excluded,
each file hashed over its raw bytes.
```

That layout is what `sha256sum` prints, so the whole digest can be reproduced from the bundle
root with coreutils alone, without running any script in this bundle:

```sh
find . -type f ! -name MANIFEST.json ! -name DIGEST.txt -printf '%P\n' \
  | LC_ALL=C sort | xargs -d'\n' sha256sum | sha256sum
```

That command is verified to produce the value in `DIGEST.txt`. The rule is also written out in
full in the `compute_digest.py` docstring so either side can reimplement it from the text alone —
which is the point of pinning a digest at all, and the reason neither side should simply run the
other's script and call the values agreed.

**Line endings are part of the artifact.** Files are hashed as raw bytes, so a checkout that
converts LF to CRLF produces a different digest from the same logical bundle. The shipped
`.gitattributes` pins LF.

**Do not pin an archive hash.** A `.tar.gz` of this directory identifies one transferred file,
not the bundle: `gzip` embeds a modification timestamp, so re-archiving the byte-identical tree
yields a different hash. The content digest above is the only reproducible pin.

## Invariants, and why they are separate

Seven normative rules cannot be expressed in JSON Schema, either because they concern ordering or
because they relate one endpoint's response to another's. They live in
`vectors/invariants/invariants.json` with their own paired vectors. RC3 defines every health
status over two sets — `E`, the advertised capabilities with `state=enabled`, and `I`, the
contents of `degraded_capabilities` — and a single `/health` response cannot see `E`, so most of
that definition can only be enforced here.

- **I-01** — arrays are sorted ascending (§8). JSON Schema has no ordering keyword.
- **I-02** — no duplicate `capability_id` (§12). Schema `uniqueItems` only catches wholly
  identical entries, not the same ID advertised twice with different state.
- **I-03** — `/health` `management_provider_release_id` equals `/version`
  `management_provider.release_id` (§11.2). The members are spelled differently and live in
  different responses. This catches an adapter reading a build-time value on one endpoint and
  live configuration on the other.
- **I-04** — status matches the relationship between `E` and `I` (§10): `healthy` needs `E`
  non-empty and `I` empty; `degraded` needs `I` a non-empty proper subset of `E`; `unavailable`
  needs either `I = E` with `E` non-empty, or the zero-enabled branch; `unknown` needs `E`
  non-empty with `I` empty or a proper subset. It assumes `I ⊆ E` and defers to I-06 when that
  fails, so an out-of-set impairment is reported against one rule rather than two.
- **I-05** — the transitional adapter reports `unknown` with an empty impaired set and
  `health_coverage_limited`, and never claims `healthy` (§10, criterion 10).
- **I-06** — every impaired capability is advertised and `enabled` (§10). A `disabled` capability
  is a policy state, not an impairment; reporting one as impaired would let a deliberate shutdown
  read to Control as a fault.
- **I-07** — `no_enabled_capabilities` is present exactly when `E` is empty (§10). Both
  directions matter: one stops an unexplained `unavailable` while nothing is switched on, the
  other stops a provider claiming a zero-enabled configuration while serving live capabilities.

`invariants.json` also records what **cannot** be machine-checked at all. Every status rule has an
evidentiary half — whether the provider actually held authoritative evidence — and the wire cannot
reveal it. With an empty impaired set both `healthy` and `unknown` are structurally legal; with a
non-empty proper subset both `degraded` and `unknown` are. I-05 covers the one case the first
proof depends on, and only because the conformance run declares `provider_mode`. The same applies
to the truthfulness of an `unspecified` reason code, to the absence of exception text in error
messages, and to the JWT skew boundary. Recording them keeps them from being assumed covered
because a conformance run went green.

## Why there is no positive `degraded` vector

§10 states that `degraded` is unreachable while one capability is enabled, and forbids the
first-proof vectors from inventing a second capability to manufacture a positive case. The schema
still accepts `degraded`, and invariant I-04 enforces the reachability rule, but no positive
operational `degraded` vector exists and none should be added until a second capability genuinely
exists. Two capability entries appear in three fixtures — `inv.I-01.neg.003`, `inv.I-02.neg.001`
and `inv.I-04.neg.002` — and all three are rejection cases for ordering, uniqueness and
set-completeness. None is paired with a positive health state.

When a second capability arrives, that is a v1.1 bundle revision with a new digest, not an edit
here.

## Interpretations taken

RC3 resolved two of the five interpretations the previous bundle recorded: the
`management_provider.release_id` length bound is now stated explicitly in §11.2, and both health
arrays are now defined as sets in the contract, so their `uniqueItems` constraints encode the
text rather than exceeding it. Three remain, each resolved the way that seemed most faithful and
each recorded so it can be contested — changing any of them changes the digest.

- **I-1 — `deployed_at` precision.** §8 requires whole-second precision with a trailing `Z` for
  `observed_at`. §11.2 calls `deployed_at` an "RFC 3339 UTC timestamp" without restating that rule.
  The bundle requires UTC (`Z`) but permits optional fractional seconds on `deployed_at` only.
- **I-2 — UUID case.** The contract says "UUID v4" without specifying case. The bundle accepts
  uppercase hexadecimal, partly because §13 requires the caller's request ID to be echoed as an
  exact value rather than normalised. Version and variant nibbles are enforced.
- **I-4 — no `observed_at` on errors.** §8's `observed_at` requirement is stated for *successful*
  responses, and §13's envelope names only `contract_version` and `error`. Since §2 makes member
  names normative, the error schema rejects `observed_at`. Vector `error.neg.009` is the one to
  contest if Control wants a provider-side timestamp on errors.

## Vector inventory

| Group | Positive | Negative |
| --- | --- | --- |
| `/identity` (§9) | 3 | 10 |
| `/health` (§10) | 9 | 21 |
| `/version` (§11) | 3 | 12 |
| `/capabilities` (§12) | 4 | 8 |
| Error envelope (§13) | 5 | 9 |
| Invariants (§8, §10-§12) | 12 hold | 16 violation |

Some negative vectors exist to fail implementations built against superseded drafts rather than
to catch ordinary mistakes: `health.neg.002` (the reason code `unknown`, renamed to `unspecified`
before RC2), `health.neg.012` (the member `release_id`, renamed to
`management_provider_release_id`), `version.neg.008` (the flat pre-RC1 `/version` layout that let
an adapter redeploy read as a Homes Prime release), and `health.neg.018` and `inv.I-04.neg.003`,
which are the two states the RC2 bundle wrongly shipped as positive vectors.
`inv.I-05.neg.003` plays the same role for behaviour rather than shape: it rejects the
transitional adapter reporting `degraded`, which is what the Homes-side Draft 0.1 review
originally proposed and RC1 corrected.

## Changed since the RC2 bundle

- Six positive fixtures corrected or replaced: `health.pos.003`, `health.pos.004`,
  `health.pos.005`, `health.pos.007`, `inv.I-01.pos.001`, `inv.I-04.pos.002`. Four paired
  `unavailable` with an empty impaired set; one reported `unknown` while naming the sole enabled
  capability; one invariant fixture declared that illegal pairing as holding.
- `no_enabled_capabilities` added to the reason-code set; `unspecified` made stand-alone at every
  status; `reason_codes` required non-empty at `status=unknown`; both health arrays made sets.
- Three new health schema conditionals make the zero-enabled branch and the RC2 defect catchable
  from a single response rather than only in a pairing.
- Invariants I-06 and I-07 added; I-04 rewritten from a single reachability check to the full
  `E`/`I` status semantics.
- The complete-state gate and the `also_violates` accuracy check added to the verifier.
