# Public Lucy model Milestone A

Status: implemented, locally evaluated on 2026-09-13, and accepted in isolated Render
staging on 2026-09-14. Production remains on the deterministic Public Lucy R1 path. The
model service is suspended, visitor model routing and transcript capture are disabled, and
no DNS record or website production deployment was changed by this work.

## Delivered boundary

- A separate private `lucy.public_model_runtime` process accepts a strict, authenticated
  model request from the existing public API. The browser never receives an OpenRouter
  credential or a direct provider route.
- The public API still performs the existing hostname, origin, bearer, session, projection,
  lifecycle, and rate checks before model work. It passes only the current question,
  bounded browser-memory history, bounded page context, and the exact approved public
  projection.
- The model context assembler supplies all 25 effective public entries in a typed packet.
  It excludes withdrawn or not-yet-effective entries and gives the model identifiers rather
  than trusting it to construct URLs.
- The generator returns a strict answer contract with typed segments and evidence IDs. A
  separate verifier evaluates the final displayed answer against the evidence. The server
  independently validates structured property facts, exact numbers, property identity,
  evidence IDs, effective dates, and approved link destinations.
- Clarifications, corrections, and general guidance can remain conversational without
  artificial citations. Business claims require evidence. Unsupported or live/private
  claims fail closed.
- Every generator and verifier attempt is admitted through the existing durable cost
  coordinator. Provider response IDs are reduced to keyed commitments before durable
  storage; questions, answers, and packet content are not written to the cost journal.
- The model path is separately feature-gated. Setting `LUCY_PUBLIC_MODEL_ENABLED=false`
  preserves the current deterministic R1 response path as the immediate rollback.

## Authority and time precedence

Authorization is established before the question is interpreted. Intent and conversation
history may narrow the property or service being discussed; neither can expand access or
become evidence.

When sources disagree, the intended precedence is:

1. the authorized public projection and its effective/withdrawal state;
2. a reservation-specific exception, once an authenticated reservation surface exists,
   for that reservation only;
3. an active operational restriction for the affected dates or amenity;
4. current PMS availability and stay restrictions, once a PMS adapter is connected;
5. structured property, service, and pricing-explanation facts;
6. approved descriptive content.

Milestone A implements the first, fifth, and sixth levels. It has no reservation identity,
operational-status feed, or PMS data. A question requiring any absent higher-precedence
source must receive an honest partial answer or fallback. A profile saying that a home has
a pool does not imply that the pool is open for a requested month.

## Model evaluation

Evaluation used only the approved public packet and synthetic conversations. OpenRouter
requests required zero-data-retention routing, denied data-collecting endpoints, disabled
provider fallbacks, enforced price ceilings, and requested structured JSON output. Public
transcript capture remained off.

| Candidate | Main repeated run | Average latency | Approx. p95 | Result |
| --- | ---: | ---: | ---: | --- |
| Google Gemini 3.1 Flash Lite | 19/24 accepted, 0 provider errors | 2,484 ms | 2,817 ms | Provisional development default |
| Anthropic Claude Haiku 4.5 | 15/24 accepted, 5 provider errors | 3,622 ms | 4,503 ms | Not selected |
| OpenAI GPT-5 Mini | 3/12 accepted, 7 errors in the candidate run | 5,498 ms | not material | Not selected for this envelope |

The result is not a claim that prompting guarantees grounding. It is evidence that the
contracts and validator can support ordinary conversation while rejecting unsupported
business claims. After validator and rubric corrections, one complete Gemini run accepted
11 of 12 scenarios. The remaining pronoun/number parsing defect was corrected; focused
reruns then accepted both affected requirements, and separate boundary reruns accepted all
four identity/live-data cases. A final current-code run pinned to the exact `google-vertex`
route then accepted all 12 scenarios with no provider error, 3,167 ms average end-to-end
latency, and 8,782 ms approximate p95 latency. Repeated staging trials remain necessary to
measure production-like tail behavior.

The exact containerized Render candidate subsequently passed the same 12-turn rubric as a
content-free one-off gate inside the protected network. Job
`job-dak2k40jo6nc73b8t39g` ran commit
`d2a76b2e82fa390bf8c5d0afc2d6c81b9f5de197` and suite digest
`7abb8332a9c19290cfa4f106024dfac3c490acbd7cce8e78be01ad36e5cfc6c0`. The gate failed
the job on any non-200 response, response-binding mismatch, or rubric failure; it completed
12/12. The model service was then suspended. Per-turn staging tail latency remains an
activation-soak measurement because Render retained no logs for the earlier output-bearing
smoke job.

The final scenarios cover ordinary wording, a follow-up, correction after a poor answer,
multi-property comparison, multiple requirements, missing seasonal information, published
Design estimate behavior, relevant travel guidance, identity/private access, live
availability, changed requirements with no match, and prompt-injection/wrong-number
resistance.

Provider-reported costs across every saved evaluation report total 596,121 microusd.
Charging four ambiguous/aborted calls at their complete reservations adds 120,000
microusd, for a conservative accounted total of 716,121 microusd ($0.716121) against Ray's
$5 authorization.

Primary evidence files are stored outside the repository beside this isolated worktree:

| Evidence | SHA-256 |
| --- | --- |
| `public-model-eval-candidates-2.json` | `e71f8391f89f70e28812d7fb37a8af51b6a3a2eabd95122968829ab191bb1452` |
| `public-model-eval-finalists.json` | `22149c6305f3be03c6099086fc6994941f4f7a74bea733d3ebd4ac7b53a59de2` |
| `public-model-eval-final-code.json` | `74daf616af127455705360c9273007b3b7019e9d8e73e23d7f49966094d0d8ba` |
| `public-model-eval-boundaries-final.json` | `30b48ef79461efb88db59d6b50bca91d77916da0f123be670927f777bb6d7e49` |
| `public-model-eval-changed-requirements-final.json` | `b45d402a9f0a3ecb23ab3ad80a3b9d71b0a718a12cbe187bf890667ab4afc5df` |
| `public-model-eval-google-vertex-final.json` | `305162883e98e8405c2a66b5d1e1c11d6a517bb76ad5243e9bc51d6e10612481` |

## Local verification ledger

- Ruff: passed repository-wide after the model implementation and again after synchronization.
- Strict mypy: passed across 118 source files after synchronization.
- Pytest: 873 tests passed and 250 PostgreSQL/Docker-dependent tests skipped in the
  repository-wide run. The sole initial failure was the known Windows line-ending digest
  of an immutable AWS fixture; regenerating its LF bytes from the pinned source made all
  eight affected reproducibility tests pass. The fixture normalization was then discarded.
- One additional fail-closed private-host configuration test was added after the complete
  run and passed with its focused ten-test public API suite. Combined unchanged evidence is
  therefore 874 passing tests; PostgreSQL integration remains an activation-stage gate.
- The website adapter passed TypeScript, repository-wide ESLint, all 92 Vitest tests, and a
  Next.js production build of 27 routes after its upstream timeout was aligned with the
  isolated model handoff.
- After rebasing onto Private migration `0071` and adding the V2 activation contract, the
  complete merged Python suite passed 1,005 tests with 263 PostgreSQL/Docker-dependent
  skips. Alembic reported exactly one head: `0071_memory_import_job_replay`.
- After commissioning hardening and Docker packaging, the complete unit suite passed 1,009
  tests; Ruff passed repository-wide and strict mypy passed across 118 source files. The 17
  focused Docker/commissioner packaging checks and the dedicated disposable PostgreSQL
  commissioning integration test passed. The candidate Docker image built successfully for
  `linux/amd64` with immutable image ID
  `977efed4c73fefe605239c257f2dc89c8d0d1861a108f06fa6f00185a1283e37`.

## Activation configuration and order

The reviewed development defaults are Gemini 3.1 Flash Lite for both generation and
verification, a six-second per-provider-call limit, a 15-second public-API-to-model limit,
an 18-second website-to-public-API limit, strict output/token/cost bounds, a nonempty
provider allowlist, zero-data-retention routing, data collection denied, and fallbacks
disabled. The reviewed route is the OpenRouter `google-vertex` base slug, which matches
Vertex regions while request-level ZDR excludes Google AI Studio. A dedicated
account-capped production key remains an activation input.

Activation must keep staging, approval, and traffic movement distinct:

1. synchronize with a clean Private Lucy checkpoint and reconcile the current migration
   head and shared cost-admission contracts;
2. install compatible, disabled readers and the isolated model service;
3. stage and approve an eligible public snapshot without changing the active route;
4. test readiness, identity/grant boundaries, provider privacy routing, cost settlement,
   latency, and response behavior in staging;
5. atomically activate the eligible snapshot;
6. enable the model feature separately only with explicit product activation authority.

Rollback first disables the model feature, returning traffic to deterministic R1. A prior
snapshot may be reactivated only if it remains eligible. A digest withdrawn for incorrect
or sensitive content must not be revived merely because it was previously approved.

## Synchronization checkpoint

Private Lucy paused cleanly at commit
`beaa2031b6ef69bd8b50177b6771469a5253c836`, migration
`0071_memory_import_job_replay`. Public Lucy rebased without conflicts and now includes
that complete ancestry; the rebased Milestone A commit is
`a6473c26ea1fa34ca19d0a809698150f367be37f`. No `0072` migration was created.

The legacy V1 activation manifest remains unchanged because it is evidence for the
deterministic launch and intentionally forbids paid inference in `public_only` mode. The
model release instead uses
`deploy/render/utopia-public-model-activation-manifest.v2.json.example`. Its validator
distinguishes `staged-disabled`, `staging-test`, and `active`; only the last state permits
visitor model traffic. Each populated manifest pins one exact schema; the reviewed contract
accepts both the deployed public bridge `0057_public_conversation` and synchronized private
head `0071_memory_import_job_replay`. It also pins both repositories, privacy routing, an
exact provider allowlist, cost and timeout envelopes, browser-only history, eligible and
withdrawn snapshot sets, and the transcript-capture-off boundary.

## Remaining activation gates

- The 2026-09-14 pre-activation recheck found five matching endpoints in OpenRouter's live
  ZDR inventory, current rates below the configured ceilings, and the dedicated key at its
  exact $1 daily-reset limit with $1 remaining. Re-read those volatile values at the actual
  traffic transition and measure per-turn tail latency during the activation soak.
- Convert the fully populated, validated `staging-test` manifest into a separately reviewed
  exact `active` manifest. Do not reuse staging authorization as traffic authority.
- Obtain explicit product activation authorization, install the public reader's private
  model credential and enable flag, and verify live same-origin behavior plus immediate
  deterministic rollback. This implementation and staging authorization does not publish
  the model path.
