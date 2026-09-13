# Public Lucy R1 implementation plan

Status: local implementation in progress on `codex/public-conversation-r1`. Nothing in
this plan authorizes production mutation, paid inference, a provider selection, or
publication of a new knowledge snapshot.

Integration note: this branch is synchronized onto the clean Private Lucy checkpoint
`d7b872c69c5fed4f738d23e36ac569a6ed3b57a9`. Migrations `0055` and `0056` are now in
its ancestry, and Public Lucy migration `0057` follows the accepted `0056` revision.
Future migration numbers must be coordinated at the next merge point while the two
tracks continue in separate worktrees and branches.

## Finish line and exclusions

R1 accepts ordinary public questions, retrieves only currently effective approved
Utopia knowledge, returns a fully supported answer or an honest partial/fallback,
understands an allowlisted page context, and supports a short conversation that exists
only in browser memory. Customer identity, reservation access, historical-message
ingestion, private knowledge, PMS access, and business actions remain later releases.

The PMS adapter remains provider-neutral. No Lodgify or Guesty decision is encoded in
this release.

## Request path

1. The website establishes its same-origin request and opaque public session.
2. The Cloud public runtime authenticates bearer, origin, hostname, session, request
   size, and rate limits before parsing or interpreting the question.
3. The execute-only public database identity reads the active, digest-pinned public
   projection through one security-definer function. The function rechecks tenant,
   lifecycle, storage epoch, snapshot schema, and effective dates.
4. Structured property/page context narrows retrieval. Typed property facets evaluate
   explicit capacity, parking, pool, hot-tub, and pet requirements. Bounded history may
   resolve a conversational subject, but cannot provide evidence or expand authorization.
5. Deterministic lexical retrieval ranks the eligible approved records and measures requested-topic
   coverage. R1's active safe composer returns only exact approved text. Valid source IDs
   do not authorize paraphrases, altered numbers, negation, or policy exceptions.
6. The browser receives only the answer, clarification, descriptive sources, and useful
   links. Snapshot version, digest, evidence IDs, missing-topic diagnostics, and trace
   data remain internal.

## Implementation map

| Boundary | Existing foundation | R1 extension |
| --- | --- | --- |
| Website session | Same-origin `/api/lucy`, opaque cookie, request limits | Six-turn/4,000-character history in React memory, 30-minute expiry, explicit Start over, page context |
| Public HTTP | Exact bearer/origin/host/session checks | Strict R1 request/response contracts and full/partial/fallback results |
| Knowledge | Immutable approved FAQ projection | Typed property knowledge and facets, aliases/topics, source/links, effective and withdrawal dates |
| Database | Tenant-bound projection route and epoch gate | `public_projection_knowledge_v1(text,uuid)` and execute-only realm grant |
| Retrieval | Exact normalized FAQ match | Structured narrowing plus tested lexical retrieval for vocabulary changes, comparisons, and multiple requirements |
| Grounding | Owner-approved immutable bytes | Extractive answer gate plus unsupported-number, wrong-property, negation, and exception tests |
| Inference | Durable cost admission and separate provider coordinator | Remains disconnected until model/provider, retention behavior, and numeric caps are approved |
| PMS | No public capability | Provider-neutral future boundary only; no PMS reads in R1 |

## Coverage contract

- `answered`: every requested recognized topic has approved supporting knowledge.
- `partial`: at least one requested topic is supported and at least one is missing. Return
  only the supported portion and name the missing detail plainly.
- `fallback`: no approved support is available, or the question asks for live stay
  pricing, live availability, or an individual reservation.

Published explanations of Utopia Design estimates and general booking-process questions
are not live-data requests and remain answerable.

## Privacy and retention

- Browser history is never written to local storage, session storage, a database, or an
  analytics payload. It is cleared by refresh, Start over, or 30 minutes of inactivity.
- The server receives at most six turns and 4,000 history characters.
- Application responses are `no-store`; no request or answer body is logged by the code.
- Analytics contains only fixed outcome events, never content, session IDs, IPs, or page
  paths.
- Production activation requires verification of host/platform request logs, error
  reporting, tracing, and the selected inference provider's retention controls. Those
  external controls are not proven by local tests.

## Publication, activation, and rollback order

1. Build and review a candidate `lucy-public-knowledge-v1` corpus.
2. Stage and approve its exact digest without changing the active route.
3. Install compatible Cloud and website readers with conversation disabled.
4. Apply the additive database migration and exact realm-role grant under quarantine.
5. Verify negative controls and the approved digest in the deployed environment.
6. Atomically activate the new projection, then enable the conversational reader.

The local R1 release controller now enforces this order with distinct `stage`,
`approve`, and `activate` manifests and authorization markers. Stage and approval are
accepted only at `0056` and leave the current route untouched. Activation is accepted
only at `0057`, under quarantine, and compare-and-swaps the exact reviewed prior route
to the separately approved candidate. The V0 all-in-one bootstrap remains unchanged
and is not an R1 publication path.

A rollback digest is not eligible merely because it was once approved. The rollback
candidate must be separately reviewed, remain within its effective dates, exclude
withdrawn or sensitive facts, and be explicitly pinned in both Cloud and website
configuration before its route is activated.

## Acceptance conversations

Automated tests cover:

1. “Tell me about Buttercup.” then “How many cars fit?”
2. “Which homes have pools, and how do they differ?”
3. “We have 20 people, four cars, and want a pool.”
4. “Is the Buttercup pool open in November?” when seasonality is absent.
5. “How does your design estimate work?” without treating it as live stay pricing.

They also cover wrong-property isolation, effective/expired/future knowledge, restricted
topic distinctions, unsupported claims attached to valid citations, browser navigation
continuity, strict source URLs, outage versus knowledge-miss behavior, and database
tenant/quarantine/epoch enforcement.

## Approved test-corpus checkpoint

Ray approved the exact 25-entry corpus for R1 testing on 2026-09-12 while explicitly
treating it as a temporary testing foundation rather than Lucy's long-term intelligence.
The website repository owns the source artifact derived from its committed public content;
the Cloud repository owns the byte-identical packaged release artifact. Their canonical digest is
`95e2e20a9e4a3786e3daa63a73bb5ff2866b5bae295e6dc138bf432e4361c422`.
`deploy/render/validate_public_knowledge.py` validates an arbitrary candidate path and
prints only its schema, entry count, and canonical digest; it does not connect to a database
or stage content. Cloud and website validators independently reproduce this digest.

`deploy/render/evaluate_public_knowledge.py` runs the evidence-exact suite in
`deploy/render/public_knowledge_acceptance.v1.json`. Its ten cases include the five required
conversations plus booking-process, pet-policy, owner-service, restricted-reservation, and
unknown-amenity checks. A case fails when the outcome, evidence IDs, or missing-topic set
differs; plausible text backed by the wrong record does not pass.

The test corpus deliberately excludes live rates/availability, reservations, provider names,
email addresses, pending biographies, private knowledge, and inference-provider details.
It remains inactive. The testing approval does not authorize production publication,
deployment, provider use, spending, or transcript capture; production use requires a
separate release authorization for these exact bytes or an approved replacement digest.

## Explicit release decisions

The following remain owner release gates and do not block local contract/retrieval work:

- production authorization for the approved test corpus or a replacement corpus and digest;
- final inference provider/model and verified provider retention settings;
- rate, token, concurrency, timeout, and spend caps;
- production migration, role reprovisioning, snapshot activation, and website enablement.

## Verification ledger

| Check | Result on 2026-09-12 | Invalidated by |
| --- | --- | --- |
| Ruff and strict mypy | Passed after release-controller implementation: all files; 92 typed source files | Source/dependency/config changes |
| Unit and contract tests | Passed after packaging the approved test corpus: 832; 250 database-gated tests skipped; one unrelated AWS frozen-template hash test deliberately deselected after reproducing its pre-existing mismatch | Source/test/dependency changes |
| Public retrieval acceptance | Passed: 10 evidence-exact conversations against the actual 25-entry candidate, partial coverage, topic distinctions, freshness, wrong-property isolation, structured multi-requirement matching, and adversarial grounding | Knowledge/retrieval/grounding contract changes |
| PostgreSQL boundary | Passed after packaging the approved test corpus: one Alembic head; clean migration `0001` through `0057`; 8 focused live-SQL tests on isolated loopback/tmpfs databases; the exact 25-entry artifact round-tripped through the admitted public identity; disposable containers removed afterward | Migration, roles, publication, readiness, database image, or approved snapshot changes |
| Three-step release controller | Passed locally: exact action/revision/authorization contracts plus one staged, approved, activated, and replayed live-SQL release; publisher/approver substitution rejected; active route advanced atomically from version 1 to 2 | Release controller, publication tables, roles, migration, or snapshot contract changes |
| Website compatibility | Passed without website source drift: TypeScript, repository-wide ESLint, 91 unit tests, and a 27-route Next.js webpack production build; the earlier 22-scenario browser result remains valid because website code and dependencies are unchanged | Website source, dependencies, browser matrix, or public request/response contract changes |
| Provider inference | Not executed or enabled | Requires approved provider/model, retention controls, credentials, and limits |
| Production activation | Not executed | Requires explicit production authorization and completed release gates |
