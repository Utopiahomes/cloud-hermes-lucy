# Public Lucy Claude reproduction access

Status: local Cloud implementation complete; hosted staging blocked pending an isolated runtime

Authorized by Ray: 2026-09-15

Production changes authorized: none

## Ownership and exact starting point

Claude owns the Utopia Homes website, browser reproduction harness, website releases, and
website rollback. Lyra owns Cloud Lucy, cost admission, model execution, Cloud diagnostics,
Cloud deployment, and Cloud rollback. Shared HTTP contracts require coordinated tests before
either side activates them.

The website production checkpoint is
`c4554b5c5b8b5e2ccf63039571c87c2ad0866a5a`. The Cloud evidence checkpoint is
`c2c8a292885223e17a6a2e4b88e1fe171f707a13`; the diagnostic implementation checkpoint is
`2dda6f150859ffabc4458e672c56544281b58f17`; the currently deployed Cloud runtime remains
`d2a76b2e82fa390bf8c5d0afc2d6c81b9f5de197`. This implementation creates no migration and
does not consume migration `0072`.

## Authorization boundary

Ray approved:

- preservation of the old dirty website workspace;
- transfer of its provider-neutral booking architecture and candidate photography for
  Claude's review;
- retirement of Uplisting-specific destinations;
- content-free trace diagnostics with transcript capture still disabled;
- an isolated public-only staging environment;
- a $5 aggregate provider-exercise ceiling, two concurrent requests, 20 assistant-response
  attempts per session, 40 attempts across the two-session exercise, and no automatic top-up;
- complete isolation from production guest capacity.

The authorization does not permit a production deployment, DNS change, Private Lucy change,
local-guide expansion, prompt change, model/provider change, or publication of candidate
photography.

## Cloud diagnostic contract

Diagnostics are off by default and fail closed unless all staging bindings are present.
Successful and model-unavailable answer requests return these response headers when the
diagnostic gate is enabled:

- `X-Lucy-Trace-Id`: random UUIDv4 generated after public authorization and request validation;
- `X-Lucy-Cloud-Release`: exact 40-character Cloud source commit;
- `X-Lucy-Snapshot-Version`: admitted public projection version;
- `X-Lucy-Snapshot-Digest`: admitted public projection SHA-256.

The operator-only endpoint is:

```text
GET /v1/operations/public-diagnostic/{trace-id}
Authorization: Bearer <operator-only diagnostic token>
```

The endpoint is absent in effect when diagnostics are disabled, is never called by the browser,
and returns `Cache-Control: no-store`. Its one-process TTL store defaults to one hour and 200
receipts. Restarting or redeploying the service erases it.

A successful receipt contains only:

- trace time, environment, Cloud/model release commits, snapshot version/digest, and latency;
- generator/verifier purpose and deterministic attempt UUIDs;
- configured and observed model/provider identifiers;
- rate version and answer/verifier policy digests;
- token counts, admitted maximum cost, incurred cost, and validation outcome.

An unavailable receipt contains only the public release/snapshot bindings, elapsed time, and
the generic `unavailable` outcome. It deliberately does not preserve the internal exception.

No receipt contains the question, answer, history, source text, IP address, session/cookie,
request commitment, provider reference, model reasoning, credential, or response body. The
website still captures raw request/response bodies only inside Claude's explicitly ignored,
local evidence artifact for the owner-approved reproduction questions.

## Staging exercise limits

`LUCY_PUBLIC_EXERCISE_MODE=true` is valid only with diagnostics enabled and deployment tier
`staging`. The public process counts a request before paid execution, including a failed paid
attempt. It enforces:

- two simultaneous answer requests;
- 20 attempts for one temporary browser session;
- 40 attempts across the entire process lifetime.

These are additional to the existing IP/session rate limits and durable provider-cost policy.
The staging database policy must separately set its platform, node, site, and provider caps to
5,000,000 microusd or less, concurrency to two, and a per-attempt maximum compatible with the
generator plus verifier bounds. A dedicated OpenRouter key must have a non-resetting $5 limit
and no automatic top-up. The database, channel binding, provider key, site-to-Cloud bearer,
model bearer, diagnostic bearer, and commitment keys must be staging-only.

The 20/40 attempt limiter is intentionally process-local and non-resettable through HTTP. A
restart resets it, so the operator must not restart merely to bypass the approved exercise.
The dedicated provider key and durable staging cost policy remain the aggregate backstop.

## Website contract for Claude

Claude should preserve the current same-origin browser route. The browser receives no Cloud
credential. The Next.js server attaches the staging site-to-Cloud bearer, exact staging origin,
staging hostname, and temporary UUID session.

For the reproduction build only, the Next.js route should copy the four allowlisted headers
above from Cloud to the same-origin browser response. It must reject malformed or missing values,
strip every other upstream header, and keep `Cache-Control: no-store`. It should attach its own
server-derived website build identifier using a separate allowlisted header. No diagnostic token
or operator endpoint URL enters Vercel or browser code.

Claude's ignored evidence directory should contain one timestamped folder per run with:

- sanitized request/response JSON;
- the temporary history supplied on each turn;
- the five allowlisted build/trace/snapshot headers;
- rendered source and useful-link anchors;
- DOM excerpt and screenshot;
- browser-visible error state and elapsed time.

The greeting must be captured as UI state and confirmed absent from model history. The original
three-question sequence and three fresh sessions are run twice without credential repair:

1. `What makes a Utopia stay different?`
2. `How many properties do you manage?`
3. `Where is a good spot to get coffee in Wildwood?`

The reported empty Sources state is classified by comparing raw `sources` and `links`, DOM,
visible UI, and copied transcript. A true empty array must not render a Sources heading. A
nonempty valid source must render a working descriptive anchor.

## Deployment order

1. Commit and publish this Cloud contract on its dedicated reviewed branch.
2. Provision a separate empty PostgreSQL service and public-only Render environment; do not copy
   the production database.
3. Migrate and commission the staging realm, projection, cost identity, recovery services, and
   immutable $5 policy with no provider key present.
4. Create a dedicated non-resetting $5 OpenRouter key and install it only on the private staging
   model service.
5. Deploy compatible public/model readers with model traffic disabled, verify identities and
   operator receipt authentication, then enable staging exercise traffic.
6. Connect only a Vercel Preview/reproduction build to the staging public service. Production
   environment variables remain unchanged.
7. Run two bounded reproduction suites, retrieve receipts by trace ID, and disable/suspend the
   staging model afterward.
8. Preserve content-free evidence; revoke the staging provider key and all staging bearers when
   Claude confirms reproduction is complete.

Any hosted plan price, lack of an isolated database, inability to create a non-resetting key, or
need to reuse production credentials is a blocker. It must not be worked around by sharing
production capacity.

## Verification ledger

Executed locally against Cloud diagnostic commit
`2dda6f150859ffabc4458e672c56544281b58f17`:

- 2026-09-15: 21 focused unit tests passed for public API, private model API/service, diagnostic
  receipt storage, expiry/eviction, response bindings, and staging limiter behavior.
- 2026-09-15: the complete unit suite passed: 1,015 tests.
- 2026-09-15: repository-wide Ruff passed.
- 2026-09-15: strict mypy passed across all 119 source files.
- 2026-09-15: Docker Desktop 4.90.0 on Windows build 26200 reproduced the known stale AF_UNIX
  socket startup defect. Preserving and moving aside the `Docker/run` and
  `docker-secrets-engine` parent directories advanced between the Ingest and Secrets Engine
  failures but did not recover the daemon; a subsequent start recreated the Ingest socket
  failure. No factory reset, uninstall, or destructive cleanup was attempted. A local-only
  diagnostic bundle was gathered and not uploaded.
- 2026-09-15: the current Render Hobby workspace has 23 of 25 service slots occupied and the
  existing project already uses its two-environment limit. The remaining two service slots are
  insufficient for the separately credentialed public, model, database, cost-writer, and
  recovery boundaries required by this plan. No production service was deleted, shared, or
  repurposed, and no paid plan change was initiated.

This evidence is invalidated by changes to the diagnostic models, public/model API paths,
exercise accounting, provider admission, cost policy, or deployment configuration. Hosted
staging, the dedicated provider key, Claude's website harness, two live runs, and the controlled
limit-exhaustion check remain unexecuted. Commissioning can resume only after Docker Desktop is
recovered or Ray explicitly authorizes a separately isolated hosted environment with enough
resources; production capacity remains ineligible.
