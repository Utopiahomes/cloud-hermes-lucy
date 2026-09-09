# R1 tenant foundation — implementation plan

Status: approved; R1-0 and the R1-1 synthetic local slice are complete; R1-2 scoped
contracts, single-realm credential selection, authenticated-admission interfaces,
database-backed Utopia/Raymond workspace authorization, and the first execute-only
memory boundary are implemented locally. No cloud
deployment, production data migration or activation performed. Read with the original
Node/Tenancy v1.1 specification and correction addendum A1; A1 controls conflicts.

## Finish line

R1 delivers a Utopia website Lucy that uses only an approved public snapshot,
and an authenticated Utopia internal Lucy with scoped memory. Raymond is an
independent private realm. Alpha proves unrelated-customer isolation. Every paid
request has durable provider-cost admission. Evidence, authority and cost
recovery cannot silently revive deleted data, revoked access or available spend.

All five logical nodes exist: Raymond, Utopia, SC Consulting, Cloud Lucy Service,
Alpha. Each has an immutable initial tenure and exactly one wallet ID in
REGISTERED_NONSPENDABLE state. Only tested realms receive readiness claims.
Recommended first continuously deployed realms: Raymond and Utopia. Others remain
registered or synthetic-only. Activation can select Utopia first; R2/R3 are not
prerequisites. Live Telegram capture remains false throughout this work.

## Reconciled baseline and implementation map

Inspected source: `aa157bded743976e934887b996ea8d79a5ebacef` (documentation-only
successor to accepted runtime `52527fa9d8eaa3be766986101b6a8f51c1b1c208`). Current
migration head in source: `0021_recovery_capture_safety`. AWS executor artifact
remains the separately recorded `0020aaa` release. Preserve all v1.2 artifacts
and evidence; this inspection does not reassert current cloud state.

| Existing location | R1 work |
| --- | --- |
| `src/lucy/security_workflows.py` | Preserve SQL claim → policy reads claim/signs grant → Lambda executes → policy attests receipt → SQL reconciliation. Add scope and current authority checks in the new generation. |
| `src/lucy/contracts/security_v1_2.py`, `contracts/canonical.py` | Preserve issued V2 permits, V1 grants/receipts and `lucy-cjson-1`; introduce separate scoped contract models and golden fixtures. Do not switch existing signed bytes to JCS. |
| `src/lucy/executors/{core,handlers,aws}.py` | Fixed realm/caller/key/alias bindings; no PostgreSQL client or new Lambda-to-Render connection. |
| `src/lucy/{api,authorization,policy,readiness}.py`, `db/session.py` | Add trusted actor/workload/channel resolution and realm-bound connection factories; no default tenant or request-selected database credential. |
| `src/lucy/{memory,proposals,corrections,provenance,archive,retention}.py`, `db/models.py` | Scope every implemented read/write/derivation; preserve OTR and deletion fences; inventory historical rows before any cutover. |
| `src/lucy/{model_execution,actions}.py` | Reuse bounded-request and idempotency behavior; replace the single fixed model/reservation assumption in the R1 path with versioned provider-cost admission. |
| `src/lucy/{authorized_deletion_recovery,recovery,finality}.py` | Realm-specific signed replay plus fresh authority/cost overlays and recorded recovery timing. |
| `deploy/aws/security-baseline-v1.2.yaml`, `deploy/render/security-baseline-v1.2.yaml.example` | New v1.3 templates with explicit realm parameters; preserve accepted templates. Source Blueprint specifies PostgreSQL 18; verify actual new target version/extensions before provisioning. |
| New `tenancy`, `publication`, `cost_admission`, `authority_recovery` modules | Identity/binding operations, public snapshot path, minimal exposure controller and authority replay. These names are proposed, not implemented. |

Use an isolated development branch and test databases. Append migrations after
the actual head when implementation begins. New realms start empty; legacy data
classification/import is a separate reviewed cutover manifest, never a default
assignment of all records to Raymond. No production dual-write.

## Security guarantees and grant timing

| Credential/process | Ordinary access | Complete compromise limit |
| --- | --- | --- |
| Website | Exact public snapshot and admitted visitor session; no private search | Approved public dataset plus whatever visitor capabilities that process actually holds; not proof of session isolation against its full credential set |
| Realm routine | Membership/workspace/action-scoped memory and ingestion | Potentially all semantic-memory authority of its realm credentials; no evidence decrypt or foreign realm |
| Realm policy | Read persisted claim, sign grant, attest receipt | Can abuse its own signing authority; no direct content/AWS/cross-realm credential. Do not claim protection against collusion with another compromised boundary. |
| Evidence/deletion workflow | Named SQL functions and exact qualified alias | Cannot enumerate/directly mutate tables or call KMS/DynamoDB; cannot forge policy signatures |
| Retrieval/deletion executor | Exact verified grant and scoped AWS operation | Known-ID abuse inside its realm as accepted; no foreign keys, enumeration or administration; deletion has no evidence-key action |
| Directory/cost controller | Directory or cost metadata through named operations | May disrupt routing or cost admission within held authority; cannot mint realm owner proofs, redirect authenticated content or read private bodies |
| Privileged administrator | Explicit administrative operations | Host/cloud/DB/IdP/deployment administration remains an ultimate trust boundary |

Sensitive finance/employee workspaces that need stronger compromise containment
require dedicated restricted credentials/processes before activation. R1 does
not automatically make every workspace a separate realm. Future consulting runs
inside the client boundary with no SC operational credentials; that feature is R3.

Existing state names include ISSUED, CLAIMED, EXECUTING, EXECUTOR_RECEIPTED,
DELIVERY_CONFIRMED/DELIVERY_UNKNOWN and EFFECTIVE/FINALITY_PENDING/
FINALITY_EXTENDED/FINALITY_VERIFIED. Preserve their ambiguity semantics.
Current code has a ten-minute execution window and 30-second skew; the source
Lambda template has 60-second retrieval and 120-second deletion timeouts.

R1 candidate policy: at most 60 seconds to admit a new sensitive invocation,
at most five seconds allowed skew, and separately bounded execution duration
(initially no more than the existing 60/120-second Lambda limits). Separate
start-by and completion deadlines in new contracts so a legitimate signed
completion is not rejected merely because admission expired during execution.
Check authority atomically at SQL claim and immediately before policy grant
issuance; recheck recipient authority before delivery. Epochs in old grants
alone do not establish fresh revocation knowledge in Lambda.

Revocation reports ISSUANCE_BLOCKED → DRAIN_PENDING → RECONCILED. A previously
issued grant may still execute; receipt/reconciliation must record the actual
effect. Expiry or invocation timeout alone cannot prove an AWS request had no
effect. Unknown operations keep reconciliation pending. Test revocation before
claim, between claim/grant, after issuance, during execution and before delivery;
also test duplicate invocation and delayed receipt. No instantaneous revocation
claim and no new online Lambda authorization service in R1.

## Six bounded work packages

| Package | Deliverable and dependencies | Required exit evidence |
| --- | --- | --- |
| R1-0: reconcile | Freeze baseline manifest, complete scope inventory for implemented surfaces, draft identity/role map and provisioning bill of materials | Exact source/schema references; unresolved hosting/authentication facts listed; v1.2 untouched |
| R1-1: identity/public slice | Accounts, nodes, tenures, principals, realm/workspace/channel bindings, nonspendable wallet IDs; separate public publisher/store/runtime; depends on 0 | Utopia fixture → approved FAQ snapshot → answer with source/version; foreign/private canaries denied, spoofed ingress denied, approval invalidation and withdrawal proved |
| R1-2: private realm/security | Parameterized stamps, new scoped contracts, authenticated internal UI/API, scoped memory and sensitive chain; depends on 1 | Actual Raymond/Utopia/Alpha role/key isolation, workspace positive/negative controls, revocation race and receipt tests, OTR/deletion closure |
| R1-3: cost admission | Durable bounded synchronous requests, reservation/reconciliation, public abuse limits and kill switch; depends on 1, integrates 2 | Concurrent free/public/retry attempts cannot oversubscribe caps; unknown exposure survives restart/period rollover; no model call without admitted reservation |
| R1-4: recovery | Independent authority/cost heads and replay; reuses scoped evidence recovery; depends on 2 and 3 | Pre-deletion/pre-revocation/pre-reservation restore, stale-prefix rejection, acknowledgement loss and repeat replay; no unauthorized release or reset spend |
| R1-5: commissioned acceptance | Exact deployment identities, real OIDC/IAM/SQL denials, privacy scan, resource/cost inventory, runbooks and activation manifest | Cumulative evidence for implemented R1; every production-ready realm checked; deferred endpoints unavailable; no open exploitable boundary |

R1-1 initially uses deterministic mock inference. R1-3 may be developed alongside
R1-2, but paid calls require its gate. Each package is a reviewable commit/PR
series; schema freeze occurs after its first successful slice. The useful UI is
a minimal site chat and authenticated node/workspace selector with scoped answer
sources, explicit unavailable states and approved publication review. Customer
authentication uses an issuer/subject adapter with test IdP fixtures first; pin
the actual owner IdP, audience and strong-auth proof before internal activation.
AWS operator SSO is not automatically the customer authentication system.

## Minimal provider-cost controller

Put only content-free cost metadata in a dedicated shared database, with separate
cost-admission and recovery-writer identities. The directory database is separate.
Private model calls originate in realm/site workers with their own credentials.

- `provider_cost_policies`: immutable version, platform/node/site/provider period
  caps, outstanding-exposure cap, approved rate/model/usage limits and kill state.
- `provider_attempts`: scoped unique idempotency key, request commitment, policy
  version, maximum micro-USD, provider reference, state and submission generation.
- `exposure_reservations`: exact attempt, admission period, reserved maximum,
  incurred cost, unresolved amount and reconciliation reference; no float values.
- `cost_events` and `recovery_outbox`: immutable transitions, event IDs/digests,
  dependency heads, acknowledgement and rebuildable counters.

Named functions reserve all applicable caps under deterministic locks; require
incurred + unresolved + proposed <= each cap. Submission requires the independent
journal acknowledgement and a one-attempt admission. A crash near submission is
UNKNOWN until proven otherwise, never an automatic resubmit. Every new paid
retry needs separate capacity. Actual over-cap provider cost is recorded honestly,
raises an exception and blocks further work; do not clamp it to the reserved cap.
Only proven unused exposure is released. Old-period unresolved exposure continues
to count against the global outstanding ceiling. Restores start paused.

Activation must supply explicit numeric global, node/site and provider daily
limits; outstanding exposure; concurrency; request/session/IP rates; maximum
input/output tokens and request bytes; timeout; approved model/rate version and
provider credential cap where supported. Missing values deny paid execution.
No customer credits, ledger posting or R2 scheduler is needed. The admission
capability does not prevent a fully compromised provider-key holder making
out-of-band calls; provider limits and credential blast radius are recorded.

## Authoritative recovery design

| Stream | Approver | Writer / store | Required completion barrier |
| --- | --- | --- | --- |
| Evidence deletion | Realm owner/policy chain | Realm deletion executor; scoped existing-style DynamoDB intent/receipt authority | Signed durable effect plus policy attestation and SQL reconciliation; governed derivative closure complete |
| Membership/binding/withdrawal | Current realm owner/admin; deployment authority for binding trust changes | Separate realm authority writer; realm authority events/head tables | Durable head acknowledged before enabling access/publication; revocation closes issuance first and reports drain separately |
| Provider exposure | Cost policy within owner-set ceilings | Restricted cost journal writer; shared cost events/head tables | Reservation acknowledged before submission; verified outcome/release acknowledged before capacity reuse |

For new streams, event insert and head advance are one conditional DynamoDB
transaction. Head = stream ID, authority epoch, sequence, event digest. The
writer validates source authority and event type; append permission alone cannot
mint memberships or arbitrary budget increases. Permanent event-ID/digest
comparison handles lost acknowledgement. SQL stages pending state in its outbox;
dependent effects remain blocked until the exact acknowledgement is verified.

Pin exact store identities, writer/recovery roles and authority epochs in the
deployment-controlled manifest outside restored SQL. Recovery reads the live
head consistently and replays to that head; a valid lower prefix is rejected.
Routine roles cannot rewind heads, restore tables or replace the trusted locator.
If the independent authority is unavailable or rolled back, stay quarantined
unless an independently retained acknowledged witness proves freshness; R1 does
not build automatic recovery of simultaneous loss of every trust authority.
Publication withdrawal must replay before public routing returns. Record recovery
request, ready, replay, verified and cleanup timestamps; test idempotence and
cross-realm denial without claiming a production RTO before measuring it.

Revocation and withdrawal block local access as soon as the authoritative change
is accepted. They are reported as `PERSISTENCE_PENDING` until the exact event and
head advance are durably acknowledged; only then may the API report the restriction
as durably recorded. A failed acknowledgement leaves access blocked and the scope
quarantined for reconciliation, so restoring the application database cannot
silently discard a restriction the owner was told had completed.

Recovery also uses a protected final handoff. After replay reaches the observed
head, keep ingress closed while the authority writer either pauses changes for
that scope or atomically records an activation barrier against the expected head.
Re-read and compare the head immediately before reopening. If it advanced, replay
the suffix and repeat the barrier; if the barrier cannot be established, remain
quarantined. A strongly consistent read establishes the value at that instant,
not that no later revocation exists.

## Deployment and cost worksheet

Five logical fixture nodes; full concurrent private test realms for Raymond,
Utopia and Alpha. SC/Service remain registered unless their resources are actually
commissioned/tested. Production proposal: two complete realm stamps, one per
Raymond/Utopia, each with four private backends, one metadata-only finality job,
three KMS keys, two Lambdas and separate authoritative stores. Public runtimes
and authenticated private ingress terminate content only inside their own node
boundary. Publication workers have distinct identities and may run on demand.
Prefer one managed private PostgreSQL instance per production realm initially;
logical-database consolidation requires proven hosting/grant/restore support.

| Component | Planning quantity | Cost status |
| --- | --- | --- |
| Private workflow compute | 8 continuous processes for two realms | Existing template shape 0.5 CPU/512 MB; account quote needed |
| Content ingress/public compute | Budget for 2 public + 2 private ingress processes; merge only where credentials/audiences remain safe | Account quote needed |
| Shared metadata services | Directory and cost controller, separate identities/processes | Account quote needed |
| Databases | 2 realm + directory + cost logical databases; conservative estimate uses 4 managed instances | Instance/storage/backup quote needed; existing realm template 0.5 CPU/1 GB, 5 GB storage |
| KMS | 6 new realm keys | USD 6/month base key storage, before rotation/request charges |
| Other AWS/Render | 4 Lambdas, realm tables plus authority/cost journals, PITR, audit/logs, finality/publication jobs, bandwidth, workspace | Usage-based quote needed |
| Transitional resources | Existing v1.2 plus temporary Alpha/test realm while retained | Track separately; do not silently delete accepted resources |
| Inference | Explicit owner-approved request and period ceilings | Disabled until configured |

KMS base storage follows [AWS pricing](https://aws.amazon.com/kms/pricing/).
[Render pricing](https://render.com/pricing) did not expose an authoritative
numeric compute table in the retrieved page; this plan intentionally does not
substitute older Starter prices for the current plan IDs. Total monthly cost is
not yet quoted or measured. R1-0 must attach the account-specific fixed-cost,
variable-cost and temporary-resource estimate before production provisioning.
This open quote does not block local identity/public-slice work.

## Verification and handoff

Retain the original test IDs as coverage references, assigned by implemented
surface. R1 covers applicable ISO/PUB/SEC/CAP/COMP, provisioning, and evidence/
authority/cost recovery cases; it adds explicit issued-grant and exposure-barrier
tests. R2 JOB/WAL and R3 GRANT/TOOL/RUN/transfer/rehost cases are deferred with
their endpoints disabled, not labeled passed. Test wallet-ID uniqueness now.

Use existing focused workflow, contract, executor, model-budget and PostgreSQL
boundary tests as starting points. Changes to shared validators or recovery may
justify wider tests; unchanged passing evidence is reused after relevant drift
checks. Each newly deployed realm gets its own binding/permission test even with
identical code. No blanket final rerun solely because a release is ending.

Handoff includes source/schema/contract/deployment identities, coverage/evidence
manifest, actual credential blast radii, costs/limits, recovery timings and
exceptions, rollback/quarantine instructions and exact proposed activation scope.
Production provisioning, live DNS, customer data and capture activation remain
separate from this planning task. Next implementation action after plan review:
R1-0, then R1-1's synthetic Utopia public slice. R2 wallets/jobs and R3 consulting,
local runners, exports/rehosting/transfer and StoinNet behavior are excluded.
