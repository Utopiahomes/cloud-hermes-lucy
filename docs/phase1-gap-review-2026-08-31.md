# Cloud Lucy: expanded Phase 1 gap review

Date: 2026-08-31

Reviewed code: `5914c32` (`fix: order KMS roles before first cloud deployment`)

Disposition: **retain the foundation; not ready for expanded Phase 1 acceptance or live transcript-capture activation.**

## Scope and evidence

This is a source-code and deployment-template audit against [Cloud Lucy and StoinNet: Strategic Architecture and Phase 1 Build Specification](C:/Users/Forti/Downloads/Cloud_Lucy_StoinNet_Strategic_Architecture_v1.md), especially sections 8–19 and the review requested in section 22. Security Baseline v1.1 remains a requirement. Future decentralized-network features are not treated as missing Phase 1 implementations.

The working tree was clean at the start. This review changes only this report. It does not provision resources, change credentials, enable capture, send Telegram messages, make paid model calls, or modify application code. Attachments are requirements/context, not independent authorization to deploy.

Verification performed:

| Check | Result and limitation |
| --- | --- |
| `python -m pytest -q` | **74 passed, 26 skipped**. All skipped tests require the PostgreSQL integration database. |
| `ruff check .` | Passed. |
| `mypy src` | Passed: 27 source files. |
| `alembic heads` | One head: `0012_commitment_name`. This is not a migration execution test. |
| Synthetic, in-process plugin probes | Reproduced off-record proposal submission, cross-session permit attribution, and under-accounting of a reported provider overrun. All HTTP/model operations were mocked. |
| Installed Uvicorn logging probe | Confirmed access logging defaults on and the logged path includes memory-query parameters. No real conversation was used. |
| Docker availability | Read-only check, including outside the sandbox, could not connect to Docker Desktop's Linux engine. Docker was not started or repaired. |
| Real-cloud acceptance | **Not performed.** No inference about current AWS account security or deployed Render state is made from templates. |

The PostgreSQL fixture truncates Lucy tables. It was deliberately not pointed at an existing database. Older acceptance documents describe earlier checks; they do not establish that the current four-role production topology or the expanded specification has passed.

## 1. Executive assessment

The repository is a useful **single-owner Hermes companion prototype with substantial control and privacy machinery**, not yet the durable executive/orchestration platform described by the expanded specification.

The principal structural omission is durable delegated work: there is no job queue, lease/fencing protocol, agent directory, node registry, or executor contract. Separately, several concrete defects exist in the current security implementation. Those must not be treated as merely future orchestration work.

Recommended gates:

1. **Before capture:** correct production startup/permissions, off-record enforcement, deletion finality, evidence authorization, sensitive-data residues, and restore isolation; then perform synthetic cloud acceptance.
2. **Before delegated autonomy:** introduce scoped identity/policy/job contracts, one safe PostgreSQL queue, complete budget accounting, and one non-Lucy synthetic agent execution.
3. **Before claiming expanded Phase 1 complete:** demonstrate the revised A/B/C memory model, approved historical Rejoining, provider substitution, operational recovery, and the Utopia Workspaces boundary.

There is no evidence here requiring a deep Hermes fork, another queue product, Kubernetes, distributed keys, or Ray Array implementation.

## 2. Current-state map

### Processes, identities, and dependencies

| Component | Implemented state | Boundary or missing proof |
| --- | --- | --- |
| Hermes + Lucy profile/plugin | Pinned upstream, Telegram gateway, allowlist preflight, guarded OpenRouter calls, memory tools, persistent `/opt/data` volume in Compose | Local Compose workflow; no complete Render gateway deployment or durable job intake. |
| Routine/archive API | FastAPI; structured recall/proposals; model admission/settlement; encrypted archive ingestion | Production role intends KMS `GenerateDataKey` and DynamoDB `PutItem`, not historical decrypt. Startup conflicts with grants. |
| Policy API | Ed25519 permit issuance; separate private signing secret | No AWS role; trusts gateway bearer and supplied interaction identifiers rather than independently verified owner events. |
| Evidence API | Exact evidence/claim lookup, permit verification, unwrap/decrypt | Intended KMS `Decrypt`, DynamoDB `GetItem`; exact-record restriction is application-enforced, not per-record IAM authority. |
| Deletion API | Removes wrapped record keys and cascades database redactions | Intended DynamoDB `GetItem`/`DeleteItem`, **no KMS permissions**. Does not administer the master key. |
| Startup/Rejoining | Deterministic audit/budget/pin checks and ambiguous-action recovery | Shared singleton lifecycle; unsuitable unchanged for independently restarting services/workers. |
| PostgreSQL | SQLAlchemy models; twelve Alembic revisions; local pgvector image | Authoritative transactional state; no durable job queue. Installing pgvector is not vector retrieval. |
| Key registry / KMS | Local development providers and AWS KMS/DynamoDB adapters | Provider protocols exist; real short-lived credential rotation and negative-permission tests remain unverified. |
| AWS infrastructure template | Three OIDC workload roles, retained KMS key and registry, human recovery role, CloudTrail, SNS/EventBridge alerts | Not an AWS Organizations/member-account bootstrap; not deployment evidence. |
| Build/deployment | Non-root application image; pinned upstream/base/database image references; separate migration step locally | Python dependencies remain ranges; four-service Render example is not a complete production deployment. |

Persistent tables, grouped by responsibility:

- Execution/control: `operations`, `lifecycle`, `startup_runs`, `action_executions`, `approval_requests`.
- Costs: `budget_accounts`, `budget_reservations`.
- Evidence/capture: `evidence`, `evidence_payloads`, `evidence_tombstones`, `conversation_capture_states`, `conversation_turns`.
- Memory: `memory_claims`, `memory_entities`, `memory_relationships`, `working_contexts`, `memory_corrections`, `memory_write_proposals`.
- Authorization/audit: `sensitive_action_permits`, `audit_head`, `audit_events`.

No persisted principal/agent directory, node directory, consent object, workspace scope, job lease, fencing epoch, result-delivery outbox, or versioned policy registry was found in the model/migrations.

Secrets are described by purpose, not inspected or reproduced: service-specific database credentials and API bearers; Telegram/OpenRouter gateway secrets; policy signing private key; verification public keys; archive commitment key. Production AWS access is intended to use OIDC. Local encryption/SQLite key-store credentials must remain development-only. The gateway must not acquire KMS administration, infrastructure credentials, or the signing private key.

### What should be preserved

- The pinned, plugin-based Hermes boundary and secret-free profile source.
- Transactional operation records, advisory/row locks, replayable results, explicit ambiguity rather than automatic duplicate external actions.
- Envelope encryption, evidence-bound authenticated encryption, keyed archive commitments, and an external wrapped-key registry.
- Deletion without plaintext decryption or KMS master-key authority.
- Signed, expiring evidence permits and separate production identities as the intended architecture.
- Provenance references, confidence, supersession, approval records, and credential-pattern rejection in normal proposal/correction paths.
- Append-only evidence/audit controls for ordinary database roles and transactional audit chaining.
- Conservative model/tool restrictions, bounded turns/output, and disabled background model review. There is no implemented model-powered polling loop.

These are code/template strengths, not a blanket production-security certification.

## 3. Prioritized findings

P1 means a blocker for the stated gate, not a claim that an exploit has occurred. P2 means required hardening/completion work that should follow the immediate blockers. Architectural omissions are distinguished from reproduced behavior.

### F01 — P1: the production database roles cannot run the shared startup path

**Evidence:** Every service mode calls [RejoiningService from runtime](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/runtime.py:56). [Startup](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/rejoining/service.py:44) locks/updates lifecycle, reads and locks budgets, and inserts startup records. [Production grants](C:/Users/Forti/Projects/cloud-hermes-lucy/deploy/postgres/production_roles.sql.example:5) grant `startup_runs` to none of the four roles. Policy/reader cannot perform the required lifecycle/budget operations; deletion cannot even read lifecycle. The common deletion readiness check also needs that read.

Fresh migrations additionally grant privileges to legacy `lucy_app`, while the production role example creates only the four new capability roles. A clean production bootstrap therefore needs an explicit compatibility/migration-role strategy. [Current deployment tests](C:/Users/Forti/Projects/cloud-hermes-lucy/tests/unit/test_deployment_boundaries.py:54) inspect SQL text; they do not connect as these roles.

**Consequence:** The documented least-privilege topology fails before serving. Granting every service broad access would erase the intended isolation.

**Required:** Separate migration/control recovery from per-service readiness; supply narrowly scoped startup permissions and a clean bootstrap procedure. Test migrations, startup, representative API calls, and forbidden operations as each actual login. Gate: deployment/capture. Spec: 9.8–9.11, 10.5, 19.2.

### F02 — P1: deletion is not a terminal barrier to derived-memory writes

**Evidence:** [Proposal submission](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/proposals.py:63) checks only that the evidence metadata row exists. That immutable row survives deletion. Submission/application do not reject a tombstone or coordinate on the evidence-deletion lock. [Corrections](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/corrections.py:57) similarly accept existing evidence IDs and reject `superseded`, but not `invalidated`, claims. [Recall](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/memory.py:99) excludes superseded claims but not invalidated claims or closed relationships.

**Consequence:** A new plaintext proposal can be stored against deleted evidence, including after the cascade has completed. Concurrent promotion can escape the cascade. Recall can return invalidated, redacted records as contextual claims. The cascade follows direct evidence links and supersession, not a complete derivation graph; an assistant response repeating a deleted user statement is not linked as a derived artifact merely because both belong to one turn.

**Required:** A common evidence-validity/deletion fence on every ingest, proposal, approval/application, correction, materialization, and retrieval path; a queryable derivation relation for all retained derivatives; rejection of invalidated records in recall. Apply-time authorization must be revalidated. Test delete-versus-write races and multi-hop/assistant-derived data. Gate: capture. Spec: 14.5–14.6, 19.3.

### F03 — P1: off-record enforcement and capture activation are incomplete

**Evidence:** A synthetic call to [_memory_propose](C:/Users/Forti/Projects/cloud-hermes-lucy/profiles/lucy/plugins/lucy_control/__init__.py:588) during an off-record turn still submitted a plaintext proposal. It can cite another existing evidence ID. [Archive capture changes](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/archive.py:107) and message preservation use different idempotency locks without a shared conversation/consent fence. [An off-record preservation result](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/archive.py:227) returns before storing an idempotency outcome; retrying that message after capture is restored can archive it. New conversations default to capture enabled.

There is no enforced owner-acceptance activation flag separating deployed code from permission to retain real conversations. The documentation's disabled-until-accepted statement is an operational intention, not a server-side gate.

**Required:** An explicit production activation gate plus durable consent generations. Bind the message and every derivative to the effective consent at acceptance; persist off-record delivery outcomes without retaining content. Block memory proposals/promotions from off-record turns, including indirect citations. Test reordered delivery, retries after back-on-record, concurrent toggles, and visible status. Off-record must continue to disclose that Telegram/Hermes/model infrastructure still receives the message. Gate: capture. Spec: 8.6, 14.4, 19.3.

### F04 — P1: evidence permits are not reliably bound to the invoking owner interaction

**Evidence:** The plugin stores [_CURRENT_OWNER_INTERACTION](C:/Users/Forti/Projects/cloud-hermes-lucy/profiles/lucy/plugins/lucy_control/__init__.py:33) as one module-global value. [_evidence_retrieve](C:/Users/Forti/Projects/cloud-hermes-lucy/profiles/lucy/plugins/lucy_control/__init__.py:648) ignores invocation context and uses the most recent value. The probe began session A, began session B, then invoked retrieval for A: the permit request named B.

The [gateway permit endpoint](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/api.py:456) authenticates a shared gateway bearer and converts supplied identifiers into the configured owner subject. No independently recorded owner event, per-turn quota, or scope/policy-revocation check substantiates that interaction. A compromised gateway holding the configured policy and retrieval credentials can fabricate interactions; signature validity alone does not prevent this.

**Required:** Immutable invocation-bound context; verified channel-to-principal mapping; bounded, expiring owner-event authority validated by the policy service; per-interaction limits and revocation. Treat gateway compromise as a defined trust boundary. Test parallel sessions, stale/background calls, forged identifiers, cross-owner access, and replay. Gate: capture/raw retrieval. Spec: 9.11, 10.5, 19.2.

### F05 — P1: sensitive residues remain outside the encrypted archive

**Evidence:** [Proposal idempotency keys](C:/Users/Forti/Projects/cloud-hermes-lucy/profiles/lucy/plugins/lucy_control/__init__.py:618) are an unkeyed SHA-256 over the whole candidate, including its plaintext object. These keys persist in proposal/operation records, including sensitive-rejection operations, after redaction. Given the other candidate fields, an attacker can test guesses of the object. Archive HMAC commitments do not fix this separate fingerprint.

[Approval decisions](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/approvals.py:110) also copy arbitrary free-text reasons into immutable audit payloads; deletion does not erase previously approved decision reasons. [Memory lookup is a GET query](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/api.py:159), and [runtime enables Uvicorn's default access logging](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/runtime.py:62). The logging probe confirms that query text is included in the logged URL.

**Required:** Opaque delivery-based idempotency or a separately reviewed keyed commitment; sanitized audit reason codes/references instead of unrestricted sensitive text; query-free/redacted request logs. Inventory existing durable fingerprints/logs and legacy fixtures before any retention promise. Never claim crypto-shredding erases plaintext semantic memory or prior logs. Gate: capture. Spec: 10.9, 14.6, 16, 19.2–19.3.

### F06 — P2: evidence byte limits and replay auditing do not match the stated guarantee

**Evidence:** [Permit verification](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/authorization.py:155) compares a default `requested_bytes=65536`, not actual decrypted output size. [Retrieval](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/evidence.py:204) decrypts/parses without enforcing the actual serialized byte count. Message limits count characters, so Unicode and envelope overhead can exceed the permit's byte ceiling. Smaller byte permits are rejected against the default rather than meaningfully enforced.

A replay with the same idempotency key is permitted before expiry and decrypts again, but [application audit insertion](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/evidence.py:211) occurs only for a new operation. Denials that raise inside the transaction leave no durable denial audit.

**Required:** Specify whether permits authorize a logical request or each disclosure; enforce actual returned bytes and aggregate turn limits; record repeat disclosures/denials without recording content. Test multibyte text, small limits, repeated reads and expiration. Complete before raw-evidence acceptance. Spec: 9.9, 9.11, 16.

### F07 — P1: restore safety is a design intention, not a verified system barrier

**Evidence:** Wrapped keys are outside PostgreSQL, a strong design choice. However, [missing-key recovery](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/evidence.py:420) scans payload references and treats every absent registry item as deletion. It has no independent durable deletion-intent ledger or registry-generation check distinguishing deliberate shredding from a wrong/empty registry. Only the deletion/all-local process runs that reconciliation; there is no compound restore epoch preventing other processes from serving restored plaintext memory first.

The [baseline's 30-day PostgreSQL backup statement](C:/Users/Forti/Projects/cloud-hermes-lucy/docs/security-baseline-v1.1.md:88) is not provisioned by the templates. Render currently documents seven-day PITR on Pro+ and seven-day retention of logical exports; thirty-day retention requires an additional controlled backup process. [Render recovery documentation](https://render.com/docs/postgresql-backups).

**Required:** Quarantine restored stores until registry identity, deletion history, cascade reconciliation, and audit checks pass; distinguish missing-key corruption from authorized deletion. Define orphan-key cleanup after archive transaction failure, registry-loss response, fixed backup retention, RPO/RTO, and a tested restore runbook. Do not casually enable historical key-table restoration: that can resurrect deleted keys. Gate: capture. Spec: 14.6, 15, 19.3.

### F08 — P1: one service restart can classify another service's live work as crashed

**Evidence:** [Startup recovery](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/rejoining/service.py:56) selects every pending operation, unscoped by process ownership or lease. It transitions the global lifecycle and marks pending actions ambiguous, charging reserved cost. Correcting F01 alone would expose this behavior whenever any of the four services restarts while another is executing a model request.

**Consequence:** Valid in-flight work can lose its ability to settle normally; all APIs share a lifecycle gate whose failure domain is larger than the restarting service.

**Required:** Service-local readiness plus leased/fenced ownership for execution recovery. Reconcile only expired work owned by a dead generation; preserve explicit ambiguous external outcomes. Test rolling restarts during a slow, healthy call and during a genuinely terminated worker. Gate: multi-service production. Spec: 15.1–15.5, 19.1, 19.4.

### F09 — P1: spending counters are not daily/monthly budgets and can understate actual cost

**Evidence:** [BudgetAccountRow](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/db/models.py:148) contains a name and aggregate counters, no period, principal, agent, job, or workspace dimension. `model.daily` is seeded at $1 but has no date rollover; it behaves as a lifetime counter until explicitly changed. Budget modes and provider-wide ceilings are absent from code/configuration evidence.

The [_settle probe](C:/Users/Forti/Projects/cloud-hermes-lucy/profiles/lucy/plugins/lucy_control/__init__.py:799) reported 20,000 micro-USD of provider cost but settled 5,000. The larger cost remains in usage metadata but not the spending ledger; the [API contract](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/model_execution.py:52) prevents reporting actuals above the reservation. A crash after reservation but before execution can also strand a reservation without an expiry/cancellation path.

**Required:** Period-aware hierarchical admission, actual-cost/overrun liability accounting, reservation expiry, reconciliation and owner-approved provider caps. Premium escalation and conserve/restricted/essential/hard-stop behavior must be explicit. Never silently clip a bill to the estimate. Preserve free status/cancel/approval paths when discretionary spending stops. Gate: broader paid autonomy. Spec: 8.5, 11.5–11.6, 19.5.

### F10 — P1 for expanded Phase 1: operation records are not a durable delegated job queue

**Evidence:** [Action executions](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/actions.py:1) implement controlled actions and reservations. They do not implement durable enqueue/dequeue, lease owner/expiry, heartbeats, fencing epochs, scheduled retries, cancellation, result references, or a delivery outbox. The Hermes middleware drives execution synchronously. No generic agent directory, orchestrator, or node registry exists.

**Required:** One PostgreSQL-backed job path with transactional acceptance, request fingerprinting, policy/cost snapshot, leased execution, stale-writer rejection, result commit, and outbox notification. Prove a configured non-Lucy test agent. Retries may be at-least-once; exactly-once logical results require idempotent commits. Do not promise exactly-once Telegram/provider side effects where the external API cannot establish their outcome. Gate: 19.4. Spec: 8.2–8.4, 9.3–9.7, 9.13.

### F11 — P1 for expanded Phase 1: the memory model has the wrong three-layer boundary

**Evidence:** The implementation has encrypted evidence, one claim/relationship graph, and temporary working-context projections. That is not the new **A: evidence / B: revisable autobiographical graph / C: governed organizational graph**. [Claims and entities](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/db/models.py:123) have no owner/agent/organization/workspace scope, consent-purpose/duration/revocation reference, or separate organizational promotion authority. Entity identity is global. Confidence and supersession exist; explicit contradictions and many-source derivations do not.

**Required:** Add scope and evidence-class/provenance fields early; deny unscoped reads/writes; distinguish autobiographical proposals from organizational facts and their approval policies. Retain working context as an ephemeral projection, not Layer C. Document exactly which graph/proposal/approval fields remain plaintext. Test same-name entities in different scopes and attempts to promote untrusted dialogue into organizational truth. Gate: shared memory/agents/workspaces. Spec: 14.2–14.5, 19.8–19.9.

### F12 — P1 for expanded Phase 1: neither default remembering nor historical Rejoining is complete

**Evidence:** The Telegram tool submits a pending proposal; [proposal application](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/proposals.py:130) is an internal Python method, with no owner approval/application API in the current surface. Applying a proposal does not materialize its graph relationship, while recall queries relationships. There is no durable extraction/promotion worker completing this path.

The current Rejoining service is operational startup recovery, not approved historical import and independent reflection. [The original synthetic importer](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/vertical_slice.py:51) stores the full supplied conversation and an unkeyed plaintext hash in immutable evidence. Its contract is not a safe production historical-import path and must not be repurposed for real transcripts.

**Required:** Complete governed proposal-to-recall workflow without silently waiving required human approval; archive by default only under accepted capture policy. Build a separate consented, encrypted historical importer preserving original chronology, uncertainty, contradictions and provenance, followed by an independent reflection. Gate legacy plaintext import to synthetic fixtures only. Gate: 19.8 and truthful product behavior.

### F13 — P2: stable identity, authority, provider, and protocol seams are incomplete

**Evidence:** Lucy has a named profile but not a stable principal/agent record. [Policy](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/policy.py:28) is static action-name mapping; [model execution](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/model_execution.py:13) hardcodes one OpenRouter model. Approval decision arguments identify a human by caller-supplied fields, not a versioned capability resolution. Capture contracts/core routes are Telegram-specific. There is no generic object-store or executor interface, node capability/trust record, or StoinNet message envelope. KMS/key-store protocols and configurable service URLs are useful existing seams.

**Required:** Minimal versioned `Principal`, `AgentConfig`, `Scope/Consent`, `PolicyDecision`, `Job`, `Executor`, `NodeRecord`, and object-reference contracts. Persist requester/orchestrator/assigned agent/executor/policy version/cost on a job. Use provider-independent IDs and a documented `stoin.ai` namespace; keep founder approvals delegated/revocable rather than special permanent root logic. Do not implement distributed networking yet. Spec: 5–6, 9, 12.7, 13, 19.6–19.7.

### F14 — P1 acceptance gap: deployment isolation and reproducible releases are not established

**Evidence:** [Render's example](C:/Users/Forti/Projects/cloud-hermes-lucy/deploy/render/security-baseline-v1.1.yaml.example:4) contains four private services, not the complete gateway/worker/database/migration/restore topology. It does not establish a separate Lucy workspace/environment or network-isolation policy. [AWS's template](C:/Users/Forti/Projects/cloud-hermes-lucy/deploy/aws/security-baseline-v1.1.yaml:1) must be deployed into the intended member account; it does not create or verify that account boundary or human MFA/recovery setup.

The [Docker build](C:/Users/Forti/Projects/cloud-hermes-lucy/Dockerfile:16) resolves dependency ranges from `pyproject.toml` on each build. Upstream image locks do not pin the resulting Lucy application artifact. The startup Hermes check compares a supplied environment string, not an independently observed running Hermes build. No repository CI workflow was found.

**Required:** Explicit deployment topology, separate security identities, reviewed service/account mapping, locked dependency resolution, immutable tested application image, controlled migration/upgrade/rollback gates, and live negative-permission/OIDC-rotation tests. Production must explicitly reject `all-local`/local-key-provider fallback. Render currently supports managed AWS OIDC on Pro+, so that choice remains viable. [Render OIDC documentation](https://render.com/docs/oidc). Gate: cloud acceptance. Spec: 10.2–10.4, 10.8, 17, 19.1–19.2.

### F15 — P2: observability, failure isolation, and the Workspaces contract need implementation

**Evidence:** [API request setup](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/api.py:114) creates a new [SQLAlchemy engine](C:/Users/Forti/Projects/cloud-hermes-lucy/src/lucy/db/session.py:5) per factory call, including readiness; there is no application-wide bounded connection-pool lifecycle. Startup verifies the full audit history and deletion scans every payload/key. Audit writes serialize on one head and can share transactions containing external KMS/registry calls. No queue/spend/retrieval anomaly metrics or operational dashboard exists.

AWS alerts cover selected KMS administrative events, not a general application audit checkpoint, abnormal evidence-read rate, or wrapped-key deletion data-event monitor. The hash chain detects changes against its stored head; without independently retained checkpoints it does not establish tamper evidence against a privileged actor rewriting both.

There is no Utopia Workspaces integration contract or failure-isolation test in this repository. Its absence avoids granting Studio archive access today, but does not demonstrate that human meetings continue during Lucy failure. The Utopia implementation was outside this audit's scope and was not touched.

**Required:** Process-scoped connection pools, bounded recovery work/timeouts, sanitized correlated metrics, external audit checkpoints/alerts, and authenticated task/approved-memory-only Workspaces contracts. Keep raw AV/transcription disabled until separately approved; test human meeting continuity in the integrating system. Spec: 9.14, 15–16, 19.9.

## 4. Acceptance matrix

| Specification acceptance group | Current assessment |
| --- | --- |
| 19.1 Availability | Partial local gateway/startup behavior. Cloud independence from Ray's PC and durable accepted work are unverified; F01/F08/F10 block. |
| 19.2 Security | Strong intended separation and crypto primitives; F01/F04/F05/F14 prevent acceptance. Human/cloud setup not verified. |
| 19.3 Privacy | Envelope/cascade machinery exists; F02/F03/F05/F06/F07 prevent the full retention/deletion promise. |
| 19.4 Orchestration | Not implemented as specified: generic agents, queue, leases, fencing and job provenance absent. |
| 19.5 Cost safety | Reservation and route guards exist. Period budgets, accurate overruns, modes and provider cap acceptance missing. |
| 19.6 Provider independence | Partial: key protocols and configurable URLs. Executor/object interfaces and stable runtime-independent identities missing. |
| 19.7 Governance | Sensitive permit seam exists; capability/policy versioning, delegated authority and revocation incomplete. |
| 19.8 Rejoining/identity | Confidence/provenance/supersession primitives exist. Historical import/reflection and A/B/C separation missing. |
| 19.9 Workspaces | No integration here; no raw-AV integration enabled by this code. Positive safety/availability acceptance still requires contract and cross-system tests. |

## 5. Smallest useful Phase 1 target

Keep one Python codebase and PostgreSQL. Separate deployment identities where permissions demand it, not one service for every conceptual plane.

| Boundary | Target responsibility and authority |
| --- | --- |
| Channel ingress | Verify Telegram owner events; durable accept/deduplicate; maintain visible capture state; acknowledge/status without a model. No signing key, infrastructure administration or historical-decrypt identity. |
| Control + ordinary archive | Agent directory, policy resolution, queue, memory and costs; ciphertext ingestion. These modules may initially share the routine service where privileges remain appropriate. |
| Policy/permit | Validate owner interaction/capability, scope, action, limits, expiry and policy version; mint narrowly bound permits. Separate signing identity; no plaintext archive or AWS role. |
| Generic executor | Lease a job as an execution node; run an agent configuration via an allowed model/provider; return evidence/provenance/cost. No inherent network governance power. |
| Evidence retrieval | Exact authorized record and byte limit; KMS unwrap and registry read; audited disclosure. No ingestion, deletion or master-key administration. |
| Governed deletion | Durable deletion intent, record-key destruction, derivation cascade, reconciliation. No KMS operations. |
| Storage | PostgreSQL state/ciphertext; external wrapped-key registry; KMS; provider-neutral encrypted object references for artifacts/backups. Key availability and deletion history are part of the compound authoritative boundary. |
| Human administration | Separate AWS management/member-account roles and recovery, deployment/backup authority, reviewed upgrades. Never ordinary Lucy credentials. |
| Utopia Workspaces | Separate human collaboration service; narrow task/approved-memory API only. No archive/permit signing/cloud secrets in browser code. |

Critical lifecycles:

- Work: verified input → scoped durable job → policy/approval → reserve → lease/epoch → execute → fenced result + actual-cost settlement → outbox → Lucy communicates.
- Failure: lease expires → determine external outcome → retry only safe work under a new epoch, or retain an explicit ambiguous outcome; stale workers cannot commit. A provider outage never selects a less-private or more-expensive route implicitly.
- Approval: immutable action/scope/cost request → authenticated owner capability → expiring policy-bound decision → revalidate at execution → consume/audit. Approval is not a caller-provided `human_owner` label.
- Memory: encrypted evidence → provenance-linked autobiographical candidate → governed organizational promotion where authorized. Working context is a disposable projection. Deletion fences all later derivation.
- Idle: deterministic queue/timer checks only; zero paid inference solely to discover whether work exists.

The generic executor may share a process with ordinary orchestration initially, but its jobs, identities and leases must remain explicit. Do not place evidence-decryption or permit-signing authority there to save a service fee.

Durable jobs must reference authorized encrypted evidence or approved memory, not duplicate raw transcripts into queue payloads. Off-record content must not enter a durable job, result, retry cache, or derivative merely to obtain reliable scheduling. New signed-contract semantics require an explicit version/migration; do not silently reinterpret existing v1 permits.

## 6. Migration order, compatibility, and rollback

| Stage | Rationale / affected areas | Risk and compatibility | Acceptance and rollback |
| --- | --- | --- | --- |
| 1. Close immediate retention defects | F02–F06; archive, evidence, plugin, proposals/corrections, log configuration | Medium. Introduce consent/deletion checks before allowing new capture. Existing unsafe fingerprints need a separately reviewed cleanup strategy. | Synthetic privacy/concurrency regressions. Capture stays off. Never roll back to code that ignores tombstones/consent once real retention is enabled. |
| 2. Repair production bootstrap and recovery | F01/F07/F08; grants, runtime, role-specific health, restore gate | High security sensitivity. Separate deploy/migration owner from service logins; use additive schema changes. | Disposable PostgreSQL with exact production grants; restart services independently. Roll back binaries only to a compatible safe version, retaining keys/deletion history and closed capture gate. |
| 3. Introduce minimal critical contracts | F11/F13; stable principals, scopes, policy versions, job/agent/node/object references | Medium schema work; do not infer ownership of existing rows silently. Explicitly label reviewed legacy data as single-owner scope. | Cross-scope denials and serialization/version tests. Additive migration; disable new consumers to roll back. No real historical import yet. |
| 4. Prove one queue/agent/budget slice | F09/F10; queue, executor, outbox, period ledgers | Substantial bounded feature, not a naming refactor. Keep existing Telegram path behind a compatibility boundary. | Non-Lucy synthetic agent, duplicate delivery, worker kill, stale epoch, cost overrun and hard-stop tests. Drain/fence new work before rollback; never restore an old spending snapshot over incurred charges. |
| 5. Complete memory and Rejoining | F02/F11/F12; scoped A/B/C storage, promotion workflow, encrypted importer/reflection | High data semantics risk. Synthetic imports first; never route real transcripts through legacy plaintext importer. | Conflicting historical claims, chronology, review, deletion and reflection acceptance. Disable importer/new promotion; retain evidence and deletion lineage, not destructive schema downgrade. |
| 6. Complete and accept cloud topology | F14/F15; Render/AWS boundaries, release artifact, observability, backup/object-store adapter | External authority/cost required. Confirm actual account/workspace/service IDs and budget before provisioning. | Real OIDC/role denial tests, isolated restore, offline-PC Telegram test, no-model idle test. Roll back to tested immutable digest; no automatic master-key/registry deletion. |
| 7. Workspaces contract and final review | F15/19.9; task and approved-memory integration | Separate project changes require that project's scope/authorization. Human AV remains independent. | Lucy/provider outage does not interrupt meetings; no secret/raw archive browser access. Disable integration to roll back. Present final acceptance report before capture activation. |

Stages 1–4 should each remain concrete and testable. Do not spend weeks implementing an abstract distributed protocol before one synthetic job works. Node transport and governance seams need only the fields and interfaces exercised by this slice.

Changes that become expensive if postponed: identity-versus-process separation; scoped memory and consent; job ownership/fencing; policy/cost snapshots; organizational-versus-autobiographical authority; non-plaintext idempotency; deletion lineage; stable object/protocol references. The durable queue and historical-memory pipeline are genuine feature work, not merely small refactors.

## 7. Initial cost envelope and cap behavior

This is a **planning estimate, not an approved purchase or measured bill**. Prices checked 2026-08-31. Service sizing requires measurement; security boundaries must not be merged to fit a budget.

| Item | Initial monthly planning amount | Assumptions |
| --- | --- | --- |
| Separate Render Pro workspace | $25 | Needed for intended managed AWS OIDC. [Render plan information](https://render.com/articles/how-much-does-cloud-application-hosting-cost-for-small-businesses), [OIDC requirement](https://render.com/docs/oidc). |
| Four private control/security services | $28 floor | Four $7 Starter instances; capacity unproven. [Render instance pricing](https://render.com/articles/top-heroku-alternatives-agencies). |
| Hermes gateway / initial executor | $7–25 | One always-on process initially, provided job durability does not depend on it. Add $7–25 if an independent worker is needed. [Render instance pricing](https://render.com/articles/top-heroku-alternatives-agencies). |
| PostgreSQL compute allowance | $10–25 | Planning allowance, not a selected SKU or validated capacity quote. |
| PostgreSQL storage / Hermes cache | About $2.75 | Illustrative 5 GB PostgreSQL × $0.30 plus 5 GB disk × $0.25. [Render storage rates](https://render.com/articles/how-much-does-cloud-application-hosting-cost-for-small-businesses). |
| KMS wrapping key | Initially $1 plus requests | Eligible free tier includes 20,000 requests/month; rotation history can add key-storage charges. [AWS KMS pricing](https://aws.amazon.com/kms/pricing/). |
| Registry, security logs and alerts | $1–5 allowance | Usage-dependent; not a provider-enforced hard cap. |
| Encrypted object storage / 30-day backup handling | $1–5 allowance | Storage, requests and backup-job compute must be priced once volume/provider are selected. No current implementation establishes this cost. |
| Model/API use | $5–15 trial allowance | Proposed owner-approved ceiling, not observed usage; admission must enforce it. |
| Transcription / optional local or GPU compute | $0 in initial scope | Disabled; separately approved if introduced. |

Illustrative subtotal: **about $81–132/month**, or approximately **$95–160 with operating headroom**, before tax, a second worker, significant egress/build overages, larger instances or temporary restore environments. This is a range to approve/refine, not permission to spend. A $1 KMS key is only a small part of the whole system's operating cost.

Required cap consequences:

- Per-job/agent/day/month model limits: refuse or queue discretionary paid work before execution; request approval for escalation. Record actual overruns even when admission estimation was wrong.
- At conserve/restricted thresholds: prefer deterministic/approved cheaper routes and postpone nonessential work. Do not degrade provider privacy policy.
- At hard stop: halt discretionary paid calls; retain deterministic status, cancellation and required security operations. Security recovery/deletion must not become dependent on purchasing a model call.
- Provider API cap: independently configured and tested. An internal ledger cannot constrain a stolen provider key used outside Lucy.
- Hosting/storage/AWS budgets: fixed service counts, quotas, bounded request volume and alerts reduce exposure; alerts are **not** a universal hard billing stop. Never automatically destroy keys, backups or evidence to reduce a bill.

## 8. Threat review

| Threat | Present protection / residual exposure / required Phase 1 response |
| --- | --- |
| Compromised Telegram account | Allowlist blocks unrelated users, not takeover of the allowed account. Exact bounded permits, rate limits/revocation and an independent recovery channel are needed. Catastrophic KMS/admin powers remain outside Telegram. |
| Compromised ordinary Render service | Intended writer role cannot decrypt historical evidence, but can see new plaintext and structured memory; broad routine SQL writes can alter memory/approvals/budgets. Minimize privileges and enforce consequential decisions through policy-owned authority. |
| Compromised evidence service | It can enumerate database evidence IDs and use allowed `GetItem`/KMS decrypt for those IDs. Exact-record restriction is in application code, not cryptographic containment after total reader compromise. Minimize exposure, monitor disclosures, limit authorization and document this residual. |
| Compromised policy/deletion service | Policy compromise can forge application permits; deletion compromise can remove wrapped keys whose references it can read. Separate deployment authority, audit and recovery remain essential; neither gets master-key administration. |
| Compromised Ray laptop | Local files/tokens and administrative sessions are exposed. No permanent AWS keys, MFA/short sessions, separate admin identity and recovery devices; do not claim MFA defeats an already-compromised session. |
| Future partner node / stolen node credential | No external-node execution now. Future credentials must be revocable/scoped, with data-locality and trust-class enforcement. Never send archive/signing/admin secrets to nodes. |
| Malicious or stale worker | Current execution lacks fencing. Commit must require the current job lease epoch; revocation/reassignment must invalidate older workers. |
| Infinite loop / unexpected model billing | Existing turn/output limits help. Hierarchical reservations, honest overrun accounting, retry limits and provider-side caps remain necessary. |
| Prompt/tool injection | Restricted tools and provenance checks help. Source content cannot grant permissions; deterministic policy and current owner authority must gate every consequential action. |
| Broad evidence retrieval | Current global interaction and bearer-minting trust are insufficient. Fix F04/F06; enforce per-turn bounds and audit anomaly detection. |
| Deletion bypass / stale restore | External key destruction helps raw transcripts. F02/F05/F07 must close derivative resurrection, plaintext residues and restore races. |
| Compromised model provider | The provider sees submitted prompts/output irrespective of at-rest encryption. Minimize shared structured/source data; retain privacy-route controls and disclose the residual. |
| DNS/provider/storage outage | Persist accepted jobs, expose degraded state, retry with bounds. No implicit alternate trust/provider policy. Meeting availability remains independent. |
| Founder credential loss | Stable KMS recovery role is a useful template; actual identity assignment and recovery drills are unverified. Separate management/member-account recovery and contacts are required. |
| Coercion or one approval-device compromise | Baseline does not solve duress or full quorum authority. Keep catastrophic operations outside ordinary permits, use revocation and human administrative controls; Ray Array remains explicitly deferred. |
| Future governance capture | Versioned capabilities/policy and auditable authority changes now; no permanent founder-root assumption or coin constitution. Distributed governance is not implemented in Phase 1. |

## 9. Acceptance test backlog

Run database tests only in a disposable, explicitly identified database. Use synthetic records for cloud security tests. No live capture until the owner reviews the resulting report.

1. **Production identity matrix:** migrate a clean database, connect as each actual service login, start each mode, exercise permitted endpoints and prove forbidden reads/writes/DDL/KMS/registry actions fail. No broad `lucy_app` substitute.
2. **Privacy concurrency:** off-record delivery retries after resumption; concurrent mode toggles; direct/indirect memory proposals; delete during promotion/materialization; multi-hop derivatives; invalidated recall; Unicode byte limits; no query/plaintext-fingerprint leakage into retained logs/audit.
3. **Authorization:** parallel sessions, spoofed owner events, absent/stale interaction, revoked policy, mismatched action/scope/audience, exact evidence IDs, repeated disclosures, quota exhaustion, and durable sanitized denial audits.
4. **Crash/restore:** stop between registry put and SQL commit, key deletion and SQL cascade, result commit and notification; restore older PostgreSQL in isolation while deletion history remains current; detect wrong registry identity; prove no deleted plaintext or structured derivative is served before reconciliation.
5. **Jobs:** duplicate source delivery with same/different payload, killed worker, lease renewal/expiry, stale epoch commit, cancellation, bounded retry, ambiguous external outcome, outbox replay, and independent service restart during healthy execution.
6. **Cost:** concurrent admission at every limit, period boundaries, overrun actuals, unknown cost, abandoned reservations, retry billing, provider caps, premium approval, conserve/restricted/essential/hard-stop; prove zero paid calls during idle polling.
7. **Agent/provider independence:** execute a configured synthetic non-Lucy agent through the same runtime; substitute a fake executor/model and storage provider without changing agent identity or policy semantics; demonstrate node records without deploying external nodes.
8. **Historical Rejoining:** approved encrypted import with original timestamps, conflicting claims, supersession and uncertainty; no automatic promotion to organization truth; bounded budget; independent reflection; restart and recall with `/opt/data` replaced after durable commit.
9. **Real cloud:** service-bound OIDC identity/rotation, KMS negative permissions, effective network isolation, alerts and recovery identity; pinned build/deploy evidence; owner Telegram channel works with the development PC offline. Include timestamps and sanitized proof, not credential values.
10. **Workspaces:** human meeting continues when Lucy/transcription/provider/control API fails; ordinary meetings stay summon-only unless policy explicitly changes; no browser secrets or raw archive; approved task/memory access only; raw recording/transcription remains separately gated.

Explicitly deferred: public/partner/mobile node clients, actual local GPU scheduling, peer-to-peer transports, decentralized discovery/consensus/storage, coin/voting rules, multi-party Ray Array enforcement, Kubernetes/Kafka/service mesh, and a large simulated executive team. Build their interfaces only where the single concrete Phase 1 slice needs them.

## Recommendation

**Continue with this repository; do not declare Phase 1 complete or turn transcript capture on yet.** First close the security/retention defects and prove the separated runtime against real PostgreSQL roles. Then immediately exercise the minimal scoped job/agent/budget contracts through one end-to-end synthetic slice. Finish historical-memory and cloud acceptance afterward, keeping Utopia integration and future distributed features behind their explicit boundaries.
