# Private memory import synthetic-slice checkpoint

## Personal Lucy development resumed: 2026-09-22

Ray accepted a basic configuration-level separation check and authorized starting the
synthetic-memory work. See [separation audit](personal-lucy-separation-audit-2026-09-22.md).
The first new increment is implemented and verified locally on top of `a04eef6`.
Raymond's quarantined cloud database advanced to `0073` on 2026-09-22; policy and routine
remain suspended. The historical entries below are retained.

The new scoped memory path had a concrete correction gap: `supersedes_candidate_id` was
stored but not applied to recall. Two regression cases reproduced both Plan A and Plan B
being returned after approving Plan B, in ordinary and protected recall.

Migration `0073_memory_candidate_correction` adds an immutable, content-free supersession
ledger. Exact approved promotion atomically records the replacement; all three scoped recall
functions omit superseded claims before applying their result limits. Original claims and
evidence remain unchanged. A missing, already superseded, ambiguous, unrelated or unchanged
target is rejected. Promotions serialize per scope. Replays cannot reactivate the old claim,
and loss of the replacement source cannot make the old decision reappear.

Runtime and recovery admission recognize this exact new schema alongside the existing
milestones; the realm bootstrap target advances to it. The Raymond-only deployed migration
and separate six-check head verification later succeeded on pinned commit `d126f706`.

### Observed synthetic demonstration

| Operation | Result |
|---|---|
| Import | Synthetic fixture archived with exact manifest/source bindings and replay suppression |
| Review | Exact candidate review contracts and loopback review-console tests pass; unapproved correction does not change recall |
| Remember and cite | Approved claims return their source evidence IDs; fixture quote spans retain source provenance |
| Correct | Plan A is recalled initially; after exact Plan B approval, only Plan B is recalled in ordinary and protected paths |
| Preserve history | Both claims and three source links survive, with one immutable correction record |
| Forget / source withdrawal | Replacement disappears when its source becomes unavailable; old Plan A stays excluded; existing deletion/restore tests also pass |

This is a local, deterministic demonstration with synthetic actors and provider boundaries,
not a live Telegram conversation, owner review session, cloud IAM test or real-history import.

### Fresh verification ledger

[Machine-readable receipt](evidence/personal-lucy-synthetic-memory-2026-09-22.json).

- Two correction regression cases failed as expected on `0072`, returning both plans.
- Clean disposable PostgreSQL migrated `0001` through `0072`, then applied `0073` successfully.
- All 19 focused import integration cases passed, including five new correction cases.
- 28 import/review/transport unit tests passed; 52 readiness/bootstrap/verifier unit tests passed.
- Ruff passed on changed Python files; strict mypy passed on the three changed source files.
- Evidence applies to this local increment. Changes to promotion, recall, schema, readiness,
  bootstrap, test fixture or PostgreSQL image invalidate the corresponding check.

Docker startup was restored by backing up both inaccessible runtime socket directories under
`C:\Users\Forti\AppData\Local` and allowing Docker to recreate them. Images and volumes were
not reset. Windows reserved port 54329, so this run used 55429. `compose.test.yaml` now accepts
`LUCY_TEST_POSTGRES_PORT` (default 54329); the memory-import test cleanup guard permits only
the exact loopback `lucy_test` database on 54329 or 55429. Other integration files may still
require their documented default ports. Socket backups have the suffixes
`.personal-lucy-backup-20260922` and `.personal-lucy-combined-20260922`.

### Exact next action

The [cloud staging package](personal-lucy-cloud-stage-2026-09-22.md) is prepared. The release
image builds and passes its network-disabled packaging check. Head verification and commissioning
now pin 0073; 34 focused checks pass. A new local operator prepares credential staging for the
two existing suspended Raymond services without a provider key or pilot authorization; its three
focused tests pass, including rollback after an uncertain second write. Ray approved the exact
staging, and independent Render GETs confirmed both services remain suspended with matching
credentials, disabled capture/ingress/executor/intake and saved rollback snapshots. Ray then
approved publication and the quarantined Raymond migration. The published source is pinned at
`d126f7064c58acdb644fbf14f4def78353f49996`; the cloud migration and separate six-check
read-only verifier jobs both succeeded on it. The temporary runner was deleted, and a fresh
GET confirmed policy and routine are still suspended. Prepare the bounded synthetic cloud
demonstration. Coordinate the new migration number with shared-repository work.

Automatic approval review blocked the historical mixed-purpose commissioning helper because
it supports persistent secret/configuration changes. It was not run. No cloud mutation was made.
The actual saved real-history pilot authorization expired September 21, 2026; synthetic staging
does not depend on it, and real import needs fresh exact authorization later.

The active Telegram bot still points to Utopia. Its eventual Raymond cutover needs an exact
service/routing plan and a decision on existing transcript history; this does not block local
Personal Lucy development. No personal records, paid provider requests or live channel changes
occurred during this increment.

Date: 2026-09-12
Branch: `codex/r1-tenant-foundation`
Starting revision: `207d3af6c782747e104fa24f2b72a2a2c4eea8ff`
Status: exact personal pilot authorized; protected cloud intake commissioning in progress
Current implementation checkpoint: `a70cb63` (protected intake plus read-only head verifier)
Current private-memory revisions: `d747509` (schema/import foundation), `d973d41`
(bounded extraction coordinator), `204c38c` (isolated provider adapter), and `a655292`
(atomic completion fence), plus the pilot-completion, executable-budget, immutable-request,
deterministic-compiler, and exact source-eligibility increments recorded here. Public Lucy's
accepted `0057` migration is merged at `2807dad`.

## Scope and safety state

- All evidence and identities used by this slice are synthetic.
- No personal export, transcript, attachment, or secret was processed.
- No model/provider request was made and model spend was zero.
- No AWS, Render, Telegram, or live PostgreSQL state was changed.
- Live Telegram capture and its existing Stage 2 deployment were not changed.
- Real pilot intake, bulk import, and automatic promotion remain disabled. The loopback-only
  Import Console exists locally but has not processed a personal export.

## Implemented boundary

1. A strict synthetic conversation contract preserves roles, timestamps, revisions,
   displayed/alternate branches, and parent relationships.
2. An HMAC-bound manifest fixes the exact selected records, source revisions, content
   commitments, destination private content scope, parser/extractor/prompt/model versions,
   expiry, record/byte/token ceilings, retry count, and campaign spend ceiling.
3. The import-only archive path verifies the authorized manifest record and authenticated
   envelope header before using the existing independently wrapped AES-256-GCM evidence
   representation. It does not create or require a live Telegram capture receipt.
4. Untrusted model JSON is parsed through a strict, size-bounded contract. Deterministic code
   re-verifies the local exact manifest, rejects candidate secrets, resolves unique UTF-8 quote
   spans to archived evidence IDs, assigns stable candidate IDs, and forces protected status.
   Candidate versions bind the campaign, full manifest digest, extraction job and tool versions,
   destination scope, semantic content, and exact evidence byte spans. PostgreSQL rejects a
   mismatched source-record/evidence pairing.
5. Extraction may stage candidates but cannot approve or promote them. The policy identity
   approves exact candidate bytes, promotes accepted candidates, and owns audited protected
   recall. Owner review is two-step: a non-authorizing proposal first shows every final exact
   candidate/digest, then an owner authorization binds that proposal digest. Changing protection
   or uncertainty creates the next candidate version rather than reusing an old approval.
   Ordinary runtime identities cannot directly mutate claims or protected tables.
6. Promotion locks the same evidence-derivation fence used by governed deletion, rechecks
   source activity/version, and refuses a source removed after review.
7. Ordinary recall excludes protected material. Protected recall requires a current owner
   interaction reference and emits a content-free access record.
8. Campaign reservations enforce one cumulative spending and attempt ceiling. Failed and
   retried attempts remain charged against the authorized campaign ceiling.
9. The context compiler allocates memory inside one total request budget rather than treating
   model context and import expense as interchangeable budgets.
10. Successful provider completion stages the entire candidate batch and settles its campaign
   reservation in one PostgreSQL transaction. A failed candidate rolls back the whole batch and
   settlement; an uncertain commit acknowledgement returns no output and requires reconciliation
   rather than automatically paying for a second provider call.
11. The pilot completion adapter parses the strict provider contract, independently resolves exact
   quotes to archived evidence, creates protected candidates and the owner-review artifact before
   the atomic database completion. Deterministically invalid output is charged and discarded;
   uncertain persistence exposes no candidate artifact.
12. Real provider execution now requires an import-manifest V2 contract. V1 remains readable with
   its historical digest and source-only token meaning, but cannot silently authorize a real call.
   V2 separately binds selected-source estimates, complete request input, reserved output, total
   request tokens, and the immutable token-accounting implementation.
13. The provider request is frozen as canonical JSON before transport. Its system instructions,
   user evidence, schema, routing, privacy controls, Unicode bytes, and output setting share one
   commitment and conservative byte-based input-token upper bound. Forged counts or changed request
   bytes fail before network access.
14. The local selection proposal now displays and binds the V2 request input, output, and total
   ceilings plus the accounting version. Exact manifest generation emits V2 rather than silently
   interpreting a source-only V1 estimate as execution authority.
15. The deterministic compiler packs complete records without truncation, proves exact one-time
   coverage, blocks an individually oversized record, respects the attempt and per-attempt cost
   ceilings, and accounts for repeated request framing in every batch. Provider-reported input
   usage is required and must remain inside the admitted conservative bound.
16. PostgreSQL now performs an execute-only, realm-scoped eligibility check at admission,
    immediately before provider dispatch, and after provider return. It binds every requested
    source to the campaign's exact manifest, active evidence identity and version, and absence of
    a deletion fence. Duplicate, blank, oversized, outside-manifest, cross-scope, stale, or deleted
    source references fail closed.
17. Every provider dispatch now has a deterministic extraction-job identity derived from its
    campaign, attempt key, and immutable full-request commitment. PostgreSQL durably binds that
    job to the exact reservation, realm, manifest, sources, route, token ceilings, and cost ceiling
    before provider execution. A replayed reservation with no job may safely create the job and
    proceed; a replayed durable job never repeats the provider call and requires outcome
    reconciliation. Job registration and settlement serialize on the same reservation lock.
18. Provider output is envelope-encrypted before completion and stored behind an exact-job,
    execute-only PostgreSQL operation; its wrapped data key remains in the external registry.
    The authenticated binding covers realm, campaign, manifest, reservation, complete request
    commitment, source set, route, policy, and maximum cost. PostgreSQL exposes only billed cost
    and a keyed provider-reference commitment as content-free metadata. Replays must match exactly,
    missing keys and altered ciphertext fail closed, and recovery resumes from the encrypted result
    without another paid provider call.
19. A pilot-only runner now assembles the entire local vertical slice in the required order:
    exact plaintext recheck, protected evidence archival, omission-free compilation, durable job
    registration, bounded provider execution, encrypted outcome persistence, post-call source
    recheck, atomic protected-candidate staging/settlement, and owner-review artifact creation.
    It exposes no raw provider output and rejects a batch plan whose combined reservations could
    exceed the campaign cap.
20. Source revocation now closes two additional recovery paths at the database boundary. A new
    candidate approval is rejected after any exact source is deleted, revised, or fenced, and a
    previously stored encrypted provider outcome can no longer be loaded through the extraction
    identity after that source becomes unavailable. Existing approvals still cannot promote
    because promotion already performs the same source check.
21. The deletion closure now has an additive V3 wire contract ready for database implementation.
    It preserves V2 semantics and digest domains, identifies every memory-candidate version,
    identifies provider outcomes by exact extraction job and record version, and binds each
    encrypted outcome to its representation, wrapped-key reference, and external key registry.
    Only encrypted archive and provider-outcome classes can carry key-destruction authority.
22. PostgreSQL can now build the exact V3 target set for one claimed, realm-bound deletion
    operation while holding the evidence-derivation advisory lock. The closure includes the root
    archive, every candidate version and promoted claim sourced from it, and every encrypted
    provider outcome whose immutable extraction job included it. The policy operation receives
    identifiers and key references only; content remains unavailable.
23. A separately named V3 manifest table and V4 database operation now persist the signed closure
    without changing the historical V2 tables or the existing V3 database wrapper for V2. Target
    identity includes artifact version, so every candidate revision survives the freeze. The
    verified Python boundary checks the policy signature before storage; PostgreSQL independently
    re-derives the closure under lock, binds it to the claimed permit, installs the deletion fence,
    and provides exact idempotent replay.
24. The realm policy signer can now read a content-free V3 deletion-authority snapshot, sign the
    exact versioned closure, and freeze it through the verified V3 manifest adapter. PostgreSQL
    requires the claimed, realm-bound permit, rechecks its admission deadline, enforces the
    permit's target ceiling, and replays an already frozen V3 manifest without rebuilding or
    silently changing its authority. The V2 authority and signing path remain unchanged.
25. The Lambda executor boundary now understands an additive V3 invocation and validates the
    deployment's exact archive record version plus closure, tombstone, and finality policy version
    before any mutation. Its AWS transaction replaces each wrapped key with an authenticated,
    content-free in-place tombstone rather than deleting the registry row. The stable outcome-key
    commitment excludes the deletion root, allowing the same multi-source provider outcome to be
    proven destroyed by later source deletions. Foreign outcome registries fail closed, Lambda now
    receives the exact configured registry ID, and its role has UpdateItem rather than DeleteItem.
    V2 invocation, admission, and physical key-deletion behavior remain unchanged.
26. PostgreSQL now binds the signed V3 manifest to one strict post-claim execution grant,
    attests the exact deletion receipt, and atomically reconciles successful execution to
    immutable candidate-version and encrypted-provider-outcome tombstones plus 30-day finality
    pending. Grant admission rechecks current owner/channel/realm/service authority; receipt
    admission binds every identity, scope, deadline, manifest, grant, and transaction token.
    Reconciliation is replay-safe for shared multi-source artifacts, and a provider outcome that
    arrives after any source is deletion-fenced is rejected even when that outcome was absent
    from the frozen closure. The policy API, private-network client, deletion coordinator, and
    Lambda invocation now select the additive V3 path; historical V2 remains unchanged.
27. Quarantined restore replay now verifies the historical V3 permit, manifest, grant, and
    successful receipt chain before constructing a content-free recovery contract. PostgreSQL
    accepts that contract only while capture is off and runtime admission is quarantined, under
    the same exclusive lock used by the protected activation handoff. It stores immutable proof,
    exact versioned targets, and a root-evidence fence without recreating any wrapped key. Targets
    remain durable even when the restored backup predates their candidate or provider-outcome
    rows. Existing rows must match the historical scope, provenance, version, representation, and
    key registry; conflicting replay fails atomically. Recovery fences now block retrieval,
    candidate source attachment, approval/promotion, provider-outcome write/read, and ordinary or
    protected recall. The existing production recovery utility now verifies and dispatches both
    historical V2 bundles and new V3 bundles to their separately versioned database gates. Shared
    targets preserve per-operation provenance while intrinsic target metadata must agree.
28. The real-pilot operator boundary now uses a separately materialized, plaintext-free owner
    authorization bound to one exact bundle digest, source set, destination, provider/model route,
    versions, expiry, attempt ceiling, and total spend ceiling. Its confirmation phrase must name
    that digest exactly. A no-network preflight rebuilds the bundle from the untouched ZIP and
    reviewed inventory/selection immediately before execution. The effect-bearing wrapper repeats
    the same digest, bundle, approval-time, and expiry checks before the first archive write. A
    mismatch or expired/future authorization therefore produces zero AWS, database, provider, or
    spending effects; candidate approval and promotion remain separate and disabled.
29. Provider-outcome persistence is now split into write and exact-job recovery capabilities.
    The first-write journal encrypts and conditionally stores the wrapped key and PostgreSQL
    envelope, verifies the exact acknowledgement, and returns the still-in-memory result to
    deterministic completion without any wrapped-key read or KMS decrypt. A durable replay with
    no separately supplied recovery capability stops as `reconciliation_required` before the
    provider. Conditional-key conflicts and uncertain or changed envelope acknowledgements also
    stop for exact-job recovery; they never trigger an automatic second paid call. The historical
    combined journal remains available only for explicitly trusted local tests and compatibility.
30. Exact-job outcome recovery now has a separate v1 contract and additive AWS security stamp.
    The extraction/archive role can generate an outcome DEK, create one wrapped-key record, and
    invoke the qualified recovery alias, but it has no outcome-key read or decrypt permission.
    The recovery Lambda has exact `GetItem`, receipt `PutItem`, and outcome-key `Decrypt` only; it
    has no provider credential, evidence key, key-write/delete, candidate approval, scan, or query
    capability. A policy-notary grant binds the caller, realm and execution epochs, campaign,
    manifest, reservation/job, destination scope, encryption/registry identities, exact encrypted
    package digest, pilot authorization, deadlines, and plaintext ceiling. PostgreSQL's existing
    exact-job load/source-eligibility gate is re-run before grant issuance and again before
    completion. One operation releases plaintext once; replay is content-free and a lost response
    requires a fresh eligibility check and grant without repeating the paid model call. The
    additive Utopia stack is now deployed in `us-east-1`, termination-protected, and verified
    against its effective AWS permissions. No personal import or provider request was executed.
31. Recovery grant issuance is now typed behind a grant-issuer protocol so the deployed path can
    use the isolated policy service rather than copying its signing key into the archive service.
    Both claim and completion deadlines are capped by the authorized campaign expiry. The next
    bridge will use the existing private authenticated policy transport plus a content-free,
    exact-job database eligibility check; the archive service will receive only the signed grant.
32. The isolated policy bridge is implemented at migration `0069`. A migration-identity-only
    registration function materializes one exact owner authorization; routine cannot register it
    and policy cannot enumerate either authorizations or encrypted outcomes. The private policy
    endpoint authenticates routine with the existing gateway token, rechecks current campaign,
    exact job, service/scope binding, unsettled budget reservation, source availability, and
    deletion fences, then durably records one signed grant. PostgreSQL independently recomputes
    the request, package, and unsigned-grant digests and rejects changed realm, deployment, job,
    reservation, encryption, or registry bindings. Replay returns the winning immutable grant.
    The migration is deliberately forward-only because dropping its immutable authorization and
    grant ledger would erase security evidence; application rollback leaves these inert records
    in place. No personal import, provider request, or cloud deployment was performed.
33. The operator and routine handoffs are now explicit. A `register` CLI command accepts only one
    exact owner authorization plus a matching, unexpired preflight no more than 15 minutes old,
    requires a digest-specific confirmation phrase, and calls only the migration-owned exact
    registration function. Its receipt is content-free. Routine assembly is restricted to v1.3
    routine mode and combines PostgreSQL exact-job loading/rechecks, the authenticated private
    policy client, and one qualified Lambda alias. The assembly has no policy signing key. These
    paths were tested with synthetic artifacts and injected clients only; registration against
    production and any personal-data execution remain separately gated.
34. The Windows-to-Render pilot transport is now an additive, synthetic-only boundary at migration
    `0070`. Windows retains the full ZIP and permanent fingerprint key, rebuilds the exact locally
    authorized selection, and emits only a plaintext-free transport registration. Every sensitive
    batch is bound by a separate random transfer-key HMAC; the runtime receives neither the
    fingerprint key nor authority to register its own commitments. PostgreSQL stores only campaign,
    capability, batch, request, and byte commitments. The realm-evidence login needs one random
    campaign capability plus a known batch ID, cannot enumerate the transport tables, and passes no
    plaintext to PostgreSQL. Admission is synchronous and replay-safe; durable operator revocation
    blocks both new and replayed admission. The CLI can prepare and register the content-free plan,
    and a bounded, documentation-free HTTP surface admits an exact batch. No personal data,
    provider call, AWS operation, or cloud deployment was performed.
35. The admitted-batch executor now preserves original conversation identity without receiving the
    permanent fingerprint key, rechecks current transport authority before each archive effect and
    before dispatch, and passes the original immutable dispatch into the durable extraction
    coordinator. Candidate provenance is limited to the current verified batch; archive requests
    are byte-for-byte equivalent to the local verified path. The synchronous execution endpoint
    returns a content-free status plus the separately typed protected review artifact with
    `Cache-Control: no-store`. A deterministic zero-cost fake provider has no credential, network,
    or production fallback. Partial archive retry and full execution replay reuse stable identities
    and do not repeat the provider call. This remains synthetic/injected-boundary evidence only.
36. A protected Windows uploader now sends exact batches sequentially over HTTPS, keeps the random
    capability in memory, bounds response bytes, validates the returned campaign/batch/job identity,
    and refuses review output outside the existing intake root. A lost response stops with an
    explicit exact-identity retry requirement; retry sends identical canonical batch bytes. Existing
    review artifacts can only be replayed byte-for-byte, never overwritten. No endpoint was contacted.
37. The local CLI now reconstructs the authorized batch set directly from the untouched ZIP before
    upload, compares the complete reconstructed registration with the operator-registered artifact,
    and requires a digest-specific upload confirmation. It writes only the content-free upload
    receipt and protected review artifacts under the intake root. The CLI path was exercised with an
    injected HTTPS uploader; no real endpoint or personal export was used.
38. The complete verified transport executor now runs against the real PostgreSQL admission,
    archive-intent, campaign-accounting, candidate, settlement, and encrypted provider-outcome
    adapters. One synthetic batch produces one independently encrypted evidence record, one
    encrypted provider outcome, one provenance-linked pending candidate, and one successful
    settlement. Exact replay performs no second archive write or provider call. This proof exposed
    and fixed a database recovery-ordering defect at migration `0071`: an already-settled
    reservation may now replay only its byte-for-byte identical, still-current existing extraction
    job after all current realm, campaign, source, and deletion checks pass; it still cannot create
    a new job. The provider output remains absent from the PostgreSQL envelope plaintext. No real
    provider, AWS operation, personal data, or cloud endpoint was used.
39. Raymond's personal import now has a stable pre-commissioning realm identity rather than
    borrowing Utopia's production scope or using an ephemeral console UUID. The content-free,
    `planned_not_authorized` plan allocates 22 distinct tenant/node/realm/scope/workspace/service,
    executor, registry, journal, and wallet identities under the Raymond namespace. None overlap
    the commissioned Utopia binding. The reusable generator refuses overwrite and performs no
    AWS, Render, database, credential, capture, inference, upload, or activation effect. The local
    selection console may bind to the planned Raymond scope; cloud execution remains unavailable
    until a separately authorized and validated realm security stamp is commissioned.
40. The owner accepted a local 11-conversation pilot selection containing 628 inventoried records
    and approximately 258,985 source tokens. The exact selection digest is
    `ed25e8f6719ea3cc15a64bee2d303bbc289dcfe47cc8de4e51b0c8692da97aff`; it remains
    `proposed_not_authorized`. Real-data feasibility inspection made no network call and exposed
    two synthetic-limit assumptions before manifest authorization: campaign source volume was
    incorrectly required to fit one request, and a 67,844-byte message exceeded the old record
    bound. Campaign and per-request limits are now independent, while the compiler still rejects
    any individual request or total batch count outside the owner-selected limits. The local scan
    found one credential-like record; exact manifest construction now quarantines such records
    locally with a content-free reason so they cannot be uploaded or sent to a model.
41. A measured diagnostic build shows that the accepted records need a request ceiling above
    60,000 conservative byte-counted input tokens. A proposed 76,000-input/4,000-output/80,000-total
    limit compiles into 15 batches and reserves $1.50 when each attempt is capped at $0.10, within
    the existing $2 campaign ceiling. This measurement is not a revised owner authorization; a new
    immutable proposal and digest are required before manifest construction.
42. The owner authorized exact pilot bundle
    `7a1627621068987980aaa20f0be9cc3a85885bb9875f9ec522f56cdb1194a8d9` and separately
    authorized commissioning Raymond's isolated realm. The local authorization and no-network
    preflight are exact and content-free; no personal record has left the protected intake root.
    Commissioning review found and corrected a pre-deployment compatibility gap: the reusable
    V1.3 realm bootstrap stopped at migration `0053`, and recovery workloads rejected the pilot's
    current `0071` schema. New realm bootstrap now targets `0071`; recovery services accept the
    explicitly reviewed additive V1.3 milestone revisions, while unknown/intermediate revisions
    remain fail-closed. Raymond still requires a separate protected Render environment/database,
    eight private workload identities, and both per-realm AWS stacks before transport registration
    or upload.
43. A protected recheck rebuilt every exact archive request from the untouched local export. The
    largest actual archive plaintext is 39,410 bytes, below the unchanged 65,536-byte archive
    ceiling. The earlier 67,844-byte observation measured a broader manifest-layer record and does
    not require widening the encryption contract, splitting a message, or changing the owner's
    exact authorization. The recheck made zero network calls.
44. The public pilot surface is now a database-free proxy with a fixed private Render destination.
    It rejects redirects, compression, non-canonical JSON, changed response identity, database/AWS/
    provider credentials, and product or transcript ingress. A separate gateway credential protects
    the proxy-to-executor hop while the original random campaign capability remains end-to-end.
45. The private routine/archive service has a temporary pilot-only executor runtime. It composes the
    existing realm archive, cumulative PostgreSQL budget, strict OpenRouter ZDR provider, write-only
    encrypted outcome journal, policy-issued exact-job recovery, and protected candidate staging.
    It cannot start with Telegram credentials, transcript capture, product ingress, an unpinned
    Hermes revision, or the wrong realm database identity.
46. Migration `0072` returns the already-registered, plaintext-free exact owner authorization only
    through the same capability-scoped, realm-bound transport admission operation. That lets the
    executor recover an ambiguous provider outcome for the admitted campaign without storing the
    large authorization artifact in Render configuration or granting table enumeration.
47. Raymond's forward migration job reported `succeeded` at the protected-intake revision and
    rotated the still-unused realm runtime database passwords, but Render did not return its JSON
    receipt through the log API before the evidence timeout. Subsequent read-only verifier jobs
    exposed and corrected three verifier assumptions (one service binding versus four actor
    bindings, `offline` lifecycle while quarantined, and Render's omitted default port) but still
    exited failed without retained diagnostic output. All temporary runners were deleted. This is
    an unresolved cloud-evidence gate: no campaign was registered, no provider was called, and no
    personal record was uploaded. Do not retry another opaque job; the next diagnostic must retain
    failure evidence or isolate individual predicates without changing realm state.
48. The Raymond cloud-head blocker is closed. The verifier was changed from one opaque tuple to
    six allowlisted, read-only predicates and a CLI-selection defect was covered by regression
    tests. The repeated common failure was then traced to the verifier not being copied into the
    explicitly allowlisted Render image. After adding that packaging boundary, one disabled job at
    source commit `ee52a20` passed migration `0072`, quarantined admission, offline lifecycle, the
    database capture fence, the exact Raymond content scope, and its single active service binding.
    The temporary runner was deleted. No personal data, provider request, campaign registration,
    product ingress, or transcript capture was involved.
49. Raymond's separate provider-outcome recovery boundary is commissioned and termination
    protected. It reuses the exact previously accepted outcome-recovery Lambda artifact, but has
    its own rotating KMS key, outcome registry identity, write-only key registry, recovery receipt
    ledger, recovery runtime role, and qualified Lambda alias. Both DynamoDB tables are on-demand,
    deletion protected, and have point-in-time recovery enabled. This adds one customer-managed
    KMS key (approximately $1/month before request charges). No provider call, personal data,
    product ingress, or transcript capture was involved.
50. The temporary Render topology now names all three components required by the actual
    implementation: the existing isolated policy service, the existing private routine service
    running the pilot executor, and the temporary database-free intake proxy. A read-only
    commissioning preflight validated the exact authorized bundle, Raymond scope, database
    identities, AWS archive/outcome boundaries, pinned Hermes commit, provider route, and
    rollback inputs. Both existing services remain suspended and unchanged. Applying their
    secret-bearing environment is pending one explicit destination-specific authorization;
    no personal records were uploaded and the public proxy was not created.

## Verification ledger

| Check | Result | Evidence | Invalidated by |
|---|---|---|---|
| Fresh PostgreSQL migration `0001` through `0067_memory_deletion_recovery` | Passed | Clean disposable PostgreSQL on `127.0.0.1:54329`, including integrated Workspaces `0066`, 2026-09-12 | Migration or PostgreSQL-image change |
| Synthetic memory-import integration | Passed, 12 tests on current revision | `tests/integration/test_memory_import_slice.py` against PostgreSQL at `0067`; proves present and absent derived-row restore, exact replay/conflicting replay rejection, durable candidate/outcome targets, recall/outcome/derivation fencing, plus V3 grant/receipt/reconciliation | Import, recovery, grant, receipt, migration, or scoped-memory change |
| Historical V3 recovery contract | Passed, focused unit test | Historical policy/receipt keys, exact permit/manifest/grant/receipt binding, provider-outcome key registry preservation, changed-scope rejection | Contract, canonicalization, trust-store, or recovery change |
| Integrated Workspaces queue | Passed, 1 PostgreSQL integration test | `tests/integration/test_workspaces_task_queue.py` at migration `0067`; exact enqueue/claim/complete/replay boundary from Public Lucy checkpoint | Workspaces runtime, task queue, or migration change |
| Python unit suite | Passed, 981 tests; one known Starlette deprecation warning | Full `tests/unit` after protected intake, executor, migration `0072`, and Render head-verifier changes, 2026-09-14 | Relevant Python, dependency, migration, or runtime configuration change |
| Ruff | Passed | Full `src`, `tests`, and `migrations` tree after V3 recovery | Relevant source change |
| Mypy strict | Passed, 104 source files | Full strict source and production recovery-utility check after V3 recovery | Python source or type-config change |
| Candidate materialization | Passed, 4 focused tests | Strict output parsing, stable IDs, UTF-8 spans, exact evidence binding, ambiguous-quote rejection, and secret quarantine | Candidate contract, manifest, provenance, or secret-filter change |
| Exact owner-review contracts | Passed, 7 focused tests | Complete-batch decisions, protected/ordinary/uncertain transforms, stale/duplicate/incomplete rejection, and exact two-step authorization | Candidate review contract or canonicalization change |
| Loopback candidate-review console | Passed, 5 focused tests and full-suite rerun | Token/host/origin checks, safe rendering, exact proposal, explicit authorization phrase, immutable replay/conflict behavior, and protected-path confinement | Candidate console, browser contract, or intake-path change |
| Isolated OpenRouter memory adapter | Passed, 29 focused checks plus Ruff and strict mypy; one live synthetic Gemini check | Exact manifest policy/route/extractor/prompt binding; versioned canonical JSON-object contract; Lucy-side strict parsing; ZDR plus denied data collection and fallback; token/byte bounds; usage-cost parsing; keyed generation reference; malformed-response rejection; sanitized transport errors; one nonempty candidate with exact synthetic provenance at $0.00045375; personal records sent: 0 | OpenRouter adapter, provider contract, extractor/prompt version, or approved privacy policy change |
| Pilot completion assembly | Passed, 3 focused tests and full-suite rerun | Provenance materialization, exact review artifact, pre-database deterministic rejection, and no artifact after uncertain database acknowledgement | Pilot completion, materializer, or review-artifact change |
| Executable request-budget contract | Passed, focused V1/V2 contract and coordinator/provider tests | Historical V1 round trip; V2 digest binding and separate source/input/output/total constraints; real execution typed to V2 | Manifest, request compiler, tokenizer/accounting, or provider framing change |
| Immutable provider request | Passed, focused tests and live synthetic route check | Canonical request commitment, complete byte/token upper-bound accounting, Unicode/system/output-contract inclusion, credential exclusion, tamper rejection, and pre-network count verification. Gemini rejected the complete provider-side JSON Schema as too complex, so the bounded pilot uses JSON-object mode plus fail-closed canonical parsing; there is no automatic fallback | Provider request body, output contract, system prompt, or accounting version change |
| V2 proposal and deterministic compiler | Passed, focused console/manifest/compiler/provider tests and full-suite rerun | Visible bound ceilings, exact digest, deterministic packing and coverage, oversize/attempt/cost rejection, complete request accounting, and provider input-usage reconciliation | Selection proposal, manifest generation, compiler, provider framing, or usage contract change |
| Local ChatGPT inventory, review console, and exact-manifest builder | Passed, 16 tests | Safe paths, branches, keyed commitments, attachments, compression, sync-root, token, host/origin, stale-input, idempotency, exact-record/exclusion and changed-input checks | Parser, console, manifest, or limits change |
| Exact pilot authorization and operator preflight | Passed, 4 focused paths | Plaintext-free authorization artifact, exact confirmation/digest, untouched-export rebuild, future/expiry rejection before effects, and content-free no-network preflight | Pilot authorization, manifest builder, operator CLI, runner, or canonicalization change |
| Write-only provider-outcome path | Passed, focused unit and coordinator tests | First write completes without wrapped-key read/decrypt; conflict and missing recovery stop for exact-job reconciliation with zero repeated provider calls | Outcome cipher/store, extraction coordinator, recovery interface, or provider retry change |
| Permit-bound exact-job outcome recovery | Passed, 10 focused contract/runtime/IAM paths plus full-suite rerun | Outcome-only KMS context; write-only worker; exact package/grant/deployment binding; one release; content-free replay; pre-grant/pre-completion eligibility; no scan/query/delete/provider/evidence permission | Outcome recovery contract, signer, cipher, registry, executor, IAM template, or eligibility adapter change |
| Utopia outcome-recovery AWS boundary | Passed | `docs/evidence/utopia-memory-outcome-recovery-aws-2026-09-13.json`; CloudFormation `CREATE_COMPLETE` with termination protection, artifact checksum/version, KMS rotation, table deletion protection/PITR, qualified version 1, positive/negative IAM simulation, and a content-free fail-closed canary | Stack/template, artifact/version, role or key policy, KMS/table/Lambda configuration, trust store, or realm binding change |
| Raymond outcome-recovery AWS boundary | Passed; IAM simulation remains part of deployed synthetic acceptance | `docs/evidence/raymond-memory-outcome-recovery-aws-2026-09-15.json`; CloudFormation `CREATE_COMPLETE` with termination protection, accepted artifact checksum/version, KMS rotation, table deletion protection/PITR, qualified version 1, and a content-free fail-closed canary | Stack/template, artifact/version, role or key policy, KMS/table/Lambda configuration, trust store, or Raymond realm binding change |
| Recovery grant expiry and issuer seam | Passed, 22 focused checks plus Ruff and strict mypy | Grant claim/completion never outlive campaign authorization; recovery consumes an abstract issuer so the policy signer can remain isolated | Recovery policy, issuer protocol, campaign expiry, or coordinator construction change |
| Isolated outcome-policy bridge | Passed, 89 focused checks on clean PostgreSQL through `0069`, plus Ruff and strict mypy | Independent exact authorization registration; database-recomputed request/package/grant digests; private authenticated endpoint; exact realm/job/key bindings; durable replay; policy ciphertext-table denial; deleted-source denial; Render identity separation | Migration `0069`, policy endpoint/client, grant issuer, realm role grants, Render blueprint, or relevant contract change |
| Operator registration and routine recovery assembly | Passed, 14 focused tests plus Ruff and strict mypy | Exact fresh preflight, digest-specific operator confirmation, content-free receipt, routine/v1.3 mode restriction, private policy client, qualified Lambda alias, and no signing key in routine configuration | Import CLI, preflight/authorization contracts, recovery environment assembly, or deployment variables change |
| Pilot transport contracts and database admission | Passed, focused unit/integration checks on clean PostgreSQL through `0070`, plus Ruff and strict mypy | Locally verified exact batch compilation; plaintext-free registration; separate transfer HMAC and capability; wrong-key/wrong-capability/tamper denial; execute-only realm-evidence admission; table-enumeration denial; idempotent replay; durable revocation; a real two-connection admission/revocation race that fails closed; bounded HTTP body | Migration `0070`, transport contracts/CLI/API, compiler, realm role grants, canonicalization, or PostgreSQL image change |
| Durable extraction dispatch ownership | Passed, 20 focused coordinator/pilot-runner tests plus Ruff and strict mypy | A fresh reservation paired with a replayed exact job recovers or reconciles without a second provider call; a recovered billed outcome retains its known cost if the pre-dispatch source fence closes | Extraction coordinator, job-registration semantics, outcome recovery, accounting settlement, or PostgreSQL job constraints change |
| Verified transport execution | Passed, 38 focused transport/materialization/coordinator/HTTP checks plus Ruff and strict mypy | Original conversation provenance; local/transport archive-request equivalence; authority rechecks; partial archive recovery; cross-batch quote denial; one zero-cost fake-provider call across replay; content-free status; protected no-store review response | Transport record/executor, archive request, candidate materializer, coordinator, intake API, or fake-provider boundary change |
| Protected sequential uploader | Passed, 3 focused uploader checks plus Ruff and strict mypy | HTTPS-only endpoint; sequential exact bytes; in-memory bearer capability; bounded, identity-checked response; protected-root confinement; content-free receipt; exact retry after lost response | Uploader, transport/response contracts, intake-root policy, or HTTP boundary change |
| Exact CLI upload reconstruction | Passed, focused end-to-end local CLI check plus Ruff and strict mypy | Untouched-ZIP rebuild; exact registered-plan equality; digest-specific confirmation; protected review directory; content-free receipt; injected HTTPS boundary | Import CLI, manifest builder, transport preparation/registration, uploader, or intake-root policy change |
| Complete synthetic transport execution and replay | Passed, 55 focused checks on PostgreSQL through `0071`, plus Ruff and strict mypy | Exact transport admission; encrypted archive and provider-outcome persistence; provenance-linked pending candidate; one settlement; exact replay with one archive data-key generation and one synthetic provider dispatch; settled-reservation new-job denial retained by migration ordering | Migration `0071`, executor, coordinator, archive/outcome adapters, candidate materialization, transport authority, or PostgreSQL image change |
| Raymond private-realm identity preparation | Passed, 3 focused contract/generator checks plus Ruff and strict mypy | Stable `planned_not_authorized` scope; 22 internally distinct UUIDs; zero UUID overlap with Utopia; exact service issuer and login namespace; overwrite refusal | Realm identity-plan contract/generator, Utopia binding, or planned Raymond identity artifact change |
| Real-export pilot feasibility | Passed locally with one required proposal revision, 34 focused checks plus exact protected archive preflight | Exact 11-conversation selection validation; campaign/per-request separation; largest actual archive plaintext 39,410 bytes under the unchanged 65,536-byte ceiling; no-fallback ZDR request; one credential-like record quarantined locally; corrected JSON-object request framing compiled to 13 exact batches at 76,000/4,000/80,000 with $1.30 reserved under the $2 cap; personal-data network calls: 0 | Selection, request limits, manifest/record contract, local quarantine, compiler, provider request, or model policy change |
| Current-head realm bootstrap and recovery compatibility | Passed locally through `0072`; 32 focused schema/transport tests and 14 PostgreSQL import integration tests, plus Ruff and strict mypy | New isolated realms advance to `0072`; bounded admission returns the exact registered authorization; ordinary and recovery startup accept that exact reviewed milestone; unknown revisions remain outside the allowlist | Migration head, readiness policy, realm bootstrap/commissioning, transport admission, or recovery API change |
| Protected public-proxy/private-executor runtime | Passed locally, 52 focused tests plus Ruff and strict mypy | Canonical no-redirect proxy; separate hop/campaign credentials; fail-closed environment gates; exact authorization context; archive/outcome/recovery/provider composition | Proxy/executor runtime, Render service topology, admission contract, provider policy, or credential placement change |
| Personal-data pilot | Not executed | Intentionally outside this gate | Requires separate pilot authorization |
| Deployed cloud import | Commissioning authorized; not yet ready | Exact Raymond realm and pilot authorization recorded; no personal-data network call | Requires separate realm Render/AWS/PostgreSQL commissioning and deployed acceptance |
| Raymond cloud head evidence | Passed without activation | `docs/evidence/raymond-private-memory-head-2026-09-15.json`; exact commit `ee52a20`, six read-only predicates, temporary runner deleted, no personal payload/provider call | Migration, realm foundation/binding, capture fence, verifier, Dockerfile, or Raymond database-state change |
| Raymond disabled Render pilot preflight | Passed locally against live suspended service metadata; apply not executed | Exact bundle `7a162762...a8d9`, policy/routine services, private scope, database/AWS/provider bindings, content-free rollback plan; 48 focused runtime/topology tests, Ruff, and strict helper mypy | Pilot authorization, Render service metadata, realm/AWS outputs, provider policy, runtime code, or explicit secret-destination approval |

The focused synthetic acceptance proves: exact manifest authorization; independent encrypted
records; protected staging; separate ordinary and protected approval/recall; stale-candidate
rejection; direct-write denial; source/deletion fencing; retry-safe archive registration and
promotion; restart-safe replay; and cumulative retry-inclusive spending control.

The real-export local path now also enforces the database's one-manifest-per-campaign invariant.
One pilot manifest contains every selected conversation's exact records; each record retains its
own conversation, native node/message, parent, branch, role, timestamp, revision, and keyed
content identity. A pre-intake recheck rejects local plaintext changed after manifest review.

## Remaining work before the 12–20 conversation pilot

1. Deploy the disabled public proxy and temporary private executor against Raymond's verified
   `0073` realm; then pass the synthetic cloud acceptance before registering the exact campaign
   and transport commitments.
2. Obtain a fresh exact pilot authorization (the saved one expired on 2026-09-21), then
   upload and execute only that authorized selection after a fresh local preflight.
3. Add dependency invalidation for summaries, embeddings, catalogs, briefings, caches, and
   review previews as those artifact classes are introduced. The current slice fences claims
   and their evidence provenance; those later artifact types do not yet exist in this path.

After a separately accepted pilot, the untouched ZIP is reused for the proposed bounded bulk
campaign. Inventory and reimport suppression happen locally; the bulk campaign still requires
its own exact authorization and does not start automatically.
