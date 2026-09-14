# Private memory import synthetic-slice checkpoint

Date: 2026-09-12
Branch: `codex/r1-tenant-foundation`
Starting revision: `207d3af6c782747e104fa24f2b72a2a2c4eea8ff`
Status: local synthetic slice implemented and passing; not deployed
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

## Verification ledger

| Check | Result | Evidence | Invalidated by |
|---|---|---|---|
| Fresh PostgreSQL migration `0001` through `0067_memory_deletion_recovery` | Passed | Clean disposable PostgreSQL on `127.0.0.1:54329`, including integrated Workspaces `0066`, 2026-09-12 | Migration or PostgreSQL-image change |
| Synthetic memory-import integration | Passed, 12 tests on current revision | `tests/integration/test_memory_import_slice.py` against PostgreSQL at `0067`; proves present and absent derived-row restore, exact replay/conflicting replay rejection, durable candidate/outcome targets, recall/outcome/derivation fencing, plus V3 grant/receipt/reconciliation | Import, recovery, grant, receipt, migration, or scoped-memory change |
| Historical V3 recovery contract | Passed, focused unit test | Historical policy/receipt keys, exact permit/manifest/grant/receipt binding, provider-outcome key registry preservation, changed-scope rejection | Contract, canonicalization, trust-store, or recovery change |
| Integrated Workspaces queue | Passed, 1 PostgreSQL integration test | `tests/integration/test_workspaces_task_queue.py` at migration `0067`; exact enqueue/claim/complete/replay boundary from Public Lucy checkpoint | Workspaces runtime, task queue, or migration change |
| Python unit suite | Passed, 911 tests | Full `tests/unit` after exact pilot authorization plus split write/recovery outcome capabilities, 2026-09-12 | Relevant Python or dependency change |
| Ruff | Passed | Full `src`, `tests`, and `migrations` tree after V3 recovery | Relevant source change |
| Mypy strict | Passed, 104 source files | Full strict source and production recovery-utility check after V3 recovery | Python source or type-config change |
| Candidate materialization | Passed, 4 focused tests | Strict output parsing, stable IDs, UTF-8 spans, exact evidence binding, ambiguous-quote rejection, and secret quarantine | Candidate contract, manifest, provenance, or secret-filter change |
| Exact owner-review contracts | Passed, 7 focused tests | Complete-batch decisions, protected/ordinary/uncertain transforms, stale/duplicate/incomplete rejection, and exact two-step authorization | Candidate review contract or canonicalization change |
| Loopback candidate-review console | Passed, 5 focused tests and full-suite rerun | Token/host/origin checks, safe rendering, exact proposal, explicit authorization phrase, immutable replay/conflict behavior, and protected-path confinement | Candidate console, browser contract, or intake-path change |
| Isolated OpenRouter memory adapter | Passed, 11 focused tests and full-suite rerun | Exact manifest policy/route, strict JSON Schema, ZDR plus denied data collection, token/byte bounds, usage-cost parsing, keyed generation reference, malformed-response rejection, and sanitized transport errors | OpenRouter adapter, provider contract, or approved privacy policy change |
| Pilot completion assembly | Passed, 3 focused tests and full-suite rerun | Provenance materialization, exact review artifact, pre-database deterministic rejection, and no artifact after uncertain database acknowledgement | Pilot completion, materializer, or review-artifact change |
| Executable request-budget contract | Passed, focused V1/V2 contract and coordinator/provider tests | Historical V1 round trip; V2 digest binding and separate source/input/output/total constraints; real execution typed to V2 | Manifest, request compiler, tokenizer/accounting, or provider framing change |
| Immutable provider request | Passed, 8 focused tests and full-suite rerun | Canonical request commitment, complete byte/token upper-bound accounting, Unicode/system/schema inclusion, credential exclusion, tamper rejection, and pre-network count verification | Provider request body, schema, system prompt, or accounting version change |
| V2 proposal and deterministic compiler | Passed, focused console/manifest/compiler/provider tests and full-suite rerun | Visible bound ceilings, exact digest, deterministic packing and coverage, oversize/attempt/cost rejection, complete request accounting, and provider input-usage reconciliation | Selection proposal, manifest generation, compiler, provider framing, or usage contract change |
| Local ChatGPT inventory, review console, and exact-manifest builder | Passed, 16 tests | Safe paths, branches, keyed commitments, attachments, compression, sync-root, token, host/origin, stale-input, idempotency, exact-record/exclusion and changed-input checks | Parser, console, manifest, or limits change |
| Exact pilot authorization and operator preflight | Passed, 4 focused paths | Plaintext-free authorization artifact, exact confirmation/digest, untouched-export rebuild, future/expiry rejection before effects, and content-free no-network preflight | Pilot authorization, manifest builder, operator CLI, runner, or canonicalization change |
| Write-only provider-outcome path | Passed, focused unit and coordinator tests | First write completes without wrapped-key read/decrypt; conflict and missing recovery stop for exact-job reconciliation with zero repeated provider calls | Outcome cipher/store, extraction coordinator, recovery interface, or provider retry change |
| Personal-data pilot | Not executed | Intentionally outside this gate | Requires separate pilot authorization |
| Deployed cloud import | Not executed | Intentionally outside this gate | Requires reviewed deployment plan and authorization |

The focused synthetic acceptance proves: exact manifest authorization; independent encrypted
records; protected staging; separate ordinary and protected approval/recall; stale-candidate
rejection; direct-write denial; source/deletion fencing; retry-safe archive registration and
promotion; restart-safe replay; and cumulative retry-inclusive spending control.

The real-export local path now also enforces the database's one-manifest-per-campaign invariant.
One pilot manifest contains every selected conversation's exact records; each record retains its
own conversation, native node/message, parent, branch, role, timestamp, revision, and keyed
content identity. A pre-intake recheck rejects local plaintext changed after manifest review.

## Remaining work before the 12–20 conversation pilot

1. Implement the separately authorized exact-job outcome-recovery service and its outcome-specific
   AWS boundary, then connect the protected deployment's archive, extraction, encrypted-outcome,
   and candidate-store adapters behind the guarded runner. No real provider request is currently
   enabled. The extraction worker must remain unable to read/decrypt historical outcome keys, and
   the recovery identity must remain unable to decrypt raw evidence or invoke the provider.
2. Add dependency invalidation for summaries, embeddings, catalogs, briefings, caches, and
   review previews as those artifact classes are introduced. The current slice fences claims
   and their evidence provenance; those later artifact types do not yet exist in this path.
3. Prepare a measured 12–20 conversation pilot manifest for separate authorization. Passing
   the synthetic gate does not authorize processing that export or spending money.

After a separately accepted pilot, the untouched ZIP is reused for the proposed bounded bulk
campaign. Inventory and reimport suppression happen locally; the bulk campaign still requires
its own exact authorization and does not start automatically.
