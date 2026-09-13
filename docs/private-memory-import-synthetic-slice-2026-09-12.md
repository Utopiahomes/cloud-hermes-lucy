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

## Verification ledger

| Check | Result | Evidence | Invalidated by |
|---|---|---|---|
| Fresh PostgreSQL migration `0001` through `0061_memory_import_revocation` | Passed | Clean disposable PostgreSQL on `127.0.0.1:54329`, 2026-09-12 | Migration or PostgreSQL-image change |
| Synthetic memory-import integration | Passed, 11 tests on current revision | `tests/integration/test_memory_import_slice.py` against PostgreSQL at `0061`; includes execute-only encrypted-outcome storage, immutable job replay/conflict, exact realm/source/version/deletion eligibility, post-revocation approval/outcome denial, V2 authorization/round trip, atomic completion replay, and partial-batch rollback | Import, grant, migration, or scoped-memory change |
| Python unit suite | Passed, 872 tests | Full `tests/unit` run after the additive deletion V3 contract increment, 2026-09-12 | Relevant Python or dependency change |
| Ruff | Passed | `src/lucy`, unit/import tests, migrations `0055`, `0056`, and `0058` through `0061` | Relevant source change |
| Mypy strict | Passed, 98 source files | `mypy --strict src` after the pilot-runner increment | Python source or type-config change |
| Candidate materialization | Passed, 4 focused tests | Strict output parsing, stable IDs, UTF-8 spans, exact evidence binding, ambiguous-quote rejection, and secret quarantine | Candidate contract, manifest, provenance, or secret-filter change |
| Exact owner-review contracts | Passed, 7 focused tests | Complete-batch decisions, protected/ordinary/uncertain transforms, stale/duplicate/incomplete rejection, and exact two-step authorization | Candidate review contract or canonicalization change |
| Loopback candidate-review console | Passed, 5 focused tests and full-suite rerun | Token/host/origin checks, safe rendering, exact proposal, explicit authorization phrase, immutable replay/conflict behavior, and protected-path confinement | Candidate console, browser contract, or intake-path change |
| Isolated OpenRouter memory adapter | Passed, 11 focused tests and full-suite rerun | Exact manifest policy/route, strict JSON Schema, ZDR plus denied data collection, token/byte bounds, usage-cost parsing, keyed generation reference, malformed-response rejection, and sanitized transport errors | OpenRouter adapter, provider contract, or approved privacy policy change |
| Pilot completion assembly | Passed, 3 focused tests and full-suite rerun | Provenance materialization, exact review artifact, pre-database deterministic rejection, and no artifact after uncertain database acknowledgement | Pilot completion, materializer, or review-artifact change |
| Executable request-budget contract | Passed, focused V1/V2 contract and coordinator/provider tests | Historical V1 round trip; V2 digest binding and separate source/input/output/total constraints; real execution typed to V2 | Manifest, request compiler, tokenizer/accounting, or provider framing change |
| Immutable provider request | Passed, 8 focused tests and full-suite rerun | Canonical request commitment, complete byte/token upper-bound accounting, Unicode/system/schema inclusion, credential exclusion, tamper rejection, and pre-network count verification | Provider request body, schema, system prompt, or accounting version change |
| V2 proposal and deterministic compiler | Passed, focused console/manifest/compiler/provider tests and full-suite rerun | Visible bound ceilings, exact digest, deterministic packing and coverage, oversize/attempt/cost rejection, complete request accounting, and provider input-usage reconciliation | Selection proposal, manifest generation, compiler, provider framing, or usage contract change |
| Local ChatGPT inventory, review console, and exact-manifest builder | Passed, 16 tests | Safe paths, branches, keyed commitments, attachments, compression, sync-root, token, host/origin, stale-input, idempotency, exact-record/exclusion and changed-input checks | Parser, console, manifest, or limits change |
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

1. Add a deliberately narrow operator entry point for the assembled pilot runner, but keep it
   disabled until the outcome-key lifecycle below is complete and a specific pilot manifest is
   separately authorized. No real provider request is currently enabled.
2. Implement the V3 deletion contract in PostgreSQL, the executor, receipt reconciliation, and the
   quarantined recovery reader before enabling the pilot. The additive wire contract is complete;
   V2 remains immutable. V3 execution must freeze all candidate versions and exact-job encrypted
   outcomes derived from a source, destroy each outcome's external wrapped key, record
   candidate/outcome tombstones, support restore replay, and handle a shared multi-source outcome
   idempotently. Until then, the access gates prevent approval and outcome recovery after
   revocation, but do not yet prove cryptographic shredding of the derived provider result. An
   interruption before the first encrypted outcome write also remains an explicit reconciliation
   case; no automatic provider retry is allowed.
3. Add dependency invalidation for summaries, embeddings, catalogs, briefings, caches, and
   review previews as those artifact classes are introduced. The current slice fences claims
   and their evidence provenance; those later artifact types do not yet exist in this path.
4. Prepare a measured 12–20 conversation pilot manifest for separate authorization. Passing
   the synthetic gate does not authorize processing that export or spending money.

After a separately accepted pilot, the untouched ZIP is reused for the proposed bounded bulk
campaign. Inventory and reimport suppression happen locally; the bulk campaign still requires
its own exact authorization and does not start automatically.
