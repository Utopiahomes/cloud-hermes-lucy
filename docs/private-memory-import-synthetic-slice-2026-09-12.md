# Private memory import synthetic-slice checkpoint

Date: 2026-09-12
Branch: `codex/r1-tenant-foundation`
Starting revision: `207d3af6c782747e104fa24f2b72a2a2c4eea8ff`
Status: local synthetic slice implemented and passing; not deployed
Current private-memory revisions: `d747509` (schema/import foundation), `d973d41`
(bounded extraction coordinator), plus the candidate-materialization increment recorded here.

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

## Verification ledger

| Check | Result | Evidence | Invalidated by |
|---|---|---|---|
| Fresh PostgreSQL migration `0001` through `0056_memory_import_budget` | Passed | Clean tmpfs database on `127.0.0.1:54329`, rerun after exact-manifest changes on 2026-09-12 | Migration or PostgreSQL-image change |
| Synthetic memory-import integration | Passed, 5 tests on current revision | `tests/integration/test_memory_import_slice.py` against fresh PostgreSQL | Import, grant, migration, or scoped-memory change |
| Python unit suite | Passed, 799 tests | Full `tests/unit` run after exact review contracts, 2026-09-12 | Relevant Python or dependency change |
| Ruff | Passed | `src/lucy`, import tests, migrations `0055`/`0056` | Relevant source change |
| Mypy strict | Passed, 88 source files | `mypy --strict src` after exact review contracts | Python source or type-config change |
| Candidate materialization | Passed, 4 focused tests | Strict output parsing, stable IDs, UTF-8 spans, exact evidence binding, ambiguous-quote rejection, and secret quarantine | Candidate contract, manifest, provenance, or secret-filter change |
| Exact owner-review contracts | Passed, 7 focused tests | Complete-batch decisions, protected/ordinary/uncertain transforms, stale/duplicate/incomplete rejection, and exact two-step authorization | Candidate review contract or canonicalization change |
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

1. Connect the exact two-step candidate review/approval contracts to the local console. Keep the
   fingerprint key and raw ZIP local. The contract layer is implemented; the UI/API wiring is not.
2. Connect the new bounded extraction coordinator to the existing OpenRouter policy/cost bridge.
   The coordinator now enforces exact inputs, campaign reservations, secret quarantine, and
   admission/pre-dispatch/post-dispatch source checks; the adapter must return the exact provider
   policy, model route, and billed cost before a real call can be enabled.
3. Add dependency invalidation for summaries, embeddings, catalogs, briefings, caches, and
   review previews as those artifact classes are introduced. The current slice fences claims
   and their evidence provenance; those later artifact types do not yet exist in this path.
4. Prepare a measured 12–20 conversation pilot manifest for separate authorization. Passing
   the synthetic gate does not authorize processing that export or spending money.

After a separately accepted pilot, the untouched ZIP is reused for the proposed bounded bulk
campaign. Inventory and reimport suppression happen locally; the bulk campaign still requires
its own exact authorization and does not start automatically.
