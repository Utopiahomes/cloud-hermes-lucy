# Workspaces coordinated production batch

Cloud Lucy production activation is paused. This batch is therefore a review and
coordination artifact only. Loading, building, or validating a plan performs no AWS,
Render, PostgreSQL, membership, credential, deployment, or activation action.

The coordinator is `deploy/render/workspaces_production_batch.py`. It binds the
already-reviewed single-operation gates into one exact, resumable sequence. A later
production driver must implement the `BatchDriver` protocol and may be installed only
inside a separately approved maintenance job. The coordinator has no default network
or database driver.

## Bound plan

The build input contains only the exact batch window and non-secret deployment facts:

- full Cloud Lucy and Workspaces merge commits;
- current Render service IDs, names, deployed commits, and rollback deploy IDs;
- the complete Workspaces service-membership manifest;
- the exact private-service owner, protected environment, repository, plan, command,
  health path, and disabled auto-deploy setting.

The builder reads the independent transport and Cloud Lucy authority credentials from
its process environment. It writes only domain-separated SHA-256 commitments. The
credential values are never included in the plan or status output. The complete plan,
membership, private-service configuration, stage order, accepted source schemas, and
six-hour maximum execution window are canonicalized and bound to one batch digest.

Build a plan only after the fresh read-only drift inventory is complete:

```text
set LUCY_WORKSPACES_PRODUCTION_BATCH_BUILD_AUTHORIZATION=build-workspaces-production-batch-v1
set LUCY_WORKSPACES_TRANSPORT_TOKEN=<new independent transport token>
set LUCY_WORKSPACES_AUTHORITY_TOKEN=<new independent Cloud Lucy authority token>
python -m deploy.render.workspaces_production_batch build batch-inputs.json batch-plan.json
```

Do not put either token in `batch-inputs.json`, `batch-plan.json`, the receipt ledger,
shell history, a commit, an issue, or a chat. The builder refuses tokens shorter than
32 UTF-8 bytes, reused token values, mismatched commitments, an existing output path,
or a changed manifest boundary.

Validate a new or resumed ledger with:

```text
python -m deploy.render.workspaces_production_batch status batch-plan.json --ledger receipts.json
```

Add `--containment containment.json` after a failed run. A valid containment receipt is
terminal; it deliberately produces no next stage.

## Exact stage order

1. `preflight` re-verifies AWS and Render drift, exact merge commits and rollback
   deploys, disables auto-deploy for all three Workspaces workloads, and proves the
   Cloud Lucy private URL/token pair is absent.
2. `contained` suspends Public Lucy and the private Telegram gateway/routine, drains
   their PostgreSQL sessions, quarantines admission, and proves capture safety.
3. `migrated` runs `migrate_workspaces_v1.py`. Only `0054`, `0057`, or replayed `0068`
   is accepted; the receipt must prove the `0068` target, existing-surface and queue
   grants, direct-table denial, removed schema authority, capture safety, and continued
   quarantine.
4. `membership_applied` runs `provision_workspaces_authority_v1.py` against the exact
   membership and digest embedded in the plan.
5. `existing_surfaces_restored` reopens Telegram Stage 2 and Public Lucy with their
   accepted controllers and verifies both negative-control sets.
6. `private_service_ready` creates `lucy-workspaces-private` on the exact Cloud release
   with auto-deploy off and verifies health, readiness, capture refusal, identity/token
   denials, membership denial, and direct-table denial.
7. `worker_connected` writes only the private service address and independent transport
   token to the Workspaces Lucy worker, deploys the exact Workspaces release, verifies
   the token commitment, and proves that denial leaves the human room alive.
8. `accepted` runs the bounded approved-knowledge query, idempotent task delegation,
   cross-node denial, excluded-capability denial, unavailable-Lucy room continuity,
   capture-off, and paid-inference-off checks.

Each passed stage emits one typed, content-free receipt. Its digest is the next
receipt's `prior_receipt_sha256`; a missing, duplicate, reordered, overlapping,
expired, or cross-batch receipt fails closed. `run_remaining_stages` starts at the
first unrecorded stage, persists each receipt before continuing, and invokes the
driver's containment operation on an execution, verification, or persistence failure.

## Containment and recovery

Before the existing surfaces have been restored, a failure is acceptable only after
the driver leaves those surfaces contained, admission quarantined, capture safe,
Workspaces transport disabled, and the private service absent or suspended. After the
restore stage, Telegram and Public Lucy must remain restored while Workspaces transport
stays disabled and any private service is absent or suspended.

Schema `0068` is additive and accepted by the Telegram and Public Lucy compatibility
bridges. The rollback route therefore does not downgrade PostgreSQL. It restores or
retains the plan's recorded service deploys, leaves Workspaces disconnected, and keeps
the database quarantined whenever the next safe state cannot be proven.

## Deliberate exclusions

The batch cannot authorize transcript capture, paid inference, customer-memory import,
node switching, recovery-database creation, changes to AWS infrastructure, changes to
unrelated Render services, or use of one credential for both transport and Cloud Lucy
authority. A reviewed plan is still not production authorization; the live driver and
its exact batch digest require a separate action-time approval after the pause ends.
