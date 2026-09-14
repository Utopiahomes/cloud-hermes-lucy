# Workspaces Cloud Lucy release checkpoint

Date: 2026-09-14

## Objective and selected source

Prepare the smallest production-reviewable Cloud Lucy release that can serve the
Utopia Workspaces private adapter. Production, AWS, Render, PostgreSQL, capture,
paid inference, and live admission are unchanged by this checkpoint.

The isolated release branch starts at merge commit
`feaa4d191619d0dda729711b6920cbf922796a4b`. It contains the accepted R1 tenant
foundation and reviewed Workspaces service authority, and now also merges the
separately accepted Public Lucy production release from
`origin/codex/public-conversation-r1`. This preserves the currently deployed public
runtime and its `0057` schema bridge while excluding the 15 later memory-pilot commits
and unrelated uncommitted memory adapter work.

The repository `main` branch still ends at `52527fa`, but later separately accepted
Private Telegram Stage 2 and Public Lucy releases run from pinned commits. Workspaces
must coexist with both. Advancing their shared database to `0068` requires a short,
coordinated maintenance window: stop the two runtimes, quarantine admission, keep the
capture boundary safe, migrate and reapply grants, provision Workspaces membership,
then reopen the accepted services. The new Workspaces surface remains capture-off and
unadmitted until its separate activation gate.

## Release-only corrections

- Keep the internal API allow-list aligned with the deliberately excluded memory-pilot
  route, and add OpenRouter's explicit no-fallback provider request hardening directly
  to the release candidate.
- Point the review-only Workspaces private-service Render shape at `main`, where the
  reviewed release will live, while retaining private-service type, manual deployment,
  and capture-off configuration.
- Add a structural test that freezes those Render properties and the set of secrets
  that must remain externally supplied.
- Preserve the accepted Public Lucy release in the candidate rather than regressing
  the deployed public runtime when `main` advances.
- Treat `0068_workspaces_service_auth` as a post-memory schema in shared readiness and
  let the existing digest-bound Telegram Stage 2 activation reopen either its original
  `0054` revision or the reviewed additive `0068` revision.
- Add `migrate_workspaces_v1.py`, a production-Render-only, quarantine-first migration
  gate that accepts only the reviewed `0054`, `0057`, or idempotent `0068` source,
  advances to `0068`, reapplies execute-only realm grants, verifies Public Lucy and
  Telegram functions plus Workspaces queue functions, denies direct task-table access,
  and leaves admission quarantined.

No AWS template, capture policy, customer-data policy, or live environment is changed
by this branch. Production mutation remains a later action-time gate.

## Verification ledger

| Check | Result | Evidence / limitation | Invalidated by |
| --- | --- | --- | --- |
| Release isolation | Passed | Dedicated worktree and `codex/workspaces-cloud-lucy-release` branch at `feaa4d1`; later memory-pilot and dirty shared-worktree changes excluded | Release base or cherry-pick change |
| Ruff | Passed | Refreshed `ruff check src tests migrations deploy` after the Public Lucy merge and all compatibility corrections | Relevant source, test, migration, or deploy change |
| Strict typing | Passed | Refreshed strict `mypy src`, 103 source files | Python source or type configuration change |
| Broad Python suite, initial | Diagnostic | 909 passed, 260 skipped, 3 failed: two stale expectations and the known Windows CRLF byte-hash mismatch | Superseded by corrected run |
| Corrected affected tests | Passed | 40 tests for Workspaces runtime/deploy shape, API-surface, and OpenRouter boundaries | Workspaces runtime/template, API, provider request, or tests change |
| Broad Python unit suite | Passed with two harness-specific deselections | Refreshed batch branch: 968 passed. The known frozen-template Windows CRLF byte check and one subprocess import check that deliberately removes the isolated test environment's `PYTHONPATH` were deselected; both limitations are unrelated to the coordinator or journal | Relevant code, tests, dependencies, line-ending policy, or test environment change |
| Schema/reopen compatibility unit slice | Passed | 43 focused checks cover `0054` and `0068` Telegram reopen, post-memory readiness at `0068`, exact production migration configuration, quarantine refusal, target migration, grant checks, Public Lucy migration, role rendering, Workspaces runtime/queue, direct-table denial, and Docker inclusion | Readiness, Telegram activation, migration utility, role template, runtime, or Docker change |
| Fresh PostgreSQL migration and authority boundary | Passed | Disposable loopback/tmpfs PostgreSQL 16 migrated cleanly from `0001` through `0068`; 16 live-SQL checks passed for realm provisioning, explicit Workspaces membership, execute-only production roles, task queue lifecycle, directory admission, and withdrawal/reenablement denial. The stale fixture now performs its authorized withdrawal through the owner boundary before proving the app identity cannot reactivate it. Containers and test data were removed after the run. | Migrations, role template, provisioners, directory admission, task queue, integration fixtures, or PostgreSQL image change |
| Frozen v1.2 AWS source | Passed independently | Git object SHA-256 `3acff006d2268ef03001e48caaf3e6ea4f9b510fb802aaac0337517e1b71c3df`; the Windows working copy uses CRLF and therefore has different disk bytes | Frozen Git object change |
| Workspaces PostgreSQL boundary | Reused, still valid | Prior clean `0001` through `0068`, reversal, and six live service-membership/admission/queue/role checks at preserved runtime commit `ce2164b` | Runtime, migrations, role template, provisioner, or PostgreSQL image change |
| AWS SSO access | Passed | AWS CLI v2.36.41 in the Windows development environment; `lucy-dev` browser login succeeded and `aws sts get-caller-identity` verified account `429870640638` with the existing `LucySecurityAdministrator` SSO role | SSO profile, CLI, account, or role change |
| Live AWS drift | Passed | Reviewed V1.3 deployment verifier passed against `lucy-utopia-security-v1-3`: expected account and SSO identity, termination protection, production parameters, artifact/trust digests, realm bindings, journal audit selectors, Lambda aliases/artifacts/runtimes/roles/concurrency/environment boundaries, KMS state/purpose, and encrypted/PITR/protected DynamoDB tables | Either stack, identity, policy, artifact, key, table, or audit configuration change |
| Live Render metadata | Passed with reconciled later production state | Read-only API inspection found the production PostgreSQL database available in Virginia on PostgreSQL 18 with an empty public allow-list. All inventoried services have auto-deploy off, production V1.3 configuration, no blank environment values, and no static AWS credentials. Public Lucy is live with capture false; its separate paid-model service is suspended. Private Telegram Stage 2 is live and intentionally has encrypted capture true. Policy, evidence, and deletion remain suspended. No Workspaces service exists yet. | Render service, deployment, environment, or database metadata change |
| Production PostgreSQL head/admission | Current query still required | The accepted Telegram release began at `0054`; the accepted Public Lucy release includes the `0054 -> 0056 -> 0057` production bridge, so `0057` is expected but must not be assumed. The database allow-list is empty. Recheck atomically through `migrate_workspaces_v1.py`; it accepts only `0054`, `0057`, or idempotent `0068` and refuses any non-quarantined boundary before its first write. | Database migration, activation, role/grant, or runtime state change |
| Deployed Workspaces call | Not executed | Private service remains undeployed | Requires the approved deployment gate below |
| Coordinated batch durability | Passed locally | Exact-plan journal atomically persists and reloads chained receipts, refuses overwrite/reordering/cross-batch use, fails closed on concurrent locks or tampering, and makes containment terminal; 33 focused tests pass | Coordinator, journal, receipt models, or filesystem semantics change |

## Bounded deployment gate

Before asking for production approval, prepare and review these exact actions:

1. Publish this release branch and open a Cloud Lucy pull request to `main`. Merging
   must not itself deploy because the affected Render services remain manual.
2. Reauthenticate the existing `lucy-dev` SSO profile if required, then refresh the
   read-only AWS and Render drift checks without printing secret values. Obtain the
   exact PostgreSQL head and admission state through the controlled migration job
   before its first write; do not open a workstation database allow-list solely to
   inspect it.
3. Build or select the exact reviewed release revision. Suspend Public Lucy and the
   Private Telegram gateway and routine for the maintenance window; leave policy,
   evidence, deletion, recovery, and writer services unchanged. Verify that runtime
   database sessions have drained before mutation.
4. Quarantine realm admission and make the transcript capture boundary safe without
   discarding accepted encrypted content. Run `migrate_workspaces_v1.py`. It must read
   the actual source revision under the maintenance/admission locks, reject anything
   outside `0054`, `0057`, or `0068`, advance to `0068_workspaces_service_auth`, reapply
   the execute-only realm grants, and leave admission quarantined. Do not downgrade or
   repeat accepted recovery drills.
5. Apply one digest-bound membership manifest for the exact realm-bound Workspaces
   service principal. Missing membership, a different service principal, or changed
   manifest bytes must continue to fail closed.
6. Reopen Telegram with its existing digest-bound Stage 2 manifest at `0068`, reopen
   Public Lucy through its existing release controller, and verify their negative
   controls before creating the Workspaces service.
7. Create `lucy-workspaces-private` as a Render private service with auto-deploy off,
   the reviewed command, the exact non-elevated realm and directory logins, and only
   `memory.read` plus `task.delegate` exposed to rooms. The runtime binding may include
   `task.execute` solely for its fixed internal worker path.
8. Verify private health/readiness and negative controls: capture-on refusal, wrong
   login, wrong token, wrong service principal, missing membership, direct-table
   denial, changed projection digest, and unavailable task queue.
9. Configure the Workspaces Lucy worker with the discovered private Render address
   and its independent transport token. Do not expose either value to the browser or
   reuse the Cloud Lucy authority token.
10. Run one bounded Homes Workspace test covering preflight, approved-knowledge query,
   one idempotent task delegation, cross-node/capability denial, and human-room
   continuity when Cloud Lucy is unavailable.

The gate excludes transcript capture, public Cloud Lucy activation, paid model calls,
customer memory import, node switching, recovery-database creation, and unrelated AWS
or Render changes. Any production merge, deployment, migration, membership write,
service creation, secret/configuration write, or pilot activation requires a concrete
action-time approval after the read-only checks and rollback route are ready.

## Exact next action

The Cloud Lucy and Workspaces release pull requests were merged, but Cloud Lucy
production activation is paused. Build and review the content-free coordinated batch in
`deploy/render/workspaces_production_batch.py` and
`docs/workspaces-production-batch.md`. The atomic, digest-bound journal is prepared in
`deploy/render/workspaces_production_batch_journal.py`; do not initialize a production
journal or install a live driver, migrate, create the private service, write
membership/configuration, or activate Workspaces until the pause ends and the exact
batch digest receives separate action-time approval.
