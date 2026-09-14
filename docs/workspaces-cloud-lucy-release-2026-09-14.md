# Workspaces Cloud Lucy release checkpoint

Date: 2026-09-14

## Objective and selected source

Prepare the smallest production-reviewable Cloud Lucy release that can serve the
Utopia Workspaces private adapter. Production, AWS, Render, PostgreSQL, capture,
paid inference, and live admission are unchanged by this checkpoint.

The isolated release branch starts at merge commit
`feaa4d191619d0dda729711b6920cbf922796a4b`. That commit contains the accepted R1
tenant foundation and the reviewed Workspaces service-authority change. It excludes
the 15 later memory-pilot commits currently on `codex/r1-tenant-foundation` and the
uncommitted memory adapter work in its separate worktree. The Workspaces merge is an
ancestor of the advancing foundation branch; this release branch does not overwrite
or duplicate that work.

The repository `main` branch still ends at `52527fa`, but later separately accepted
Private Telegram Stage 2 and Public Lucy releases run from pinned commits on
`codex/r1-tenant-foundation`. Workspaces must coexist with those active surfaces and
must not change their admission, capture, model, or service state. The new Workspaces
surface itself remains capture-off and unadmitted until its separate activation gate.

## Release-only corrections

- Update two stale test expectations to cover behavior already present at `feaa4d1`:
  the policy-only memory-outcome recovery route and OpenRouter's no-fallback provider
  request.
- Point the review-only Workspaces private-service Render shape at `main`, where the
  reviewed release will live, while retaining private-service type, manual deployment,
  and capture-off configuration.
- Add a structural test that freezes those Render properties and the set of secrets
  that must remain externally supplied.

No runtime authorization, migration, contract, AWS template, or customer-data logic is
changed in this release branch.

## Verification ledger

| Check | Result | Evidence / limitation | Invalidated by |
| --- | --- | --- | --- |
| Release isolation | Passed | Dedicated worktree and `codex/workspaces-cloud-lucy-release` branch at `feaa4d1`; later memory-pilot and dirty shared-worktree changes excluded | Release base or cherry-pick change |
| Ruff | Passed | `ruff check src tests migrations deploy` after all release-only changes | Relevant source, test, migration, or deploy change |
| Strict typing | Passed | `mypy src`, 103 source files | Python source or type configuration change |
| Broad Python suite, initial | Diagnostic | 909 passed, 260 skipped, 3 failed: two stale expectations and the known Windows CRLF byte-hash mismatch | Superseded by corrected run |
| Corrected affected tests | Passed | 40 tests for Workspaces runtime/deploy shape, API-surface, and OpenRouter boundaries | Workspaces runtime/template, API, provider request, or tests change |
| Broad Python suite | Passed with one platform-specific deselection | 912 passed, 260 environment-gated skips; only the frozen-template disk-byte test deselected on the CRLF checkout | Relevant code, tests, dependencies, or line-ending policy change |
| Frozen v1.2 AWS source | Passed independently | Git object SHA-256 `3acff006d2268ef03001e48caaf3e6ea4f9b510fb802aaac0337517e1b71c3df`; the Windows working copy uses CRLF and therefore has different disk bytes | Frozen Git object change |
| Workspaces PostgreSQL boundary | Reused, still valid | Prior clean `0001` through `0068`, reversal, and six live service-membership/admission/queue/role checks at preserved runtime commit `ce2164b` | Runtime, migrations, role template, provisioner, or PostgreSQL image change |
| AWS SSO access | Passed | AWS CLI v2.36.41 in the Windows development environment; `lucy-dev` browser login succeeded and `aws sts get-caller-identity` verified account `429870640638` with the existing `LucySecurityAdministrator` SSO role | SSO profile, CLI, account, or role change |
| Live AWS drift | Passed | Reviewed V1.3 deployment verifier passed against `lucy-utopia-security-v1-3`: expected account and SSO identity, termination protection, production parameters, artifact/trust digests, realm bindings, journal audit selectors, Lambda aliases/artifacts/runtimes/roles/concurrency/environment boundaries, KMS state/purpose, and encrypted/PITR/protected DynamoDB tables | Either stack, identity, policy, artifact, key, table, or audit configuration change |
| Live Render metadata | Passed with reconciled later production state | Read-only API inspection found the production PostgreSQL database available in Virginia on PostgreSQL 18 with an empty public allow-list. All inventoried services have auto-deploy off, production V1.3 configuration, no blank environment values, and no static AWS credentials. Public Lucy is live with capture false; its separate paid-model service is suspended. Private Telegram Stage 2 is live and intentionally has encrypted capture true. Policy, evidence, and deletion remain suspended. No Workspaces service exists yet. | Render service, deployment, environment, or database metadata change |
| Production PostgreSQL head/admission | Reused, current query still required | The latest accepted Telegram and Public Lucy receipts both pin production revision `0054_stage2_scoped_turn_commit`; the database allow-list is currently empty. A fresh SQL read was not attempted because every available path would create a Render job or temporarily open the public allow-list. Recheck through the controlled migration job immediately before migration. | Database migration, activation, role/grant, or runtime state change |
| Deployed Workspaces call | Not executed | Private service remains undeployed | Requires the approved deployment gate below |

## Bounded deployment gate

Before asking for production approval, prepare and review these exact actions:

1. Publish this release branch and open a Cloud Lucy pull request to `main`. Merging
   must not itself deploy because the affected Render services remain manual.
2. Reauthenticate the existing `lucy-dev` SSO profile if required, then refresh the
   read-only AWS and Render drift checks without printing secret values. Obtain the
   exact PostgreSQL head and admission state through the controlled migration job
   before its first write; do not open a workstation database allow-list solely to
   inspect it.
3. Build or select the exact reviewed release revision. Do not change or redeploy the
   accepted Public Lucy, Private Telegram, policy, evidence, deletion, recovery, or
   writer services. Create only the private Workspaces service needed for the bounded
   test, initially suspended or otherwise unadmitted.
4. Confirm production starts at the accepted `0054` head, then advance the Utopia realm
   database through `0068_workspaces_service_auth` with the existing controlled
   migration path. The migrations are additive, but the job must verify compatibility
   with the active Public Lucy and Private Telegram surfaces before committing. Keep
   Workspaces capture false and its admission closed. Do not downgrade or repeat
   accepted recovery drills.
5. Apply one digest-bound membership manifest for the exact realm-bound Workspaces
   service principal. Missing membership, a different service principal, or changed
   manifest bytes must continue to fail closed.
6. Create `lucy-workspaces-private` as a Render private service with auto-deploy off,
   the reviewed command, the exact non-elevated realm and directory logins, and only
   `memory.read` plus `task.delegate` exposed to rooms. The runtime binding may include
   `task.execute` solely for its fixed internal worker path.
7. Verify private health/readiness and negative controls: capture-on refusal, wrong
   login, wrong token, wrong service principal, missing membership, direct-table
   denial, changed projection digest, and unavailable task queue.
8. Configure the Workspaces Lucy worker with the discovered private Render address
   and its independent transport token. Do not expose either value to the browser or
   reuse the Cloud Lucy authority token.
9. Run one bounded Homes Workspace test covering preflight, approved-knowledge query,
   one idempotent task delegation, cross-node/capability denial, and human-room
   continuity when Cloud Lucy is unavailable.

The gate excludes transcript capture, public Cloud Lucy activation, paid model calls,
customer memory import, node switching, recovery-database creation, and unrelated AWS
or Render changes. Any production merge, deployment, migration, membership write,
service creation, secret/configuration write, or pilot activation requires a concrete
action-time approval after the read-only checks and rollback route are ready.

## Exact next action

Publish this tested, reconciled release branch and prepare the pull request to `main`.
Do not merge, migrate, create the private service, write membership/configuration, or
activate Workspaces without the later concrete action-time approval and rollback route.
