# Tiamat Render PostgreSQL — staging provisioning review v1

**Status:** the reviewed staging database is provisioned and public access is blocked. The dedicated
Tiamat migration lineage through `0006_render_recovery_rls`, scoped runtime/recovery role bootstrap,
day-zero ledger initialization, and recovery capability probe succeeded. Anchor write and provider
dispatch remain incomplete.

## Purpose and boundary

Create one dedicated **staging** Render PostgreSQL 16 instance for Tiamat's execution and accounting
ledger. It is neither Cloud Lucy's database nor the DynamoDB recovery-anchor store. PostgreSQL
remains the execution/accounting system of record; DynamoDB remains the independent signed recovery
authority.

The database starts dispatch-blocked. Provisioning it does not create a root key, signed witness,
release authority, spending grant, or provider route.

## Selected supported shape

| Item | Reviewed value |
| --- | --- |
| Render environment | Existing isolated Tiamat staging environment; no Utopia production attachment. |
| Region | Exact region of both existing Tiamat staging services. |
| PostgreSQL | Version 16, matching the tested migration and continuity-query implementation. |
| Initial database | `tiamat_staging`; record Render's immutable generated owner/name before creation. |
| Initial capacity | Paid 256 MB Postgres plan with 1 GB storage; a staging baseline only. |
| Network | Render internal URL only; explicitly clear the external IP allow list. |
| Recovery authority | Existing DynamoDB `stoin-staging-tiamat-recovery-anchor-v1`, never Postgres metadata. |

Render supports same-region private Postgres URLs and can disable external access with
`render pg update --clear-ip-allow-list`. Paid instances support PITR, which creates a new database
instance rather than replacing the attached ledger in place. [Connection controls](https://render.com/docs/postgresql-creating-connecting)
[Backups and PITR](https://render.com/docs/postgresql-backups)

## Cost and retention

The selected dashboard configuration records **$6.30/month** for this staging baseline before tax,
transfer, or future scale-up. That observed amount, rather than the earlier review estimate, is
recorded in the [provisioning evidence](evidence/tiamat-render-postgres-staging-provisioning-2026-09-18.json).
Reconfirm current pricing before changing the plan. [Current Render pricing](https://render.com/pricing)

Paid instances receive Render PITR: the documented window is three days for Hobby and seven days for
Pro-or-higher workspaces. Record the actual workspace plan and displayed recovery window in
commissioning evidence. A logical export, clone, point-in-time restore, data-losing failover, or
connection-string switch is a Tiamat recovery event.

## Credentials and permissions

| Identity | Permitted use | Prohibited use |
| --- | --- | --- |
| Render-created owner | Temporary migration and role/bootstrap boundary only. | Serving, recovery-anchor reads, provider dispatch. |
| `tiamat_runtime` | Private executor's RLS-scoped ledger operations. | Ownership, `BYPASSRLS`, recovery, DynamoDB updates. |
| `tiamat_release_manager` | Signed-release staging/activation only. | Provider dispatch, recovery, ownership. |
| `tiamat_recovery` | Offline initialization, capability preflight, quarantine, and reconciliation. | Serving-process configuration or `BYPASSRLS`. |

Render [the role template](../deploy/postgres/tiamat_roles.sql.example) with
`deploy/postgres/render_tiamat_role_template_v1.py --database-name tiamat_staging`, then apply the
result after migrations using the platform owner. The database owner URL is supplied only to a
disposable, private bootstrap/migration runner. It creates the three distinct database roles, but
activates and verifies only the runtime and recovery logins using two generated passwords injected
into that runner only for the run. The release-manager role remains `NOLOGIN` until its separately
deployed boundary exists, avoiding a credential with no service-scoped home.

Each resulting connection URL belongs in exactly one protected, service-scoped Render secret:
`TIAMAT_RUNTIME_DATABASE_URL` on the executor, `TIAMAT_RECOVERY_DATABASE_URL` on the recovery
boundary, and `TIAMAT_RELEASE_MANAGER_DATABASE_URL` only on the later release-management boundary.
Do not use a shared environment group, a permanent owner credential, or AWS Secrets Manager for
this staging increment. Disable or delete the bootstrap runner and remove its owner secret when its
verification succeeds. Every internal URL uses `sslmode=require`; Render's internal Postgres
certificates are self-signed, so this requires encrypted transport without claiming CA or hostname
verification that the platform does not provide. The recovery probe verifies the live TLS session
before commissioning proceeds. No static AWS credentials are permitted.

## Commissioning procedure

1. The dedicated PostgreSQL 16 instance is created in the exact Tiamat staging region with 1 GB
   storage and has no Utopia production attachment.
2. Its external IP allow list is empty. Content-free evidence records the Render ID, region, plan,
   storage, Postgres version, and resource-specific external-access block; workspace recovery-window
   evidence remains pending.
3. Completed in a temporary private bootstrap/migration boundary: run the independent lineage through
   `0006_render_recovery_rls`; apply the rendered role template; set and verify the two existing-service
   login passwords; then deliver each resulting URL to only its corresponding Render service secret.
   The release-manager role remains `NOLOGIN` until its service exists. Remove the owner URL and all
   bootstrap-only password inputs when that job exits.
4. The temporary bootstrap secrets were removed and the runner suspended. The recovery-only
   initializer ran as `tiamat_recovery`, with its exact confirmation, creating the immutable ledger
   ID and the non-authorizing `not_installed` checkpoint at recovery generation one.
5. The read-only capability probe ran as only `tiamat_recovery`. It proved TLS, the exact recovery
   login, blocked ledger state, and access to `pg_control_system()`, `pg_control_checkpoint()`, and
   `pg_current_wal_flush_lsn()`.
6. Independently review the checkpoint and capability report. A failed control/WAL query rejects
   this hosting path; it does not justify weakening continuity checks.
7. Separate root-key and signed-package authorization is required before the DynamoDB installer can
   execute. Provider dispatch remains a still-later activation.

## Restore and identity guardrails

Migration `0005` creates `ledger_identity` once; day-zero initialization never creates or replaces
it. A post-0005 restore preserves the UUID but stays blocked until the external anchor accepts its
continuity beacon. A snapshot before `0005` can later produce a different UUID only via migration;
that value cannot match the existing anchor and cannot receive authority. A new storage epoch is not
a new ledger.

Render PITR yields a new database and requires an explicit connection-string switch. That switch is
a recovery boundary: quarantine and old-worker/provider-credential isolation precede it, and the new
attachment cannot dispatch until reconciliation and a signed anchor transition succeed.

## Required evidence before provider activation

- External database access is disabled, not merely unused.
- The database and both Tiamat services share one Render region and use the internal URL.
- Authenticated PostgreSQL sessions pass over Render private networking with `sslmode=require` for
  the runtime, recovery, and release-manager roles; the capability tool passes under
  `tiamat_recovery` and proves its live TLS transport.
- Runtime cannot read `ledger_identity` or use recovery control/WAL functions.
- A restore/clone preserves the post-0005 ledger UUID; a mismatched/pre-0005 identity fails anchor
  binding and remains blocked.
- Restore/failover evidence shows quarantine and old-worker isolation before an endpoint change.
- No root key, signed release/witness, DynamoDB write, model route, or spending grant exists.

## Exclusions

This review does not select production capacity, enable HA, create a production database, deploy a
Tiamat executor, configure a provider, or grant customer-facing access.
