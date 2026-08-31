# Service admission and controlled recovery hardening

Date: 2026-08-31. Local source/test checkpoint; **not deployed or accepted for live capture**.

This records the 0014 checkpoint. The subsequent
[deletion-provenance batch](deletion-provenance-2026-08-31.md) advances the current
schema to 0015 and adds another operator admission review; earlier test counts
below remain historical evidence for this batch.

This follows the [first retention-hardening batch](retention-hardening-2026-08-31.md).
It addresses the local implementation and database proof for F01/F08 and adds a
controlled quarantine boundary toward F07. It does not close the full recovery,
deletion-provenance, owner-event, or cloud-acceptance findings.

## Service startup is read-only

`python -m lucy.runtime` checks the pinned Hermes commit and performs a read-only
database admission check before serving. It never runs Rejoining, scans pending
work, changes lifecycle, checks/deletes wrapped keys, or performs synthetic KMS
operations. Restarting one service cannot declare another service's work crashed.

Production requires an explicit isolated `LUCY_SERVICE_MODE`, exactly one matching
capability role, a non-administrative login, the reviewed schema revision, a
`ready` lifecycle and admission row, and an independently configured
`LUCY_STORAGE_EPOCH` UUID. Selecting the AWS archive backend also forbids
`all-local`, even if the environment label is missing or says development.
Readiness checks reject critical excess table/column permissions, compound or
legacy capability membership, schema/database creation, and elevated role
attributes. This is a targeted capability check, not an exhaustive IAM analyzer.

`/health` means process liveness. `/ready` repeats the non-mutating check; it does
not certify KMS availability or cloud recovery. API operations use a dedicated
SQLAlchemy session class which rechecks admission at transaction start, closing
the preflight-to-operation race. Denials return a content-free HTTP 503.

## Database boundary proved on a separate clean cluster

The second tmpfs test cluster is `lucy_roles_test`, loopback port 54330. It does
not inherit the old development application's default grants. An administrator
creates the extension, inert compatibility role, and four capability roles;
all fourteen migrations run as a **non-superuser database/schema owner**. The
post-migration SQL grants are then exercised with four independent login roles.

| Identity | Allowed path demonstrated | Important denied authority |
| --- | --- | --- |
| Routine | Model reservation, consent receipt, encrypted ingest, pending proposal, structured lookup | Ciphertext read, global recovery, DDL |
| Policy | Signed owner permit issuance | Ciphertext read, global recovery, DDL |
| Evidence reader | Consume an existing permit and retrieve one synthetic record | Mint/modify permit authority, evidence/memory mutation, DDL |
| Deletion | Consume permit, remove record key/ciphertext, invalidate direct proposal | Mint/modify permit authority, edit tombstones, evidence mutation, DDL |

All four logins are denied admission/lifecycle/startup writes and modification
of immutable evidence/audit/consent receipts. Negative tests require PostgreSQL
SQLSTATE `42501` (permission denied), not a syntax error or an empty result.
The positive path uses synthetic local cryptography/key storage: this proves
PostgreSQL capabilities, **not AWS IAM/KMS/DynamoDB or Render isolation**.

Fresh production bootstrap order is:

1. Have the database role administrator run
   `deploy/postgres/production_bootstrap.sql.example` and provision the vector
   extension plus a separate non-superuser migration/schema-owner login.
2. Run migrations with the migration credential, never a service credential.
3. As the schema owner, apply `deploy/postgres/production_roles.sql.example`.
4. Create separate non-administrative service logins with exactly one matching
   capability each. Never grant them `lucy_app`, schema ownership or maintenance
   credentials. Ordinary service logins inherit their one capability's grants.
5. Perform controlled maintenance/admission and independently configure the
   same approved storage epoch in all four services before starting them.

This is a **fresh-cluster** procedure, not an in-place grant-cleanup script.
Bootstrap deliberately fails on pre-existing roles rather than trusting them.
Existing production/default grants require an inventory and a reviewed migration;
reapplying the grant file alone does not revoke every historical excess grant.
Actual Render role-administration constraints remain part of cloud acceptance.

## Operator-controlled quarantine

Migration `0014_service_admission` creates an operator-owned admission row in
`quarantined` state. Service logins can read but cannot open it. A separate CLI
uses `LUCY_MAINTENANCE_DATABASE_URL`; that credential is never injected into the
HTTP services. There is no model-visible or HTTP maintenance endpoint.

Each service transaction acquires a shared admission advisory lock before the
retention/operation locks. Quarantine acquires the exclusive counterpart, waits
for admitted transactions to finish, and durably closes the gate. Transactions
from already-created pools must then fail admission. Admitted transactions use
READ COMMITTED explicitly so a prior repeatable-read default cannot preserve a
pre-lock view of an open gate.

`python -m lucy.maintenance quarantine` only closes admission. `prepare` requires:

- explicit operator confirmation that **all external executors are stopped**;
- no connected service database sessions, including idle pools and the legacy
  development login;
- a fresh storage epoch supplied by the operator;
- no unresolved ambiguous outcomes; pending work requires explicit
  `--recover-ambiguous` review and never results in automatic external replay;
- every remaining ciphertext key reference to exist in the supplied registry;
- successful pin, audit, budget and Rejoining checks before reopening.

The quarantine commit survives a later verification/recovery failure. Concurrent
maintenance commands are serialized. Converting pending work to ambiguous leaves
the lifecycle degraded and admission closed; retrying `prepare` cannot silently
clear that condition. Resolving ambiguous external effects requires a separate
reviewed reconciliation procedure; this CLI does not invent one.

Stopping service DB sessions is not proof that an external model/tool invocation
has stopped. Operator confirmation is still a real requirement. Do not restore a
database while executors or old application processes are running.

## Storage epoch: deliberately limited guarantee

The independently supplied UUID identifies an operator-approved storage admission
generation. After a controlled restore, rotate it outside the database and keep
all services stopped/quarantined until reconciliation succeeds. A stale database
snapshot that carries the old ready row cannot serve through a service expecting
the new epoch. An old client also cannot access newly admitted storage.

**This is not automatic rollback detection.** Restoring both an old ready row and
its matching external epoch would defeat that check. The epoch is not a deletion
ledger, a cryptographic registry identity, or a proof of backup freshness. The
key-reference check detects absent keys but does not authenticate registry
generation, key contents, orphan keys, or deletion intent. Missing keys close the
gate; they never authorize a cascade on their own.

The transaction gate protects supported HTTP paths. A compromised direct DB
client can bypass application advisory-lock discipline within its granted SQL
rights. Database roles remain the separate capability boundary. Plaintext
structured memory accessible to the routine identity is still an explicitly
accepted residual confidentiality boundary, not encrypted semantic memory.

## Local startup after this migration

Normal Compose startup no longer performs recovery. A fresh database will remain
quarantined until an explicit maintenance run. `lucy-maintenance` is opt-in via
the `maintenance` profile, defaults to **quarantine**, and is not a dependency of
the API or gateway.

For a **new, empty, synthetic local database only**, after supplying development
configuration, the sequence is:

```powershell
docker compose up -d --wait postgres
docker compose run --rm --build lucy-migrate
if ($LASTEXITCODE -ne 0) { throw 'Migration failed; stop here' }
$env:LUCY_STORAGE_EPOCH = [guid]::NewGuid().ToString()
docker compose --profile maintenance run --rm --build lucy-maintenance prepare --storage-epoch $env:LUCY_STORAGE_EPOCH --confirm-executors-stopped
if ($LASTEXITCODE -ne 0) { throw 'Admission failed; leave services stopped' }
docker compose up -d --build lucy-api
```

Keep the approved epoch in the independent deployment configuration for later
restarts. The combined development mode permits a missing epoch for legacy local
acceptance only; it is not a production restore boundary. The default maintenance
Compose job has no archive registry mount or cloud credentials. A database with
encrypted records needs an explicitly reviewed registry configuration; never
omit it to bypass a failed check. Do not use this fresh-database example as an
upgrade recipe for the running gateway or a database with real conversations.

## Verification and reproduction

Use only `compose.test.yaml`. Both databases are disposable; tests truncate them.
Do not substitute a development or production URL. Public synthetic credentials:

```powershell
docker compose -f compose.test.yaml up -d --wait --wait-timeout 45
$env:LUCY_MIGRATION_DATABASE_URL = 'postgresql+psycopg://lucy_owner:synthetic-owner-only@127.0.0.1:54329/lucy_test'
.\.venv\Scripts\python.exe -m alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw 'Synthetic migration failed' }
$env:LUCY_TEST_DATABASE_URL = 'postgresql+psycopg://lucy_app:synthetic-app-only@127.0.0.1:54329/lucy_test'
$env:LUCY_TEST_OWNER_DATABASE_URL = $env:LUCY_MIGRATION_DATABASE_URL
$env:LUCY_TEST_ROLES_ADMIN_DATABASE_URL = 'postgresql+psycopg://lucy_owner:synthetic-owner-only@127.0.0.1:54330/lucy_roles_test'
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src
docker compose -f compose.test.yaml down
Remove-Item Env:LUCY_MIGRATION_DATABASE_URL, Env:LUCY_TEST_DATABASE_URL, Env:LUCY_TEST_OWNER_DATABASE_URL, Env:LUCY_TEST_ROLES_ADMIN_DATABASE_URL
```

The role-test fixture bootstraps/migrates only the validated `127.0.0.1:54330`
`lucy_roles_test` database.

Final verification:

- **210 tests passed**, zero skips: 101 unit and 109 PostgreSQL integration
  tests, including 70 separate-role/admission tests.
- Clean migrations through `0014_service_admission`; one Alembic head.
- Ruff, strict MyPy (30 source files), Python compilation, Git whitespace
  checks, and Compose validation passed.
- The admission-lock race and both deletion/promotion orderings passed five
  additional repetitions (15 successful test cases).
- The pinned Hermes middleware/registry/output-hook probe passed again in a
  disposable network-disabled container. Only synthetic probe/plugin files were
  mounted read-only; zero cloud/model calls.
- Two non-failing dependency warnings remain: Starlette's HTTPX test-client
  deprecation and Alembic's legacy `prepend_sys_path` separator warning.
- Both test containers and their network were removed after verification,
  discarding only synthetic tmpfs data. The live API/PostgreSQL stayed healthy
  and the gateway stayed running; none was restarted.

The database suite covers live-work-safe restarts, actual role allow/deny paths,
column-grant and compound-membership drift, HTTP readiness, the transaction race,
quarantine interruption, wrong/missing registry, stale epochs and ambiguity.

## Next acceptance blockers

1. Complete derivation closure across assistant responses, historical sources,
   summaries and future embeddings; test deletion against all those paths.
2. Independent deletion-intent history, registry identity/generation verification,
   orphan-key handling and a **real compound backup/restore** rehearsal. The
   stale-row simulation in this batch is not that rehearsal.
3. Independently verified owner events, revocation and interaction disclosure
   limits; gateway permit minting remains disabled.
4. Legacy plaintext/fingerprint/log inventory, complete budget accounting, and
   actual Render/AWS identity, recovery and backup-retention acceptance.
5. Coordinated migration/API/plugin rollout and owner acceptance before enabling
   live Telegram capture. Do not upgrade just the database beneath old services:
   old binaries do not honor the new admission gate.

No live gateway reseed/rebuild, real-database migration, cloud provisioning,
credential change, model call or transcript activation was performed in this batch.
