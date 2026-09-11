# Security Baseline v1.2 PostgreSQL deployment

## R1 V1.3 realm role stamp (not yet deployed)

The additive R1 schema uses four distinct PostgreSQL LOGINs per private security
realm: routine/archive, policy notary, sensitive workflow, and one-off finality.
Render the reviewed execute-only grants without passwords or other secrets:

```powershell
.\.venv\Scripts\python.exe deploy\postgres\render_security_v1_3_sql.py `
  --realm-slug utopia `
  --routine-login lucy_utopia_routine `
  --policy-login lucy_utopia_policy `
  --workflow-login lucy_utopia_sensitive_workflow `
  --finality-login lucy_utopia_finality `
  --output secrets\generated\production_realm_roles_v1.3.sql
```

The renderer requires every LOGIN to use the selected realm namespace and refuses
duplicates, unsafe identifiers, unresolved markers, missing output directories, and
overwrites. The rendered SQL verifies that all four LOGINs already exist without
elevated attributes or inherited memberships, removes all prior schema privileges,
and grants only the exact R1 security-definer functions for that role. In particular,
the routine identity receives the capture-receipt-enforcing archive function, never
the lower-level raw scoped archive function. Realm directory and actor/executor
bindings are a separate provisioning artifact; this role stamp alone cannot admit a
realm. Live transcript capture remains disabled.

The v1.2 instructions below remain the accepted single-tenant production baseline.
Do not replace them until the complete V1.3 realm provisioning and commissioned cloud
acceptance gates pass.

The two production SQL templates are reviewed source artifacts. Do not insert
deployment values into either template by hand. Generate deployment-specific
SQL with `render_security_v1_2_sql.py`, review its SHA-256 and contents, apply
it through the migration/security owner, and retain the rendered files only in
the controlled acceptance record.

The renderer accepts no passwords, tokens, signing seeds, transcript data, or
other secret material. It fails closed on unsafe or duplicate PostgreSQL LOGIN
names, non-alias Lambda ARNs, `$LATEST`, cross-account AWS bindings, invalid KMS
key ARNs, bindings outside the explicit target AWS account, non-positive
versions/epochs, unresolved markers, and overwrites.

## 1. Render exact service-role grants

Create a local ignored output directory first:

```powershell
New-Item -ItemType Directory -Force secrets\generated | Out-Null
```

Then render using the exact five LOGIN names created for the Render services:

```powershell
.\.venv\Scripts\python.exe deploy\postgres\render_security_v1_2_sql.py roles `
  --routine-login <routine-login> `
  --policy-login <policy-login> `
  --evidence-login <evidence-login> `
  --deletion-login <deletion-login> `
  --finality-login <finality-login> `
  --output secrets\generated\production_roles_v1.2.sql
```

Apply the result only after migrations `0017` through `0019` have succeeded.
The LOGINs must already exist, be distinct, and have no elevated attributes or
inherited role memberships. The SQL validates these facts before granting any
capability.

## 2. Render immutable AWS bindings

After the v1.2 CloudFormation stack is deployed, use only its exact qualified
Lambda alias ARNs, exact receipt-key ARNs, published function versions, and the
reviewed security epochs:

```powershell
.\.venv\Scripts\python.exe deploy\postgres\render_security_v1_2_sql.py bindings `
  --aws-account-id <12-digit-target-account> `
  --retrieval-alias-arn <retrieval-alias-arn> `
  --deletion-alias-arn <deletion-alias-arn> `
  --retrieval-receipt-key-arn <retrieval-receipt-key-arn> `
  --deletion-receipt-key-arn <deletion-receipt-key-arn> `
  --retrieval-version <published-version> `
  --deletion-version <published-version> `
  --security-storage-epoch <epoch> `
  --security-registry-epoch <epoch> `
  --security-key-epoch <epoch> `
  --output secrets\generated\configure_security_v1.2.sql
```

Apply the result as the migration/security owner while transcript capture is
disabled and runtime admission remains quarantined. Never substitute a Lambda
function ARN without a final alias qualifier, a moving `$LATEST` target, an AWS
resource from another account, or a new epoch that has not been reviewed.

The renderer refuses to replace existing output unless `--overwrite` is
explicitly supplied. Prefer a new reviewed filename for a new deployment rather
than overwriting an acceptance artifact.

The rendered binding SQL is an **initial activation** artifact and deliberately
requires an empty sensitive-operation ledger. After synthetic or live history
exists, a reviewed Lambda publication must instead use
`rebind_executors_cloud_v1_2.py`. That utility requires quarantined admission,
the exact prior aliases, identities, receipt keys, versions, and security epochs,
and no unresolved operations. It changes only the two executor-version fields
and their configuration timestamps in one locked transaction; it never deletes
or recreates bindings, evidence, permits, grants, receipts, or operation history.

If that guard discovers unresolved work,
`inspect_unresolved_cloud_v1_2.py` provides a temporary authenticated inventory
while every normal PostgreSQL client stays suspended. It exposes only operation
IDs, state labels, timestamps, event names, and reference counts. It never
selects evidence content, encrypted packages, permits, ciphertext, wrapped
keys, credentials, or messages. Remove its migration URL, authorization value,
bearer token, and Docker command immediately after review.

## Private Render bootstrap

Production PostgreSQL must remain closed to the public internet. Do not place
the migration-owner URL on any of the four Lucy services or the finality
utility. A Render one-off job inherits the complete environment snapshot of its
base service, so none of those services is an acceptable migration base.

For a fresh private Render database, create a temporary migration-only service
from the reviewed repository image and run:

```text
python deploy/postgres/bootstrap_cloud_v1_2.py
```

The temporary service has no AWS role. Supply its migration-owner URL through a
private `fromDatabase.connectionString` binding, and supply the exact five
runtime URLs and immutable non-secret AWS binding values as environment
variables. It additionally requires:

```text
RENDER=true
LUCY_ENVIRONMENT=production
LUCY_TRANSCRIPT_CAPTURE_ENABLED=false
LUCY_DATABASE_BOOTSTRAP_AUTHORIZATION=security-v1.2-private-quarantined
```

The utility refuses external database hosts, non-production execution, missing
or elevated logins, inherited role memberships, non-TLS connections, incorrect
executor bindings, and any capture-enabled or admitted result. It applies the
role bootstrap, migrations through `0019`, the direct grants, and the immutable
executor bindings, then connects with each runtime URL to verify the boundary.
Its JSON result contains no database URL or password.

After a successful run, put only each service's matching runtime URL on that
service, remove the temporary migration resource and its environment snapshot,
and verify the database inbound allowlist is still empty. Never retain the
migration-owner URL on a continuously running service.

## Provision one V1.3 realm foundation and binding stamp

For an existing accepted V1.2 Render database, prefer the single quarantine-first
commissioning command:

```text
python -m deploy.postgres.bootstrap_realm_cloud_v1_3
```

The temporary migration-only job requires the private `lucy_migration` URL, four
password-bearing realm runtime URLs (`ROUTINE`, `POLICY`, `WORKFLOW`, and `FINALITY`),
the reviewed security stamp and foundation seed with their canonical digests, and:

```text
RENDER=true
LUCY_ENVIRONMENT=production
LUCY_TRANSCRIPT_CAPTURE_ENABLED=false
LUCY_REALM_BOOTSTRAP_AUTHORIZATION=security-v1.3-private-quarantined
```

It accepts only migration source revisions `0021_recovery_capture_safety`,
`0039_r1_scoped_capture_runtime`, `0040_r1_grant_authority_snapshot`, and
`0041_r1_deletion_auth_snapshot`, `0042_r1_permit_authority`, or
`0043_r1_provider_cost_admission`, `0044_r1_cost_outcome_recovery`, or
`0045_r1_authority_recovery`, `0046_r1_cost_journal`, or
`0047_r1_authority_replay`, `0048_r1_cost_replay`, or
`0050_r1_recovery_ack_receiver`. Before any
schema or role mutation it takes the
maintenance and admission locks, verifies TLS and the database-owned capture
boundary, and closes runtime admission. It then creates or rotates the four ordinary
realm LOGINs plus four isolated recovery LOGINs, migrates to `0050`, applies both
reviewed execute-only grant stamps, and
transactionally provisions the foundation and immutable bindings at `0050`. Its final
content-free verification reconnects through all eight LOGINs and proves that
the database remains quarantined. Exact replay is supported. The operation never
opens admission and never enables transcript capture.

R1-4 recovery workloads use a second, additive execute-only role stamp rendered by
`render_recovery_roles_v1_3.py`. It requires four exact realm-prefixed LOGINs:
`lucy_<realm>_authority_writer`, `lucy_<realm>_cost_writer`,
`lucy_<realm>_authority_recovery`, and `lucy_<realm>_cost_recovery`. The stamp
revokes all inherited schema/table/sequence/function access, grants only schema use
and schema-version read, then grants the exact pending/prepare functions to each
writer and exact pending/acknowledge/replay functions to its matching recovery
identity. It grants no membership in the
generic prerequisite roles. Production LOGIN creation/password rotation is performed
by the same quarantine-first bootstrap when the four recovery database URLs are
supplied. Do not place the migration URL on any continuous service.

## Prepare the synthetic V1.3 recovery drill

`provision_recovery_drill_fixture_v1_3.py` creates the content-free state that must
exist before the selected PITR target: a synthetic owner and member, an unreachable
`.invalid` website channel, and an immutable one-micro-USD cost policy. It requires
the reviewed realm stamp and fixture manifest with both canonical digests, production
Render, the private migration URL, quarantine, capture off, and the exact marker
`security-v1.3-synthetic-recovery-fixture`. It does not stage a journal event or call
a provider. Retain its `restore_anchor_at`; do not proceed until Render can restore a
point after that anchor and before the later events.

Build the fixture manifest before provisioning it. After the PITR target is safely
available, use the same builder's `events` subcommand immediately before staging; its
request timestamp is intentionally short-lived. Both output files are content-free,
refuse overwrite, and belong in the ignored operator evidence directory:

```powershell
python -m deploy.postgres.build_recovery_drill_manifests_v1_3 fixture `
  --realm-stamp secrets\generated\utopia-realm-security-stamp-v1.3.json `
  --output secrets\generated\utopia-recovery-drill-fixture-v1.3.json

python -m deploy.postgres.build_recovery_drill_manifests_v1_3 events `
  --realm-stamp secrets\generated\utopia-realm-security-stamp-v1.3.json `
  --fixture secrets\generated\utopia-recovery-drill-fixture-v1.3.json `
  --authority-binding secrets\generated\authority-recovery-binding-v1.3.json `
  --binding-manifest-digest <reviewed-64-character-digest> `
  --output secrets\generated\utopia-recovery-drill-events-v1.3.json
```

If staging is interrupted after the authority transaction but before the cost
transaction, preserve the first event manifest and pass it back with `--resume-from`
to a new output path. The builder refreshes only `requested_at`; every event identity,
idempotency key, commitment, and fixture binding remains exact. The stager accepts a
revoked member only when the matching generation-1-to-2 transition has every reviewed
field, so the retry cannot adopt an unrelated revocation.

`stage_recovery_drill_events_v1_3.py` then stages exactly one membership revocation
and one one-micro-USD reservation. Its reviewed event manifest pins the fixture
digest, idempotency keys, attempt ID, commitments, and request time. The command uses
the authority stream only when it matches the reviewed recovery-binding manifest,
the offline migration session with `SET LOCAL ROLE` only for the two existing function
owners, commits through the production staging functions, closes those sessions, and
stops at `PERSISTENCE_PENDING`. It never appends, acknowledges, submits, settles, or
calls a provider. The deployed authority/cost writers and acknowledgement coordinator
must durably complete both event IDs afterward. Exact retries must return the same two
events without advancing either journal twice.

These operator fixture actions prove the recovery path, not production caller-login
commissioning or the deferred shared controller topology. The synthetic source rows,
events, acknowledgements, and unresolved one-micro-USD exposure remain aligned with
the permanent production journals; do not delete or rewrite them as test cleanup.

## Run a protected V1.3 recovery handoff

`run_protected_recovery_v1_3.py` is an operator-only, one-off recovery utility. It
must run under the exact recovery-coordinator Render OIDC role while ordinary Lucy is
quarantined and capture is off. It rejects static AWS credentials and verifies the
active assumed role through STS before reading either journal. Supply the two exact
recovery database URLs, both immutable stream bindings, independently retained
pre-restore witness heads, the two journal table names, a new target runtime epoch,
and the private URL for a fresh restore-only LOGIN whose name ends in
`_recovery_activation`, and:

```text
RENDER=true
LUCY_ENVIRONMENT=production
LUCY_SECURITY_BASELINE=v1.3
LUCY_TRANSCRIPT_CAPTURE_ENABLED=false
LUCY_PROTECTED_RECOVERY_AUTHORIZATION=security-v1.3-protected-recovery-handoff
```

The runner verifies each non-elevated recovery LOGIN and the TLS/capture/quarantine
boundary, replays both journal suffixes, obtains the protected short writer pauses,
finalizes cost recovery, rechecks the heads and pauses, and only then activates the
new runtime epoch. The restore-only activation LOGIN is `NOINHERIT`, owns no schema,
has no role memberships, and receives only the exact metadata reads plus column-level
updates required for the final handoff. It must be created after restore, supplied in
the legacy-named `LUCY_MIGRATION_DATABASE_URL` variable for the one-off job, and
destroyed before the isolated restore is disposed. Do not supply the restored
`lucy_migration` schema owner: Render PITR may recreate that login with
`CREATEROLE`/`CREATEDB`, and the runner rejects it. A successful report does not
enable transcript capture; paid admission remains subject to the recovered cost
cooldown and other database-enforced limits.

The lower-level foundation and binding commands below remain available for a
reviewed recovery or diagnostic run.

Before binding authority, create the content-free tenant/node/tenure/realm,
private workspace, four service principals, and nonspendable wallet with:

```text
python deploy/postgres/provision_realm_foundation_v1_3.py
```

This temporary migration-only operation requires production Render, disabled
transcript capture, quarantined runtime admission, TLS, the private
`lucy_migration` URL, and the exact authorization marker
`security-v1.3-quarantined-realm-foundation`. Supply the reviewed realm stamp
and digest as `LUCY_REALM_SECURITY_STAMP_JSON` and
`LUCY_REALM_SECURITY_STAMP_SHA256`, plus the content-free
`lucy.realm-foundation-seed.v1` and its canonical digest as
`LUCY_REALM_FOUNDATION_SEED_JSON` and
`LUCY_REALM_FOUNDATION_SEED_SHA256`. The seed contains only labels, one stable
wallet ID, a service-principal issuer, and a fixed provisioning timestamp. It
does not create a public channel, membership, transcript, credential, or
capture authorization. Exact replay is read-only; partial or conflicting state
fails and rolls back.

After the realm LOGIN role stamp is applied and the tenant/node/tenure/realm,
workspace, four service principals, and AWS executor aliases exist, apply their
reviewed relationships with:

```text
python deploy/postgres/provision_realm_bindings_v1_3.py
```

This temporary migration-only operation requires production Render, disabled
transcript capture, quarantined runtime admission, TLS, the private
`lucy_migration` URL, and the exact authorization marker
`security-v1.3-quarantined-realm-binding-provision`. Supply the content-free
`lucy.realm-security-stamp.v1` JSON as `LUCY_REALM_SECURITY_STAMP_JSON` and its
separately reviewed canonical SHA-256 as
`LUCY_REALM_SECURITY_STAMP_SHA256`.

The stamp contains identifiers, role names, qualified Lambda alias ARNs, and KMS
key ARNs, but no passwords, tokens, private content, or signing material. The
utility verifies all four PostgreSQL LOGINs and the complete realm foundation,
takes the maintenance and admission locks, and applies the content scope,
service/actor bindings, and executor bindings in one transaction. An exact retry
is read-only; a conflicting or partial prior stamp fails closed and rolls back.
Remove the temporary service and its migration URL after the receipt is retained.
