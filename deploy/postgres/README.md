# Security Baseline v1.2 PostgreSQL deployment

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
