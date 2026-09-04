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
