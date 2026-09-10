# Security Baseline AWS deployment

## V1.3 per-realm template (local preparation only)

`security-baseline-v1.2.yaml` remains the accepted, frozen single-realm source.
The checked-in `security-baseline-v1.3.yaml` is a fail-closed derivation: its
renderer first verifies the exact accepted v1.2 SHA-256, then applies counted
changes for one explicit realm. Regenerate it after an intentional renderer
change with:

```powershell
.\.venv\Scripts\python.exe deploy\aws\render_security_v1_3_template.py `
  --output deploy\aws\security-baseline-v1.3.yaml `
  --force
```

Deploy one stack per realm with a unique `ResourceNamespace`. The realm UUIDs,
binding generations, storage epoch, Render service identities, and artifact
version are required stack parameters. Each stack creates its own KMS keys,
DynamoDB tables, caller roles, runtime roles, functions, and qualified
`realm-v13` aliases. The functions derive scope and caller identity only from
deployment-owned environment values; invocation JSON cannot choose a realm.

Build the committed executor bundle under an unambiguous V1.3 release name:

```powershell
.\deploy\aws\build-executor-artifact.ps1 `
  -ArtifactName lucy-security-executors-v1.3.zip
```

The V1.2 filename remains the wrapper's compatibility default; a V1.3 stack
must use the explicitly named V1.3 artifact and its adjacent digest manifest.

After a stack is complete and termination-protected, save its read-only
`describe-stacks` response. Combine that evidence with the reviewed,
content-free PostgreSQL binding description:

```powershell
.\.venv\Scripts\python.exe deploy\aws\build_realm_security_stamp_v1_3.py `
  --stack-description secrets\generated\utopia-stack.json `
  --binding secrets\generated\utopia-binding.json `
  --expected-account-id <12-digit-target-account> `
  --output secrets\generated\utopia-realm-security-stamp.json
```

The builder rejects incomplete stacks, missing termination protection, any
realm mismatch between parameters, outputs, and PostgreSQL identity, cross-
account or unqualified executor bindings, and unknown binding fields. Its
output contains the canonical `RealmSecurityStampV1` and digest consumed by
the quarantined PostgreSQL provisioner. These preparation tools do not call
AWS, modify PostgreSQL, enable paid traffic, or enable transcript capture.

The v1.3 template is not production authorization. After deploying one realm,
run its dedicated read-only verifier before building the security stamp or
performing synthetic acceptance:

```powershell
.\.venv\Scripts\python.exe deploy\aws\verify_realm_security_v1_3_deployment.py `
  --stack-name <realm-stack-name> `
  --expected-account-id <12-digit-target-account> `
  --profile lucy-dev `
  --report secrets\generated\<realm>-aws-deployment-v1.3.json
```

The verifier pins the CloudFormation parameters and outputs to one realm,
checks both qualified executor aliases and their immutable versions, rejects
static AWS credentials, and reuses the accepted KMS, DynamoDB, and public-key
trust-store checks from v1.2. It performs only read operations through STS,
CloudFormation, Lambda, KMS, and DynamoDB. Exit status `2` keeps the realm on
hold. Synthetic realm acceptance remains a separate commissioning gate.

## V1.2 accepted deployment

Do not retry the v1.2 CloudFormation stack until the read-only preflight passes.
It verifies the exact MFA-backed Identity Center administrator and target
account, the Render workspace OIDC provider, sufficient Lambda concurrency,
and every byte of the exact versioned S3 executor artifact against its clean
local release manifest.

The preflight accepts no AWS access keys, application tokens, database URLs,
signing seeds, or transcript data. Use the active
`LucySecurityAdministrator` Identity Center session supplied by AWS.

```powershell
.\.venv\Scripts\python.exe deploy\aws\preflight_security_v1_2.py `
  --artifact <local-executor-zip> `
  --manifest <local-executor-manifest-json> `
  --expected-account-id <12-digit-target-account> `
  --render-workspace-id <tea-workspace-id> `
  --oidc-provider-arn <exact-render-provider-arn> `
  --artifact-bucket <private-versioned-bucket> `
  --artifact-key <exact-object-key> `
  --artifact-version <exact-object-version> `
  --report secrets\generated\aws-preflight-v1.2.json
```

Exit status `0` means every gate passed. Exit status `2` means the stack must
remain on hold. The report is content-free and deliberately refuses to
overwrite an existing acceptance artifact.

The preflight requires only these AWS reads: `sts:GetCallerIdentity`,
`lambda:GetAccountSettings`, `iam:GetOpenIDConnectProvider`, and
`s3:GetObjectVersion` for the named artifact. It creates, updates, invokes, or
deletes nothing.

## Core post-deployment verification

After CloudFormation completes, run the read-only core verifier before any
executor invocation or Render activation:

```powershell
.\.venv\Scripts\python.exe deploy\aws\verify_security_v1_2_deployment.py `
  --stack-name lucy-security-baseline-v1-2 `
  --expected-account-id <12-digit-target-account> `
  --report secrets\generated\aws-deployment-v1.2.json
```

Exit status `0` proves the reviewed stack is complete and termination-protected;
its outputs, published Lambda aliases and environments are exact; policy trust
stores contain public keys only; the KMS keys are customer-managed and
purpose-separated; and every DynamoDB table has its reviewed key schema,
encryption, protection, PITR, and TTL settings. Exit status `2` keeps the
deployment on hold. The report contains check names and outcomes only and is
created without overwriting an earlier artifact.

This verifier performs only `Get*`, `Describe*`, and `List*`-equivalent reads
through STS, CloudFormation, Lambda, KMS, and DynamoDB. It does not invoke an
executor, inspect archive content, read DynamoDB records, or change AWS state.
IAM-policy simulation, audit/alert validation, synthetic executor operations,
and recovery testing remain separate acceptance gates.

Then verify the deployed trust policies, inline policies, KMS resource
policies, and critical IAM simulator decisions:

```powershell
.\.venv\Scripts\python.exe deploy\aws\verify_security_v1_2_iam.py `
  --stack-name lucy-security-baseline-v1-2 `
  --expected-account-id <12-digit-target-account> `
  --report secrets\generated\aws-iam-v1.2.json
```

This second verifier requires `iam:GetRole`, `iam:GetRolePolicy`,
`iam:ListRolePolicies`, `iam:ListAttachedRolePolicies`,
`iam:SimulatePrincipalPolicy`, and `kms:GetKeyPolicy` in addition to the STS
and CloudFormation reads. It requires every role to have exactly one reviewed
inline policy, no attached managed policy, and no permissions boundary; it
also checks the exact trust/resource policies and critical positive and
negative simulator decisions. It never assumes a workload role. Real denied
API calls under temporary workload sessions remain part of synthetic cloud
acceptance rather than this read-only inspection.

Finally, verify the audit-delivery and alerting plane after confirming the SNS
email subscription:

```powershell
.\.venv\Scripts\python.exe deploy\aws\verify_security_v1_2_audit.py `
  --stack-name lucy-security-baseline-v1-2 `
  --expected-account-id <12-digit-target-account> `
  --expected-alert-email <reviewed-alert-mailbox> `
  --report secrets\generated\aws-audit-v1.2.json
```

This read-only gate checks the three 90-day log groups; versioned, encrypted,
TLS-only, non-public CloudTrail bucket; live S3 and CloudWatch trail delivery;
exact management and data-event selectors; content-free metric filters; all
fourteen alarm routes; the single confirmed email subscription; and the
enabled security-change EventBridge target. It requires only describe/get/list
operations across CloudWatch Logs, S3, CloudTrail, CloudWatch, SNS, and
EventBridge. It neither publishes a test alert nor reads any log event or S3
object. Alert receipt is exercised later with a non-destructive synthetic
event.
