# Security Baseline AWS deployment

`r1-recovery-journals-v1.3.yaml` is the additive R1 recovery boundary. The Utopia
instance is deployed and termination-protected; other realms require their own
reviewed commissioning. It defines separate retained authority and cost journal tables plus exact
Render OIDC roles for the two writers and the operator-triggered coordinator. The
coordinator can write only `PAUSE#...` partitions and condition-check `STREAM#...`;
it may exact-read content-free stream records and `EVENT#<known-id>` acknowledgements,
but has no head-update, scan, query, delete, KMS, Lambda, or table-administration
authority. Keep this separate from the accepted realm stack until the three Render
service IDs, genesis heads, and deployed negative-permission exercise are ready for
one reviewed update. CloudTrail integration is prepared in the realm template: first
deploy this recovery stack, then update the realm stack with the exact
`AuthorityRecoveryJournalTableArn` and `CostRecoveryJournalTableArn` outputs. The
existing realm trail will then record data events for both journal tables without a
second trail or a selector-mutating custom resource.

After deployment, create the two genesis heads with the human security-administrator
identity. The initializer validates the account, region, table ARNs, stream kinds,
distinct stream IDs, and shared manifest before either write. It uses conditional
`PutItem`; an exact rerun reports both heads as already present, while any conflicting
head fails closed:

```powershell
$env:AWS_PROFILE = 'lucy-dev'
.\.venv\Scripts\python.exe deploy\aws\initialize_recovery_journals_v1_3.py `
  --account-id 429870640638 `
  --authority-table <authority-table-output> `
  --authority-binding secrets\generated\authority-recovery-binding-v1.3.json `
  --cost-table <cost-table-output> `
  --cost-binding secrets\generated\cost-recovery-binding-v1.3.json
```

The binding files contain identifiers and digests, not credentials. Keep them in the
ignored generated-evidence directory. The command relies on the existing short-lived
AWS SSO session and never accepts or creates static access keys.

After genesis and after every newly accepted journal event, retain a new immutable
two-stream witness outside PostgreSQL. The capture utility performs only two strongly
consistent exact-key DynamoDB reads, verifies the shared binding manifest and distinct
stores/streams, and refuses to overwrite prior evidence:

```powershell
.\.venv\Scripts\python.exe -m deploy.aws.capture_recovery_witness_v1_3 `
  --profile lucy-dev `
  --account-id $AWS_ACCOUNT_ID `
  --authority-binding secrets\generated\authority-recovery-binding-v1.3.json `
  --cost-binding secrets\generated\cost-recovery-binding-v1.3.json `
  --output secrets\generated\utopia-recovery-witness-v1.3.json
```

Do not replace an older witness. A protected restore uses the latest independently
retained bundle known to predate the recovery request; falling below either witness
keeps the runtime quarantined.

After the realm-stack update, run the V1.3 deployed-state verifier. It now fails unless
both ARN parameters name the exact `${ResourceNamespace}-authority-journal` and
`${ResourceNamespace}-cost-journal` tables in the expected account and `us-east-1`,
and unless the live CloudTrail selector contains both exact ARNs.

The recovery coordinator runs the private acknowledgement surface with
`python -m lucy.recovery_ack_runtime`. One exact Render service identity owns the
coordinator role and uses two distinct non-elevated PostgreSQL LOGINs, one per stream.
It accepts `POST /v1/recovery/{authority|cost}/acknowledgements/{event-id}` with an
empty body and a stream-specific private bearer credential. Authority and cost
tokens must be distinct; neither writer token authorizes the other stream. The
service independently reads the
permanent DynamoDB acknowledgement; the caller cannot submit a digest, sequence,
database URL, table, stream ID, or AWS locator.

Writer runtimes use `HttpRecoveryAcknowledgementClient`, configured with the fixed
private Render host/port and that writer's stream-specific bearer credential. It sends only the stream kind and
event UUID in the request path with a zero-byte body, then validates the returned
event, stream, and required terminal state. Attempt IDs and journal-head digests are
used only by the local workflow contract and are never trusted or transmitted to the
receiver.

Each journal writer is also a separate private Render workload running
`python -m lucy.recovery_writer_runtime`. Its path-only API accepts a zero-byte POST
containing one event UUID, exact-reads and prepares that event through its dedicated
PostgreSQL LOGIN, and conditionally appends through its one stream-bound AWS role.
The authority and cost writer services, tokens, database LOGINs, tables, bindings,
and OIDC subjects are distinct.

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

Generate a purpose-distinct policy-notary identity for each realm. Both outputs
belong under ignored local `secrets/generated`; only the public trust-store JSON
and its digest enter CloudFormation. The private seed goes only to that realm's
policy service and must never be printed, committed, or supplied to AWS:

```powershell
.\.venv\Scripts\python.exe deploy\aws\generate_policy_identity_v1_3.py `
  --key-id utopia-policy-v13-1 `
  --issuer lucy-utopia-policy `
  --environment production `
  --private-output secrets\generated\utopia-policy-private-v1.3.json `
  --trust-output secrets\generated\utopia-policy-trust-store-v1.3.json
```

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
# Tiamat external recovery anchor

`tiamat-recovery-anchor-v1.yaml` is the unprovisioned single-Region DynamoDB deployment definition
for Tiamat's signed recovery authority. Its reader and updater role parameters must name distinct
existing machine roles. Review
`../../docs/tiamat-dynamodb-recovery-anchor-deployment-review-v1.md` before creating a change set.
