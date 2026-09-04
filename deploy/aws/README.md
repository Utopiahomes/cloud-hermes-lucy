# Security Baseline v1.2 AWS deployment

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
