# Security Baseline v1.2 deployment repair checkpoint

Date: 2026-09-04

Status: **repair implemented, executed, and accepted by all three live AWS
verifiers. Live Telegram transcript capture remains disabled and is not
authorized.**

## Acceptance findings

The initial production stack reached `CREATE_COMPLETE`, and the read-only live
verification established the following:

- all nine IAM roles and all three KMS resource policies match the approved
  v1.2 contract;
- every critical IAM allow/deny simulation passed;
- the KMS keys, DynamoDB schemas, deletion protection, PITR, quota TTLs,
  Lambda artifacts, aliases, concurrency reservations, and static-credential
  exclusions passed;
- CloudTrail is logging to both protected S3 and CloudWatch destinations with
  exact management, two-Lambda, and six-table data-event coverage;
- all metric filters, fourteen alarms, and the EventBridge security-change
  route passed; and
- the owner alert subscription is confirmed with one confirmed and zero
  pending subscriptions.

Three deployment-gate findings remain:

1. Stack termination protection is disabled.
2. Both published executor versions contain the same malformed JSON policy
   trust-store value.
3. The original deployment verifier used a nonexistent SDK operation for
   termination protection, and the audit verifier did not account for the
   empty `ExcludeManagementEventSources` member returned by CloudTrail.

The two verifier defects are corrected and covered by unit tests. The
CloudTrail correction is deliberately exact: an empty exclusion list passes,
while excluding KMS or another management-event source fails.

## Narrow repair

The CloudFormation template now accepts a non-secret
`PolicyTrustStoreSha256` parameter. The value is:

- constrained to one lowercase 64-character SHA-256 value;
- exposed as a non-secret stack output for deployed-state verification; and
- included in both `AWS::Lambda::Version` descriptions.

The description binding causes CloudFormation to publish replacement immutable
executor versions whenever the reviewed trust-store bytes change, while the
production aliases remain controlled pointers. Both version resources retain
their replaced and deleted versions, preserving the reviewed rollback evidence
until acceptance and explicit cleanup. The deployment verifier checks both the
valid trust-store contract and the exact raw-byte digest in each published
version.

The cloud repair therefore:

1. provide the valid canonical public verification-key inventory;
2. provide its exact SHA-256;
3. update the two unqualified functions;
4. publish two replacement immutable versions and move the two production
   aliases to them; and
5. enable stack termination protection.

It did not broaden IAM or KMS authority, modify archive data, change backup or
audit retention, expose a new endpoint, or enable transcript capture. The
change set was inspected before execution, and all three live verifiers passed
afterward.

## Local evidence

- 265 unit tests passed after the template and verifier changes.
- Ruff passed for every changed Python file.
- Strict MyPy passed for all 42 source modules.
- The earlier full isolated synthetic run passed 442 tests, including
  PostgreSQL v1.2 role boundaries, crash/retry, real synthetic backup/restore,
  and deletion recovery. Its two tmpfs containers and isolated network were
  identity-checked and removed afterward.

These results are implementation evidence only. They do not complete real-cloud
acceptance and do not authorize live capture.

## Executed cloud change set

The reviewed source is commit `e4d213a`. Its CloudFormation template SHA-256 is
`d8761baeb00bb0c091d99dac08f91cd47d8a740f41f4dfc70ef351a92e569294`.
The exact content-addressed template was uploaded, read back byte-for-byte, and
added to the artifact bucket's overwrite-deny policy. The protected object has
one recorded version identity in the controlled, git-ignored acceptance record.

Stack termination protection is enabled. The resulting UPDATE change set
contained no add or remove action and only eight reviewed modifications:

- environment updates for the retrieval and deletion functions;
- retained replacement versions for those two functions;
- production-alias moves to the two replacement versions;
- derived re-evaluation of the exact CloudTrail function selectors; and
- derived re-evaluation of the Lambda deployer's exact function/alias policy.

The two derived modifications were caused by references to the changed function
and alias resources. Their resolved Lambda function ARNs, qualified alias ARNs,
CloudTrail table/function inventory, allowed actions, and IAM resources remain
the same.

The owner approved execution on 2026-09-04. The helper revalidated the exact
target-account Identity Center administrator, change-set ARN, stack, and full
eight-change inventory before calling CloudFormation. The stack reached
`UPDATE_COMPLETE`, the change set reached `EXECUTE_COMPLETE`, and both
production aliases now target published version `2`.

The post-repair deployment, IAM/KMS, and audit verifiers all returned success.
This includes the corrected canonical public policy trust store and its exact
SHA-256, termination protection, nine IAM roles, three KMS policies, the full
allow/deny simulator matrix, protected DynamoDB tables, CloudTrail selectors,
fourteen alarms, EventBridge routing, and the confirmed owner email alert.
The controlled execution report and three verifier reports remain git-ignored;
their SHA-256 values are recorded there. No executor was invoked and capture
remained disabled.
