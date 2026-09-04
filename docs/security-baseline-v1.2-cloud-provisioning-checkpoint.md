# Cloud Lucy Security Baseline v1.2 — cloud provisioning checkpoint

Date: 2026-09-03

Status: **Render identity bootstrap and immutable AWS release inputs exist, but
the v1.2 AWS stack is not deployed. Live Telegram transcript capture remains
disabled and is not authorized.**

This checkpoint records infrastructure state without publishing account IDs,
service IDs, support-case identifiers, database credentials, signing material,
or other deployment secrets. Exact identifiers belong in the controlled final
acceptance record.

## Render state

- The protected `cloud-lucy` production environment contains one private
  PostgreSQL 18 database, four private services, and the non-continuous finality
  utility defined by the reviewed v1.2 Blueprint.
- The four services expose only the explicit provisioning-hold process and
  return HTTP 503. No production capability runtime is admitted.
- The database external IP allowlist is empty.
- `LUCY_TRANSCRIPT_CAPTURE_ENABLED` remains exactly `false`.
- The policy signing seed remains a Render-only policy-service secret. It has
  not been copied into AWS, PostgreSQL, repository files, or this checkpoint.

## AWS release inputs

- Region: `us-east-1`.
- Human administration was verified through the MFA-backed
  `LucySecurityAdministrator` IAM Identity Center permission set.
- The exact Render workspace OIDC provider remains present.
- The private versioned artifact bucket remains present with public access
  blocked, TLS-only access, server-side encryption, and explicit write denial
  on the reviewed artifact and template object versions.
- The deterministic executor artifact is the clean commit artifact already
  recorded in the implementation checkpoint: SHA-256
  `05236e5e19cb92ba57600c59ebb0b24d0df9b62d0730a0f7dcbe5d9b27183e8e`
  (`BSNuXhnLkrpXYAxZ67CyTQ35ti0HMKD33L5dmycYPo4=`), 23,567,559 bytes.

## Failed-stack disposition

The first stack creation reached `ROLLBACK_COMPLETE` because this new AWS
account has an effective regional Lambda concurrency limit of 10. The two
reviewed executor reservations require three units while Lambda preserves ten
unreserved units.

The failed stack record was deleted. Before cleanup, all six retained DynamoDB
tables were independently confirmed to contain zero items and the retained
versioned audit bucket was confirmed to contain zero versions and zero delete
markers. The six tables, two executor log groups, and empty audit bucket were
then deleted and verified absent.

The three retained, unused KMS keys were verified by description using
`LucySecurityAdministrator` and scheduled for deletion with AWS's minimum
seven-day waiting period. Their state is `PendingDeletion`, with deletion
scheduled for 2026-09-10 UTC. Root could neither describe nor administer these
keys because their resource policies correctly exclude root; their policies
were not weakened for cleanup.

## Lambda quota hold

AWS would not accept the desired effective value of 13 because Service Quotas
requires a request at least equal to the standard 1,000-unit account quota. A
request to restore the standard quota is open with AWS Support. This does not
allocate concurrency or incur usage; the stack continues to reserve only two
units for retrieval and one for deletion.

Do not recreate the stack until `aws lambda get-account-settings` reports at
least 13 `ConcurrentExecutions`. Do not remove the reviewed per-function
reservations to bypass the hold.

## Local correction found during the hold

The v1.2 Render Blueprint names the database migration owner
`lucy_migration`, while the production bootstrap previously granted
`lucy_security_function_owner` to `lucy_migrator`. The bootstrap is now aligned
with the Blueprint, and the unit test derives the expected login from the
Blueprint so the two contracts cannot silently drift. The corrected bootstrap
migrated a fresh disposable database through revision `0019`; the production-
shaped separate-login integration suite passed all 107 cases.

Additional hold-time hardening removed manual production SQL substitution,
binds generated AWS configuration to an explicit target account, and requires
all five service LOGINs to be `NOINHERIT` as well as membership-free. A separate
read-only AWS preflight prevents a stack retry unless the SSO identity, account,
OIDC provider, full versioned artifact digest, encryption, and Lambda
concurrency all match the reviewed deployment.

The hold-time executor and audit hardening produced a refreshed deterministic
Linux AMD64 release candidate from clean commit
`b8056897cec063d3ee593d10178b78956593a949`. It was rebuilt twice with identical
bytes: SHA-256
`235bd12254a61433e81e767b5a686561aff8ad48533cc52d7786a02d2b42b9ce`
(`I1vRIlSmFDPoHnZ7WmhlYa/4rUhTPMUtd4agLStCuc4=`), 23,568,213 bytes and
2,506 files. Its manifest SHA-256 is
`bdfbf88350d21a6d44f90631c03ed0778f86e216fec5f991aa995feebfe3d8a4`.
The reviewed CloudFormation template SHA-256 is
`99922ee906da2de847a24bcf0c914eeb24f85c825fc23ec63f4131a23abdd8be`.
These are local release-candidate facts only until all three objects are
uploaded under new non-overwriting keys and their S3 version identities are
recorded. The earlier artifact remains preserved as the rollback candidate.

Deployed-state verification is now also prepared before the retry. The first
read-only verifier checks stack completion and termination protection, exact
published Lambda versions and environments, public-only policy trust stores,
KMS key purpose separation, and DynamoDB schemas/protection. The second checks
all nine live IAM roles and three KMS resource policies against the approved
contract and runs the critical IAM allow/deny simulation matrix. Both emit
content-free, non-overwriting acceptance artifacts.

The audit plane is now similarly testable before activation: CloudTrail retains
validated logs in the versioned TLS-only S3 bucket and also delivers to a
dedicated 90-day CloudWatch log group. Content-free filters and alarms cover
direct evidence-key decrypt volume, denied AWS calls by either executor,
quarantined recovery use, and finality-verifier use. Executor-emitted metrics
separately cover internal failure, binding/integrity denial, receipt failure,
and durable quota exhaustion. A third read-only verifier checks those routes,
all fourteen alarms, and the confirmed owner email subscription without
reading any audit event or publishing a notification.

That review exposed and fixed a pre-deployment Lambda logging defect: the
CloudWatch Logs `Arn` returned by CloudFormation already ends in `:*`, so the
runtime policies must use it directly. The earlier template appended another
`:*`, which would have produced an unusable `:*:*` resource. No AWS workload
resources were deployed with the faulty policy.

## Next gated sequence

1. Wait for the effective Lambda concurrency limit to reach at least 13.
   Before retrying the stack, run the read-only
   `deploy/aws/preflight_security_v1_2.py`; it also re-verifies the exact SSO
   administrator, target account, Render OIDC provider, and full versioned S3
   artifact bytes against the clean release manifest.
2. Reconstruct and review the non-secret policy verification-key inventory and
   immutable registry/journal identifiers without exporting the policy private
   seed.
3. Recreate and inspect the v1.2 CloudFormation change set, then deploy it.
4. Run all three read-only deployed-state verifiers and preserve their
   acceptance reports. Any failed core, IAM, KMS-policy, audit, or alert-route
   check keeps the rollout on hold.
5. Record stack outputs and receipt public keys; populate only the matching
   Render service variables.
6. Generate the exact PostgreSQL LOGIN grants and immutable AWS bindings with
   `deploy/postgres/render_security_v1_2_sql.py`, review their reported hashes,
   then apply them after migrations while keeping admission quarantined.
7. Run the synthetic positive, negative, crash/retry, recovery, and finality
   acceptance suite.
8. Produce the final deployed acceptance report. Live capture still requires a
   separate owner approval after that review.
