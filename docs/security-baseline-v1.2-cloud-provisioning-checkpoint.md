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
4. Record stack outputs and receipt public keys; populate only the matching
   Render service variables.
5. Generate the exact PostgreSQL LOGIN grants and immutable AWS bindings with
   `deploy/postgres/render_security_v1_2_sql.py`, review their reported hashes,
   then apply them after migrations while keeping admission quarantined.
6. Run the synthetic positive, negative, crash/retry, recovery, and finality
   acceptance suite.
7. Produce the final deployed acceptance report. Live capture still requires a
   separate owner approval after that review.
