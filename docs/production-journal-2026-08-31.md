# Production deletion journal: local implementation checkpoint

Date: 2026-08-31

Status: implementation, policy templates, and synthetic acceptance complete;
**not real-cloud acceptance and not permission to enable transcript capture**.
No AWS or Render resource, live image, live database, credential, profile, or
capture setting was changed.

## Implemented production contract

`AwsDynamoDeletionJournal` uses two separately permissioned DynamoDB tables:

- a one-item head table containing only the durable journal/registry identities,
  sequence and chain digest;
- an append-only intent table containing the signed, content-free deletion
  manifest in bounded immutable chunks.

Every read uses `ConsistentRead=true`. Append is one `TransactWriteItems` call:
it conditionally advances the expected identity/sequence/digest and creates the
metadata/chunks only if they do not exist. A competing writer therefore cannot
silently overwrite history. An SDK/network failure triggers an exact strong read
of the proposed immutable entry; only an identical committed intent is returned
as success. Every other ambiguous outcome remains fenced for operator recovery.

The provider never calls `Scan` or `Query`. Intent records are limited to twelve
200,000-byte chunks, keeping every item below DynamoDB's item limit and the whole
transaction below its request limit. The UUID request token helps short retries,
but permanent correctness does not depend on its limited idempotency window: it
comes from the conditional head and immutable exact-entry checks.

## Identity and permission boundary

The archive registry and journal each have an independently generated UUID. The
same registry UUID is bound in the key-store configuration, journal head and
PostgreSQL operator binding. A replacement empty table cannot impersonate the
reviewed registry merely by sharing a table name.

The CloudFormation and Render examples preserve these capabilities:

| Identity | DynamoDB journal access |
| --- | --- |
| Routine/archive | Strong read of four projected head attributes only |
| Policy | No AWS role, AWS variables, or journal check |
| Evidence | Strong read of four projected head attributes only |
| Deletion | Exact head/intent reads; transaction-only head update and intent puts |

Deletion retains exact wrapped-key `GetItem`/`DeleteItem` authority and zero KMS
authority. None of the service roles can scan/query a journal, administer a
table, restore a backup, change IAM, or alter the KMS master key.

Policy intentionally remains outside AWS. It cannot read evidence, memory,
ciphertext, wrapped keys or journal intents. It may sign a narrowly scoped permit
while a deletion is pending, but evidence/deletion/routine operations remain
fenced by the unmatched journal head, so that permit cannot disclose or destroy
data until controlled reconciliation completes.

## Provisioning and audit templates

The production template now creates retained, deletion-protected, on-demand head
and intent tables with point-in-time recovery. The wrapped-key table deliberately
keeps point-in-time recovery disabled because restoration could resurrect a
crypto-shredded data key.

`deploy/aws/initialize-deletion-journal.ps1` creates the sequence-zero head only
when it is absent. It has no update, delete or rewind path. The human security
administrator must run it exactly once after stack creation and before services
are configured.

CloudTrail data selectors include the wrapped-key, head and intent tables in
addition to management/KMS events. These data events can incur separate charges;
their appearance and retention must be verified in the real account.

Render configuration supplies one exact `AWS_ROLE_ARN` to routine, evidence and
deletion, and none to policy. Static access keys and a manually configured
`AWS_WEB_IDENTITY_TOKEN_FILE` are prohibited; Render's managed OIDC path supplies
the short-lived token file.

## Synthetic verification

- **314 tests passed**, zero skips: 144 unit and 170 PostgreSQL integration tests.
- The run included process-kill recovery, real `pg_dump`/`pg_restore`, journal
  rollback, append-response ambiguity, bounded chunking, wrong identity,
  malformed/missing entry, role separation and read-only startup cases.
- Ruff passed; strict MyPy passed for all 32 source files; Python compilation,
  Git whitespace validation and the single Alembic head check passed.
- CloudFormation YAML, dependency ordering, retained/protected table settings,
  CloudTrail selectors, IAM action/resource/attribute limits, Render environment
  separation and create-only initialization are regression-tested. `cfn-lint`
  was not installed, so AWS validation remains part of real-cloud acceptance.
- Two dependency warnings remain: Starlette's HTTPX test-client deprecation and
  Alembic's legacy path-separator warning.
- The disposable `cloud-lucy-retention-tests` containers and network were removed
  after their exact Compose labels were verified. The live API/PostgreSQL remained
  healthy and the gateway remained running; none was rebuilt or restarted.

## Remaining acceptance blockers

1. Deploy the reviewed stack and exact Render service identities, initialize the
   head once, and prove positive/negative authorization with short-lived OIDC
   credentials. No permanent AWS credentials may be introduced.
2. Confirm CloudTrail KMS and all three DynamoDB data-event streams, the owner SNS
   alert, table deletion protection, KMS rotation, and backup retention.
3. Exercise real DynamoDB outage, stale-writer, lost-response and restored-table
   scenarios. A DynamoDB point-in-time restore creates a separate table and must
   never be adopted automatically; identity rebinding needs explicit review.
4. Decide and test the ephemeral human-operator recovery workflow. Do not create
   a persistent fifth service with database-owner plus deletion authority merely
   for convenience.
5. Complete the clean Hermes history/reset/resumption and independently verified
   owner-event broker work described in the retention specification.
6. Record the real-cloud acceptance report and obtain explicit owner approval
   before setting `LUCY_TRANSCRIPT_CAPTURE_ENABLED=true`.

An AWS account administrator can still replace tables, roles or application
configuration. This Phase 1 design removes those powers from runtime services;
it does not claim cryptographic protection against the trusted cloud account
administrator or a coordinated rollback of every authority boundary.

## Primary implementation references

- [Render managed AWS OIDC](https://render.com/docs/oidc)
- [DynamoDB transactional writes](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html)
- [DynamoDB strongly consistent `GetItem`](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_GetItem.html)
- [DynamoDB point-in-time recovery](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Point-in-time-recovery.html)
- [CloudTrail DynamoDB data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
