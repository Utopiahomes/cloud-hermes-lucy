# Tiamat DynamoDB recovery anchor — deployment review v1

Status: local implementation complete; no AWS resource has been provisioned.

## Boundary and supported topology

- PostgreSQL remains the execution and accounting system of record.
- One single-Region DynamoDB Standard table is the external recovery authority for one Tiamat
  environment. It is outside PostgreSQL and its host/VM backup boundary.
- The table stores the exact root-signed anchor-transition JWS and exact witness JWS. Unsigned
  index attributes are checked for corruption but never grant authority.
- `GetItem` always uses `ConsistentRead=true`. A transition uses `PutItem` with an exact signed
  predecessor digest and transition-version condition. A lost compare-and-swap fails closed.
- Every stored record is signature-verified on read and again before acceptance on write.
- This adapter implements the portable `ExternalRecoveryAnchor` interface. Global tables,
  multi-provider quorum, replicas, and additional recovery sites are explicitly out of v1 scope.

AWS documents that a successful DynamoDB write is durably persisted and that a strongly
consistent read reflects all previously successful updates. It also documents conditional
expressions as the atomic guard on `PutItem` operations:

- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html
- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html

## AWS resources and permissions

`deploy/aws/tiamat-recovery-anchor-v1.yaml` creates:

- one PAY_PER_REQUEST DynamoDB table;
- deletion protection, 35-day point-in-time recovery, retention on stack replacement/deletion,
  and AWS-owned DynamoDB encryption at rest;
- a read policy for the ordinary Tiamat runtime role: `GetItem` and `DescribeTable` only;
- a separate update policy for the recovery coordinator role: `GetItem`, `PutItem`, and
  `DescribeTable` only.

Both policies restrict item operations to the environment's `ENV#...#LEDGER#...` leading key.
Neither role can scan, query, delete, restore, alter, or enumerate tables. The SDK credential
chain supplies short-lived machine credentials; no AWS key is placed in source or environment
configuration.

## AWS-unavailable behavior

| Phase | Required behavior |
| --- | --- |
| Startup or ordinary restart | A strongly consistent anchor read is mandatory. If AWS or the table is unavailable, Tiamat starts without dispatch authority and sends no provider request. |
| Running operation | The process may use its last locally verified signed authority only until the earliest signed expiry. Refresh failure is recorded but does not manufacture revocation. At expiry, new admission and dispatch stop. A known quarantine latches immediately. |
| Recovery, restore, rollback, clone, or failover | DynamoDB must accept the signed conditional transition and a subsequent strong read must verify it. If unavailable or ambiguous, recovery remains pending, old-worker isolation remains in force, and no restored executor dispatches. |

An ordinary running process can therefore tolerate a bounded AWS outage; a restart cannot. This
is the approved availability tradeoff and must be described that way operationally.

## Expected cost

Pricing basis (US East (N. Virginia), DynamoDB Standard, on-demand): AWS's current example rates
are $0.125 per million read request units and $0.625 per million write request units. Strong reads
consume one RRU per 4 KB or part; writes consume one WRU per 1 KB or part. See
https://aws.amazon.com/dynamodb/pricing/.

Conservative planning assumptions:

- one anchor item at or below 16 KB;
- one strong refresh every 30 seconds: 86,400 reads/month × 4 RRU = 345,600 RRU;
- four signed transitions/day at 16 KB: 120 writes/month × 16 WRU = 1,920 WRU.

Estimated request cost is about **$0.045/month** before any applicable free tier. The single item,
PITR data, and backup storage are far below 1 GB, so practical table-related cost should remain
well below **$1/month**. This is an estimate, not a spending guarantee. Cross-region traffic,
customer-managed KMS keys, CloudTrail data events, AWS Backup, global tables, or unexpectedly
large signed records are excluded and must be costed separately if added.

## Activation procedure (requires a later provisioning approval)

1. Validate the template and inspect the CloudFormation change set; do not execute it yet.
2. Select the AWS account/region and existing reader/updater machine roles. Confirm they are not
   PostgreSQL-host backup identities and cannot assume one another.
3. Provision the retained table with dispatch disabled.
4. Verify table deletion protection, PITR, encryption, tags, and absence of replicas/streams.
5. Run IAM negatives: the reader cannot write; neither identity can delete, scan, query, change
   the table, or access another environment's key. Verify the updater can only perform a valid CAS.
6. Configure `TIAMAT_RECOVERY_ANCHOR_TABLE` and `AWS_REGION` for the appropriate machine roles.
7. Bootstrap a root-signed quarantined transition, strong-read it, and independently verify its
   exact bytes and predecessor state.
8. With old-worker provider credentials disabled, execute the approved reconciliation and install
   the signed continuity-established transition.
9. Exercise startup success, AWS-unavailable startup, bounded running outage, CAS collision,
   expired authority, stale restore, quarantine race, and recovery-crash cases in staging.
10. Review evidence and rollback steps. Enabling model dispatch is a separate activation action.

Rollback before dispatch activation is to remove the Tiamat configuration and roles while
retaining the table and signed history. After activation, never delete or replace the authoritative
history as rollback; quarantine, isolate workers, and follow the signed recovery procedure.
