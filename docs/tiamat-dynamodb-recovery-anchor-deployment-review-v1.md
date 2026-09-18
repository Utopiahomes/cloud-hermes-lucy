# Tiamat DynamoDB recovery anchor — deployment review v1

Status: isolated dispatch-disabled staging infrastructure commissioned; signed authority is not yet bootstrapped.

AWS commissioning checkpoint (2026-09-18): AWS accepted and executed reviewed change set
`review-20260918-01` in account `429870640638`, region `us-east-1`. Stack
`tiamat-staging-recovery-anchor-v1` is `CREATE_COMPLETE`. The retained table is active with
PAY_PER_REQUEST billing, deletion protection, encryption and point-in-time recovery enabled.
Evidence is in `docs/evidence/tiamat-recovery-anchor-staging-commissioning-2026-09-18.json`; the
earlier review-only state remains recorded separately.

Dedicated roles `tiamat-staging-executor` and `tiamat-staging-recovery-coordinator` now trust only
their exact suspended Render staging service subjects. Existing Lucy/Utopia roles were not reused
or changed. Both services have auto-deploy disabled, use the inert identity-only process, and remain
manually suspended with provider dispatch disabled. Their configuration names the exact role,
region and table; no static AWS credential is configured.

## Boundary and supported topology

- PostgreSQL remains the execution and accounting system of record.
- One single-Region DynamoDB Standard table is the external recovery authority for one Tiamat
  environment. It is outside PostgreSQL and its host/VM backup boundary.
- The table stores the exact root-signed anchor-transition JWS and exact witness JWS. Unsigned
  index attributes are checked for corruption but never grant authority.
- `GetItem` always uses `ConsistentRead=true`. A transition uses `PutItem` with an exact signed
  predecessor digest and transition-version condition. A lost compare-and-swap fails closed.
- Every stored record is signature-verified on read and again before acceptance on write.
- The concrete decoder verifies the witness against the accepted recovery-witness inventory
  key/scope before verifying the root-signed transition and its exact witness binding.
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

## Remaining activation procedure

1. Reconfirm both services remain suspended and provider dispatch is disabled.
2. Resume only for the bounded staging proof and verify each live Render OIDC identity assumes its
   exact role; suspend again after evidence capture.
3. With reviewed ledger/storage identities and a complete day-zero checkpoint object, generate the purpose-distinct
   root/witness identities offline under ignored local storage. Retain the root private seed only in
   the offline recovery boundary. The builder independently computes every checkpoint digest and
   accepts no caller-supplied digest strings. Build and independently review the public signed package.
4. Run `install_tiamat_recovery_bootstrap_v1.py` without `--execute`; its verified preview must show
   version-one quarantine and the reviewed transition digest. Then run it once through the exact
   recovery-coordinator OIDC identity with `--execute` and the ledger-bound empty-bootstrap
   confirmation. Strong-read and independently verify its exact bytes and predecessor-null state.
5. With old-worker provider credentials disabled, execute the approved reconciliation and install
   the signed continuity-established transition.
6. Exercise startup success, AWS-unavailable startup, bounded running outage, CAS collision,
   expired authority, stale restore, quarantine race, and recovery-crash cases in staging.
7. Review evidence and rollback steps. Enabling model dispatch is a separate activation action.

Rollback before dispatch activation is to remove the Tiamat configuration and roles while
retaining the table and signed history. After activation, never delete or replace the authoritative
history as rollback; quarantine, isolate workers, and follow the signed recovery procedure.
