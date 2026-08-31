# Cloud Lucy Security Baseline v1.1

Date: 2026-08-29

Status: approved design; local implementation is undergoing gap remediation.
The [latest deletion-recovery checkpoint](deletion-recovery-2026-08-31.md)
records local proof and remaining blockers. Real AWS/Render provisioning and
cloud acceptance remain required. Live Telegram transcript capture must not be
activated until the owner accepts the final report. Infrastructure statements
below describe requirements/templates, not verified deployed configuration.

## Security invariant

No normal Lucy process simultaneously possesses the transcript database,
historical decryption authority, backup-destruction authority, and
infrastructure administration. The four production processes are:

| Process | Authority | Explicitly absent |
| --- | --- | --- |
| Routine/archive | KMS `GenerateDataKey`; wrapped-key `PutItem`; deletion-head metadata `GetItem`; normal memory and ciphertext ingestion | KMS `Decrypt`; wrapped-key reads/deletes; deletion-intent reads/writes; KMS/IAM/backup administration |
| Policy | Sign five-minute `SensitiveActionPermitV1` capabilities | Every AWS role and all evidence plaintext |
| Evidence | KMS `Decrypt`; exact wrapped-key and deletion-head `GetItem`; exact ciphertext reads | Archive writes; wrapped-key deletion; deletion-intent reads/writes; KMS administration; scans/exports |
| Deletion | Exact wrapped-key `GetItem`/`DeleteItem`; journal `GetItem`; transaction-only intent `PutItem`/head `UpdateItem`; governed database cascade | Every KMS action, table administration, scans/queries, and non-transactional journal writes |

The deletion service's "key deletion" means only removal of one evidence
record's KMS-wrapped data-encryption key from DynamoDB. It can never disable,
delete, rotate, re-policy, or otherwise administer the KMS customer-managed
master key.

The human administrator signs in through a permanently assigned IAM Identity
Center permission set. The KMS policy matches its generated role by a bounded
ARN pattern and also names a stable IAM recovery role that only that permission
set may assume. This prevents an Identity Center role-suffix rotation from
orphaning the key. Human key administrators can administer the key but are not
granted transcript `Decrypt` or `GenerateDataKey` through the key policy.

## SensitiveActionPermitV1

Raw retrieval and governed deletion require an Ed25519-signed, database-backed,
single-use permit. A permit binds the action, stable owner subject, active owner
interaction, exact evidence UUID, reason, record and byte limits, five-minute
expiry, and random nonce. The policy service retains the private signing key and
has no AWS identity. Evidence and deletion services retain only the public key.

The intended Hermes permit path requires an independently verified active owner
interaction. Gateway permit minting is currently disabled until that broker is
implemented and accepted; a bearer plus supplied Telegram identifiers is not
sufficient authority. Background jobs, cron, and ownerless model activity must
not retrieve raw evidence. Owner export is not implemented.
Future quorum authentication may issue the same versioned contract without
changing evidence/deletion services.

## Authoritative storage boundary

PostgreSQL is authoritative for ciphertext, non-plaintext evidence metadata,
provenance, memory, decisions, permits, and audit history. DynamoDB is
authoritative for whether a per-record wrapped DEK remains available. AWS KMS
is the wrapping authority. A separate DynamoDB head plus append-only intent table
is authoritative for accepted deletion ordering. Restoring PostgreSQL cannot
restore a deleted wrapped-key record or erase an accepted external deletion.

The wrapped-key table has deletion protection and no point-in-time recovery.
This is deliberate: restoring an older copy of that table could resurrect a
crypto-shredded DEK. AWS's multi-AZ DynamoDB durability and `DeletionPolicy:
Retain` protect availability; runtime identities cannot delete the table.

Hermes `/opt/data` is a retry cache and runtime history only. After a turn is
committed to PostgreSQL, clearing `/opt/data` cannot cause autobiographical
loss.

## Residual structured-memory boundary

Normal Lucy reads the plaintext `subject`, `predicate`, `object`, confidence,
status, claim/evidence identifiers, and relationship version required for
semantic recall. It does not receive transcript ciphertext, raw source text,
wrapped keys, keyed commitments, permit signatures, or internal audit payloads.

Phase 1 intentionally does not encrypt semantic memory. High-confidence API
keys, access tokens, passwords, recovery codes, seed phrases, private keys, and
similar credentials are rejected before proposal/correction persistence. The
rejection audit contains only detector categories and never the candidate
secret.

## Owner sovereignty and recovery

Deletion removes the individual wrapped DEK before deleting ciphertext and
invalidating or redacting derived claims, relationships, entities, proposals,
corrections, approvals, working contexts, and turn state. Multi-source closure
for the current artifact types is implemented locally; full runtime-history,
future artifact writers and cross-store recovery remain unaccepted. The previous
automatic missing-key cascade has been
removed: a missing key is not owner deletion authority. Controlled maintenance
closes admission before reconciliation and leaves it closed on missing keys.
A local independent deletion-intent journal now fences service transactions and
supports explicit interrupted-deletion/restore recovery; see the current recovery
checkpoint. A strongly consistent, conditional DynamoDB provider and scoped IAM
templates are implemented and mocked locally; identity/permissions and cloud
restore still require real-cloud acceptance before capture. Normal service startup
does not perform recovery or key-registry scans. A compromised direct SQL
credential is outside the application hook; the structured-memory plaintext
residual boundary remains explicit.

PostgreSQL backups must be encrypted and retained for 30 days; provisioning and
verification remain required. Backup restoration must be tested before
activation and periodically thereafter. Restoring a
database backup alone cannot decrypt evidence whose DynamoDB key record was
destroyed. Runtime services receive no backup deletion or restoration authority.

## AWS controls

The evidence KMS key uses automatic rotation, a 30-day deletion waiting period,
and a retained CloudFormation lifecycle. CloudTrail records management, KMS
cryptographic calls, and data events for the wrapped-key and deletion-journal
tables. EventBridge alerts the owner through SNS for `DisableKey`,
`ScheduleKeyDeletion`, `PutKeyPolicy`, and alias deletion. Only a separately
authenticated human administrative identity may administer the key.

Permanent AWS access keys are forbidden. Each Render private service assumes
one exact IAM role through Render OIDC, bound to workspace, environment, and
service subject. The policy service has no `AWS_ROLE_ARN`.

## Fail-closed rules

- Missing, invalid, expired, mismatched, or replayed permits deny sensitive actions.
- Missing service configuration denies that operation.
- Archive failure withholds an on-record response rather than claiming retention.
- Evidence retrieval never falls back to broad archive search.
- Provider or storage failure never falls back to plaintext or a less-private route.
- Live capture remains disabled until the cloud acceptance report is approved.

## Deployment sources

- `deploy/aws/security-baseline-v1.1.yaml`: KMS, DynamoDB, three Render OIDC
  roles, CloudTrail, and owner alerting.
- `deploy/render/security-baseline-v1.1.yaml.example`: four isolated private services.
- `deploy/postgres/production_roles.sql.example`: four non-DDL database roles.
- `docs/render-aws-kms-acceptance.md`: provisioning order and acceptance gate.
