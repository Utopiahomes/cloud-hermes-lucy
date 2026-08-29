# Cloud Lucy Security Baseline v1.1

Date: 2026-08-29

Status: approved and implemented locally. Real AWS/Render provisioning and the
cloud acceptance report remain required. Live Telegram transcript capture is
disabled until the owner accepts that report.

## Security invariant

No normal Lucy process simultaneously possesses the transcript database,
historical decryption authority, backup-destruction authority, and
infrastructure administration. The four production processes are:

| Process | Authority | Explicitly absent |
| --- | --- | --- |
| Routine/archive | KMS `GenerateDataKey`; DynamoDB `PutItem`; normal memory and ciphertext ingestion | KMS `Decrypt`; wrapped-key reads/deletes; KMS/IAM/backup administration |
| Policy | Sign five-minute `SensitiveActionPermitV1` capabilities | Every AWS role and all evidence plaintext |
| Evidence | KMS `Decrypt`; DynamoDB exact `GetItem`; exact ciphertext reads | Archive writes; wrapped-key deletion; KMS administration; scans/exports |
| Deletion | DynamoDB exact `GetItem`/`DeleteItem`; governed database cascade | Every KMS action, including master-key disable/delete/policy changes |

The deletion service's "key deletion" means only removal of one evidence
record's KMS-wrapped data-encryption key from DynamoDB. It can never disable,
delete, rotate, re-policy, or otherwise administer the KMS customer-managed
master key.

## SensitiveActionPermitV1

Raw retrieval and governed deletion require an Ed25519-signed, database-backed,
single-use permit. A permit binds the action, stable owner subject, active owner
interaction, exact evidence UUID, reason, record and byte limits, five-minute
expiry, and random nonce. The policy service retains the private signing key and
has no AWS identity. Evidence and deletion services retain only the public key.

Hermes can request a permit only during an active allowlisted Telegram turn.
Background jobs, cron, and ownerless model activity have no active interaction
and therefore cannot retrieve raw evidence. Owner export is not implemented.
Future quorum authentication may issue the same versioned contract without
changing evidence/deletion services.

## Authoritative storage boundary

PostgreSQL is authoritative for ciphertext, non-plaintext evidence metadata,
provenance, memory, decisions, permits, and audit history. DynamoDB is
authoritative for whether a per-record wrapped DEK remains available. AWS KMS
is the wrapping authority. Restoring PostgreSQL cannot restore a deleted
DynamoDB record.

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
corrections, approvals, working contexts, and turn state. Missing-key startup
reconciliation finishes a database cascade after a crash between DynamoDB
deletion and PostgreSQL commit.

PostgreSQL backups are encrypted and retained for 30 days. Backup restoration
must be tested before activation and periodically thereafter. Restoring a
database backup alone cannot decrypt evidence whose DynamoDB key record was
destroyed. Runtime services receive no backup deletion or restoration authority.

## AWS controls

The evidence KMS key uses automatic rotation, a 30-day deletion waiting period,
and a retained CloudFormation lifecycle. CloudTrail records management and KMS
cryptographic calls. EventBridge alerts the owner through SNS for `DisableKey`,
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
