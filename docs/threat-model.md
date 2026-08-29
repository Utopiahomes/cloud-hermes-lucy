# Initial threat model

## Protected assets

- Telegram bot token and allowlisted identities
- OpenRouter and infrastructure credentials
- private conversations, memory graph, and source archive
- approval decisions and audit history
- action and spending budgets

## Primary threats and controls

| Threat | Initial controls |
| --- | --- |
| Unauthorized messaging user | Hermes allowlist, deny-by-default DMs/groups, stable numeric IDs |
| Prompt injection from messages or retrieved content | Treat content as data, provenance labels, least-privilege tools, external effects behind policy |
| Secret disclosure | Secrets outside Git, per-service credentials, output redaction, no archive access by default |
| PostgreSQL backup disclosure | Per-message AES-GCM, AWS KMS-wrapped DEKs outside PostgreSQL, keyed commitments |
| Deleted plaintext resurrected by DB restore | Destroy wrapped DEK in the live DynamoDB registry before tombstoning and derived-data invalidation |
| Long-lived cloud credential theft | Render OIDC, rotated web identity, service-bound trust policy, no AWS access keys |
| AWS role abuse from compromised runtime | Exact KMS key/table resources, two KMS operations, three item operations, encryption-context constraints, CloudTrail |
| Arbitrary shell execution | Minimal toolsets, sandbox/container boundary, explicit approvals, constrained working directory |
| Duplicate effects after crash | Idempotency keys, durable execution journal, Rejoining reconciliation |
| Memory poisoning | Immutable evidence, proposal validation, provenance, confidence and correction history |
| Audit tampering | Append-only hash chain, restricted writer, external checkpoint/backup |
| Runaway cost or automation | Per-turn/day/month budgets, reservations, hard ceilings, cron concurrency limits |
| Supply-chain compromise | Immutable Hermes commit pin, reviewed upgrades, dependency locks, artifact verification |

## Non-negotiable invariants

- The model cannot grant itself permissions, approve its own gated action, or
  raise its own budgets.
- No untrusted text can directly become a command, memory fact, or authorization.
- An unknown recovery state cannot execute an external side effect.
- Archive evidence is append-only; deletion/redaction uses an explicit governed
  process and leaves a verifiable administrative record.
- Restoring PostgreSQL cannot restore a destroyed wrapped DEK.
- The Render runtime has no long-lived AWS credential and no KMS, DynamoDB, or
  IAM administration permission.
- Production never follows a moving upstream reference.

This is the bootstrap threat model. Each implemented service must add data-flow,
abuse-case, retention, and recovery tests before deployment.
