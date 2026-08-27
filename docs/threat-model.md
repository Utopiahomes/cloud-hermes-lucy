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
- Production never follows a moving upstream reference.

This is the bootstrap threat model. Each implemented service must add data-flow,
abuse-case, retention, and recovery tests before deployment.

