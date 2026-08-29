# Architecture

## Principle

Hermes is the replaceable execution shell. Lucy owns durable identity-adjacent
state and policy. Integration occurs through documented Hermes configuration,
profiles, skills, plugins, MCP tools, and service APIs—not edits to Hermes core.

## Responsibility boundary

| Capability | Owner | Notes |
| --- | --- | --- |
| Agent loop and model calls | Hermes | OpenRouter configured in the Lucy profile |
| Persistent profile and SOUL | Hermes | Versioned profile skeleton; secrets remain local |
| Telegram gateway and user allowlist | Hermes | Deny by default; explicit user/chat identifiers |
| Gateway supervision and restart | Hermes | Use supported service/container supervision |
| Cron dispatch | Hermes | Jobs call narrow Lucy operations |
| Tool restrictions and command approvals | Hermes | Minimum toolset and explicit command patterns |
| Three-layer memory graph | Lucy memory service | Working, relational, and durable knowledge layers |
| Encrypted source archive | Lucy memory service | Append-only envelopes; owner-governed crypto-shredding |
| Master wrapping key | AWS KMS | Render OIDC role; KMS key material never enters Lucy |
| Wrapped DEK registry | AWS DynamoDB | Exact-item operations only; isolated from PostgreSQL restore |
| Rejoining lifecycle | Lucy control service | Explicit transitions with durable checkpoints |
| High-impact approval workflow | Lucy control service | Separate policy decision from model intent |
| Audit ledger | Lucy control service | Tamper-evident, append-only event chain |
| Token/cost/action budgets | Lucy control service | Reserve before execution, settle afterward |

## Runtime flow

1. An allowlisted Telegram user sends a message to the Hermes gateway.
2. Hermes authenticates the channel and runs Lucy's restricted profile.
3. Lucy tools query memory through a narrow read API; raw archives are not
   exposed to the model by default.
4. A proposed side effect is classified by the control service.
5. Allowed low-risk actions consume a budget reservation and execute. Gated
   actions create an approval request and stop before the effect.
6. Every decision, approval, execution result, and memory mutation is appended
   to the audit ledger with correlation and causation identifiers.
7. A response is delivered through Hermes. Durable workflow state permits safe
   recovery after a restart without silently repeating an effect.

## Three-layer memory

The initial contract deliberately separates evidence from interpretation:

1. **Archive:** append-only encrypted source envelopes and keyed commitments. It
   is the provenance root; owner deletion destroys the external wrapped DEK,
   tombstones the envelope, and invalidates derived state.
2. **Graph:** versioned entities, relationships, claims, confidence, temporal
   bounds, and links back to archive records.
3. **Working context:** small, task-scoped projections assembled from graph
   queries. It is disposable and may be regenerated.

Memory writes are proposals. Deterministic validation records provenance,
deduplicates idempotency keys, and applies retention/redaction policy before a
proposal can update the graph.

## Rejoining state machine

`Rejoining` is a recovery protocol, not a prompt:

```text
OFFLINE -> REJOINING -> RECONCILING -> READY
              |             |
              +----------> DEGRADED
```

- `OFFLINE`: no work accepted.
- `REJOINING`: verify configuration, upstream pin, stores, clock, and identity.
- `RECONCILING`: recover incomplete operations and compare delivery/audit state.
- `READY`: normal message and scheduled work may execute.
- `DEGRADED`: read-only/status behavior; no external side effects.

Transitions are persisted and audited. Recovery defaults to `DEGRADED` on
ambiguity. Side effects require idempotency keys and an execution record so a
restart cannot turn an uncertain outcome into an automatic retry.

## Deployment boundary

Hermes and Lucy services should run as separate processes with separate storage
and credentials. The Hermes process receives only the credentials it directly
needs. Lucy data services bind to a private interface and authenticate every
request. Render supplies separate short-lived AWS web identities to archive,
evidence, and deletion services. Archive can generate/store new wrapped keys;
evidence can decrypt/read one permitted key; deletion can remove one wrapped
key and has no KMS action. The permit-policy service has no AWS identity. No
runtime has static AWS credentials or administrative permission. Backups
preserve encrypted archive/audit data and are tested by restore.
