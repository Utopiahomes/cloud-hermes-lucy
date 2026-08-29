# Cloud Hermes Lucy

Lucy is a security-conscious personal agent built around a pinned upstream
[Hermes Agent](https://github.com/NousResearch/hermes-agent) runtime. Hermes
provides the agent loop, profile/SOUL, Telegram gateway, scheduling, process
supervision, approvals, tool controls, and OpenRouter integration. Lucy-specific
memory, archive, lifecycle, audit, approval, and budget policy live outside the
Hermes source tree as companion services and narrowly scoped plugins.

This repository intentionally does not fork or vendor Hermes.

## Status

The first PostgreSQL-backed vertical slice is implemented and tested. It imports
one synthetic conversation, verifies and preserves immutable evidence, creates a
provenance-linked provisional memory, advances the first Rejoining transition,
reserves and settles a model budget, records a tamper-evident audit chain, and
replays the durable result exactly once after a simulated process restart.

The guarded pinned-Hermes Telegram gateway is also live: an allowlisted message
completed through Lucy's automatic OpenRouter budget bridge, the supervised
gateway restarted, and a post-restart message completed exactly once with no
stranded reservation or duplicate charge.

Telegram has first-class Lucy memory lookup and pending-only proposal tools. An
encrypted, owner-sovereign, default-on conversation archive is implemented and
under acceptance review, but it is not enabled in the live gateway. The model
has no archive search or deletion authority; its exceptional raw-evidence tool
is single-record, provenance-bound, reason-limited, and audited. Direct memory
writes, approvals, database access, files, terminal, and code execution remain
outside the model-visible tool surface.

No credentials, real conversations, or private memory belong in Git.

## Upstream pin

The reviewed baseline is recorded in [`hermes.lock`](hermes.lock):

- release: `v2026.8.19` / Hermes Agent `v0.20.5`
- source commit: `fcbd1076a93841fa88855acce810e342a5b78101`
- annotated tag object: `b05e680e63d39d5a8e3ec0f5842a41d1c4209c03`

Deployment must check out the recorded commit and verify it before use. Never
deploy `latest`, `main`, or an unverified installer result.

## Design

See:

- [`docs/architecture.md`](docs/architecture.md) for component and trust boundaries
- [`docs/threat-model.md`](docs/threat-model.md) for initial security controls
- [`docs/decisions/0001-hermes-boundary.md`](docs/decisions/0001-hermes-boundary.md) for the upstream integration decision
- [`docs/upstream-review.md`](docs/upstream-review.md) for pin provenance and the upgrade gate
- [`docs/hermes-compatibility-spike.md`](docs/hermes-compatibility-spike.md) for the passing pinned-image integration evidence
- [`docs/control-layer-acceptance.md`](docs/control-layer-acceptance.md) for the strict tool and durable approval/recovery invariants
- [`docs/memory-layer-acceptance.md`](docs/memory-layer-acceptance.md) for archive, graph, and working-context acceptance
- [`docs/rejoining-acceptance.md`](docs/rejoining-acceptance.md) for deterministic startup and degraded-mode acceptance
- [`docs/memory-correction-acceptance.md`](docs/memory-correction-acceptance.md) for governed supersession and provenance history
- [`docs/hermes-read-adapter-acceptance.md`](docs/hermes-read-adapter-acceptance.md) for the authenticated pinned-Hermes lookup boundary
- [`docs/container-startup-acceptance.md`](docs/container-startup-acceptance.md) for migration ordering and fail-closed Rejoining startup
- [`docs/memory-proposal-acceptance.md`](docs/memory-proposal-acceptance.md) for gated Hermes-originated memory candidates
- [`docs/action-policy.md`](docs/action-policy.md) for deterministic fail-closed action classification
- [`docs/action-budget-acceptance.md`](docs/action-budget-acceptance.md) for durable reserve, execute, settle, and crash recovery
- [`docs/openrouter-evaluation.md`](docs/openrouter-evaluation.md) for the capped synthetic model-policy evaluation
- [`docs/hermes-openrouter-acceptance.md`](docs/hermes-openrouter-acceptance.md) for the pinned-Hermes controlled-route evidence
- [`docs/model-budget-bridge-acceptance.md`](docs/model-budget-bridge-acceptance.md) for automatic per-provider-call reservation and settlement
- [`docs/telegram-gateway-readiness.md`](docs/telegram-gateway-readiness.md) for the deny-by-default pinned-Hermes gateway scaffold
- [`docs/hermes-memory-tools-acceptance.md`](docs/hermes-memory-tools-acceptance.md) for provenance-aware lookup and pending-only proposal tools
- [`docs/telegram-transcript-retention.md`](docs/telegram-transcript-retention.md) for encrypted default capture, owner deletion, and its deployment gate
- [`docs/render-aws-kms-acceptance.md`](docs/render-aws-kms-acceptance.md) for the Render OIDC, AWS KMS, and deletion-aware wrapped-key boundary
- [`docs/security-baseline-v1.1.md`](docs/security-baseline-v1.1.md) for the approved execution-identity, permit, memory-confidentiality, and recovery baseline

## Local verification

The development database is PostgreSQL 16 with pgvector, pinned by manifest
digest in `compose.yaml` and `deploy/images.lock`. Copy `.env.example` to `.env`,
start `postgres`, apply the Alembic migration, and run the tests with both the
restricted application URL and owner-only test-reset URL set. The integration
database contains synthetic data only.

## Planned layout

```text
profiles/lucy/         versioned, secret-free Hermes profile distribution
services/memory/       three-layer memory graph and immutable archive
services/control/      Rejoining state machine, approvals, budgets, audit
plugins/               narrow Hermes adapters; no core patches
deploy/                pinned, reproducible deployment definitions
docs/                  architecture, security, operations, decisions
```
