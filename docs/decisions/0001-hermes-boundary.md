# ADR 0001: Use pinned Hermes upstream behind companion services

- Status: accepted
- Date: 2026-08-26

## Context

Hermes already supplies the agent runtime, profile/SOUL, messaging gateways,
scheduler, supervision, model routing, tools, and approvals. Lucy additionally
requires a provenance-preserving memory graph, immutable archive, explicit
recovery lifecycle, centralized policy approvals, tamper-evident audit, and
budgets. Maintaining these as invasive changes to a fast-moving upstream would
make review and upgrades brittle.

## Decision

Use unmodified Hermes at an immutable reviewed commit. Configure native features
through a Lucy profile. Implement Lucy-owned durable state and policy in separate
services, exposed through narrow authenticated adapters/plugins.

## Consequences

- Hermes security and compatibility updates can be reviewed and adopted without
  rebasing a long-lived fork.
- Lucy's critical records have schemas and lifecycle independent of Hermes internals.
- Integration contracts and failure handling require deliberate design and tests.
- A small patch may be carried temporarily only if an essential mediation hook is
  unavailable; it must be documented, tested, and proposed upstream.

