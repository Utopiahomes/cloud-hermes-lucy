# Memory-layer acceptance

Lucy now exercises all three memory layers through one synthetic PostgreSQL
slice.

## Archive

Normalized conversation evidence is content-addressed and append-only. A
PostgreSQL trigger rejects updates and deletes even if application code attempts
them. The model-facing lookup never returns archived message content.

## Graph

A provisional claim materializes into canonical subject and value entities plus
a versioned relationship. The relationship retains both claim and evidence IDs,
so every interpretation resolves to its immutable provenance root. Advisory
locks serialize both claim materialization and canonical entity creation.
Identical retries after restart replay the same relationship; concurrent retries
also create exactly one relationship.

Graph materialization is recorded as a completed operation and adds
`memory.relationship_materialized` to the tamper-evident audit chain.

## Working context

Lookup builds a bounded, TTL-bearing projection ordered by confidence and
recency. It includes claim values, status, evidence ID, evidence hash, and graph
version, but excludes raw evidence. Projections may be persisted as disposable
cache records when explicitly requested. The Hermes-facing GET endpoint uses the
non-persisting mode, preserving its read-only contract.

## Acceptance path

The integration test imports one synthetic conversation, materializes its graph
relationship, restarts the service, replays without duplication, retrieves a
provenance-linked working projection, verifies raw archive exclusion, and
proves the archive mutation trigger and concurrent materialization behavior.
