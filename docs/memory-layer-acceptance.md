# Memory-layer acceptance

Lucy now exercises all three memory layers through one synthetic PostgreSQL
slice.

## Archive

Versioned conversation evidence envelopes are append-only. A PostgreSQL trigger
rejects updates and deletes even if application code attempts them. Message
plaintext is envelope-encrypted with a per-record DEK; only ciphertext, metadata,
an external key reference, and a keyed commitment enter PostgreSQL.

The staged Telegram bridge feeds this layer automatically for the allowlisted
owner once its deployment gate is approved. Each inbound and assistant message
has a stable turn/role identity, replays exactly once, and creates evidence plus
audit history without creating a claim. It is not enabled in the live gateway
yet. See [`telegram-transcript-retention.md`](telegram-transcript-retention.md).

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
Additional archive acceptance proves narrow audited decryption, owner retrieval,
crypto-shredding, derived-data invalidation, default-on capture state, visible
off-record behavior, and authoritative two-message turn commits.
