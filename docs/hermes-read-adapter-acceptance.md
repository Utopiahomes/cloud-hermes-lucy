# Hermes read-adapter acceptance

The pinned Hermes `v2026.8.19` image can query Lucy through one authenticated
GET endpoint on the private Compose network. The versioned local
`lucy-memory` skill sends a bearer credential supplied only through the runtime
environment; no credential is committed to Git.

The companion rejects missing or incorrect credentials with `401`, unavailable
storage with `503`, and every lifecycle state other than `READY` with `503`.
The adapter exposes no write, archive, approval, database, shell, or
administrative operation.

The container acceptance run returned one bounded current claim with confidence,
evidence ID and SHA-256, and relationship version. It excluded the superseded
claim and all raw conversation content. The response asserted `read_only: true`.

The Hermes profile volume is refreshed from the versioned, read-only profile
source on each seed run so adapter updates cannot be hidden by a stale persistent
volume. Hermes core remains unmodified and the image stays digest-pinned.

The original script remains a narrow compatibility and diagnostic adapter.
Lucy control plugin 1.1.0 now exposes the same read boundary as the first-class
`lucy_memory_lookup` Hermes tool; see
[`hermes-memory-tools-acceptance.md`](hermes-memory-tools-acceptance.md).
