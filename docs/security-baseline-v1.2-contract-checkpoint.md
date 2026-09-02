# Security Baseline v1.2 — contract-first checkpoint

Date: 2026-09-02

Status: **passed locally; PostgreSQL, AWS, Render, cloud, and recovery gates are
not yet complete. Live Telegram transcript capture remains disabled.**

## Implemented contract boundary

- Lucy Canonical JSON v1: deterministic UTF-8 JSON, lexicographically sorted
  object keys, fixed UTC timestamp representation, no floating-point values,
  and an explicit signed-contract domain prefix.
- `OwnerInteractionAssertionV1` with bounded freshness, authenticated channel,
  exact owner/event identifiers, anti-replay ID, nonce, action, evidence scope,
  environment, and epochs.
- Wire-incompatible `SensitiveActionPermitV2`; the existing V1 contract remains
  unchanged and cannot parse as V2.
- Canonical `DeletionTargetManifestV1` with exact sorted/unique evidence and key
  references, root inclusion, immutable scope/version bindings, digest, target
  count, and the 90-target/65,536-byte limits.
- `EncryptedEvidencePackageV1` with one exact evidence/key reference, bounded
  ciphertext, 12-byte AES-GCM nonce, AAD, and an exact seven-field KMS
  encryption context.
- `SensitiveExecutionGrantV1` with post-claim operation/session identity,
  package or manifest digest, idempotency and epoch bindings, exact qualified
  Lambda alias ARN, published version, and execution deadline.
- `ExecutorReceiptV1` with action-specific receipt fields and KMS-compatible
  ECDSA P-256 verification over the SHA-256 canonical digest.
- Phase 1 executor quota, retrieval/deletion state transitions, and deletion
  finality contracts.
- Pinned verification-key inventory with issuer, purpose, environment, validity
  window, live/historical mode, retirement, revocation, and suspected-compromise
  handling. Contract type determines required signing-key purpose.

## Test evidence

Commands run from the repository root:

```text
.venv/Scripts/python.exe -m ruff check .
.venv/Scripts/python.exe -m mypy
.venv/Scripts/python.exe -m pytest -q
```

Result:

- Ruff: passed.
- Mypy strict mode: passed for 34 source files.
- Pytest: 163 passed, 170 skipped, 1 upstream deprecation warning.
- V1.2 contract suite: 17 passed.
- Skips are the existing tests that require an isolated PostgreSQL or Docker
  database; they become mandatory evidence at the PostgreSQL/local-acceptance
  gates.

The deterministic non-production Ed25519 interoperability vector is stored in
`tests/fixtures/security-contract-v1.2-vectors.json`. It fixes the canonical
unsigned bytes, SHA-256 digest, public key, and signature for an exact V2 permit.

## Deliberately not done at this gate

- No production or development AWS resources were created or changed.
- No Render service, environment variable, database, or network setting was
  changed.
- No live owner-event broker was accepted.
- No V2 PostgreSQL function or service identity is trusted yet.
- No Lambda executor or durable AWS receipt ledger exists yet.
- No live or historical transcript was captured, retrieved, migrated, or used
  as test data.
- Telegram transcript capture was not enabled.

The next authorized gate is PostgreSQL enforcement: migrations, exact service
logins, hardened security-definer functions, state tables, direct-privilege
revocations, and real-login negative tests.
