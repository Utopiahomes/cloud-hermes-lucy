# Retention/security hardening — batch 1

Date: 2026-08-31. Baseline reviewed: `5914c32`.

Disposition: **local hardening checkpoint, not deployment or live-capture acceptance**.
This continues the [Phase 1 gap review](phase1-gap-review-2026-08-31.md).

## Verified environment and isolation

Docker Desktop 4.88.1 and its Linux AMD64 Engine 29.7.2 responded successfully.
The prior socket startup error did not recur; no runtime-directory repair or
factory reset was performed. The existing PostgreSQL and Lucy API containers
were healthy and the Telegram gateway was running.

All destructive integration resets ran against a **different PostgreSQL
cluster**: Compose project `cloud-lucy-retention-tests`, database `lucy_test`,
loopback port 54329, and tmpfs storage. It has no live volume or credential
mounts. The fixture refuses URLs outside that exact database/host/port tuple.
The normal database on port 54320, gateway, `.env`, and AWS/Render resources
were not changed or migrated. No paid model calls or Telegram messages were sent.

## Implemented in this batch

- Capture activation defaults off. Only exact `true` enables the server gate.
  An immutable, content-free consent receipt precedes each Telegram turn.
  Excluded turns and revoked generations cannot be reactivated by retry.
- PostgreSQL shared/exclusive transaction locks serialize deletion against
  archive writes, proposal/correction promotion, graph materialization, approval
  mutation, recall and raw reads. Current-evidence checks reject tombstones;
  recall excludes invalidated claims and closed relationships.
- Proposal/correction promotion revalidates the exact approved payload. Gateway
  proposals also revalidate their originating consent generation at apply time.
- Model proposal delivery keys are random UUIDs instead of plaintext hashes.
  Approval free-text reasons are not retained; decision codes are recorded.
  Permit requests accept action-specific reason codes only. Recall uses POST
  bodies, and the application disables Uvicorn access logging.
- Evidence byte limits measure the decrypted canonical record. A successful
  raw read consumes the permit once; replay does not silently disclose it again.
  Permission/lookup/validation denials receive separate sanitized audit events.
- Gateway bearer credentials cannot mint sensitive-action authority. That
  endpoint returns 403 pending an independently verified owner-event broker.
  Direct owner issuance checks the configured owner subject.
- Missing wrapped keys no longer trigger unauthenticated automatic cascades.
  Startup stops for controlled recovery; owner-authorized deletion can complete
  a known interrupted deletion. No KMS administration capability was added.
- Synthetic conversation imports reject non-synthetic source contracts.

The deletion fence is deliberately coarse for the present single-owner workload.
It does not provide distributed deletion-intent durability or per-workspace
authorization, and does not make already disclosed plaintext retractable.

## Pinned Hermes compatibility

Image: `nousresearch/hermes-agent:v2026.8.19` at manifest
`sha256:3811ed13da874fba2ac99b6d492db9a203d34cb6dccf90d886948c00d0ccec09`.
Reviewed commit: `fcbd1076a93841fa88855acce810e342a5b78101`.

The pinned `model_tools.py` passes `session_id`, but not `turn_id`, into tool
handlers. Its tool-execution middleware receives both. The pinned
`agent/turn_finalizer.py` likewise omits `turn_id` from `transform_llm_output`,
although `pre_llm_call` receives it. The lifecycle callbacks execute synchronously.

Lucy now binds trusted middleware metadata with a scoped `ContextVar`, resetting
it after dispatch, and carries the pre-call turn into the output hook through
execution-local context. It never reads authority from model arguments or falls
back to the last globally observed owner. Missing/mismatched context fails closed.

`tests/compatibility/hermes_retention_probe.py` passed using the actual pinned
middleware, registry and hook dispatcher in a disposable network-disabled
container. Only the probe and plugin source were mounted, read-only. Two
interleaved sessions resolved correctly, forged argument IDs were ignored, and
unbound dispatch failed. No Hermes core modification was made.

## Verification

- Clean test-cluster migrations: all revisions through `0013_capture_receipts`.
- Full suite: **128 passed** (89 unit, 39 PostgreSQL integration), zero skips.
- Ruff, strict MyPy for `src`, Python compilation and Git whitespace checks pass.
- Known non-failing warning: installed Starlette deprecates its HTTPX-backed
  test client. Dependency migration/locking is outside this batch.
- Both delete-versus-promotion orderings, immutable receipt privileges, retries
  across off-record/resumption/restart, wrong-registry fail-closed behavior,
  multibyte source limits, read replays, denial auditing and cross-session
  invocation binding are covered.
- Both concurrent deletion-order tests passed five additional repetitions.
  After verification, the disposable test container/network and synthetic tmpfs
  database were removed. The original API and PostgreSQL remained healthy and
  the original Telegram gateway remained running without restart.

## Reproduce locally (PowerShell)

Run from the repository root, after Docker Desktop is healthy. These credentials
are public synthetic-test values, not live secrets. Do not substitute `.env` URLs.

```powershell
docker compose -f compose.test.yaml up -d --wait --wait-timeout 45
$env:LUCY_MIGRATION_DATABASE_URL = 'postgresql+psycopg://lucy_owner:synthetic-owner-only@127.0.0.1:54329/lucy_test'
.\.venv\Scripts\python.exe -m alembic upgrade head
$env:LUCY_TEST_DATABASE_URL = 'postgresql+psycopg://lucy_app:synthetic-app-only@127.0.0.1:54329/lucy_test'
$env:LUCY_TEST_OWNER_DATABASE_URL = $env:LUCY_MIGRATION_DATABASE_URL
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src
docker compose -f compose.test.yaml down
Remove-Item Env:LUCY_MIGRATION_DATABASE_URL, Env:LUCY_TEST_DATABASE_URL, Env:LUCY_TEST_OWNER_DATABASE_URL
```

Stopping/removing this test container discards its synthetic tmpfs database. It
does not remove the normal project's volumes or containers. Check each command's
exit status; do not proceed past a failed migration.

## Remaining capture blockers / next batch

This is the first-batch checkpoint. The subsequent local startup/role and
controlled-quarantine work is recorded in
[service boundaries](service-boundaries-2026-08-31.md); full cloud/restore
acceptance remains outstanding.

1. **F01/F08:** separate control-plane recovery from per-service startup and
   prove migrations, readiness, allowed operations and denied operations as
   each real production login. Existing role templates are not that proof.
2. **F02/F03:** model all derivation edges, including assistant responses,
   mixed/current-turn plus historical evidence, extraction summaries and future
   embeddings. The current fence proves direct-source safety, not full closure.
3. **F04/F06:** implement independently verified, expiring/revocable owner events
   with per-interaction limits. Gateway retrieval and forget commands remain
   unavailable until that broker passes acceptance; do not restore the bearer
   minting shortcut to make a demo work.
4. **F07:** independent deletion-intent history, registry identity/epoch checks,
   orphan-key handling and a compound restore quarantine before any restored
   structured memory is served. Fail-closed missing-key detection alone is not
   an accepted recovery design. Provision and verify backup retention/RPO/RTO.
5. **F05:** inventory legacy plaintext fingerprints, audit text and infrastructure
   logs. Changing new writes does not remove old residues or protect plaintext
   structured memory from a compromised authorized routine identity.
6. Complete the remaining budget/isolation/deployment findings, synthetic cloud
   IAM/OIDC/KMS and recovery tests, and owner acceptance before live capture.

These changes were not rebuilt into the live service or seeded into the gateway.
They require a coordinated migration/API/plugin rollout after the remaining
gates pass. The old running image does not acquire these protections merely
because the local source tree changed.
