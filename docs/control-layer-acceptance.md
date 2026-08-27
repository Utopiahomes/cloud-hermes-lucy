# Control-layer acceptance

This milestone establishes a fail-closed Hermes boundary and the first durable
Lucy control workflows. All examples and tests use synthetic data only.

## Hermes boundary

The Lucy profile opts out of bundled skills with `.no-bundled-skills`. Both CLI
and Telegram platforms allow only the pinned `clarify` toolset. The profile also
declares the complete builtin and plugin toolset catalogs known to the reviewed
Hermes release, so a platform default or newly discovered pinned plugin cannot
silently become enabled. Lazy installs, cron execution, and unauthorized direct
messages remain disabled; approvals are manual.

`tests/unit/test_profile_policy.py` locks this policy to source control. The
earlier compatibility spike proves the single local `lucy-memory` skill can make
a read-only request to the companion API without modifying Hermes core.

## Approval invariants

- Request creation and human decisions use idempotency-key advisory locks.
- Creating a pending approval is itself a completed operation; it cannot be
  mistaken for an uncertain external side effect after restart.
- Only `human_owner` and `human_delegate` are valid decision actor types in the
  versioned contract and PostgreSQL constraint.
- A repeated decision key replays its stored result without another write.
- A second, conflicting decision is rejected.
- Request, decision, and operation lifecycle events enter the tamper-evident
  audit chain.

## Ambiguous recovery invariants

During `rejoining` or `reconciling`, a restart may find an operation whose
external result cannot be known. Recovery locks and marks that operation
`ambiguous`, records `retried: false`, appends an audit event, and moves Lucy to
`degraded`. It never repeats the external effect. Running recovery again is a
no-op and produces no duplicate ambiguity event.

## Verification

The PostgreSQL integration suite applies migration `0002_approvals` and verifies
the approval and recovery rules alongside the original end-to-end memory slice.
The milestone gate is:

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy src
docker compose config --quiet
```
