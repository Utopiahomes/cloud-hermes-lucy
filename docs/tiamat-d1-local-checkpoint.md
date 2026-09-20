# Tiamat D1 local implementation checkpoint

Status: D1 candidate verified on a disposable PostgreSQL 16 instance; M2 local launcher candidate added,
**not activated**. This checkpoint is subordinate to
`tiamat-recovery-lifecycle-test-plan-v0.7.md` and the signed-release/recovery contracts.

## Scope and decisions

- P1 capability evidence: `evidence/tiamat-staging-p1-capability-probe-2026-09-19.json`.
- Migration `0007_startup_attestation` adds the anchor floor, single-active-claimant attestation
  table, and three locked security-definer functions. It does not grant runtime function execution.
- A fresh database creates the recovery login **after** migrations. The separate transactional
  `finalize_tiamat_d1_v1.py` step must therefore run after role provisioning and only against a
  blocked ledger. It temporarily grants schema `CREATE` and recovery-role membership, grants
  function execution while the migration owner still owns the functions, transfers ownership to
  `tiamat_recovery`, removes those temporary grants, and revokes runtime's direct gate `UPDATE`.
- The runtime adapter defaults to attested coordinator acquisition and verifies D1 inside the
  dispatch transaction. The old path is explicitly test-only and rejects a database containing D1.
- PostgreSQL 16 gives a role creator system-granted ADMIN-only membership in a new role. The
  finalizer removes its temporary SET/INHERIT grant and verifies the owner has no effective SET
  or USAGE of `tiamat_recovery`; the ADMIN-only row remains. This managed-environment distinction
  was found and verified during the disposable database run.
- Existing pre-D1 ledger behavior tests remain pinned to migration `0006`; they are not D1
  conformance evidence.
- The anchor floor defaults to zero and D1 will reject every attestation until the M2
  recovery/launcher path writes a verified floor. This is intentional fail-closed behavior,
  not a claim that D1 alone is ready to dispatch.
- Startup-consume rejections use distinct internal SQLSTATEs: `ZX101` absent claimant,
  `ZX102` authority/fence mismatch, `ZX103` system identifier or timeline mismatch, and
  `ZX104` WAL behind. The finalizer checks all three function owners and runtime EXECUTE
  grants, plus removal of temporary schema CREATE and role membership, before commit.
- M2 adds `StartupAttestationIssuer`: an offline recovery-role primitive that strong-reads the
  signed external anchor, accepts a digest only through an injected independent checkpoint source,
  locks the gate and an active claimant without a reverse-order wait, records the verified anchor
  floor, and atomically inserts a replacement claimant. It is not exposed through HTTP, does not
  sign or write the anchor, and has no production assembly until a durable trusted checkpoint
  source exists.
- Migration `0008_attestation_expiry` makes the short-lived claimant ceiling database-enforced:
  all new inserts and expiry updates must have a non-null `created_at`, expiry after creation, and
  no more than ten minutes later. Historical D1 rows retain NULL `created_at` rather than receiving
  fabricated issuance times; the migration therefore works under forced RLS without privileged
  backfill access.
- Migration `0009_attestation_consume_v2` installs the post-gate-expiry-safe consume function and
  moves the runtime to it. This is intentionally versioned rather than editing an already-applied
  D1 function; the finalizer transfers the new function while preserving already recovery-owned
  functions on an upgrade. A waiter cannot consume an attestation that expired during its gate-lock
  wait.
- The D1 finalizer's post-condition query variable is type-safe and deployment tools are now part
  of the strict mypy invocation. The remaining PostgreSQL 16 ADMIN-only role membership is hygiene,
  not a security boundary; Render database-admin access remains the relevant privileged boundary.

## Verification ledger

| Check | Result | Scope / invalidation |
| --- | --- | --- |
| Ruff on touched code | passed | Post-review D1 revision; rerun after source edits. |
| Strict mypy on `src` plus D1 finalizer | passed, 144 source files | M2 local candidate; rerun after source or deployment-tool edits. |
| Focused D1/M2 unit tests | 34 passed | Issuer, witness binding, expiry migration, v2 runtime entrypoint, and fresh/mixed-owner finalizer paths; synthetic only. |
| Full offline unit suite | 1276 passed, 298 skipped | M2 candidate; isolated PostgreSQL suites remain skipped because no disposable URL is configured. |
| Alembic offline SQL generation | passed through `0009` | Proves revision chain and rendering, **not PostgreSQL execution**. |
| Actual PostgreSQL 16 migration/role/function execution | 15 passed | Free disposable Render PostgreSQL 16; see `evidence/tiamat-d1-disposable-postgres16-2026-09-20.json`. Invalidated by D1 source, PostgreSQL major version, or role topology change. |
| Staging migration or finalization | not run | The commissioned staging ledger was not targeted by this test; prior checkpoint recorded it at `0006` and dispatch-blocked. |

## Next action

The free PostgreSQL test resource was deleted after evidence capture and is absent from Render's
database list; the commissioned database remains listed. The local M2 candidate received an
independent Astra code review. It next needs a fresh disposable PostgreSQL 16 run that proves issuer
plus D1 consumption, the database expiry constraint, anchor-digest mismatch rejection, mixed-owner
finalization, and post-lock expiry behavior. The
commissioned staging ledger must stay at `0006` and blocked: no local candidate is authorized to
write an external anchor or commission recovery authority. C1-A automatic restart, failover, and
restore evidence remain separate work; this candidate does not claim to close the full lifecycle
plan.
