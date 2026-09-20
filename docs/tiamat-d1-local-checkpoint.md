# Tiamat D1 local implementation checkpoint

Status: local candidate, **not database-verified or activated**. This checkpoint is subordinate to
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
- Existing pre-D1 ledger behavior tests remain pinned to migration `0006`; they are not D1
  conformance evidence.

## Verification ledger

| Check | Result | Scope / invalidation |
| --- | --- | --- |
| Ruff on touched code | passed | Candidate source as of this checkpoint; rerun after source edits. |
| Strict mypy on `src` | passed, 142 source files | Candidate source; rerun after source edits. |
| Focused unit tests | 27 passed | Migration structure, finalizer preflight/order, runtime rejection, older ledger tests. |
| Alembic offline SQL generation | passed | Proves revision chain and rendering, **not PostgreSQL execution**. |
| Actual PostgreSQL migration/role/function execution | not run | Docker daemon absent and no disposable local PostgreSQL URL configured. Required before D1 is deployable. |
| Staging migration or finalization | not run | Commissioned staging ledger remains at `0006` and dispatch-blocked. |

## Next action

Run migration `0007` and the finalizer on a disposable PostgreSQL 16 ledger, then test both the
positive attestation flow and negative cases: absent/expired/superseded claimant, wrong anchor
digest/floor, wrong base fence, stale LSN or timeline, two concurrent consumers, legacy-bypass
rejection, and permission denial for direct runtime table updates. Only after that evidence and
independent review should any commissioned staging ledger be considered for migration. The
launcher/context-checkpoint implementation and C1-A automatic restart invocation remain separate
work; this candidate does not claim to close the full lifecycle plan.
