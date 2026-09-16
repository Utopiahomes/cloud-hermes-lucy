# Stoin Management Contract v1 — Control implementation checkpoint

Date: 2026-09-16. Local Control-side implementation and independent-process
compatibility proof only; nothing is deployed, provisioned, or connected to a
production Utopia Homes runtime by this checkpoint.

## Scope

This increment implements only the Stoin Control side assigned by the approved
Management Contract v1 boundary:

- pins the independently reviewed RC3 conformance bundle at canonical digest
  `c3bc25e4ae7708aba2581282d933ddd431d5ed5d0277a66477cdbe7ecc39fe33`;
- independently recomputes that digest without importing or executing Homes code;
- issues the exact `stoin-service-jwt-v1` EdDSA profile through PyJWT using a
  dedicated management-reader key;
- reads the four fixed HTTPS resources with a three-second timeout, one bounded
  retry only for the contract's retryable conditions, no redirects, and no
  caller-selected endpoint;
- parses required known fields while ignoring additive v1 response members;
- enforces the RC3 cross-resource provider-release, enabled/impaired-set, and
  zero-enabled invariants; and
- retains observations only in memory;
- supplies a fail-closed, one-shot commissioning entrypoint that verifies the
  exact staged release and transitional `guest.answer` state while emitting
  only content-free evidence; and
- provides a non-production deployment plan with explicit credential teardown
  and rollback. No database, migration, scheduler, or management mutation is
  added.

The reader is in `src/lucy/management_contract.py`; the one-shot command is
`python -m lucy.management_commission`. The exact approved contract text is
`docs/stoin-utopia-management-contract-v1.md`; the canonical artifact is under
`contracts/stoin-management-v1-bundle/`.

## Explicit exclusions

- No Homes adapter or Homes business code.
- No provider deployment or production connection.
- No key generation, distribution, or secret value.
- No polling service, persistence, alerting, mutation, or Business Contract.
- No database or migration change.
- No change to Public Lucy or Private Lucy runtime behavior.

## Verification ledger

| Check | Result | Evidence | Invalidated by |
| --- | --- | --- | --- |
| RC3 bundle digest | Passed | Independent raw-byte recomputation equals `c3bc25e4ae7708aba2581282d933ddd431d5ed5d0277a66477cdbe7ecc39fe33` | Any byte change under the pinned bundle |
| Focused management tests | Passed, 18 tests | `tests/unit/test_management_contract.py` and `tests/unit/test_management_commission.py` | Contract reader, commissioning command, bundle, JWT profile, or test-vector change |
| Complete unit suite | Passed, 1,033 tests | `python -m pytest tests/unit -q` | Source, test, or dependency change |
| Ruff | Passed | `python -m ruff check src tests` | Python source or lint configuration change |
| Strict mypy | Passed across 121 source files | `python -m mypy src/lucy` | Source, typing dependency, or mypy configuration change |
| Independent-process seam | Passed | Control commit `158601b39feb728c66147f451e5de94fbb56b727` read all four resources from Homes adapter commit `c04a97a47c9bbecb9e45b882492f756eeaaed196` over local TLS; `guest.answer` and transitional `unknown`/`health_coverage_limited` matched RC3; invalid JWT signature was rejected | Either implementation commit, pinned bundle, TLS/JWT profile, or compatibility probe change |

The unit run emitted two existing dependency deprecation warnings from
FastAPI/Starlette test-client imports. They are unrelated to this increment.

## Independent-process proof

The reusable probe is
`tests/compatibility/stoin_management_v1_seam_probe.py`. It runs the Control
one-shot commissioning command and Claude's separately checked-out Homes adapter
in different OS processes, generates temporary local TLS and Ed25519 material,
verifies the exact adapter commit and clean worktree, and removes the key material
at exit. It does not import Homes source into the Control process or bypass the
client's HTTPS requirement. The invalid-signature run also verifies the command's
generic, content-free failure output.

The prepared execution plan is
`docs/stoin-management-v1-nonproduction-deployment-plan.md`. Its next step
requires explicit authorization to push the exact branches, create isolated
staging workloads, and provision an ephemeral test key. This checkpoint does not
authorize deployment, production credentials, polling, persistence, alerts, DNS
changes, or any guest request-path dependency on Control.
