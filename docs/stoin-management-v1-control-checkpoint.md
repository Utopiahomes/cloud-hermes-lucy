# Stoin Management Contract v1 — Control implementation checkpoint

Date: 2026-09-15. Local Control-side implementation only; nothing is deployed,
provisioned, or connected to Utopia Homes by this checkpoint.

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
- retains observations only in memory. No database, migration, scheduler, or
  management mutation is added.

The implementation is in `src/lucy/management_contract.py`. The exact approved
contract text is `docs/stoin-utopia-management-contract-v1.md`; the canonical
artifact is under `contracts/stoin-management-v1-bundle/`.

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
| Focused management tests | Passed, 12 tests | `tests/unit/test_management_contract.py` | Contract reader, bundle, JWT profile, or test-vector change |
| Complete unit suite | Passed, 1,027 tests | `python -m pytest tests/unit -q` | Source, test, or dependency change |
| Ruff | Passed | `python -m ruff check src tests` | Python source or lint configuration change |
| Strict mypy | Passed across 120 source files | `python -m mypy src/lucy` | Source, typing dependency, or mypy configuration change |

The unit run emitted two existing dependency deprecation warnings from
FastAPI/Starlette test-client imports. They are unrelated to this increment.

## Next integration seam

Claude owns the independently deployed Homes management adapter and its
provider-side conformance proof. Once that endpoint exists in a non-production
test environment, the next Control task is the contract-required network HTTP
proof between the two independent processes. That proof will use separately
provisioned test keys and an exact test base URL; it does not authorize production
activation.
