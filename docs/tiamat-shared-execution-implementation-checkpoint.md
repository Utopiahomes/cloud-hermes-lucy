# Tiamat Shared Model Execution — implementation checkpoint

**Date:** 2026-09-17  
**Contract:** Stoin Shared Model Execution v1.0 RC1  
**Contract digest:** `a010c2cd5d501dd5586be3e1c54753ed7bf82505b9971d19c007e227bb9a75a8`  
**Conformance-bundle digest:** `5185680e2cb9ac9aff6006c9abc6a582b67933db077d5c7bd5dcc596f574cb85`

## Completed locally

- Frozen Tier A bundle with strict provider schemas, all 29 exact error tuples, positive and
  negative vectors, cross-field invariants, header/JWT/state fixtures, complete acceptance-criteria
  classification, an independent verifier, and a reproducible raw-content digest.
- Strict Pydantic request and response models for the RC1 message, output, usage, and cost shapes.
- Initial restricted-JSON-Schema admission validator.
- Profile-pinned local execution service with atomic in-memory create/reserve, dispatch-before-send,
  scoped canonical-identity conflict, single dispatch, terminal replay, and synchronous settlement.
- Fake-provider unit tests including concurrent same-key admission.
- Private local FastAPI endpoint with bounded raw-body handling, required request headers, exact
  authenticated response headers, no cookies, and release-header suppression on authentication and
  unknown-route failures.
- EdDSA workload JWT verification with provisioned key/issuer/subject/profile binding, fixed
  audience/scope, temporal limits, request binding, and scoped atomic in-memory `jti` replay state.
- Focused ordered-gate tests for invalid-token versus replay-store failure, step-6 digest mismatch,
  malformed request identity, fresh-token idempotent replay, and release-information disclosure.
- Executor-side provider-output enforcement for text/JSON byte bounds, the restricted caller schema,
  combined generated-token ceilings, usage arithmetic, response-envelope size, and cost overrun,
  with distinct fail-closed RC1 error codes.
- Topology-neutral local spending-partition reference model covering grant validity and budget-period
  applicability, predecessor/successor activation, no predecessor fallback, active versus pending
  exposure, the `2N` bound, contingency-reserve sizing, carried obligations, settlement, and
  forfeiture.
- Runtime RFC 8785 canonicalization for idempotency identity, requested-schema byte bounds, and JSON
  candidate byte bounds, verified against all five already-vendored official reference vectors.
- Content-free fenced transition reference model with lease epochs, record generations, CAS-style
  owner checks, admitted/dispatched reaping, stale-owner rejection, outcome uncertainty, and final
  eligibility suppression.
- Dedicated Tiamat PostgreSQL migration lineage through `0003_signed_release_authority`; Cloud Lucy remains at
  `0071` and does not consume migration `0072`.
- Content-free PostgreSQL adapters for durable scoped JWT replay, coordinator-generation fencing,
  atomic create/reserve, durable-before-send dispatch, terminal settlement, outcome uncertainty,
  authoritative lease reaping, and 24-hour reservation forfeiture.
- Forced row-level security for caller, realm, environment, and spending-partition isolation; the
  serving-role template is a non-owner with `NOBYPASSRLS`, while the separately held recovery role
  is excluded from serving processes.
- Restore quarantine uses deployment-owned storage epoch and recovery generation plus a database
  coordinator generation. A stale restore cannot resume against a newer witness until an offline
  reconciliation explicitly advances and unblocks the gate.
- A disposable PostgreSQL 16 integration environment proves migration, durable JWT replay,
  concurrent single admission, dispatch-before-send, settlement, non-owner RLS isolation,
  coordinator failover/takeover, admitted/dispatched reaping, recovery-generation mismatch, and a
  stale physical database snapshot failing closed under a newer external witness.
- Durable unclear-dispatch resolution aborts at zero cost only for the exact live owner epoch. If a
  newer reaper result exists, the lookup preserves `outcome_unknown` and its held reservation.
- Exact provider route and rate releases are pinned on every durable execution. A synchronous or
  asynchronously discovered overrun records the full external charge, spends contingency only for
  the excess, quarantines that exact pair, invalidates replay, and blocks the partition when the
  remaining contingency cannot cover the liability.
- Content-free financial events survive eligible idempotency-row expiry. Ordinary settled records
  retain the ten-minute contract window; unresolved forfeitures retain a 30-day tombstone before
  expiry, while their accounting event remains.
- Real PostgreSQL backend termination while dispatch and settlement transactions are open proves
  that execution state, spend, contingency, quarantine, and financial-event writes roll back as one
  unit. The separately tested unclear-commit resolver covers the case where commit may have landed.
- Frozen Tiamat Signed Release Format v1 RC1 plus a 71-file conformance bundle containing 55
  deterministic synthetic vectors, strict payload schemas, root/release Ed25519 fixtures, an
  independent verifier, a coverage map, and a reproducible raw-content digest.
- Executor-side compact-JWS verification preserves and hashes the exact received bytes, rejects
  duplicate JSON members and nonconformant headers, validates root-signed trust inventory and exact
  release-key scope, checks RFC 8785 content identity, and enforces time, subject, privacy-route,
  contingency, and budget-period relationships.
- A complete signed execution authority now requires one current profile, its exact privacy-policy
  release, and one applicable current spending grant. Missing trust inventory or grant fails closed
  before a service capable of dispatch can be constructed.
- Migration `0003_signed_release_authority` separates immutable exact-JWS artifacts from small
  monotonic activation heads and root-signed trust-inventory generations. Forced RLS applies to all
  three tables; the runtime role receives read-only authority while a separate non-bypass release
  manager receives staging/activation writes.
- The PostgreSQL authority adapter now provides idempotent exact-byte staging, conflict detection,
  root-inventory successor activation, scoped release-head locking, predecessor/sequence checks,
  atomic supersession, and exact active-JWS loading. Activation and loading both lock against the
  restore gate and fail closed when no reconciled environment row is open.

No provider credentials, real model route, spending grant, provider call, deployment, migration, or
production change was created.

## Deliberately not yet claimed

The in-memory store is a test adapter. It does not establish durable or multi-replica conformance.
Before any deployment or real provider activation, Tier B must add and prove:

1. complete the private FastAPI ordered gate from §6.3, including gross framing, duplicate-header,
   cross-product precedence, timing-class, response-size, method, redirect, and disconnect proof;
2. wire the implemented durable scoped `jti` replay adapter and prove digest-key/key rotation against
   real PostgreSQL;
3. add transactional signed revocation application, couple spending-grant activation to the
   existing budget projection, and complete restore reconciliation against Control; verified
   staging, monotonic activation, exact active-byte loading, and restore-gate enforcement are done;
4. add caller-side differential proof that Homes Prime produces the same RFC 8785 identity;
5. complete every error-envelope/receipt variant and tolerant-consumer test against the bundle;
6. finish differential and adversarial coverage for the restricted-schema evaluator;
7. deadline, disconnect, crash, stale-owner, late-result, recovery, reconciliation, and rollback
   failure injection;
8. a separately authorized provider adapter and provider/model/rate selection;
9. independently deployed Homes Prime ↔ Tiamat network conformance and privacy evidence.

The existing Homes corpus remains local-test-only and is not authorized for provider use.

## Verification ledger

At local commit preparation on 2026-09-17:

- Signed-release RC1 bundle: 106 independent checks passed after fresh archive extraction; raw
  content digest `51b0f943c59b685f261bf0c58abad79a92f7c9fae5074517036c18e0884978d9`.
- Signed-authority and neighboring Shared Execution unit boundary: 76 passed. A broader `-k` run
  was discarded because pytest imported unrelated deployment tests without the repository root on
  `PYTHONPATH`; the explicit affected-file run is the valid evidence.
- Dedicated PostgreSQL 16 authority-store proof: all 17 integration tests passed against a fresh,
  loopback-only, tmpfs-backed disposable container, including blocked-before-recovery behavior,
  idempotent staging, inventory activation, release activation/loading, and missing-predecessor
  rejection. The container was stopped and removed after the run.

- RC1 conformance bundle: 130 independent checks passed; digest remained
  `5185680e2cb9ac9aff6006c9abc6a582b67933db077d5c7bd5dcc596f574cb85`.
- Complete unit suite: 1,085 passed with two dependency deprecation warnings.
- Ruff: passed for `src`, unit tests, the Tiamat migration lineage, and the new integration test.
- Strict mypy: passed across 132 source files.
- Alembic: the independent migration lineage through `0002_route_settlement_retention` rendered successfully as PostgreSQL
  offline SQL.
- Focused durable-ledger tests: seven unit tests and 16 real PostgreSQL integration tests passed using
  a loopback-only, tmpfs-backed PostgreSQL 16 container with synthetic credentials. This establishes
  local database behavior, not production replication or failover.
