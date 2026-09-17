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

No provider credentials, real model route, spending grant, provider call, deployment, migration, or
production change was created.

## Deliberately not yet claimed

The in-memory store is a test adapter. It does not establish durable or multi-replica conformance.
Before any deployment or real provider activation, Tier B must add and prove:

1. the private FastAPI transport and exact ordered gate from §6.3;
2. EdDSA workload JWT verification, request binding, and durable scoped `jti` replay state;
3. a durable PostgreSQL execution/accounting store with leases, epochs, fencing, CAS transitions,
   ambiguous-commit lookup, reaping, tombstones, and partition blocking;
4. signed profile, privacy-policy, grant, period, successor, revocation, and exposure admission;
5. full RFC 8785 canonicalization and differential fixtures for identity and requested schemas;
6. exact error-envelope/header behavior and tolerant-consumer tests against the bundle;
7. executor-side validation of provider JSON against the caller's restricted schema;
8. deadline, disconnect, crash, stale-owner, late-result, recovery, reconciliation, and rollback
   failure injection;
9. a separately authorized provider adapter and provider/model/rate selection;
10. independently deployed Homes Prime ↔ Tiamat network conformance and privacy evidence.

The existing Homes corpus remains local-test-only and is not authorized for provider use.
