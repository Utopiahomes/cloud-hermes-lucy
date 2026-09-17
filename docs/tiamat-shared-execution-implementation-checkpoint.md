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

No provider credentials, real model route, spending grant, provider call, deployment, migration, or
production change was created.

## Deliberately not yet claimed

The in-memory store is a test adapter. It does not establish durable or multi-replica conformance.
Before any deployment or real provider activation, Tier B must add and prove:

1. complete the private FastAPI ordered gate from §6.3, including gross framing, duplicate-header,
   cross-product precedence, timing-class, response-size, method, redirect, and disconnect proof;
2. replace the local atomic `jti` replay adapter with durable scoped replay state and prove rotation;
3. implement the tested lease/epoch/generation behavior in a durable store with atomic accounting,
   ambiguous-commit lookup, tombstones, and partition blocking once deployment topology is settled;
4. signed profile, privacy-policy, and grant formats plus durable activation/revocation state; the
   local period/successor/exposure semantics are implemented but not yet signature- or store-backed;
5. add caller-side differential proof that Homes Prime produces the same RFC 8785 identity;
6. complete every error-envelope/receipt variant and tolerant-consumer test against the bundle;
7. finish differential and adversarial coverage for the restricted-schema evaluator;
8. deadline, disconnect, crash, stale-owner, late-result, recovery, reconciliation, and rollback
   failure injection;
9. a separately authorized provider adapter and provider/model/rate selection;
10. independently deployed Homes Prime ↔ Tiamat network conformance and privacy evidence.

The existing Homes corpus remains local-test-only and is not authorized for provider use.
