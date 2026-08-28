# Hermes model-budget bridge acceptance

Date: 2026-08-27

## Result

Every approved Hermes OpenRouter request now crosses Lucy's durable action and
budget boundary before the provider call. The user plugin is loaded from the
secret-free Lucy profile; no Hermes core source is patched.

The accepted sequence is:

1. Hermes' request middleware injects or clamps the wire-level output limit to
   1,024 tokens.
2. Execution middleware revalidates the fixed model, custom-provider identity,
   official OpenRouter endpoint, output cap, ZDR controls, parameter support,
   and price ceilings.
3. The plugin asks Lucy to reserve 5,000 micro-USD from `model.daily` under the
   idempotency key `hermes-model:{session_id}:{api_request_id}`.
4. Exactly one caller receives permission to invoke the provider.
5. The plugin settles against OpenRouter's reported usage cost when present,
   capped by the reservation. A failed or unpriced call is charged the full
   reservation conservatively.
6. If settlement cannot reach Lucy, the durable reservation remains executing;
   Rejoining later marks it ambiguous and charges it conservatively.

The reservation covers the configured rate ceiling: a 16,384-token prompt at
$0.10/M plus a 1,024-token completion at $0.50/M is at most $0.0021504, below
the $0.005 reservation.

## Fail-closed controls

- The internal begin and settle endpoints use the existing bearer-authenticated
  private companion boundary and are not added to the public `/v1` API.
- The API accepts only `openai/gpt-oss-20b`, the fixed reservation, and a
  request-derived idempotency key.
- A missing companion, rejected reservation, duplicate execution, route drift,
  or routing-policy drift blocks the provider call locally.
- The live Compose service receives the OpenRouter key only after a separate,
  keyless `hermes plugins doctor --ci lucy_control` preflight succeeds.
- Profile tests require the plugin to remain enabled and the route constraints
  to remain fixed.

## Live evidence

The final positive pinned-container smoke returned exactly:

```text
LUCY_HERMES_OPENROUTER_OK
```

Its durable action succeeded with a 5,000 micro-USD reservation and a 116
micro-USD settlement. OpenRouter usage reported 3,079 input tokens, 175 output
tokens, and 181 reasoning tokens.

With the Lucy API stopped, the same Hermes command returned the local blocked
message, created no action row, and left both reserved and spent budget totals
unchanged. The plugin doctor passed import and registration checks in the pinned
Hermes container.

Automated coverage includes exact-once begin replay, settlement validation,
API authentication, provider exception charging, companion outage, duplicate
execution, policy drift, output clamping, profile configuration, and the
keyless preflight dependency.

## Residual boundary

This protects normal and faulty Hermes execution, including plugin middleware
failures. It is not an adversarial sandbox around a fully compromised Hermes
process: that process holds the OpenRouter credential after preflight and could
attempt to bypass its own middleware. Production should therefore use a
dedicated restricted OpenRouter key with an account-side spending limit. An
egress-enforcing proxy is the stronger option if compromise containment is a
deployment requirement.
