# Hermes OpenRouter route acceptance

Date: 2026-08-27

## Result

The pinned Hermes v0.20.5 container completed one synthetic inference through
Lucy's bounded OpenRouter provider configuration and returned the exact expected
sentinel:

```text
LUCY_HERMES_OPENROUTER_OK
```

No real conversation, archive evidence, production action, Telegram credential,
or tool output was included. The smoke prompt ran with context/rules disabled and
only the `clarify` toolset available.

## Enforced profile controls

- Hermes image: `v2026.8.19` at manifest digest
  `sha256:3811ed13da874fba2ac99b6d492db9a203d34cb6dccf90d886948c00d0ccec09`
- Provider identity: `custom:lucy-openrouter`
- Endpoint: `https://openrouter.ai/api/v1`
- Model allowlist: only `openai/gpt-oss-20b`
- Credential source: `OPENROUTER_API_KEY` environment variable; no key is stored
  in the profile or Compose command
- Zero-data-retention route required with both `zdr: true` and
  `data_collection: deny`
- Provider routing sorted by price and required to support every request parameter
- Hard route price ceiling: $0.10/M prompt tokens and $0.50/M completion tokens
- OpenRouter response caching disabled
- No fallback providers
- Context metadata clamped to 16,384 tokens and output to 1,024 tokens
- Four agent turns, 120 seconds, and one Hermes-level API retry per run
- Automatic title generation and background review disabled
- Compression explicitly uses the same model and provider-routing policy

Hermes' own v0.20.5 `config check` accepted the seeded profile in an isolated
writable `/opt/data` volume before the live call.

## Usage evidence

Hermes wrote this non-secret usage summary for the passing call:

| Field | Value |
| --- | ---: |
| API calls | 1 |
| Input tokens | 3,015 |
| Output tokens | 71 |
| Reasoning tokens | 50 |
| Total tokens | 3,150 |
| Estimated provider cost | $0.0001016 |

Hermes marked this cost as an estimate derived from the provider models API. It
is not represented as authoritative OpenRouter billing.

Lucy reserved $0.03 before launching the container and conservatively settled
the full reservation after success. The durable evaluation ledger therefore
advanced from 177 to 30,177 micro-USD, remaining below the original $0.10 cap.

## Production gate closure

The first smoke used one explicit reservation around the whole container
invocation. The subsequent automatic bridge closes that gap for ordinary Hermes
requests: it reserves before each provider call, permits exactly one execution,
settles reported cost, and fails closed when Lucy is unavailable. The key-bearing
service also waits for a keyless plugin preflight. See
[`model-budget-bridge-acceptance.md`](model-budget-bridge-acceptance.md) for the
implementation, live outage proof, and residual compromised-process boundary.
