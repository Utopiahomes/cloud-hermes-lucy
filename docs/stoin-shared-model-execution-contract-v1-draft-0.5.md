# Stoin Shared Model Execution Contract — `inference.execute` Draft 0.5

**Document revision:** Draft 0.5\
**Capability version:** `inference.execute@1.0`\
**Status:** architecture and wire-contract review candidate; no implementation, credential, spending, deployment, or production authority\
**Review state:** Claude's independent reviews through Draft 0.4, Fable's blind Draft 0.3 review, Lucy's Draft 0.4 review, Astra's independent Draft 0.5 freeze review, Ray's accepted decisions, and Lyra's dispositions are incorporated; §23 records the Draft 0.5 changes and final freeze focus\
**Initial caller:** Utopia Homes Prime\
**Provider:** Tiamat Shared Model Execution\
**Date:** 2026-09-17

## 1. Purpose

This contract lets an authorized calling synth request one bounded, provider-neutral model inference
from an independently deployed Tiamat Shared Model Execution service. A Business Prime is one
application of the calling-synth role; the initial caller is Utopia Homes Prime.

The caller supplies the complete inference input. Shared Model Execution authenticates the caller,
admits the request under a versioned execution profile and local spending authority, invokes one
approved provider route, and returns a candidate output with content-free usage and settlement
metadata.

This is a private serving-plane contract. It is not a public API, a Business Contract capability, a
Management Contract endpoint, or a replacement for the calling synth.

## 2. Architectural boundary

```text
Utopia Homes website
        |
        | guest.answer@1.0 Business Contract
        v
Calling synth (initially Utopia Homes Prime)
  - owns prompts and bounded context
  - owns approved knowledge and retrieval
  - owns business policy and factual validation
  - owns final answer, sources, actions, and fallback
        |
        | inference.execute@1.0 private contract
        v
Tiamat Shared Model Execution
  - authenticates and authorizes the workload
  - resolves an approved execution profile
  - enforces privacy, limits, and spending authority
  - invokes an approved provider route
  - returns a candidate and content-free receipt
```

The governing boundary is: **the calling synth owns the purpose, context, and interpretation of its
request; Tiamat provides authorized execution.** Providing execution does not transfer ownership of
the caller's data or decisions and does not implicitly grant maintenance access. Tiamat may receive
separately scoped maintenance authority only through an explicit grant.

Stoin Control and Shared Model Execution are functions on the Tiamat side; this contract does not
require them to be separate synth identities or nodes. Their operational boundary remains normative:
the management function may distribute signed policy and bounded budget grants asynchronously and
observe content-free state through separate interfaces, while the execution function performs
admitted model calls without a synchronous management dependency. The management function is not a
caller, request-time authorizer, router, data source, fallback, or cost-admission service.

Shared Model Execution does not read a caller database, a Control database, a public-knowledge
projection, or a conversation store. It does not retrieve, augment, ground, approve, or publish a
caller answer. It is nevertheless a trusted processor of the plaintext content deliberately
submitted for the active execution. Database isolation and the prohibition on durable content do not
mean that the runtime cannot transiently process that authorized content.

## 3. Normative language and identifiers

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

Examples are illustrative unless marked normative. Paths, field names, values, bounds, error
messages, authentication claims, and header rules become normative only after this contract is
accepted and frozen.

A UUID v4 is canonical lowercase RFC 4122 text matching:

```regex
^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$
```

A stable ID is 1–128 visible ASCII characters matching:

```regex
^[a-z][a-z0-9]*(?:[.-][a-z][a-z0-9]*)+$
```

Release IDs are 1–128 visible ASCII characters. They are opaque and compared byte-for-byte.

## 4. V1 scope

Version 1.0 supports:

- one private, authenticated, non-streaming inference operation;
- ordered `system`, `user`, and `assistant` text messages supplied completely by the caller;
- plain-text output or structurally constrained JSON output;
- caller-selected execution profiles from an identity-specific allowlist;
- local privacy, provider-route, token, deadline, concurrency, rate, and cost enforcement;
- content-free idempotency, accounting, tracing, and recovery state; and
- exact fail-closed behavior when an approved route or authoritative spending state is unavailable.

Version 1.0 does not support:

- browser or public access;
- retrieval, embeddings, vector search, knowledge lookup, memory, or prompt-template storage;
- business-policy evaluation, factual grounding, citations, customer-facing refusal, or final-answer
  approval;
- provider names, model names, provider payloads, or arbitrary generation parameters chosen by the
  caller;
- images, audio, video, files, URLs that the executor fetches, or multimodal input;
- tools, function calls, browsing, code execution, agents, actions, booking, payment, or mutation;
- durable conversations, transcript capture, fine-tuning data collection, or customer memory;
- streaming, batch jobs, asynchronous job queues, or general-purpose background inference;
- automatic provider or model fallback; or
- synchronous Control-plane authorization, policy lookup, accounting, or recovery.

### 4.1 Protocol and runtime-recovery specifications

This draft records two independently reviewable normative layers:

- the caller-facing wire protocol: transport, authentication, request/response/error schemas,
  observable retry and compatibility behavior; and
- the initial runtime-recovery profile: authoritative state, fencing, admission, dispatch, cost,
  reconciliation, and single-active-coordinator rules needed to make those observable promises true.

At freeze, the runtime-recovery profile MUST be published as a separately versioned companion
specification and pinned alongside the wire contract and conformance digest. A caller does not depend
on internal table layouts, process topology, or implementation classes, but the initial provider MUST
meet the pinned recovery invariants. A future implementation may change mechanisms only when it
preserves the frozen wire behavior, privacy, single-dispatch guarantee, cost semantics, and failure
invariants. The v1 initial topology remains exactly one active admission/replay coordinator per
environment with durable authoritative state; future topology is deferred.

## 5. Parties and ownership

| Responsibility | Owner |
| --- | --- |
| Prompt text, message selection, bounded context, and purpose of the call | Calling synth |
| Public or private knowledge and its authorization | Calling synth |
| Retrieval, factual grounding, evidence, personal or business rules, final decisions, and actions | Calling synth |
| Requested output shape and validation beyond structural JSON conformance | Calling synth |
| Workload authentication, execution-profile authorization, route privacy, and provider transport | Tiamat Shared Model Execution |
| Request, model, execution, concurrency, rate, and cost enforcement | Tiamat Shared Model Execution |
| Local cost reservation, settlement, and uncertain-charge recovery | Tiamat Shared Model Execution |
| Policy distribution, maintenance, offline evaluation, and deployment observation | Tiamat management function through separate interfaces |

Personal and business synths are instances of the same node architecture and use the same permission
framework with independently assigned grants. Their distinct purposes do not create different node
types. Every caller has independently scoped workload identity, credentials, permitted profiles,
spending partition, data authority, and capabilities. This contract does not define Tiamat's eventual
relationship to StoinNet or require separate execution-service instances for personal and business
callers.

Generated content is an untrusted candidate. Shared Model Execution never represents it as a
business-approved answer, verified fact, authorized action, or safe instruction.

## 6. Endpoint and transport

```http
POST /execution/v1/inference
```

- HTTPS is mandatory outside loopback tests.
- The endpoint is private and MUST NOT be reachable from a browser or public network route.
- Requests and responses use UTF-8 JSON with `Content-Type: application/json`.
- Request bodies larger than 262,144 raw bytes are rejected before JSON parsing.
- Response bodies are limited to 131,072 raw bytes.
- Compression is disabled in v1.0 so byte bounds are unambiguous.
- Responses include `Cache-Control: no-store` and MUST NOT include `Set-Cookie`.
- Redirects are prohibited. A client MUST NOT follow one.
- Streaming and connection upgrade are prohibited.

### 6.1 Required request headers

```http
Authorization: Bearer <stoin-service-jwt-v1>
X-Request-ID: <UUID-v4>
Idempotency-Key: <UUID-v4>
X-Execution-Timeout-Ms: <integer 1000-18000>
X-Content-SHA256: <unpadded-base64url-SHA-256-of-exact-body-bytes>
Content-Type: application/json
Accept: application/json
```

The provider echoes a valid `X-Request-ID`. A missing or malformed `X-Request-ID` returns step-4
`400`; a missing or malformed `Idempotency-Key` returns generic step-3 `401`. Both fail before cost
admission or provider dispatch. `X-Execution-Timeout-Ms` is an attempt-specific wait ceiling and is
not part of canonical request identity. The caller MUST NOT increase it on retry. That is a caller
conformance rule; the server is not required to retain or compare the preceding attempt header, and
the original stored execution deadline prevents any later header from extending the execution.
`X-Content-SHA256` is exactly 43 unpadded base64url characters matching
`^[A-Za-z0-9_-]{43}$`.

### 6.2 Required response headers

Every authenticated contract response includes:

```http
Content-Type: application/json
Cache-Control: no-store
X-Stoin-Execution-Release: <release-id>
X-Stoin-Execution-Policy-Release: <release-id>
```

A response also echoes a valid inbound `X-Request-ID`. Errors include an opaque UUID v4
`X-Correlation-ID`. `Retry-After` is present only where this contract permits it and is an integer
from 1 through 30 seconds.

Authentication failures and `authentication_state_unavailable` do not include either release
header. Responses for an unknown path or an unsupported method are ordinary private-service
transport responses and likewise do not disclose execution or policy releases.

### 6.3 Request-check order

The provider applies checks in this exact order so conformance vectors have one deterministic result:

1. route and method (`404` or `405`);
2. malformed transfer framing or the gross unauthenticated hard cap of 1,048,576 raw body bytes;
3. service authentication, including JWT signature/claims, required canonical
   `Idempotency-Key`/`X-Content-SHA256`, request binding, and `jti` replay (`401` or
   `503 authentication_state_unavailable`);
4. `X-Request-ID`, `X-Execution-Timeout-Ms`, `Content-Type`, and `Accept` (`400`, `415`, or `406`);
5. raw request-body size before JSON parsing (`413`);
6. exact raw-body digest verification against `X-Content-SHA256` (`401`);
7. strict JSON decoding and request/schema validation (`400`);
8. capability and execution-profile authorization (`403`);
9. output/profile compatibility (`422`);
10. read-only idempotency/state lookup (`200` replay, `409`, or `503`);
11. privacy-route and local policy eligibility (`503`);
12. exact route readiness before record creation (`503 temporarily_unavailable`);
13. concurrency and rate admission (`429`);
14. worst-case cost and locally authoritative spending eligibility (`422` or `503`); and
15. one atomic create-and-reserve operation that writes the execution record, admitted lease, and
    complete cost reservation. If another caller wins that race, the loser performs step 10 again and
    returns the resulting in-progress, conflict, replay, terminal-failure, unknown, or invalidated
    response.

Authentication therefore precedes every response that could reveal a profile, route, budget, or
idempotency state. Gross framing rejection is limited to transport safety and MUST NOT include
release, profile, or policy information.

A correctly framed body at or below 1,048,576 bytes proceeds to authentication even when its declared
or observed length exceeds the 262,144-byte contract bound; that authenticated request receives the
step-5 `413 request_too_large`. Step 2 handles only malformed framing or the gross hard cap and emits
an unauthenticated generic transport rejection without execution/policy release headers.

Missing, duplicated, or malformed `Idempotency-Key` or `X-Content-SHA256` prevents request-binding
verification and returns the same generic `401 authentication_failed` as every other authentication
failure. Those two headers therefore never produce step-4 `400` responses.

Steps 10–14 create no execution record and reserve no money. If a same-key request later arrives
after a pre-record `rate_limited`, `privacy_route_unavailable`, `state_store_unavailable`,
`spending_authority_exhausted`, or `temporarily_unavailable` response, it is evaluated afresh. Only a
successful step 15 creates the durable idempotency record and `execution_id`.

At step 15, a different-key race that consumes the remaining spending authority returns
`spending_authority_exhausted` and creates no record. A definitely non-committed store write returns
`state_store_unavailable` and creates no record or reservation. If the client cannot determine
whether the atomic transaction committed, the partition blocks every new dispatch until an
authoritative lookup establishes the record/reservation outcome; the current request returns
`state_store_unavailable` and no assumption of non-commit is permitted.

The `502` and `504` error family occurs only after step 15 and provider-dispatch processing; it is not
part of the pre-record ordered gate above. A quarantined route returns `privacy_route_unavailable`.
A partition blocked by exhausted ordinary or contingency authority returns
`spending_authority_exhausted`; a partition blocked because authoritative state is unavailable
returns `state_store_unavailable`.

## 7. Authentication and authorization

### 7.1 Workload identity

- The caller signs a dedicated service JWT with Ed25519 and `alg=EdDSA`.
- The JOSE header contains the provisioned `kid` and no unrecognized critical header.
- Shared Model Execution maps the provisioned key and exact `sub` to a realm, environment, permitted
  execution profiles, and spending partition in local serving configuration.
- The request body MUST NOT supply or override caller, realm, environment, provider, or model identity.
- Execution JWT keys MUST NOT be reused for Management Contract, Business Contract, deployment,
  customer-authentication, or policy-signing purposes.

### 7.2 Required JWT claims

| Claim | Requirement |
| --- | --- |
| `iss` | Exact provisioned issuer for the calling deployment |
| `sub` | Exact stable synth identity, initially `stoin:synth:utopia-homes-prime` |
| `aud` | Exact string `stoin:shared-model-execution` |
| `scope` | Exact string `inference.execute` |
| `iat` | Integer NumericDate |
| `nbf` | Integer NumericDate |
| `exp` | Integer NumericDate, no more than 300 seconds after `iat` |
| `jti` | UUID v4 unique to the token |
| `req` | Base64url SHA-256 request-binding digest from §7.3 |

Verification uses one fixed 30-second clock-skew allowance. The provider rejects missing,
malformed, expired, premature, wrong-issuer, wrong-subject, wrong-audience, wrong-scope, unknown-key,
wrong-algorithm, and reused-`jti` tokens before reading the request body into application objects.
It also requires `nbf <= exp`, rejects `iat` more than 30 seconds in the future, and rejects a token
whose `req` does not match the received request.

Because this capability can incur cost, `jti` is atomically consumed for ten minutes in durable,
content-free replay state. Its replay key is the exact provisioned issuer, subject, mapped realm,
environment, and `jti`; it is not global across callers. Key rotation for that same provisioned
identity preserves and checks the replay namespace until every live token/replay record expires.
Within step 3, the provider first completes JOSE structure, signature, provisioned key/subject
binding, all static and temporal claim checks, and request-binding validation; atomic `jti`
lookup/consumption is the final authentication substep. Thus an invalid token returns the generic
`401` even when the replay store is unavailable, while an otherwise valid token whose `jti` cannot be
checked returns `authentication_state_unavailable`. A retry uses a fresh JWT and `jti`, the same exact
body bytes and canonical identity, and the same `Idempotency-Key`.

Authentication failure returns one generic response. Authorization failure never reveals whether a
profile, provider, model, realm, or budget partition exists.

If the `jti` replay store is unavailable, step 3 returns
`503 authentication_state_unavailable` without execution or policy release headers and does not read
the body into application objects. It never treats replay protection as optional availability
degradation.

Step-3 authentication failures share one generic timing class. Step-6 body-digest mismatch returns
the same `401 authentication_failed` body and omits release headers, but it is explicitly exempt from
the step-3 timing class because the bounded request body must be read and hashed. Conformance tests
compare step-6 cases only with other step-6 cases.

### 7.3 Request-bound tokens

Before issuing the JWT, the caller serializes the already validated request once and computes:

```text
body_hash = BASE64URL(SHA-256(exact_request_body_bytes))
req = BASE64URL(SHA-256(
  "POST\n/execution/v1/inference\n" +
  Idempotency-Key + "\n" +
  body_hash
))
```

Base64url values are unpadded. The caller sends `body_hash` as `X-Content-SHA256`; the JWT `req` binds
that declared digest to the method, path, and idempotency key before any profile-sensitive check. The
provider then verifies the declared digest against the bounded raw body bytes before JSON decoding.
Idempotency later uses RFC 8785 canonical identity under §11. `X-Request-ID` and
`X-Execution-Timeout-Ms` are intentionally excluded so an authorized retry can use a fresh request
ID and a smaller remaining wait budget. Any change to the method, path, idempotency key, or body bytes
requires a newly signed token with a different `req`. A retry therefore reuses the exact body bytes.
Mutual TLS may be added as defense in depth but does not replace this binding in v1.0.

## 8. Execution profiles

The caller selects an `execution_profile_id`, not a provider or model. The authenticated identity is
authorized for an explicit allowlist of profiles.

Each versioned profile resolves locally to:

- one exact provider route and model revision;
- allowed input and output modes;
- data-handling, region, retention, and training restrictions;
- whether the provider has zero-data-retention or equivalent approved handling;
- input, output, reasoning, request, and response bounds;
- deadline, concurrency, and rate bounds;
- price data and a maximum reservable charge;
- whether provider-side structured-output enforcement is supported; and
- a release identifier used for admission, receipts, and rollback.

Profiles describe inference mechanics and privacy constraints. They MUST NOT contain Homes facts,
retrieval logic, customer-facing answer rules, source policy, or hospitality workflows.

An exact profile may be replaced only by activating a new policy release. The caller cannot request
fallbacks, alternate providers, model aliases, or provider-specific options. If the admitted route
cannot satisfy the request, the call fails closed.

## 9. Request contract

```json
{
  "contract": "stoin.inference.execute.request.v1",
  "execution_profile_id": "utopia-homes.public-answer.generate.v1",
  "messages": [
    {"role": "system", "content": "<Homes-owned instructions and context>"},
    {"role": "user", "content": "<bounded current request>"}
  ],
  "output": {
    "mode": "json_schema",
    "name": "guest-answer-candidate",
    "schema": {"type": "object", "properties": {}, "required": [], "additionalProperties": false}
  },
  "limits": {
    "max_output_tokens": 1200,
    "max_cost_microusd": 2000
  }
}
```

### 9.1 Top-level members

| Member | Requirement |
| --- | --- |
| `contract` | Exact string `stoin.inference.execute.request.v1` |
| `execution_profile_id` | Stable ID, authorized for the caller |
| `messages` | Ordered array of 2–32 message objects |
| `output` | Exact output contract from §9.3 |
| `limits` | Exact caller ceilings from §9.5 |

Unknown members are rejected by a v1.0 provider. A tolerant consumer ignores unknown response
members introduced by a compatible minor revision.

### 9.2 Messages

Each message has exactly:

```json
{"role": "system", "content": "text"}
```

- `role` is one of `system`, `user`, or `assistant`.
- `content` is a nonempty string of 1–65,536 Unicode scalar values.
- Total message content is at most 196,608 UTF-8 bytes.
- There is exactly one `system` message and it is first.
- After `system`, roles alternate `user`, `assistant`, `user`, `assistant`, and so on.
- The final message has role `user`.
- Consequently, the second message is `user`, no later `system` message is allowed, and adjacent
  messages never have the same role.
- Messages preserve exact order and role semantics; the executor MUST NOT flatten or reorder them.
- NUL, unpaired surrogate, and invalid UTF-8 input is rejected.

The executor treats all message content as opaque. It does not parse source IDs, fetch URLs, resolve
knowledge references, add prompts, or infer authorization from text.

### 9.3 Output modes

#### 9.3.1 Text

```json
{"mode": "text"}
```

The result is a UTF-8 text candidate. The calling synth remains responsible for every semantic,
personal, and business validation.

#### 9.3.2 JSON Schema

```json
{
  "mode": "json_schema",
  "name": "guest-answer-candidate",
  "schema": {}
}
```

- `name` is a stable ID.
- `schema` is caller-owned and limited to 32,768 canonical UTF-8 bytes.
- The root type is `object`.
- Every object declares `properties`, `required`, and `additionalProperties: false`.
- `required` contains every key declared by that object's `properties`, exactly once. Optional
  semantics are represented only through an explicitly nullable value.
- Supported schema keywords are only: `type`, `properties`, `required`, `additionalProperties`,
  `items`, `enum`, `const`, `minLength`, `maxLength`, `minimum`, `maximum`, `minItems`, and
  `maxItems`.
- Supported types are `object`, `array`, `string`, `integer`, `number`, `boolean`, and `null`.
- `type` is either one supported type string or a two-member array containing one non-null supported
  type and `null`. No other union or repeated type is allowed.
- When a nullable type also uses `enum`, `enum` includes `null` exactly once. A nullable constant that
  permits one non-null value and null is expressed as a two-member `enum`; `const` with a nullable
  type is valid only when the constant itself is null.
- Maximum nesting depth is 8, counting the root schema as depth 1 and adding one whenever validation
  descends through an object property schema or array `items` schema. Maximum total property count is
  128 across all object schemas. Each individual `enum` has at most 64 members; there is no separate
  aggregate enum-member bound beyond the canonical schema-byte limit.
- Every schema numeric literal is a finite IEEE-754 binary64 value accepted and serialized under RFC
  8785/ECMAScript number rules. Integer literals are restricted to the inclusive safe-integer range
  `-(2^53 - 1)` through `2^53 - 1`. NaN, infinities, and numeric values that cannot round-trip through
  that domain are rejected; negative zero is canonicalized as zero and is not a distinct value.
- `$ref`, remote references, annotations, defaults, patterns, formats, conditionals, and combinators
  are unsupported in v1.0.

The executor always parses and validates the returned JSON against this restricted schema before
success. Provider-side constrained generation is defense in depth and never substitutes for
executor-side validation, including `minLength`, `maxLength`, `minimum`, `maximum`, `minItems`, and
`maxItems`. Structural validation does not establish factual support, safety, source validity,
personal/business conformance, or authorization. Those remain calling-synth responsibilities.

If an admitted profile cannot faithfully enforce the requested output mode, the request fails before
provider dispatch. The executor does not silently downgrade structured output to text.

### 9.4 No provider parameters

The request has no temperature, seed, sampling, reasoning-effort, provider, model, fallback, tool,
storage, safety, or logging controls. Those are profile policy. Adding caller-tunable parameters
requires a compatible contract revision with explicit bounds and authorization semantics.

### 9.5 Caller ceilings

| Member | Bound |
| --- | --- |
| `max_output_tokens` | Integer 1–4,096 |
| `max_cost_microusd` | Integer 1–1,000,000 |

Each value is a caller ceiling, not an entitlement. The executor admits the declared output and cost
contract only when it fits every profile, route, environment, and locally authoritative budget bound.
It rejects a request that cannot be admitted as declared; it does not silently lower a requested
limit and dispatch.

`max_output_tokens` bounds exact combined generated tokens: visible output plus hidden reasoning.
Every eligible route reports an exact combined count even when it cannot report the breakdown. A
route that bills generated or reasoning tokens without an exact combined count is ineligible for
v1.0.

The usage receipt always contains integer `generated_tokens`. When the route reports a trustworthy
breakdown, `output_tokens` and `reasoning_tokens` are both nonnegative integers and their sum equals
`generated_tokens`. When it reports only the exact combined count, both breakdown fields are `null`.
One breakdown field MUST NOT be null without the other. A reported zero is an exact observed zero;
null means that the breakdown is unavailable, not that the category consumed zero. Admission, limit,
and cost calculations use `generated_tokens` exactly once, so hidden reasoning is never omitted or
double-counted.

Request-size, model-context, output-token, wall-clock, provider-timeout, concurrency, rate, and cost
limits are independent. Exhausting one MUST NOT silently relax another.

## 10. Response contract

```json
{
  "contract": "stoin.inference.execute.response.v1",
  "request_id": "7c606a49-357b-4d76-8678-b0f754c65016",
  "execution_id": "59eeddf3-35a1-4d22-a51e-08acf5d5f34d",
  "replayed": false,
  "execution_profile_id": "utopia-homes.public-answer.generate.v1",
  "profile_release_id": "profiles-2026-09-16.1",
  "output": {
    "mode": "json_schema",
    "content": {"answer": "Candidate text"}
  },
  "finish_reason": "stop",
  "usage": {
    "input_tokens": 1850,
    "generated_tokens": 212,
    "output_tokens": 212,
    "reasoning_tokens": 0
  },
  "cost": {
    "reserved_microusd": 2000,
    "settled_microusd": 417,
    "settlement_status": "settled"
  }
}
```

### 10.1 Members

| Member | Requirement |
| --- | --- |
| `contract` | Exact string `stoin.inference.execute.response.v1` |
| `request_id` | Exact valid inbound `X-Request-ID` |
| `execution_id` | Provider-generated UUID v4; stable for the admitted idempotent operation |
| `replayed` | Boolean; false for original completion and true for a volatile replay |
| `execution_profile_id` | Exact requested authorized profile |
| `profile_release_id` | Exact locally admitted profile release |
| `output` | Exact mode plus text string or JSON value conforming to the request |
| `finish_reason` | Exact string `stop` |
| `usage` | Exact nonnegative `input_tokens` and `generated_tokens`, plus the paired integer-or-null `output_tokens`/`reasoning_tokens` breakdown under §9.5 |
| `cost` | Reservation and settlement receipt from §13 |

For `text`, `output.content` is a string of at most 65,536 UTF-8 bytes. For `json_schema`, it is the
parsed JSON object, not a JSON-encoded string, and its RFC 8785 canonical form is at most 65,536 UTF-8
bytes. The complete response, including its envelope, remains bounded by 131,072 raw bytes. An
oversized provider result uses `provider_response_too_large` and exposes no partial content.

Length-limited and content-filtered provider outcomes use the error contract and do not expose
partial generated content. A successful response never authorizes the candidate for customer display
or action.

Provider and model names are deliberately absent. Approved internal telemetry may record an opaque
route ID under §15, but the wire contract remains provider-neutral.

## 11. Canonical request identity and idempotency

The provider scopes `Idempotency-Key` to the authenticated service identity, mapped realm,
environment, operation, and exact contract major version.

Before hashing, the provider:

1. strictly decodes UTF-8 JSON;
2. rejects duplicate object names and non-integer numeric values where integers are required;
3. validates the complete request and restricted schema;
4. serializes the validated request using RFC 8785 JSON Canonicalization Scheme; and
5. computes a keyed digest using an environment-specific secret.

After steps 10–14 pass, the provider performs step 15 and atomically creates the scoped key digest,
canonical request digest, admitted profile release, `admitted` state, lease
owner/deadline/fencing epoch, complete cost reservation, cost reference, and timestamps. No request
or response content enters durable idempotency state.

States are `admitted`, `dispatched`, `completed`, `failed`, and `outcome_unknown`.

- Same key and different canonical request returns `409 idempotency_conflict`.
- A duplicate while active waits for a state change for at most the smaller of its own
  `X-Execution-Timeout-Ms` and the time remaining through the original execution deadline plus the
  30-second settlement margin. It then returns the applicable replay, terminal failure,
  outcome-unknown, invalidated, or recovery-unavailable result. It returns
  `409 request_in_progress` with `Retry-After` only when the record remains `admitted` or `dispatched`
  when that wait ends. Waiting never renews the owner's lease or dispatches a second provider call.
- Every `admitted` or `dispatched` owner holds a renewable lease with a fencing epoch represented as
  the ordered pair `(coordinator_generation, record_generation)`. Failover atomically increases the
  coordinator generation before a successor may acquire leases. Every acquisition, renewal, reaper
  expiry, failover adoption, reconciliation mutation, invalidation, and other owner or non-owner
  state transition increases the record generation. Owner writes compare-and-set both the expected
  state and the complete held epoch.
- An `admitted` lease expires no later than five seconds after admission. Because no provider request
  may have started in that state, expiry atomically changes it to `failed`, releases the entire cost
  reservation, and retains the content-free deduplication record through its normal ten-minute
  window. It records `execution_aborted`, with `settlement_status: settled` and
  `settled_microusd: 0`.
- The owner atomically changes `admitted` to `dispatched` and durably confirms that commit before the
  first provider-request byte is sent. If the commit outcome is unclear, it sends nothing and performs
  a fenced authoritative lookup. If lookup proves `dispatched` under the same live owner epoch, the
  owner—being the only possible sender—atomically commits `failed`, releases the reservation, and
  records `execution_aborted` at zero settled cost. If ownership or the lease is lost first, the
  authoritative reaper transition governs and may conservatively produce `outcome_unknown`. If the
  owner cannot read or write authoritative state, it returns `state_store_unavailable` without an
  execution-state or cost receipt; it never infers release of the reservation. Once `dispatched` is
  confirmed, failure to prove whether provider bytes were sent is treated as potentially billable.
- Every `dispatched` operation holds a renewable content-free lease whose deadline is no later than
  the admitted execution deadline plus 30 seconds. If the lease expires without a live owner or an
  authoritative provider outcome, the store atomically changes the state to `outcome_unknown`.
- A late or partitioned owner whose fencing epoch is stale cannot write `completed`, `failed`, replay
  content, or a new operational state over the authoritative record. Its content-free provider cost
  reference may still enter the separate reconciliation path; any candidate output it holds is not
  replayed. An owner may return `200` only after it durably commits `completed` using the expected
  state and epoch. If that commit fails or proves the owner stale while its original HTTP connection
  remains open, it discards the candidate. It returns `execution_outcome_unknown` with the current
  execution/cost receipt only after authoritative lookup establishes that state; otherwise it returns
  `state_store_unavailable` without fabricating current state or settlement.
- A completed duplicate may replay the candidate only while it remains in volatile memory, for at
  most ten minutes, and the admitted profile release remains eligible. Eligible means that exact
  release remains active, its route is not quarantined, and no settlement overrun invalidated the
  execution. Activating a successor profile release therefore invalidates replay from the predecessor,
  even when both releases resolve to the same provider route. Replay preserves `execution_id`,
  candidate output, usage, profile ID/release, and finish reason. It echoes the retry's new
  `X-Request-ID`/`request_id`, marks `replayed: true`, and returns the latest authoritative cost state.
  The original response has `replayed: false`.
- If durable state proves completion but volatile output is absent, the provider returns
  `409 idempotency_recovery_unavailable`; it never silently executes again under that key.
- If dispatch may have reached the provider but the outcome is unknown, the provider returns
  `409 execution_outcome_unknown` and never automatically repeats the billable generation.
- If the admitted profile or route is withdrawn, a cached result is not replayed and the provider
  returns `409 execution_invalidated`.
- A `failed` record is terminal for that idempotency key. A duplicate returns the recorded generic
  error and current receipt when eligible, or `idempotency_recovery_unavailable` when it cannot do so;
  it never re-admits or dispatches the execution. A caller may begin a new logical execution only
  under the calling synth's ordinary policy and a new idempotency key, never as an implicit transport
  retry. An unclear step-15 commit can therefore consume the one transport retry: if its record was
  created and the reaper aborts it, that retry receives terminal `execution_aborted`. Starting a new
  logical execution and key is a separate caller decision subject to normal policy and budget.
- Completed and definitively failed deduplication records may expire ten minutes after admission.
  An unresolved, dispatched, outcome-unknown, or unsettled record MUST NOT expire into a state that
  permits another dispatch. Its content-free tombstone remains until the provider outcome and cost
  are authoritatively reconciled and for at least ten minutes afterward. If cost reaches
  `reservation_forfeited` without later authoritative reconciliation, the idempotency tombstone is
  retained for 30 days after forfeiture and then may expire; the separate content-free financial
  accounting reference follows its approved longer retention policy.

Lease expiry is applied only by the authoritative store's fenced reaper, not by a step-10 reader.
When lookup observes an elapsed timestamp whose reaper transition is not yet committed, it waits
within the current attempt budget for the authoritative transition and otherwise returns
`state_store_unavailable`; it neither reports the stale lease as active nor mutates it locally.

For a transport or dispatch failure after step 15 with no authoritative terminal provider outcome,
proof that zero provider-request bytes were sent atomically produces `failed`, releases the
reservation, and records `execution_aborted` with zero settled cost. An unconfirmed `admitted` to
`dispatched` write follows the fenced-lookup procedure above; uncertainty is never described as a
definite commit failure. When dispatch or the provider's terminal execution outcome remains ambiguous,
the executor uses `outcome_unknown` and retains the reservation. An authoritative terminal provider
failure instead becomes `failed` under §16 even when provider bytes were sent. Cost uncertainty alone
changes settlement status; it never changes a definitive execution outcome to `outcome_unknown`.

The initial v1.0 deployment uses exactly one active admission/replay coordinator per environment.
Provider transport workers may scale behind it. A later multi-coordinator profile must provide
deterministic request affinity or a shared non-persistent replay cache. Without that mechanism, a
retry that reaches a coordinator without the volatile candidate returns
`idempotency_recovery_unavailable`; it never dispatches again.

Coordinator failover is fail-closed for replay: the successor obtains a higher fencing epoch before
admitting work and returns `idempotency_recovery_unavailable` for a completed execution whose
candidate existed only in the predecessor's memory. At most one coordinator can hold a current lease
epoch at a time. Cost settlement and reconciliation also compare-and-set state and epoch so a stale
owner and a reaper cannot settle the same provider charge twice.

The authoritative idempotency, lease, and accounting store survives loss of any single node. If the
authoritative state is lost entirely or quorum cannot establish the latest fencing epoch, the
spending partition blocks every new dispatch until an operator reconciles provider charges and
restores an authoritative state. The system does not claim that a lost store preserved a tombstone.

Keyed-digest records carry a digest-key version. During rotation, the service retains and checks every
key version needed by live ten-minute records and unresolved tombstones. A previous digest key is not
retired until no record depending on it can authorize, block, replay, or reconcile an execution.

One execution permits exactly one billable provider dispatch. A calling synth may intentionally perform a
separate generation, support review, or repair call only as a new operation with a new idempotency
key and a separately admitted cost ceiling. Caller-pipeline retries and repairs remain caller-owned.

## 12. Deadlines and retry

The caller communicates its remaining attempt budget through `X-Execution-Timeout-Ms`. The provider
stores an absolute execution deadline at first admission and enforces the earlier of that deadline,
the current attempt ceiling, and the profile deadline. It uses a shorter provider timeout that leaves
time to settle or mark the charge uncertain and return a normalized response. A duplicate's smaller
attempt ceiling is a long-poll ceiling under §11; it does not extend or restart the original
execution.

The caller may make at most one automatic retry after a transport failure or an explicitly retryable
response. It uses:

- the same exact body bytes, canonical identity, and `Idempotency-Key`;
- a fresh JWT, `jti`, and `X-Request-ID`;
- the server's `Retry-After` when present, otherwise randomized 250–750 ms backoff; and
- the original enclosing Business Contract interaction deadline.

The calling synth skips the retry when `Retry-After`, randomized backoff, minimum request transit allowance, and
the retry's complete profile ceiling cannot all fit inside the remaining Business Contract budget. It
never begins a retry merely because the first response was marked retryable.

The retry observes the original operation; it does not authorize another dispatch. Validation,
authentication, authorization, profile, privacy, cost, and idempotency-conflict errors are not
retried automatically.

HTTP clients, provider SDKs, proxies, and transport libraries have automatic retries disabled. Only
the explicit caller retry above is permitted. In particular, no generic retry behavior may react to
`429`, `502`, `503`, or `504` independently of this contract.

Cancellation or client disconnect does not prove provider cancellation and does not release a cost
reservation until settlement or uncertain-charge recovery completes.

After `dispatched`, a response deadline that expires without an authoritative provider outcome first
durably commits `outcome_unknown` under the current fencing epoch and then returns
`504 deadline_exceeded` with the authoritative current cost receipt. If the executor authoritatively
proves a completed non-usable/cancelled outcome and cost, it first durably commits `failed` and the
settlement, then returns the same error with the settled receipt. If either transition cannot be
established authoritatively, the service returns `state_store_unavailable` without claiming a current
state or receipt. A candidate arriving after the response
deadline is never committed as replayable `completed`, never returned to Homes, and is discarded from
content memory; only its content-free provider/cost evidence enters fenced reconciliation. Late
reconciliation may change `outcome_unknown` to `failed` and settle cost, but it cannot make that
candidate eligible for replay.

## 13. Cost admission and settlement

Shared Model Execution owns a locally authoritative, atomic reservation and accounting store. Every
serving replica either uses that shared store or receives a disjoint spending partition. Replicas
MUST NOT independently spend the same grant.

Before dispatch, the executor:

1. resolves the exact authorized profile and pinned rate release;
2. computes a conservative input-token upper bound using either the exact pinned route tokenizer plus
   profile framing overhead or the fallback bound
   `message_utf8_bytes + schema_canonical_utf8_bytes + (16 * message_count) + 256`, where schema bytes
   are zero for text mode and otherwise include the complete RFC 8785-canonical output schema;
3. admits the fallback only when route conformance evidence proves it cannot understate that route's
   tokenizer or framing cost; otherwise the route is ineligible;
4. computes the worst-case charge from that input bound, the requested combined visible/reasoning
   token bound, pinned rates, provider rounding, and every permitted charge category;
5. rejects with `cost_ceiling_insufficient` if the worst-case charge exceeds the request, profile,
   route, or environment per-call ceiling;
6. rejects with `spending_authority_exhausted` if locally authoritative unreserved spending authority
   cannot cover the complete worst-case charge; and
7. supplies that complete worst-case charge to the §6.3 step-15 atomic create-and-reserve operation.

The executor never truncates a reservation to a smaller ceiling and dispatches anyway.

Routes with unbounded, unpublished, or unmodeled charge categories are ineligible for v1.0.
Automatic top-up is prohibited.

After provider completion, an authenticated final provider response that identifies the exact
admitted route and supplies exact usage under §9.5 is authoritative for synchronous settlement when
that usage multiplied by the pinned rate release covers every charge category. The service atomically
settles that calculated cost and releases the remainder. Later provider billing evidence confirms the
settlement or triggers the overrun/reconciliation rules below; it is not required before ordinary
calls can settle. When the final response or required usage is absent, ambiguous, or not sufficient
under the pinned rate model, the reservation remains held and the cost settlement status becomes
`pending_reconciliation`; asynchronous recovery may settle it later using content-free
provider/accounting references. A reservation is never released merely because the caller timed out.

Each spending partition also holds a bounded, non-dispatchable settlement-contingency reserve. If an
authoritative provider charge exceeds the admitted reservation because of rate drift, provider
rounding, or incorrect provider metadata, the service atomically debits the full actual charge,
using the contingency reserve only for the excess; marks `settlement_overrun`; quarantines that
route/rate release; starts no further call through it; and returns `cost_settlement_violation` rather
than a candidate. If the contingency reserve cannot cover the excess, the partition records the full
external liability, blocks all new dispatch, and requires operator reconciliation. It never hides or
clips the charge to preserve an apparent ceiling.

The same quarantine, accounting, and blocking rules apply when asynchronous reconciliation discovers
an overrun after a candidate was already returned with `pending_reconciliation`. The earlier customer
response cannot be withdrawn, but the service records a content-free overrun event, marks the
execution ineligible for replay, and every later duplicate returns `execution_invalidated` with the
updated `settlement_overrun` receipt instead of replaying the candidate.

The contingency reserve is at least `2 × partition maximum concurrency × partition largest per-call
ceiling`. Active executions are capped at the partition maximum concurrency `N`; saturating that
request-time concurrency gate returns step-13 `429 rate_limited`. Admission also atomically requires
`active + pending_reconciliation < 2N` before adding a new active exposure; saturating that financial-
exposure gate returns step-14 `503 spending_authority_exhausted`. An active execution may always move
to `pending_reconciliation` without losing or rejecting its liability, so pending exposure alone may
reach `2N`. Completion and admission update the combined exposure count atomically. Thus combined
active-plus-pending exposure never exceeds `2N`, matching the reserve formula even across concurrent
completions and new admissions. The formula is a minimum buffer for that bounded exposure set, not
proof that arbitrary or very-late provider overcharging is bounded. A late post-forfeiture overrun can
still exhaust it; exhaustion blocks the partition and requires manual reconciliation.

The response cost object is:

| Member | Requirement |
| --- | --- |
| `reserved_microusd` | Nonnegative integer |
| `settled_microusd` | Nonnegative integer or null |
| `settlement_status` | `settled`, `pending_reconciliation`, `reservation_forfeited`, or `settlement_overrun` |

When `settlement_status` is `settled`, `settled_microusd` is non-null and no greater than
`reserved_microusd`. When it is `pending_reconciliation`, `settled_microusd` is null and the full
reservation remains held. `settlement_overrun` appears only on an error receipt; its settled amount is
non-null and greater than the reservation. `reservation_forfeited` means the 24-hour reconciliation
deadline elapsed without authoritative cost; its settled amount equals the full reservation.

If cost is pending, a successful model candidate MAY still be returned when the provider response is
authoritative and all other checks pass. The calling synth does not retry that execution.
Content-free recovery continues without the caller or Tiamat management function being in the
synchronous path.

Reconciliation has a 24-hour deadline from dispatch. At that deadline an unresolved charge becomes
`reservation_forfeited`: the full reservation is treated as spent, the unresolved tombstone remains,
and an operator alert is recorded, but the partition does not block solely for that unresolved call.
Later authoritative cost may replace that accounting state with `settled` or
`settlement_overrun`. An overrun that exhausts the contingency reserve blocks the partition, pages an
operator, and permits no automatic resume. The forfeited idempotency tombstone follows the fixed
30-day retention from §11; longer financial evidence retention does not preserve replay or permit
re-execution.

### 13.1 Policy and budget distribution

The Tiamat management function may publish signed policy releases and bounded spending grants
asynchronously. The execution service validates and loads them before serving; it never calls the
management function to admit an individual request. Equivalent locally provisioned releases are
permitted during the initial seam proof.

Every policy and grant has `not_before`, `not_after`, environment, spending partition, release
identity, `budget_period_id`, and exact period start/end. Expired, premature, revoked, malformed,
wrong-environment, or exhausted authority fails closed. Initial grants remain valid for at least 36
hours from issuance and refresh no more than 12 hours apart, producing a minimum intended 24-hour
offline operating window after any successfully activated refresh. No contract guarantee extends
beyond the last locally valid grant. The availability objective depends on that issuance schedule;
grant validity alone does not guarantee that an outage begins immediately after refresh.

A grant represents a period-based allowance, not a lifetime cumulative ceiling. A successor grant
inside the same `budget_period_id` replaces its predecessor; overlapping validity never adds ceilings
or replenishes spend. Settled spend, active reservations, pending reconciliation, forfeitures,
contingency exposure, and later credits carry into the successor's accounting before any new
authority is available. A successor for a new period renews the configured allowance, but every
unresolved reservation, external liability, pending charge, forfeiture, and contingency obligation
still carries forward and reduces effective available authority until resolved. If carried
obligations meet or exceed the successor ceiling, no new dispatch is admitted. Expiry or replacement
never releases an obligation. A later credit or released remainder is applied to the partition's
then-current accounting, not resurrected on an expired grant.

During overlap, the active release is the valid, non-revoked grant with the latest `not_before`.
Activation records a monotonic predecessor-to-successor relationship for the spending partition. An
activated predecessor can never resume merely because its successor expires, is revoked, or is
exhausted while the predecessor's wall-clock validity remains. Rollback or resumption requires a newly
signed and explicitly activated release. Two candidate successors with equal `not_before` and no
explicit signed total-order value are conflicting and fail closed; a deployment may resolve the tie
only through a signed ordering field defined by the grant format and compared byte-for-byte.

Routine profile or policy replacement does not invalidate an already admitted execution: it may
finish under its pinned release, subject to current route eligibility and the checks below. Budget
replacement carries that admitted reservation and liability into current partition accounting.

The executor rechecks authoritative local eligibility immediately before provider dispatch and again
before candidate release. A security or privacy revocation known before dispatch prevents dispatch.
If it becomes known after dispatch but before candidate release, the candidate is suppressed and the
execution/cost state is settled honestly under the definitive-failure rules; an already delivered
candidate cannot be recalled. A routine replacement alone does not suppress delivery.

Emergency revocation is a deployment/security operation outside this request protocol. Until a
mechanism mechanically enforces a bound, the initial one-hour emergency redeployment objective is an
operational target, not a protocol guarantee. The fail-closed expiry bound remains the active grant's
remaining validity.

## 14. Provider privacy and route enforcement

Before dispatch, the executor proves from local profile state that the exact route satisfies the
approved policy for:

- provider and model allowlists;
- data retention and zero-data-retention requirements;
- provider training and data-collection denial;
- permitted processing region where applicable;
- no provider fallback or model substitution;
- no prompt, response, or tool storage;
- no browsing, tools, or external action; and
- exact price and capability bounds.

If any property is unavailable, stale, ambiguous, or contradicted by provider response metadata, the
request fails closed. The executor never weakens privacy, changes output mode, broadens provider
access, or selects an unapproved fallback to improve availability.

Provider requests include only the validated messages, output constraint, and profile-controlled
mechanical parameters needed for execution. They do not include internal credentials, realm database
access, raw browser/session identifiers, Business Contract authentication, or Control metadata.

## 15. Privacy, retention, and telemetry

No transcript capture is enabled by this contract.

Request and response content may exist only in volatile process memory for active execution and
eligible replay, for at most ten minutes from admission. Content MUST NOT enter persistent caches,
queues, disks, databases, backups, traces, crash dumps, access logs, error reports, analytics, or
accounting records. Encryption alone does not satisfy this rule.

Hosts disable swap for content-bearing processes or use an approved no-swap/locked-memory execution
profile, disable core dumps and process-memory capture, configure provider SDKs with body logging and
debug capture off, and verify that TLS terminators, service meshes, proxies, APM agents, and exception
collectors do not retain bodies or authorization headers. A component that cannot meet those
conditions is not an eligible serving path.

Allowed durable content-free telemetry includes:

- request, execution, correlation, policy, profile-release, cost, and idempotency identifiers;
- mapped realm, caller, environment, and opaque route IDs;
- timestamps and bounded latency stages;
- outcome, finish, failure, and settlement categories;
- input/output byte and token buckets;
- provider-reported token and cost totals; and
- authentication, authorization, rate, concurrency, and policy decision categories.

It MUST NOT include message text, generated text or JSON, schemas, prompts, source snippets, names,
emails, IP-derived profiles, user agents, URLs, exception text, JWTs, authorization headers, raw
idempotency keys, raw session identifiers, or provider request/response bodies.

Infrastructure access logging is body-free and minimizes or redacts IP addresses and user agents.
Security audit records authentication and abuse categories without token or body content.

The provider's actual retention and data-use behavior is part of route acceptance. A local no-log
claim does not compensate for provider retention.

## 16. Error contract

Errors use:

```json
{
  "contract": "stoin.inference.execute.error.v1",
  "correlation_id": "34a5eef4-b1f4-4aaa-b05d-19c3b31cb293",
  "request_id": "7c606a49-357b-4d76-8678-b0f754c65016",
  "execution": {
    "execution_id": "59eeddf3-35a1-4d22-a51e-08acf5d5f34d",
    "state": "outcome_unknown"
  },
  "cost": {
    "reserved_microusd": 2000,
    "settled_microusd": null,
    "settlement_status": "pending_reconciliation"
  },
  "error": {
    "code": "execution_outcome_unknown",
    "message": "The execution outcome could not be determined.",
    "retryable": false
  }
}
```

If the inbound request ID is absent or malformed, `request_id` and the response
`X-Request-ID` are absent. The provider always supplies a correlation ID. Messages are exact generic
strings and never contain exception or provider text.

`execution` is absent before idempotency admission and otherwise present only when authoritative
state establishes the stable `execution_id` and current state. `cost` is absent before a reservation
exists and otherwise present only when authoritative accounting establishes the current receipt.
Consequently, every error that can follow a paid dispatch—including provider-response, deadline,
content-filter, output-limit, outcome-unknown, and settlement errors—contains both when the
authoritative store is available. Those fields contain no prompt or output content.

`state_store_unavailable` always omits both `execution` and `cost`, including when an owner remembers
an execution identifier or a step-10 lookup knows that some record exists. Local memory and a
last-confirmed observation are not current authoritative state. The caller uses the same scoped
idempotency key for the one permitted lookup retry; the service never labels remembered accounting as
current, fabricates settlement certainty, or aliases store unavailability to provider
`outcome_unknown`.

`idempotency_conflict` omits both `execution` and `cost` because the existing record belongs to a
different canonical operation and its identifiers or accounting are not disclosed to the conflicting
request.

A step-15 `state_store_unavailable` caused by an ambiguous transaction commit follows the same rule
because neither admission nor non-admission is authoritative yet. The blocked partition and later
same-key lookup resolve that uncertainty; the initial error never fabricates a receipt.

| HTTP | Code | Exact message | Retryable | Meaning |
| --- | --- | --- | --- | --- |
| 400 | `invalid_request` | `The execution request is invalid.` | no | Invalid non-binding headers, JSON, fields, bounds, roles, or schema |
| 401 | `authentication_failed` | `Service authentication failed.` | no | Missing or invalid JWT, binding headers/digest, or reused `jti` |
| 403 | `capability_forbidden` | `This execution capability is not permitted.` | no | Valid identity lacks capability or profile authorization |
| 404 | `route_not_found` | `The requested execution route was not found.` | no | Wrong private-service path |
| 405 | `method_not_allowed` | `The execution method is not allowed.` | no | Wrong method on the exact path |
| 406 | `response_media_not_acceptable` | `The requested response media type is not supported.` | no | `Accept` excludes JSON |
| 409 | `execution_aborted` | `The execution ended before model dispatch.` | no | Record exists, zero provider-request bytes are proven, and reservation is released at zero cost |
| 409 | `idempotency_conflict` | `The idempotency key conflicts with an earlier request.` | no | Same scoped key, different canonical body |
| 409 | `request_in_progress` | `The execution request is already in progress.` | yes | Original operation remains active |
| 409 | `idempotency_recovery_unavailable` | `The earlier execution result is no longer available.` | no | Durable completion exists without volatile output |
| 409 | `execution_outcome_unknown` | `The execution outcome could not be determined.` | no | Dispatch may have incurred cost; no automatic repeat |
| 409 | `execution_invalidated` | `The earlier execution result is no longer eligible.` | no | Admitted release replaced/withdrawn, route quarantined, or settlement overrun invalidated replay |
| 413 | `request_too_large` | `The execution request is too large.` | no | Raw request exceeds 262,144 bytes |
| 415 | `unsupported_media_type` | `The execution request media type is not supported.` | no | Request is not JSON |
| 422 | `output_contract_unsupported` | `The requested output contract is not supported.` | no | Valid shape cannot be satisfied by authorized profile |
| 422 | `cost_ceiling_insufficient` | `The execution cost ceiling is insufficient.` | no | Worst-case charge exceeds a declared per-call ceiling |
| 429 | `rate_limited` | `Execution capacity is temporarily limited.` | yes | Rate or concurrency admission failed |
| 502 | `provider_response_invalid` | `The model returned an unusable result.` | no | Wrong route/model or invalid structure |
| 502 | `provider_response_too_large` | `The model response is too large.` | no | Candidate or complete response exceeds its byte bound |
| 502 | `output_limit_reached` | `The model reached its output limit.` | no | Provider stopped at the combined generated-token bound |
| 502 | `content_filtered` | `The model response was filtered.` | no | Provider returned a filtered or blocked completion |
| 502 | `provider_execution_failed` | `The model execution failed.` | no | Definitive provider throttle, service, or credential failure after admission |
| 502 | `cost_settlement_violation` | `The provider charge exceeded its reservation.` | no | Actual charge exceeded the admitted worst-case reservation |
| 503 | `privacy_route_unavailable` | `No approved private execution route is available.` | no | Exact privacy route cannot be proven or used |
| 503 | `authentication_state_unavailable` | `Service authentication state is temporarily unavailable.` | yes | `jti` replay protection unavailable before authentication completes |
| 503 | `state_store_unavailable` | `Execution state is temporarily unavailable.` | yes | State/accounting unavailable or step-15 transaction outcome cannot be established |
| 503 | `spending_authority_exhausted` | `Execution spending authority is unavailable.` | no | Local grant cannot reserve the complete worst-case charge |
| 503 | `temporarily_unavailable` | `Model execution is temporarily unavailable.` | yes | Exact admitted route is not ready at step 12 before record creation |
| 504 | `deadline_exceeded` | `Model execution exceeded its deadline.` | no | Deadline elapsed after admission; execution and cost receipt carry current state |

Definitive upstream failures after admission use this mapping:

| Provider outcome | Execution state and public error | Reservation treatment | Required evidence |
| --- | --- | --- | --- |
| Throttle or capacity rejection that definitively produced no generation | `failed`; `provider_execution_failed` | Settle at zero and release only when zero charge is authoritative; otherwise hold `pending_reconciliation` | Authenticated final provider status, exact admitted route identity, provider request reference, and approved route terms/rate evidence |
| Service failure that definitively ended the attempt without a usable candidate | `failed`; `provider_execution_failed` | Settle an authoritative observed charge, or zero when authoritatively nonbillable; otherwise hold `pending_reconciliation` | Authenticated terminal response plus exact usage/cost evidence or approved proof of nonbilling |
| Credential rejection from the exact route | `failed`; `provider_execution_failed`; quarantine the credential/route release | Zero only when provider terms and terminal evidence prove nonbilling; otherwise hold `pending_reconciliation` | Authenticated terminal status, route/credential release reference, and approved billing semantics |
| Security/privacy revocation after dispatch but before delivery | `failed`; `execution_invalidated`; suppress candidate | Settle from authoritative usage and pinned rates, otherwise hold `pending_reconciliation` | Activated revocation release and fenced execution/cost record |
| Transport proves zero provider-request bytes | `failed`; `execution_aborted` | Settle zero and release | Transport evidence sufficient under the approved adapter to prove no byte left the executor |
| Whether dispatch occurred or whether the provider reached a terminal execution outcome remains ambiguous | `outcome_unknown`; `execution_outcome_unknown` or `deadline_exceeded` | Hold the full reservation pending reconciliation | Authoritative fenced `outcome_unknown` record after the commit/lease resolution rules in §11; unresolved store or commit uncertainty returns `state_store_unavailable` without execution/cost receipts |

A provider-originated throttle is never returned as the pre-record local `rate_limited` error, and a
post-admission provider or credential failure is never returned as the pre-record
`temporarily_unavailable` error. The same idempotency key is terminal after a definitive failure; the
calling synth decides whether policy and remaining budget permit a new logical execution under a new
key. Cost uncertainty alone changes only `settlement_status`; it does not turn an authoritative
terminal success or failure into `outcome_unknown`.

All step-3 authentication failures have identical status, body shape, message, and timing class
regardless of the underlying reason. Step-6 digest mismatch has the identical `401` body and headers
but its separate body-read timing class from §7.2. Profile and budget existence is not exposed through
authentication responses.

`Retry-After` appears only for `request_in_progress`, `rate_limited`,
`authentication_state_unavailable`, `state_store_unavailable`, and `temporarily_unavailable`. It MUST
NOT be supplied for outcome-unknown or cost-authority errors.

## 17. Compatibility and release behavior

- The HTTP major version is `/execution/v1`; capability version is `inference.execute@1.0`.
- Providers reject unknown request members so callers cannot believe ignored controls were applied.
- Consumers ignore unknown response members added by a compatible minor release.
- Consumers fail closed on an unknown enum or discriminator value unless a field explicitly defines
  another behavior. They never reinterpret an unknown finish, state, settlement, or error value.
- Removing a member, changing meaning, lowering a published maximum, widening accepted provider
  behavior, weakening privacy, or changing an exact error requires a new contract major version.
  Raising a provider-accepted maximum is compatible for existing callers but requires a minor
  contract revision and new boundary vectors; profiles may continue enforcing lower values.
- Profile and implementation releases are independent of contract version and are carried in
  response headers/receipts.
- Compatible readers are deployed before a policy release is activated.
- Rollback may select only a still-approved profile and execution release. A withdrawn privacy route
  or price policy is not restored merely because an older release once used it.

## 18. Initial Utopia Homes profile

The first Stage 2 deployment may provision two separately authorized profiles:

```text
utopia-homes.public-answer.generate.v1
utopia-homes.public-answer.support-review.v1
```

These names identify distinct mechanical limit and evaluation profiles. They do not transfer prompt,
answer, source, or business-policy ownership to Shared Model Execution.

Homes Prime constructs every message and output schema for each call. A support-review call receives
only the bounded evidence and candidate that Homes chooses to disclose, runs as a new execution with
its own idempotency key and cost admission, and returns an untrusted structural candidate. Homes
interprets and enforces the review result.

The initial profile is non-streaming, has one exact approved provider/model route, has no fallback,
and allows at most one billable dispatch per execution. Exact model, provider, token, price, latency,
and aggregate spending choices are activation configuration selected from repeated evaluations; they
are not frozen into this wire contract.

The normative timing invariant is that the sum of every sequential execution ceiling and Prime's
non-execution reserve is no greater than the enclosing Business Contract deadline. Prime does not
begin support review unless the remaining interaction budget can satisfy its complete profile ceiling.

The initial Homes activation plan selects an 11-second generation ceiling, a 5-second support-review
ceiling, and a 6-second Prime reserve inside the current 22-second `guest.answer` deadline. Those are
activation settings, not frozen wire values. An evaluated activation may change them without changing
this contract or the hard 18-second per-attempt maximum, provided the normative timing invariant and
Business Contract remain satisfied.

## 19. Stage 2 migration seam

The extraction sequence is:

1. Homes owns and loads its approved prompt, knowledge projection, answer policy, and validation.
2. Homes assembles a complete bounded execution request without relying on Public Lucy retrieval or
   business behavior.
3. Homes calls independently deployed Shared Model Execution through this contract.
4. Shared Model Execution returns only a candidate and content-free receipt.
5. Homes validates exact facts, evidence support, links, restrictions, answer policy, and final
   customer response.
6. The website continues to call only `guest.answer@1.0`; it never sees execution credentials or this
   private response.
7. The former Public Lucy guest-path bridge is removed only after isolated Stage 2 acceptance and
   rollback evidence.

The existing R1 public corpus has separate testing-only authority. This contract does not broaden its
approval to provider transmission, production use, deployment, or a new digest.

Stage 2 is incomplete if any legacy component still performs Homes retrieval, Homes prompt
ownership, business validation, final-answer assembly, or serving-path Control routing behind the
new endpoint.

## 20. Acceptance criteria

### 20.1 Boundary and isolation

1. Homes Prime and Shared Model Execution run as two independently deployed processes with separate
   releases, credentials, and failure domains.
2. The website cannot reach Shared Model Execution and never receives its credential or response.
3. Shared Model Execution has no Homes or Control database credential and no filesystem copy of Homes
   knowledge or prompts.
4. A Control outage during the test window has no effect on a healthy, locally authorized execution.
5. Homes facts, prompts, retrieval, grounding, final validation, and customer fallback remain in the
   Homes release and can change without an execution-service release.
6. Provider/model routing changes through a profile/policy release without a Homes code change.

### 20.2 Authentication and authorization

7. Missing, malformed, expired, premature, wrong-issuer, wrong-subject, wrong-audience, wrong-scope,
   unknown-key, wrong-algorithm, reused-`jti`, and wrong-request-binding tokens fail before provider
   dispatch.
8. JWT skew tests accept the exact 30-second allowance, reject beyond it, reject future `iat`, and
   require `nbf <= exp`.
9. A valid caller cannot use an unlisted execution profile or influence provider/model selection.
10. Execution, Management, Business, policy-signing, and customer-authentication keys are distinct.

### 20.3 Request and output

11. Message order and roles reach the provider adapter unchanged; unsupported semantics are rejected,
    not flattened.
12. Raw request, message aggregate, output, schema depth/size, token, and deadline boundaries have
    positive, exact-boundary, and negative vectors.
13. JSON output is parsed and structurally validated before success; unsupported structured output
    fails before dispatch and never downgrades to text.
14. A syntactically valid but factually false candidate is rejected by Homes, proving that execution
    conformance cannot authorize a customer answer.
15. No model-suggested URL, source, action, or tool call is executed or returned to the customer
    without Homes validation.

### 20.4 Idempotency and cost

16. Two concurrent identical requests cause at most one provider dispatch and one reservation.
17. Same key with different canonical content returns the exact conflict response.
18. Lost volatile output after recorded completion returns recovery-unavailable without re-execution.
19. Ambiguous provider timeout becomes outcome-unknown and is never automatically redispatched.
20. Cost is reserved atomically before dispatch and settled or held for content-free reconciliation.
21. Concurrent replicas cannot spend the same grant, and exhausted authority starts no provider call.
22. Routes with unbounded auxiliary charges are rejected from the profile.

### 20.5 Privacy and failure

23. Request/response bodies, schemas, prompts, and model output are absent from logs, traces, errors,
    crash reporting, queues, durable caches, accounting, and backups.
24. The exact provider route is verified for approved retention and data-use behavior before
    activation; fallback is disabled and tested.
25. A provider response naming an unexpected model/route fails closed and is not exposed.
26. Client disconnect and deadline tests preserve reservation/recovery state and do not infer that
    provider charging stopped.
27. Error bodies contain only exact generic text; step-3 authentication failures share one timing
    class, while step-6 digest failures have the same body/headers and their separately tested
    body-read timing class.
28. The content-free telemetry allowlist is enforced mechanically.

### 20.6 End-to-end Stage 2

29. A real Homes `guest.answer` evaluation uses Homes-owned context, calls this private seam, validates
    the candidate in Homes, and returns a conformant Business Contract response.
30. The test covers ordinary conversation, follow-up, comparison, multiple requirements, missing
    information, correction, and approved local recommendation behavior.
31. Recorded evidence includes latency stages, tokens, cost, profile/policy releases, Homes behavior
    and knowledge releases, and pass/fail categories without transcript content.
32. Rollback independently restores the prior eligible Homes and execution releases without
    restoring a withdrawn route or knowledge snapshot.
33. The legacy Public Lucy guest-path dependency is absent from the candidate Stage 2 request path.

### 20.7 Crash, replay, and precedence

34. A crashed owner leaves a dispatched lease that mechanically becomes `outcome_unknown` after the
    execution deadline plus margin and never becomes eligible for another dispatch.
35. An unavailable replay, idempotency, lease, or accounting store fails closed before dispatch; a
    single-node loss preserves authoritative state, while total authoritative-state loss blocks the
    partition until manual reconciliation.
36. Synchronous and asynchronous settlement-overrun negative controls debit the bounded contingency
    reserve, return or record the exact receipt, quarantine the route/rate release, invalidate replay,
    and start no subsequent call through it.
37. A retry routed away from the volatile candidate returns the specified recovery-unavailable result
    and never causes a second paid call; the initial topology's coordinator/affinity rule is proven.
38. Oversized text, JSON content, and full envelopes return `provider_response_too_large` without
    exposing partial output.
39. Cross-product vectors for path, method, authentication, headers, media negotiation, raw size,
    JSON, authorization, profile compatibility, state, privacy, rate, and cost prove the exact §6.3
    error-check order.
40. Homes, HTTP libraries, provider SDKs, proxies, and transport adapters have automatic retries off;
    only the explicit one-retry state machine can retry.
41. Input-token upper bounds never understate the admitted route tokenizer/framing in published
    boundary vectors, including complete canonical schema bytes, and reasoning-token
    null/zero/billing semantics are mechanically checked.
42. A pre-record `429` or `503` creates no idempotency record or reservation; if a same-key request
    later arrives, it is evaluated afresh through the full ordered gate without implying permission
    to retry a non-retryable error.
43. A crash in `admitted` expires its fenced lease, atomically changes the state to `failed`, releases
    the complete reservation, never records a provider dispatch, and makes same-key duplicates return
    the terminal stored failure without re-admission.
44. The `dispatched` transition is durably committed before the first provider-request byte; every
    owner/non-owner transition advances `(coordinator_generation, record_generation)`; and a late
    owner cannot write `completed` or return `200` over `outcome_unknown`.
45. Missing, duplicated, and malformed `Idempotency-Key` and `X-Content-SHA256` cases all return the
    generic step-3 `401`, never a step-4 `400`.
46. A pending charge that exceeds its reservation during later reconciliation quarantines the route
    and makes a same-key replay return `execution_invalidated` with the updated overrun receipt.
47. Reconciliation-deadline tests forfeit the complete reservation after 24 hours without blocking
    the partition, preserve the tombstone for 30 days, alert an operator, and still process later cost
    evidence through separate retained accounting references.
48. Retry tests prove that the calling synth skips an otherwise permitted retry whenever delay plus the complete
    retry ceiling cannot fit inside the remaining Business Contract budget.
49. Nullable `enum` and `const` positive and negative vectors enforce the exact §9.3.2 rules.
50. Every post-record, authoritatively zero-byte failure returns non-retryable `execution_aborted`,
    releases the reservation, reports settled cost zero, and remains terminal for that key.
51. An active duplicate long-polls within both ceilings, returns the completed/failed/unknown result
    when available, and returns `request_in_progress` only if still active when that wait ends.
52. Fencing tests increment the record generation for reaper, failover, reconciliation, and
    invalidation transitions; a stale live owner cannot commit or return its candidate, and duplicate
    cost settlement is rejected.
53. Step-15 race tests cover same-key winner lookup, different-key budget loss, definite non-commit,
    and ambiguous commit that blocks the partition until authoritative lookup.
54. Overlapping-grant tests prove successor replacement rather than addition and carry reservations,
    contingency, settlements, forfeitures, and later credits into current partition accounting.
55. An unavailable `jti` replay store returns `authentication_state_unavailable` without release
    headers, while digest-mismatch timing is compared only against other step-6 cases.
56. `idempotency_conflict` omits the existing operation's execution and cost receipt.
57. Malformed framing and bodies above 1,048,576 bytes stop at step 2; correctly framed bodies from
    262,145 through 1,048,576 bytes authenticate before the step-5 `413`.
58. Only the authoritative fenced reaper applies lease expiry; an elapsed but unreaped lease is not
    reported active or mutated by a step-10 reader.
59. Admission atomically preserves `active <= N` and `active + pending_reconciliation <= 2N`;
    simultaneous completions may move pending alone to `2N` without losing a liability. Active
    saturation returns `rate_limited`, combined financial-exposure saturation returns
    `spending_authority_exhausted`, and later post-forfeiture overruns still exercise partition
    blocking.
60. A forfeited idempotency tombstone expires only after its fixed 30-day window; financial evidence
    may outlive it without restoring replay or dispatch eligibility.
61. A post-dispatch deadline produces the defined `failed` or `outcome_unknown` state and receipt; a
    late candidate is discarded, never replayed, and contributes only content-free reconciliation.
62. Retry timeout non-increase is tested as a caller rule, while server tests prove no later attempt
    header can extend the original stored deadline.
63. A quarantined route returns `privacy_route_unavailable`; an authority-blocked partition returns
    `spending_authority_exhausted`; and unavailable authoritative state returns
    `state_store_unavailable`.
64. Activating a successor profile release invalidates predecessor replay even when the provider route
    is unchanged, and settlement-overrun invalidation returns the updated receipt.
65. An ambiguous step-15 commit returns `state_store_unavailable` without a fabricated execution or
    cost receipt, blocks the partition, and is resolved only by authoritative same-key lookup.

### 20.8 Draft 0.5 isolation, revocation, accounting, and recovery

66. Two independently authorized calling synths cannot read, replay, conflict with, or receive one
    another's requests, candidates, execution records, profiles, spending state, or errors, even when
    they intentionally reuse identical request, idempotency UUID, or `jti` values. Except for the
    explicitly permitted content-free aggregate pressure effects in criterion 67, neither can infer
    the other's identity, traffic, budget, or state.
67. Cross-caller tests prove independent workload keys, profile allowlists, spending partitions,
    rate/concurrency partitions, and result isolation. Any intentionally shared provider capacity or
    route quarantine is documented and tested for bounded, content-free effects without exposing the
    identity, traffic, budget, or state of another caller.
68. An unclear `admitted` to `dispatched` commit sends no provider byte. Fenced resolution produces
    either authoritatively failed `execution_aborted` or the reaper's conservative
    `outcome_unknown`; store unavailability returns no invented execution or cost receipt.
69. A race with `N=2` proves two active calls may become one active/one pending, admit a replacement,
    and then complete both active calls into three pending obligations without exceeding `2N`, losing
    a liability, or misclassifying the active and financial exposure gates. The minimum contingency
    reserve is sized for the exact `2N` bound.
70. Every `504` is returned only after the owner durably commits the authoritative `failed` or
    `outcome_unknown` state and applicable cost receipt; inability to establish that state returns
    `state_store_unavailable` without current-state claims.
71. Synchronous settlement tests prove exact provider usage multiplied by the pinned rate settles an
    ordinary call once, while later billing evidence confirms it or exercises reconciliation and
    overrun behavior without double-counting.
72. JWT tests prove signature, key/subject binding, claims, timing, and request binding are checked
    before `jti` consumption, so an invalid token returns `401` during replay-store failure and only an
    otherwise valid token can receive `authentication_state_unavailable`. Identical `jti` values from
    two independently authenticated caller scopes both succeed once; reuse within one caller scope
    fails, including across credential rotation.
73. Same-period grant rotation never replenishes spend; new-period renewal carries every unresolved
    obligation; and the latest valid `not_before` wins overlap. Expiring, revoking, or exhausting an
    activated successor never restores a predecessor. Conflicting equal-time successors fail closed
    unless a signed total-order field resolves them.
74. Routine profile replacement permits a pinned admitted execution to finish. A security/privacy
    revocation blocks pre-dispatch work and suppresses a not-yet-delivered candidate after dispatch
    while preserving authoritative cost and terminal-state accounting.
75. Exact combined generated-token vectors cover both complete visible/reasoning breakdowns and the
    paired-null breakdown case, proving that admission, receipts, and cost count generated tokens once.
76. Definitive provider throttle, service failure, credential rejection, zero-byte transport failure,
    revocation-after-dispatch, and ambiguous outcome each reach only their specified state, error,
    reservation treatment, and evidence path.
77. Before deployment acceptance, the chosen host proves the no-swap or locked-memory profile, core-
    dump prohibition, process-memory-capture prohibition, and content-free observability controls at
    the infrastructure level; disabling application logs alone is insufficient.

## 21. Conformance artifacts required before implementation acceptance

The frozen contract should produce an independent bundle containing:

- strict provider schemas and tolerant consumer models;
- positive, boundary, and negative request/response/error vectors;
- cross-field invariants for messages, schema subset, headers, JWT claims, idempotency, and cost;
- canonicalization vectors verified against an independent RFC 8785 implementation or published
  fixtures;
- exact error and retry vectors;
- a coverage map from every normative wire rule to tests;
- an independent verifier that does not reuse generator validation logic;
- proof that every negative vector fails for its declared reason and no undeclared invariant; and
- a raw-content digest reproducible from a fresh archive extraction without running generator or
  verifier code.

The bundle identifies the pinned caller-facing wire revision and the separately versioned initial
runtime-recovery companion revision from §4.1. Strict provider validation enforces the frozen request
contract; tolerant consumers accept compatible additive response members while failing closed on
unknown discriminators. Runtime-mechanism tests are reported separately from wire vectors so an
internal implementation choice does not accidentally become a caller requirement.

Schema conformance alone does not prove privacy, cost, route, isolation, or semantic Stage 2
conformance. Those require execution-dependent acceptance evidence.

## 22. Decisions intentionally deferred

The following do not block review of the v1.0 seam but must be settled before activation where noted:

1. Whether Shared Model Execution is centralized, per-realm, or a hybrid deployment. The contract
   requires logical isolation and atomic spending partitions in every topology.
2. The exact provider, model, region, price release, token limits, and aggregate spending ceiling.
3. Repository ownership and release packaging for Shared Model Execution and its client SDK.
4. Whether later versions add streaming, multimodal input, tool execution, asynchronous jobs, or a
   broader structured-output language. None is implicitly authorized by v1.0.

## 23. Draft 0.5 dispositions and final freeze focus

Draft 0.5 retains every settled Draft 0.4 decision and incorporates Lucy's and Claude's Draft 0.4
reviews plus Astra's independent Draft 0.5 freeze review as follows:

1. The generic party is the **calling synth**. Personal and business callers use one node and
   permission model with independent grants. Stoin Control and Shared Model Execution are operational
   functions on the Tiamat side, not necessarily separate synth identities.
2. Execution is a trusted transient processor of submitted plaintext without acquiring ownership,
   database access, durable conversation memory, or implicit maintenance authority.
3. The caller-facing wire protocol and the initial runtime-recovery profile are separately
   reviewable and MUST be published as jointly pinned companion specifications.
4. An unclear `admitted` to `dispatched` commit never sends provider bytes. It is resolved through a
   fenced authoritative lookup; store unavailability never fabricates a release or receipt.
5. A deadline response follows, rather than precedes, the durable terminal or outcome-unknown state
   transition. A stale or unavailable store produces `state_store_unavailable`, not a guessed state.
6. Exact provider usage multiplied by the pinned complete rate is authoritative for ordinary
   synchronous settlement. Later billing evidence confirms or reconciles that settlement.
7. Admission enforces `active <= N` and `active + pending_reconciliation <= 2N`; pending alone may
   reach `2N`, and the minimum contingency reserve covers `2 × N × largest per-call ceiling`.
8. Spending authority is period-based. Same-period grant replacement never replenishes spend; new
   periods carry unresolved obligations; latest `not_before` wins overlap; successor revocation fails
   closed.
9. Initial grants last at least 36 hours and refresh no more than 12 hours apart to target at least 24
   hours of offline authority after a successful refresh. The emergency one-hour deployment goal is
   expressly non-normative until mechanically enforced.
10. Routine replacement permits pinned work to finish. Security/privacy revocation is rechecked before
    dispatch and candidate release and can suppress undelivered output without hiding cost.
11. `generated_tokens` is the exact combined count. Visible/reasoning breakdown fields are both
    integers summing to it or both null, and accounting counts the combined total once.
12. Definitive provider throttling, service failure, credential rejection, revocation, proven
    zero-byte failure, and ambiguous outcomes have explicit state/error/reservation/evidence mappings.
13. JWT signature, claims, identity binding, timing, and request binding precede atomic `jti`
    consumption, preserving `401` for invalid tokens during replay-store outages.
14. Cross-caller acceptance tests cover results, credentials, profiles, spending partitions, shared
    capacity, and route quarantine without cross-caller disclosure.
15. Hosting feasibility for no-swap, core-dump, memory-capture, and content-free observability rules
    is an explicit predeployment acceptance gate.
16. Admission enforces `active <= N` and combined active-plus-pending exposure `<= 2N`; pending alone
    may reach `2N`, preserving every valid liability across concurrent completions.
17. Definitive provider outcome and cost settlement are orthogonal: a known success or failure may
    carry pending cost, while only ambiguous dispatch or terminal execution outcome uses
    `outcome_unknown`.
18. Activated grant succession is monotonic, so expiry, revocation, or exhaustion cannot resurrect a
    predecessor; conflicting equal-time successors fail closed without a signed total order.
19. `jti` replay state is scoped to issuer, subject, realm, environment, and token identifier and
    remains effective across key rotation for the same identity.
20. JSON-schema depth, per-enum cardinality, and RFC 8785 numeric-domain rules are explicit for
    boundary-vector generation.

No known product or architecture decision now blocks protocol freeze. Final review should confirm
internal consistency, exact error reachability, the new unavailable-state receipt exception,
generated-token invariants, cross-caller isolation, and the wire/runtime-companion split.
Provider/model selection, total aggregate spending, Tiamat's future relationship to StoinNet, and
repository packaging remain activation or implementation decisions rather than wire-contract gaps.

## 24. Authorization boundary

This document authorizes no code changes, repositories, databases, migrations, provider calls,
credentials, secrets, spending, infrastructure, deployment, traffic, or production activation.

Acceptance of the text authorizes only the next separately approved implementation-planning or
conformance-bundle step. Existing corpus, provider, budget, and production approvals remain limited
to their original scopes.
