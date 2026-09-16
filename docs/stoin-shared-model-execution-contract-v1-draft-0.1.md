# Stoin Shared Model Execution Contract — `inference.execute` Draft 0.1

**Document revision:** Draft 0.1\
**Capability version:** `inference.execute@1.0`\
**Status:** architecture and wire-contract review candidate; no implementation, credential, spending, deployment, or production authority\
**Initial caller:** Utopia Homes Prime\
**Provider:** Shared Model Execution\
**Date:** 2026-09-16

## 1. Purpose

This contract lets an authorized Business Prime request one bounded, provider-neutral model
inference from an independently deployed Shared Model Execution service.

The caller supplies the complete inference input. Shared Model Execution authenticates the caller,
admits the request under a versioned execution profile and local spending authority, invokes one
approved provider route, and returns a candidate output with content-free usage and settlement
metadata.

This is a private serving-plane contract. It is not a public API, a Business Contract capability, a
Management Contract endpoint, or a replacement for the Business Prime.

## 2. Architectural boundary

```text
Utopia Homes website
        |
        | guest.answer@1.0 Business Contract
        v
Utopia Homes Prime
  - owns prompts and bounded context
  - owns approved knowledge and retrieval
  - owns business policy and factual validation
  - owns final answer, sources, actions, and fallback
        |
        | inference.execute@1.0 private contract
        v
Shared Model Execution
  - authenticates and authorizes the workload
  - resolves an approved execution profile
  - enforces privacy, limits, and spending authority
  - invokes an approved provider route
  - returns a candidate and content-free receipt
```

Stoin Control is not a caller, authorizer, router, data source, fallback, cost-admission service, or
synchronous dependency for an execution. Control may distribute signed policy and bounded budget
grants asynchronously and observe content-free state through separate management interfaces.

Shared Model Execution does not read a Homes database, a Control database, a public-knowledge
projection, or a conversation store. It does not retrieve, augment, ground, approve, or publish a
Homes answer.

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

## 5. Parties and ownership

| Responsibility | Owner |
| --- | --- |
| Prompt text, message selection, bounded context, and purpose of the call | Calling Business Prime |
| Public or private business knowledge and its authorization | Calling Business Prime |
| Retrieval, factual grounding, evidence, business rules, and final customer behavior | Calling Business Prime |
| Requested output shape and validation beyond structural JSON conformance | Calling Business Prime |
| Workload authentication, execution-profile authorization, route privacy, and provider transport | Shared Model Execution |
| Request, model, execution, concurrency, rate, and cost enforcement | Shared Model Execution |
| Local cost reservation, settlement, and uncertain-charge recovery | Shared Model Execution |
| Offline evaluation and deployment observation | Stoin Control through separate interfaces |

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
Content-Type: application/json
Accept: application/json
```

The provider echoes a valid `X-Request-ID`. Missing or malformed request and idempotency identifiers
fail before cost admission or provider dispatch.

### 6.2 Required response headers

Every response includes:

```http
Content-Type: application/json
Cache-Control: no-store
X-Stoin-Execution-Release: <release-id>
X-Stoin-Execution-Policy-Release: <release-id>
```

A response also echoes a valid inbound `X-Request-ID`. Errors include an opaque UUID v4
`X-Correlation-ID`. `Retry-After` is present only where this contract permits it and is an integer
from 1 through 30 seconds.

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

Verification uses one fixed 30-second clock-skew allowance. The provider rejects missing,
malformed, expired, premature, wrong-issuer, wrong-subject, wrong-audience, wrong-scope, unknown-key,
wrong-algorithm, and reused-`jti` tokens before reading the request body into application objects.

Because this capability can incur cost, `jti` is atomically consumed for ten minutes in durable,
content-free replay state. A retry uses a fresh JWT and `jti`, the same canonical body, and the same
`Idempotency-Key`.

Authentication failure returns one generic response. Authorization failure never reveals whether a
profile, provider, model, realm, or budget partition exists.

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
    "deadline_ms": 15000,
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
| `messages` | Ordered array of 1–32 message objects |
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
- The final message has role `user`.
- Adjacent messages MUST NOT have the same role.
- Messages preserve exact order and role semantics; the executor MUST NOT flatten or reorder them.
- NUL, unpaired surrogate, and invalid UTF-8 input is rejected.

The executor treats all message content as opaque. It does not parse source IDs, fetch URLs, resolve
knowledge references, add prompts, or infer authorization from text.

### 9.3 Output modes

#### 9.3.1 Text

```json
{"mode": "text"}
```

The result is a UTF-8 text candidate. Homes remains responsible for every semantic and business
validation.

#### 9.3.2 JSON Schema

```json
{
  "mode": "json_schema",
  "name": "guest_answer_candidate",
  "schema": {}
}
```

- `name` is a stable ID.
- `schema` is caller-owned and limited to 32,768 canonical UTF-8 bytes.
- The root type is `object`.
- Every object declares `properties`, `required`, and `additionalProperties: false`.
- Supported schema keywords are only: `type`, `properties`, `required`, `additionalProperties`,
  `items`, `enum`, `const`, `minLength`, `maxLength`, `minimum`, `maximum`, `minItems`, and
  `maxItems`.
- Supported types are `object`, `array`, `string`, `integer`, `number`, `boolean`, and `null`.
- Maximum nesting depth is 8; maximum total property count is 128; maximum enum member count is 64.
- `$ref`, remote references, annotations, defaults, patterns, formats, conditionals, and combinators
  are unsupported in v1.0.

The executor validates the returned JSON against this restricted schema before success. Structural
validation does not establish factual support, safety, source validity, business conformance, or
authorization. Those remain Homes responsibilities.

If an admitted profile cannot faithfully enforce the requested output mode, the request fails before
provider dispatch. The executor does not silently downgrade structured output to text.

### 9.4 No provider parameters

The request has no temperature, seed, sampling, reasoning-effort, provider, model, fallback, tool,
storage, safety, or logging controls. Those are profile policy. Adding caller-tunable parameters
requires a compatible contract revision with explicit bounds and authorization semantics.

### 9.5 Caller ceilings

| Member | Bound |
| --- | --- |
| `deadline_ms` | Integer 1,000–18,000 |
| `max_output_tokens` | Integer 1–4,096 |
| `max_cost_microusd` | Integer 1–1,000,000 |

Each value is a caller ceiling, not an entitlement. The executor applies the minimum of the request,
profile, route, environment, and remaining locally authoritative budget bounds. It rejects a request
that cannot be admitted without changing its declared output or cost contract.

Request-size, model-context, output-token, wall-clock, provider-timeout, concurrency, rate, and cost
limits are independent. Exhausting one MUST NOT silently relax another.

## 10. Response contract

```json
{
  "contract": "stoin.inference.execute.response.v1",
  "request_id": "7c606a49-357b-4d76-8678-b0f754c65016",
  "execution_id": "59eeddf3-35a1-4d22-a51e-08acf5d5f34d",
  "execution_profile_id": "utopia-homes.public-answer.generate.v1",
  "profile_release_id": "profiles-2026-09-16.1",
  "output": {
    "mode": "json_schema",
    "content": {"answer": "Candidate text"}
  },
  "finish_reason": "stop",
  "usage": {
    "input_tokens": 1850,
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
| `execution_profile_id` | Exact requested authorized profile |
| `profile_release_id` | Exact locally admitted profile release |
| `output` | Exact mode plus text string or JSON value conforming to the request |
| `finish_reason` | Exact string `stop` |
| `usage` | Nonnegative integer token counts; `reasoning_tokens` is null when unavailable |
| `cost` | Reservation and settlement receipt from §13 |

For `text`, `output.content` is a string of at most 65,536 UTF-8 bytes. For `json_schema`, it is the
parsed JSON object, not a JSON-encoded string.

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

The provider atomically records the scoped key digest, canonical request digest, admitted profile
release, execution state, cost reference, and timestamps before any provider dispatch. No request or
response content enters durable idempotency state.

States are `admitted`, `dispatched`, `completed`, `failed`, and `outcome_unknown`.

- Same key and different canonical request returns `409 idempotency_conflict`.
- A duplicate while active returns `409 request_in_progress` with `Retry-After` and cannot dispatch a
  second provider call.
- A completed duplicate may return the exact result only while it remains in volatile memory, for at
  most ten minutes, and the admitted profile remains eligible.
- If durable state proves completion but volatile output is absent, the provider returns
  `409 idempotency_recovery_unavailable`; it never silently executes again under that key.
- If dispatch may have reached the provider but the outcome is unknown, the provider returns
  `409 execution_outcome_unknown` and never automatically repeats the billable generation.
- If the admitted profile or route is withdrawn, a cached result is not replayed and the provider
  returns `409 execution_invalidated`.
- Idempotency state expires after ten minutes. Outside that window this contract provides no
  deduplication guarantee, and callers MUST NOT intentionally reuse the key.

One execution permits exactly one billable provider dispatch. Homes may intentionally perform a
separate generation, support review, or repair call only as a new operation with a new idempotency
key and a separately admitted cost ceiling. Business-pipeline retries and repairs remain Prime-owned.

## 12. Deadlines and retry

The caller communicates `deadline_ms`; the provider enforces a shorter internal provider timeout
that leaves time to settle or mark the charge uncertain and return a normalized response.

The caller may make at most one automatic retry after a transport failure or an explicitly retryable
response. It uses:

- the same canonical body and `Idempotency-Key`;
- a fresh JWT, `jti`, and `X-Request-ID`;
- the server's `Retry-After` when present, otherwise randomized 250–750 ms backoff; and
- the original enclosing Business Contract interaction deadline.

The retry observes the original operation; it does not authorize another dispatch. Validation,
authentication, authorization, profile, privacy, cost, and idempotency-conflict errors are not
retried automatically.

Cancellation or client disconnect does not prove provider cancellation and does not release a cost
reservation until settlement or uncertain-charge recovery completes.

## 13. Cost admission and settlement

Shared Model Execution owns a locally authoritative, atomic reservation and accounting store. Every
serving replica either uses that shared store or receives a disjoint spending partition. Replicas
MUST NOT independently spend the same grant.

Before dispatch, the executor:

1. resolves the exact authorized profile and pinned rate release;
2. computes a conservative maximum charge from bounded input, requested output, billable reasoning,
   and every provider charge category permitted by the profile;
3. takes the minimum of that amount and the request/profile/environment ceilings;
4. confirms sufficient unreserved spending authority; and
5. atomically reserves the maximum charge against the idempotent execution.

Routes with unbounded, unpublished, or unmodeled charge categories are ineligible for v1.0.
Automatic top-up is prohibited.

After provider completion, the service atomically settles actual observed cost and releases the
remainder. If authoritative cost is delayed or ambiguous, the reservation remains held and the state
becomes `pending_reconciliation`; asynchronous recovery may settle it later using content-free
provider/accounting references. A reservation is never released merely because the caller timed out.

The response cost object is:

| Member | Requirement |
| --- | --- |
| `reserved_microusd` | Nonnegative integer |
| `settled_microusd` | Nonnegative integer or null |
| `settlement_status` | `settled` or `pending_reconciliation` |

When `settlement_status` is `settled`, `settled_microusd` is non-null and no greater than
`reserved_microusd`. When it is `pending_reconciliation`, `settled_microusd` is null and the full
reservation remains held.

If cost is pending, a successful model candidate MAY still be returned when the provider response is
authoritative and all other checks pass. Homes does not retry that execution. Content-free recovery
continues without Homes or Control being in the synchronous path.

### 13.1 Policy and budget distribution

Control may publish signed policy releases and bounded spending grants asynchronously. The execution
service validates and loads them before serving; it never calls Control to admit an individual
request. Equivalent locally provisioned releases are permitted during the initial seam proof.

Every policy and grant has `not_before`, `not_after`, environment, spending partition, and release
identity. Expired, premature, revoked, malformed, wrong-environment, or exhausted authority fails
closed. Operators rotate grants with overlap so a temporary Control outage does not interrupt a
healthy serving plane. No contract guarantee extends beyond the last locally valid grant.

Emergency revocation is a deployment/security operation outside this request protocol. The bounded
revocation delay is the shorter of the active grant's remaining validity and the environment's
documented emergency rollout objective.

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
  "error": {
    "code": "temporarily_unavailable",
    "message": "Model execution is temporarily unavailable.",
    "retryable": true
  }
}
```

If the inbound request ID is absent or malformed, `request_id` and the response
`X-Request-ID` are absent. The provider always supplies a correlation ID. Messages are exact generic
strings and never contain exception or provider text.

| HTTP | Code | Exact message | Retryable | Meaning |
| --- | --- | --- | --- | --- |
| 400 | `invalid_request` | `The execution request is invalid.` | no | Invalid headers, JSON, fields, bounds, roles, or schema |
| 401 | `authentication_failed` | `Service authentication failed.` | no | Missing or invalid JWT, including reused `jti` |
| 403 | `capability_forbidden` | `This execution capability is not permitted.` | no | Valid identity lacks capability or profile authorization |
| 409 | `idempotency_conflict` | `The idempotency key conflicts with an earlier request.` | no | Same scoped key, different canonical body |
| 409 | `request_in_progress` | `The execution request is already in progress.` | yes | Original operation remains active |
| 409 | `idempotency_recovery_unavailable` | `The earlier execution result is no longer available.` | no | Durable completion exists without volatile output |
| 409 | `execution_outcome_unknown` | `The earlier execution outcome is not yet known.` | no | Dispatch may have incurred cost; no automatic repeat |
| 409 | `execution_invalidated` | `The earlier execution result is no longer eligible.` | no | Admitted profile or route was withdrawn |
| 413 | `request_too_large` | `The execution request is too large.` | no | Raw request exceeds 262,144 bytes |
| 422 | `output_contract_unsupported` | `The requested output contract is not supported.` | no | Valid shape cannot be satisfied by authorized profile |
| 429 | `rate_limited` | `Execution capacity is temporarily limited.` | yes | Rate or concurrency admission failed |
| 429 | `spending_authority_exhausted` | `Execution spending authority is unavailable.` | no | Local grant cannot reserve the bounded charge |
| 502 | `provider_response_invalid` | `The model returned an unusable result.` | no | Wrong route/model, invalid structure, partial output, or bounds failure |
| 503 | `privacy_route_unavailable` | `No approved private execution route is available.` | no | Exact privacy route cannot be proven or used |
| 503 | `temporarily_unavailable` | `Model execution is temporarily unavailable.` | yes | Internal or provider dependency unavailable before ambiguous dispatch |
| 504 | `deadline_exceeded` | `Model execution exceeded its deadline.` | no | Deadline elapsed; charge status is safely recorded |

Authentication failures have identical status, body shape, message, and timing class regardless of
the underlying reason. Profile and budget existence is not exposed through authentication responses.

`Retry-After` appears only for `request_in_progress`, `rate_limited`, and
`temporarily_unavailable`. It MUST NOT be supplied for outcome-unknown or cost-authority errors.

## 17. Compatibility and release behavior

- The HTTP major version is `/execution/v1`; capability version is `inference.execute@1.0`.
- Providers reject unknown request members so callers cannot believe ignored controls were applied.
- Consumers ignore unknown response members added by a compatible minor release.
- Removing a member, changing meaning or bounds, widening accepted provider behavior, weakening
  privacy, or changing an exact error requires a new contract major version.
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
   unknown-key, wrong-algorithm, and reused-`jti` tokens fail before provider dispatch.
8. JWT skew tests accept the exact 30-second allowance and reject beyond it.
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
27. Error bodies contain only exact generic text; authentication failures are indistinguishable.
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

Schema conformance alone does not prove privacy, cost, route, isolation, or semantic Stage 2
conformance. Those require execution-dependent acceptance evidence.

## 22. Decisions intentionally deferred

The following do not block review of the v1.0 seam but must be settled before activation where noted:

1. Whether Shared Model Execution is centralized, per-realm, or a hybrid deployment. The contract
   requires logical isolation and atomic spending partitions in every topology.
2. The exact provider, model, region, price release, token limits, and aggregate spending ceiling.
3. The policy/grant validity duration and emergency revocation objective. These are deployment
   decisions, but their selected values must satisfy §13 and be tested.
4. The reconciliation deadline and operational disposition for charges that remain uncertain.
5. Repository ownership and release packaging for Shared Model Execution and its client SDK.
6. Whether later versions add streaming, multimodal input, tool execution, asynchronous jobs, or a
   broader structured-output language. None is implicitly authorized by v1.0.

## 23. Review questions

Reviewers should decide explicitly:

1. Is the restricted JSON Schema subset necessary for Stage 2, or should v1.0 be text/JSON-object only?
2. Should one billable provider dispatch remain an absolute v1.0 rule, leaving every repair and
   support-review call to Homes orchestration?
3. Are the 256 KiB request, 128 KiB response, 18-second deadline, 4,096 output-token, and $1 per-call
   hard maxima appropriate ceilings rather than deployment defaults?
4. Should `pending_reconciliation` permit returning an otherwise authoritative candidate, or should
   uncertain cost always fail the call?
5. What maximum policy/grant validity and emergency revocation objective balance Control-outage
   isolation with prompt route revocation?
6. Does the initial caller identity and profile naming remain Utopia-specific while the execution
   service implementation stays reusable?

## 24. Authorization boundary

This document authorizes no code changes, repositories, databases, migrations, provider calls,
credentials, secrets, spending, infrastructure, deployment, traffic, or production activation.

Acceptance of the text authorizes only the next separately approved implementation-planning or
conformance-bundle step. Existing corpus, provider, budget, and production approvals remain limited
to their original scopes.
