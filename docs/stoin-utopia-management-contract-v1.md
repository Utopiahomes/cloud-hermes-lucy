# Stoin Control ↔ Utopia Homes Management Contract v1.0

**Document revision:** v1.0 Release Candidate 3

**Contract version:** `1.0`

**Status:** Design only; no implementation or deployment authority

**Review state:** Claude's Homes-side review, Lyra's Control-side determinations, and Lucy's protocol
review are incorporated. The normative text is frozen for the RC3 conformance-bundle rebuild and
fresh independent review. This document still grants no implementation or deployment authority.

**Provider:** Utopia Homes Prime management adapter

**Consumer:** Stoin Control management client

**Date:** 2026-09-15

## 1. Purpose

This contract gives Stoin Control a small, read-only way to identify and observe Utopia Homes Prime
without reading the Homes database, carrying guest traffic, or becoming a runtime dependency of the
business.

Version 1.0 exposes exactly four management resources:

- identity;
- health;
- version; and
- capabilities.

The first implementation proof must use an independently deployed Stoin Control process and an
independently deployed transitional Homes management-adapter process. They communicate only through
this authenticated HTTP contract. They do not share a database connection, ORM, migration chain,
runtime, or release artifact.

## 2. Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative requirements.

Examples are illustrative unless explicitly labeled normative. JSON member names, enumerated values,
paths, authentication claims, and size/time limits in this document are normative for contract v1.0.

## 3. Non-goals

Management Contract v1.0 does not:

- answer guest questions or carry guest/customer content;
- expose Homes business records, knowledge snapshots, prompts, conversation history, citations, or
  provider/model details;
- create, update, delete, deploy, restart, back up, restore, or configure anything;
- provision identities, keys, realms, databases, runtimes, or service principals;
- authorize business operations;
- define the Homes Business Contract or `guest.answer` payload;
- define Shared Model Execution or `inference.execute`;
- expose logs, traces, stack traces, environment variables, secrets, hostnames, database identifiers,
  IP addresses, or cloud-resource identifiers;
- require Homes to call Stoin Control while serving ordinary business traffic; or
- imply that the website Application is Utopia Homes Prime.

Provisioning, key distribution, trust rotation, deployment, and rollback remain out-of-band operations.

## 4. Parties and authority

| Role | Stable identity | Responsibility |
| --- | --- | --- |
| Managed synth | `stoin:synth:utopia-homes-prime` | Stable Business Prime identity |
| Owning realm | `stoin:realm:utopia-homes` | Owns Homes business data, policy, capabilities, and releases |
| Management provider | Homes management adapter | Serves the four read-only resources on behalf of Homes Prime |
| Management consumer | Stoin Control management reader | Authenticated polling and opaque management observation |
| Implementation steward, Homes side | Claude | Reviews and implements the provider after separate authorization |
| Implementation steward, Control side | Lyra | Reviews and implements the consumer after separate authorization |

Implementation stewardship does not transfer business-data or runtime authority to either coding
teammate.

## 5. Transport and base path

- Transport **MUST** be HTTPS with TLS 1.2 or later.
- Private networking **SHOULD** be used where the deployment platform supports it.
- The contract base path is `/management/v1`.
- All v1.0 operations are HTTP `GET` and **MUST NOT** accept a request body.
- Responses use UTF-8 JSON with `Content-Type: application/json`. Requests have no body and need not
  send `Content-Type`.
- Successful responses **MUST NOT** exceed 64 KiB. `/health` **MUST NOT** exceed 16 KiB.
- The provider **MUST** reject credential-bearing redirects and **MUST NOT** redirect a management
  request to another host.
- The provider **MUST** complete each request within two seconds. It **SHOULD** normally answer within
  500 milliseconds because no endpoint performs customer-data retrieval.
- The consumer **MUST** use a total timeout of three seconds or less.
- The consumer **MAY** retry once with bounded jitter only after a network failure, timeout, or `429`,
  `500`, or `503` response. It **MUST NOT** retry any other HTTP response.

The deployment platform may expose a separate process-liveness endpoint. Such an endpoint is not part
of this contract and does not represent Homes business health.

Stoin Control receives the exact adapter base URL through out-of-band provisioning as opaque management
registry metadata. Version 1.0 has no dynamic discovery. The Control client pins the configured HTTPS
scheme and host, does not accept caller-selected endpoints, and does not follow redirects.

## 6. Service authentication profile

### 6.1 Profile name

Contract v1.0 uses `stoin-service-jwt-v1`.

### 6.2 Requirements

- Stoin Control **MUST** send `Authorization: Bearer <JWT>`.
- The JWT **MUST** be signed with a dedicated Ed25519 management-client key using `alg=EdDSA`.
- The JWT header **MUST** contain the provisioned key identifier in `kid`.
- Homes **MUST** verify the signature locally against an exact allowlist of provisioned public keys.
- Homes **MUST NOT** call Stoin Control, a shared directory, or an external introspection endpoint to
  authorize a request.
- Management JWT keys **MUST NOT** be reused as deployment, policy-notary, customer-authentication,
  provider, or business-contract keys.
- Key provisioning and rotation are outside this contract.
- A static shared bearer token is not an accepted production profile.

### 6.3 Required JWT claims

| Claim | Required value or rule |
| --- | --- |
| `iss` | `stoin:control` |
| `sub` | `stoin:service:control-management-reader` |
| `aud` | `stoin:management:utopia-homes-prime` |
| `scope` | Exact string `management.read` for v1.0 |
| `iat` | Integer UTC epoch seconds; no more than 30 seconds in the future |
| `nbf` | Integer UTC epoch seconds; no more than 30 seconds in the future |
| `exp` | Integer UTC epoch seconds; later than `iat` and no more than 300 seconds after `iat` |
| `jti` | UUID v4 string unique to the issued token |

Both hosts **MUST** maintain synchronized UTC clocks using their platform time service or NTP. JWT
verification permits at most 30 seconds of symmetric clock skew when evaluating `iat`, `nbf`, and
`exp`. A host known to exceed that bound **MUST** treat the management channel as unavailable until
clock synchronization is restored; it must not widen the allowance dynamically.

The provider **MUST** reject missing, malformed, expired, premature, wrong-issuer, wrong-subject,
wrong-audience, wrong-scope, unknown-key, and wrong-algorithm tokens before assembling a management
response. Authentication failures return the same generic body and must not disclose which check
failed.

The JWT's nominal lifetime is no more than 300 seconds. With the fixed 30-second verification skew, the
latest accepted instant is `exp + 30 seconds`: a token may therefore be accepted for at most 330 seconds
after `iat`. It is accepted exactly at `exp + 30` and rejected after that instant. Because v1.0 is
read-only, the provider is not required to maintain a durable `jti` replay store. A future mutating
contract would require stronger anti-replay semantics.

## 7. Common request requirements

Every request **MUST** include:

```http
Authorization: Bearer <stoin-service-jwt-v1>
Accept: application/json
X-Request-ID: <UUID-v4>
```

The provider **MUST** return the same `X-Request-ID`. If the request ID is missing or invalid, the
provider returns `400 invalid_request` and does not substitute a server-generated request ID. Error
responses use the separate provider-generated correlation ID defined in §13.

Requests **MUST NOT** contain query parameters. Unknown query parameters return `400 invalid_request`.

## 8. Common response rules

Every successful response contains:

```json
{
  "contract_version": "1.0",
  "observed_at": "2026-09-15T20:15:30Z"
}
```

These members appear alongside the resource-specific members defined below.

- `contract_version` is exactly `1.0`.
- `observed_at` is an RFC 3339 UTC timestamp with whole-second precision and a trailing `Z`.
- Responses **MUST** include `Cache-Control: no-store` unless an endpoint specifies otherwise.
- Responses **MUST NOT** include cookies.
- Identifiers are case-sensitive and **MUST NOT** contain secrets or customer data.
- Arrays whose ordering is not otherwise meaningful **MUST** be sorted lexicographically by stable ID.
  Arrays described as sets **MUST NOT** contain duplicate entries.
- Numbers representing counts **MUST** be JSON integers, never floats or numeric strings.
- Null members are prohibited unless a field explicitly permits null.

## 9. `GET /management/v1/identity`

Returns the stable synth and realm identity. Runtime, deployment, release, and infrastructure
identifiers do not belong in this response.

### 9.1 Response

```json
{
  "contract_version": "1.0",
  "observed_at": "2026-09-15T20:15:30Z",
  "synth_id": "stoin:synth:utopia-homes-prime",
  "realm_id": "stoin:realm:utopia-homes",
  "synth_class": "business-prime",
  "display_name": "Utopia Homes Prime"
}
```

### 9.2 Constraints

| Member | Type | Constraint |
| --- | --- | --- |
| `synth_id` | string | Exact stable value `stoin:synth:utopia-homes-prime` |
| `realm_id` | string | Exact stable value `stoin:realm:utopia-homes` |
| `synth_class` | string | Exact value `business-prime` |
| `display_name` | string | 1–100 Unicode characters; presentation only, never authority |

The consumer must authenticate every request and must not treat a prior identity response as proof of
current health or deployment state.

## 10. `GET /management/v1/health`

Reports whether Homes Prime can currently perform its advertised business capabilities. A successful
HTTP response means only that the management adapter responded and authenticated the caller.

Business health is represented in the JSON body, not by converting every degraded state into an HTTP
error.

### 10.1 Response

```json
{
  "contract_version": "1.0",
  "observed_at": "2026-09-15T20:15:30Z",
  "status": "unknown",
  "management_provider_release_id": "homes-management:release:2026-09-15.1",
  "degraded_capabilities": [],
  "reason_codes": ["health_coverage_limited"]
}
```

### 10.2 Constraints

| Member | Type | Constraint |
| --- | --- | --- |
| `status` | string | `healthy`, `degraded`, `unavailable`, or `unknown` |
| `management_provider_release_id` | string | Current opaque management-provider release ID; 1–128 printable ASCII characters |
| `degraded_capabilities` | string array | Sorted set of unique advertised, enabled capability IDs authoritatively known to be impaired |
| `reason_codes` | string array | Sorted set of unique safe codes from the v1.0 set below; non-empty when `status=unknown` |
| `retry_after_seconds` | integer or absent | 1–3600; absent when no estimate is available |

Allowed v1.0 reason codes:

- `capacity_limited`
- `configuration_error`
- `dependency_unavailable`
- `health_coverage_limited`
- `maintenance`
- `no_enabled_capabilities`
- `release_in_progress`
- `unspecified`

Reason codes are content-free categories. They **MUST NOT** name vendors, hosts, databases, credentials,
customer records, or internal exceptions. `unspecified` **MUST NOT** appear alongside any other reason
code at any status. It **MAY** be used alone only when no more specific v1.0 reason code truthfully
describes the condition. Whether that evidentiary judgment was truthful cannot be proven from the wire
response or schema alone. `no_enabled_capabilities` **MUST** be present when no capability is enabled and
**MUST NOT** be present when any capability is enabled.

Status is defined over two sets observed together:

- `E` is the set of capabilities currently advertised with `state=enabled`; and
- `I` is the set returned in `degraded_capabilities`.

`I` **MUST** be a subset of `E`; disabled and deprecated capabilities are not impaired capabilities and
**MUST NOT** appear in `I`. The status rules are:

- `healthy`: `E` is non-empty, `I` is empty, and every member of `E` is authoritatively known to be
  serviceable;
- `degraded`: `I` is a non-empty proper subset of `E`, and every member of `E` outside `I` is
  authoritatively known to be serviceable;
- `unavailable`: either `E` is non-empty and `I = E`, meaning every enabled capability is
  authoritatively known to be unserviceable, or `E` is empty, `I` is empty, and `reason_codes` contains
  `no_enabled_capabilities`; and
- `unknown`: `E` is non-empty, `I` is empty or a proper subset of `E`, serviceability of the remainder
  cannot be established authoritatively, and `reason_codes` is non-empty. Unknown is an observability
  state, not evidence of impairment.

When `status=unknown`, `unspecified` may satisfy the non-empty reason-code requirement only under the
fallback rule above. In transitional provider mode, `reason_codes` **MUST** include
`health_coverage_limited`; `unspecified` alone is not sufficient.

`degraded` becomes reachable only when two or more capabilities are advertised and enabled. With the single v1.0
capability `guest.answer`, the reachable operational states are `healthy`, `unavailable`, and `unknown`.
The first-proof conformance vectors **MUST NOT** invent a second capability merely to manufacture a
positive `degraded` case; the schema retains the value for the first real multi-capability release.

The provider **MUST NOT** perform a model call, guest query, customer-data read, or synthetic business
transaction to answer `/health`. It may use bounded local status and content-free dependency probes.

The transitional adapter cannot verify the existing shared-database knowledge query without receiving
authority this proof deliberately withholds. Until Homes exposes an authoritative, content-free health
signal covering the actual `guest.answer` knowledge path, the adapter **MUST NOT** report
`status=healthy` for that capability. It returns `status=unknown`, leaves `degraded_capabilities` empty,
and includes `health_coverage_limited` in `reason_codes`. With only one enabled capability, the allowance
for an `unknown` response to name an independently known impaired proper subset is inert: naming
`guest.answer` would make `I = E` and therefore require `status=unavailable`. This is an explicit
transitional limitation, not evidence that the business capability is failing.

## 11. `GET /management/v1/version`

Returns independently verifiable runtime and release identity without revealing source credentials or
infrastructure topology.

### 11.1 Response

```json
{
  "contract_version": "1.0",
  "observed_at": "2026-09-15T20:15:30Z",
  "management_provider": {
    "deployment_id": "stoin:deployment:utopia-homes-management:production",
    "runtime_id": "stoin:runtime:utopia-homes-management:01J7XYZEXAMPLE",
    "release_id": "homes-management:release:2026-09-15.1",
    "software_version": "0.1.0",
    "artifact_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "deployed_at": "2026-09-15T19:45:00Z"
  },
  "managed_synth": {
    "synth_id": "stoin:synth:utopia-homes-prime",
    "observed_release_id": "homes-prime:release:legacy-public-2026-09-14.1"
  },
  "supported_management_contracts": ["1.0"]
}
```

### 11.2 Constraints

| Member | Type | Constraint |
| --- | --- | --- |
| `management_provider.deployment_id` | string | Stable management-provider deployment-slot ID; 1–160 printable ASCII characters |
| `management_provider.runtime_id` | string | Unique management-provider runtime ID; 1–160 printable ASCII characters |
| `management_provider.release_id` | string | Exact opaque provider release ID matching `/health`; 1–128 printable ASCII characters |
| `management_provider.software_version` | string | Provider semantic version `MAJOR.MINOR.PATCH` |
| `management_provider.artifact_digest` | string | Lowercase `sha256:` plus exactly 64 hexadecimal characters |
| `management_provider.deployed_at` | string | Provider deployment RFC 3339 UTC timestamp |
| `managed_synth.synth_id` | string | Exact stable value `stoin:synth:utopia-homes-prime` |
| `managed_synth.observed_release_id` | string or absent | Opaque observed Homes Prime release ID; absent when no authoritative release observation exists |
| `supported_management_contracts` | string array | Sorted, non-empty; includes `1.0` |

The management-provider fields identify the adapter answering this contract. The managed-synth fields
identify the synth it represents. Redeploying the adapter changes provider identity/version fields but
**MUST NOT** imply a Homes Prime upgrade. `observed_release_id` changes only when the adapter has an
authoritative content-free observation of the managed synth release. Neither identity authorizes
release, rollback, or deployment.

The values returned here are provider-neutral Stoin/Homes identifiers supplied by the Homes release
process. Raw Vercel, Render, or other host-specific identifiers **MUST NOT** become contract authority.
Homes may map provider identifiers to these values in deployment evidence outside this response.

## 12. `GET /management/v1/capabilities`

Returns the business capabilities Homes Prime advertises. It does not execute those capabilities or
expose their business payloads.

### 12.1 Response

```json
{
  "contract_version": "1.0",
  "observed_at": "2026-09-15T20:15:30Z",
  "capabilities": [
    {
      "capability_id": "guest.answer",
      "contract_version": "1.0",
      "state": "enabled"
    }
  ]
}
```

### 12.2 Capability constraints

| Member | Type | Constraint |
| --- | --- | --- |
| `capability_id` | string | Lowercase dot-separated identifier matching `^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$` |
| `contract_version` | string | Capability contract semantic version `MAJOR.MINOR` |
| `state` | string | `enabled`, `disabled`, or `deprecated` |
| `business_contract_id` | string or absent | Stable, non-secret identifier; present only after the Business Contract is formally approved |

The array is sorted by `capability_id`, contains no duplicates, and **MUST NOT** include provider,
model, prompt, database, schema, customer, or secret metadata.

Transient impairment belongs in `/health`; it does not change capability `state`. A capability is
`disabled` only when business policy or release configuration disables it, not merely because a
dependency is temporarily unavailable.

Version 1.0 does not require `business_contract_id` for `guest.answer`. Capability advertisement must
not invent or reserve the identifier of a Business Contract that has not yet been approved.

## 13. Error contract

All non-success responses use:

```json
{
  "contract_version": "1.0",
  "error": {
    "code": "invalid_request",
    "message": "The management request is invalid.",
    "correlation_id": "1eb6c24c-adfb-4512-987c-13ae318741bb",
    "retryable": false
  }
}
```

Every error includes a provider-generated UUID v4 `correlation_id`, returned in both the body and the
`X-Correlation-ID` header. If the inbound `X-Request-ID` is a valid UUID v4, the error also includes
`request_id` with that exact value and echoes it in the `X-Request-ID` header. If it is missing or
invalid, `request_id` and the `X-Request-ID` response header are absent. A correlation ID is never
presented as the caller's request ID.

| HTTP status | Code | Meaning | Retryable |
| --- | --- | --- | --- |
| `400` | `invalid_request` | Invalid request ID, query, method framing, or headers | false |
| `401` | `authentication_failed` | Missing or invalid service JWT | false |
| `403` | `authorization_denied` | Valid identity lacks `management.read` | false |
| `405` | `method_not_allowed` | Method is not `GET` | false |
| `406` | `contract_not_supported` | Requested contract representation is unsupported | false |
| `413` | `request_too_large` | Request exceeds configured header/transport limits | false |
| `429` | `rate_limited` | Management reader exceeded its bounded rate | true |
| `500` | `internal_error` | Provider could not assemble a valid response | true |
| `503` | `management_unavailable` | Management adapter cannot currently report state | true |

Error messages are fixed, generic strings. They **MUST NOT** contain exception text or internal
identifiers. Retryable errors **SHOULD** include HTTP `Retry-After` when a bounded estimate exists.

The consumer retries only the network/timeout and `429`/`500`/`503` conditions allowed by §5, regardless
of any conflicting intermediary behavior.

The provider **SHOULD** permit at least 12 requests per minute from the exact management principal.
The consumer **SHOULD** poll `/health` no more often than once every 30 seconds during normal operation.
The consumer **SHOULD** read `/version` at startup and once every five minutes during normal operation;
it **MAY** refresh sooner after observing `release_in_progress`, while remaining inside the provider's
rate limit.

## 14. Versioning and compatibility

- The URL carries the contract major version: `/management/v1`.
- The body carries exact major/minor version: `contract_version: "1.0"`.
- Removing a field, changing field meaning/type, changing an identifier, narrowing an accepted value,
  or changing authentication semantics is breaking and requires `/management/v2`.
- An additive optional field may be introduced in a later v1 minor version.
- Consumers **MUST** ignore unknown response members within major version 1.
- Providers **MUST** return all v1.0 required members while claiming support for `1.0`.
- New enum values require a minor version. A v1.0 consumer encountering an enum token not defined by
  the exact approved v1.0 schema **MUST** treat that resource as unavailable rather than guessing its
  meaning. The defined health status `unknown` is a recognized value and **MUST NOT** trigger this rule.
- Capability contracts version independently from this management contract.
- Control **MUST NOT** infer a capability from source code, model name, or historical release. Only the
  authenticated capability response is authoritative for current advertisement.

Before implementation, the stewards will approve a machine-readable v1.0 artifact bundle containing
the four response schemas, the error schema, and positive/negative conformance vectors. The bundle has
one canonical SHA-256 digest pinned independently by both repositories. It is a contract artifact, not
a shared runtime library; neither implementation imports the other repository.

Every positive conformance vector **MUST** first satisfy every applicable structural schema and
cross-resource invariant as a complete legal state before it may count as evidence for the particular
field behavior it targets. Structural conformance can prove set membership, uniqueness, ordering, and
the relationships among `E`, `I`, and `status`; it cannot prove that the provider actually possessed
sufficient evidence for a serviceability judgment. Evidentiary correctness remains a provider-mode and
acceptance-test obligation.

## 15. Privacy, data minimization, and logging

Management requests and responses are content-free operational metadata.

The provider and consumer may log only:

- request ID;
- provider correlation ID;
- endpoint name;
- authenticated service-principal ID;
- HTTP response class;
- latency;
- contract version;
- synth ID;
- opaque release ID; and
- safe health status/reason codes.

They **MUST NOT** log JWTs, authorization headers, questions, answers, prompts, knowledge content,
conversation/session identifiers, customer identifiers, booking information, personal data, secrets,
or internal exception text.

Stoin Control may persist the latest authenticated identity, version, capabilities, health status,
safe reason codes, and observation timestamps. It **MUST NOT** persist Homes business content through
this interface.

## 16. Failure isolation

- Homes business traffic **MUST NOT** synchronously call this management interface.
- Homes business traffic **MUST NOT** call Stoin Control for authorization, routing, health, model
  execution, or release selection.
- Stoin Control outage, timeout, bad credentials, or stale observations **MUST NOT** make Homes business
  capabilities unavailable.
- Management adapter failure **MUST NOT** make Homes business capabilities unavailable.
- A failed or stale health observation means Control's knowledge is stale; it does not authorize
  Control to mark Homes business data invalid or change Homes state.
- Control may alert or stop management actions when observations are stale. It may not mutate Homes in
  v1.0.

## 17. Transitional Homes adapter

The first provider may be a transitional adapter while Utopia Homes Prime is still emerging as an
independent runtime.

The adapter:

- **MUST** be deployed as a process independent from Stoin Control;
- **MUST** have its own artifact, version, deployment identity, runtime identity, and release lifecycle;
- **MUST NOT** be implemented as a Vercel function inside `utopia-homes-web`, or as any artifact that is
  rebuilt or redeployed merely because the website Application changes;
- **MUST NOT** use Stoin Control's database or credentials;
- **MUST NOT** receive a Homes customer-data database credential for this proof;
- **MAY** use deployment-owned static identity/version/capability configuration;
- **MAY** use bounded, content-free probes to determine capability health;
- **MUST NOT** proxy `guest.answer` or any business payload through the management contract; and
- **MUST** be replaceable by a native Homes Prime implementation without changing the Control client.

This adapter proves the seam. It is not a permanent second Homes runtime.

Its hosting provider and price tier are deployment decisions, not contract semantics. It may share a
cloud vendor with either system, but it must remain a distinct Homes-owned service, artifact, identity,
and release lifecycle.

## 18. Acceptance criteria for the first proof

The contract is ready for implementation only after both implementation stewards approve this draft.
Implementation is accepted only when evidence shows all of the following:

1. Control and the Homes adapter are independently deployed processes with distinct artifacts and
   runtime identities.
2. Either process can be released without rebuilding or redeploying the other.
3. There is no shared database URL, ORM import, migration chain, filesystem state, or direct table access
   across the seam.
4. All four authenticated endpoints return schema-valid responses. `/identity` returns the exact Utopia
   Homes synth and realm IDs, and `/version` returns the exact managed synth ID.
5. Missing, malformed, expired, premature, wrong-issuer, wrong-subject, wrong-audience, wrong-scope,
   unknown-key, and wrong-algorithm JWTs fail before response assembly.
6. Authentication failures are indistinguishable except for content-free internal metrics.
7. Identity remains stable across adapter restarts and release changes.
8. Management-provider and managed-synth identities are distinct in `/version`; an adapter release does
   not appear as a Homes Prime release.
9. Capability ordering is deterministic and contains no provider, model, prompt, database, or customer
   metadata.
10. The transitional adapter reports `status=unknown` with `health_coverage_limited`, an empty
    `degraded_capabilities` array, and no false `healthy` or known-impairment claim until an authoritative
    content-free signal covers the real knowledge path.
11. Stopping Stoin Control does not interrupt the existing Homes guest path.
12. Stopping the management adapter does not interrupt the existing Homes guest path; Control observes a
    timeout/unavailable state only.
13. Making the sole Homes business capability non-serviceable during the acceptance test yields either
    `unavailable` naming the complete enabled set when the adapter can authoritatively establish the
    impairment, or `unknown` with an empty impaired set when it cannot. The response is bounded and
    content-free, no synthetic customer request is executed, and the first proof does not claim an
    operational `degraded` case.
14. Timeouts and one-retry limits are enforced; no retry storm occurs.
15. Logs and traces contain no JWTs, business content, customer identifiers, secrets, or exception text.
16. Contract tests run over network HTTP between the two processes rather than importing both
    implementations into one test process.
17. Rollback of either process restores its prior compatible release without changing the other process
    or Homes business data.
18. A missing or malformed `X-Request-ID` returns `400` with a provider correlation ID and without a
    fabricated request ID; a valid request ID is echoed exactly.
19. JWT boundary tests cover accepted skew and rejection beyond the 30-second allowance on `iat`, `nbf`,
    and `exp`, including acceptance exactly at `exp + 30` and rejection after that instant, with both
    hosts configured for synchronized UTC clocks.

## 19. Homes and architecture review disposition

Claude's Homes-side reviews and Lucy's protocol review are incorporated as follows:

1. The stable synth ID, realm ID, synth class, and `guest.answer` capability ID are accepted.
2. Per-capability state objects remain deferred, but the overall health model now has an explicit
   `unknown` state so incomplete observability is not mislabeled as impairment.
3. The transitional adapter's coarse health limitation is explicit. It reports `unknown`, not
   `healthy` or `degraded`, until a content-free signal covers the real knowledge path.
4. The adapter is an independently deployed Homes-owned process, not a Vercel function embedded in the
   website Application.
5. `/api/lucy` remains a website Application adapter and is absent from the management surface.
6. The nominal five-minute read-only `jti` tradeoff is accepted for v1.0, with the effective
   330-second skew boundary stated explicitly. Any future mutating contract requires stronger replay
   protection.
7. The proposed minimum rate capacity and normal polling cadence are accepted.
8. `/version` separates management-provider identity from the managed synth's observed release.
9. Error correlation is valid even when the caller's request ID is absent or malformed.
10. `business_contract_id` remains optional until a Homes Business Contract is formally approved.
11. Retries are restricted to network/timeouts and `429`, `500`, or `503`.
12. Both hosts maintain synchronized clocks and enforce one fixed 30-second JWT skew allowance.
13. The recognized health status `unknown` is distinct from an unrecognized enum token.
14. The generic reason code is `unspecified`, not `unknown`.
15. Acceptance criteria require identity fields only from the endpoints that define them.
16. `degraded` remains in the schema but has no fabricated positive operational vector while
    `guest.answer` is the sole advertised capability.
17. `/version` has an explicit five-minute normal polling cadence.
18. Health semantics are set-based: the impaired set is unique, ordered, and restricted to advertised
    enabled capabilities; complete impairment is `unavailable`, partial impairment with a known
    serviceable remainder is `degraded`, and incomplete evidence is `unknown`.
19. Zero enabled capabilities is an explicit `unavailable` configuration state with
    `no_enabled_capabilities`, not a vacuously healthy or unknown state.
20. `unknown` always carries at least one safe reason code; transitional mode specifically requires
    `health_coverage_limited`.
21. `unspecified` is a stand-alone fallback reason at every status and never accompanies a more specific
    code.
22. Positive vectors must be complete legal states before they exercise a narrower field behavior;
    evidentiary truth remains outside what schemas alone can prove.

## 20. Control-side determinations

1. **Authentication is feasible as specified.** The Control codebase already has reviewed Ed25519
   primitives and an exact cryptography dependency. Implementation must use an audited JOSE/JWT
   implementation rather than hand-written token parsing. A new dedicated management-client key and
   purpose are required; existing policy or receipt keys are not reused.
2. **The consumer can remain business-schema-free.** Its persistence allowlist is limited to the fields
   named in §§9–12 plus observation timestamps and safe error/status metadata. It does not import Homes
   models, knowledge schemas, or business contracts.
3. **Polling is sufficient for v1.0.** The timeout, one-retry ceiling, safe reason codes, and stale-state
   behavior cover the first read-only proof. Events, subscriptions, and mutations remain deferred.
4. **Conformance remains repository-independent.** Each side tests its deployed HTTP implementation
   against the same digest-pinned schema/vector bundle. Neither side imports the other's implementation
   or runtime library.
5. **Connection is explicit, not discovered at request time.** Control receives one exact HTTPS base URL
   during out-of-band provisioning and authenticates each call with a short-lived service JWT. Homes
   verifies locally, so neither ordinary management reads nor business traffic require an online
   Control authorization service.

## 21. Deferred to later versions

The following remain deliberately absent:

- events or webhooks;
- configuration status or mutation;
- grants and revocation management;
- task dispatch;
- evaluation invocation or results;
- backup/restore status;
- usage or billing details;
- deployment or rollback actions;
- business capability invocation;
- customer identity; and
- cross-realm discovery.

Their absence is a boundary feature, not unfinished v1.0 scope.

## 22. Implementation stewardship after approval

This draft does not authorize implementation. If implementation is later approved:

- Claude owns the Homes management adapter, Homes-side schemas and response assembly, deployment
  packaging, provider-side tests, and Homes rollback evidence.
- Lyra owns only the Stoin Control JWT issuer/client, the narrow Control observation model,
  consumer-side conformance tests, and Control failure-isolation evidence.
- Claude should own ambiguous seam code when it can live cleanly on the Homes side. Shared execution or
  Control infrastructure remains Lyra's responsibility only when the boundary register assigns it
  there.
- Neither steward changes the other's database or internal implementation to make the proof pass.
