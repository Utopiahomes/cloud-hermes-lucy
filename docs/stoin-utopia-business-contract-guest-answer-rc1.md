# Utopia Homes Business Contract — `guest.answer` RC1

**Document revision:** Release Candidate 1  
**Capability version:** `guest.answer@1.0`  
**Status:** protocol freeze candidate; no implementation or deployment authority  
**Review state:** Claude's Homes-side corrections, Lucy's product/architecture review, and an independent architecture challenge pass are incorporated; §23 records the settled freeze decisions  
**Business provider:** Utopia Homes Prime  
**Initial application consumer:** Utopia Homes website guest adapter  
**Date:** 2026-09-16

## 1. Purpose

This contract lets an approved Utopia application ask Utopia Homes Prime to answer an anonymous
prospective guest's ordinary hospitality question. It defines the first request-time Business
Contract seam while keeping Stoin Control out of the guest path.

The capability must produce a useful, conversational Utopia answer by combining:

- normal LLM language and reasoning;
- Utopia-owned approved public knowledge;
- bounded temporary conversation history;
- current page context; and
- approved public links and actions.

It must not rebuild ordinary conversation from handwritten query patterns. Exact business facts
remain grounded and validated even though the language around them is model-generated.

## 2. Architectural boundary

```text
anonymous browser
      |
      | same-origin public request
      v
Utopia Homes website application
  /api/lucy guest adapter
      |
      | authenticated Business Contract
      v
Utopia Homes Prime
  guest.answer@1.0
      |
      +-- Homes-owned public data and policy
      |
      +-- Shared Model Execution (private implementation dependency)
```

Stoin Control is not a caller, authorizer, router, fallback, data source, or runtime dependency for
this operation. A Control outage must not prevent a healthy Homes deployment from answering guests.

The website application is not Utopia Homes Prime. It is an independently released consumer and
presentation adapter. Shared Model Execution supplies provider-neutral inference mechanics; it does
not own Homes prompts, knowledge, business rules, or answers.

## 3. Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

Examples are illustrative unless marked normative. Paths, member names, enumerated values, limits,
and authentication claims are normative for `guest.answer@1.0` once the contract is accepted.

## 4. V1 scope

Version 1.0 supports:

- free-form, public, guest-oriented conversation;
- approved property, destination, owner-service, and Utopia Design information;
- comparisons and multi-constraint questions using verified public facts;
- approved curated local recommendations;
- general hospitality guidance clearly distinguished from Utopia-specific facts;
- temporary multi-turn continuity;
- page-aware answers and approved property/service links;
- natural correction, clarification, partial-answer, and out-of-scope behavior; and
- content-free operational diagnostics.

Version 1.0 does not support:

- customer identity, login, persistent memory, or cross-device conversation recovery;
- reservation, owner, guest, payment, access-code, maintenance, or private Design-project data;
- live availability, live price, quote, booking, hold, payment, or reservation mutation;
- sending messages or email, creating tasks, or taking any external action;
- arbitrary web browsing or unreviewed local-business claims;
- browser-to-Prime credentials;
- Control-plane data, management operations, or management credentials; or
- a public API for Shared Model Execution.

Published explanations of the booking process or Design estimate process are allowed. They must not
be confused with live availability, a binding price, or reservation access.

Public information owned by another Utopia business domain, including a future independent Utopia
Design domain, may be consumed only through an approved published projection or versioned contract.
Including that information in a Homes answer does not transfer canonical ownership to the Homes realm.

## 5. Parties and ownership

| Responsibility | Owner |
| --- | --- |
| Public business knowledge, effective operational restrictions, approved links, answer behavior, evidence policy, and customer-facing fallbacks | Utopia Homes Prime |
| Browser session state, panel behavior, same-origin abuse controls, and presentation | Utopia Homes website application |
| Provider routing, bounded inference execution, provider privacy controls, and execution cost settlement | Shared Model Execution |
| Deployment observation and offline evaluation orchestration | Stoin Control, through separate management interfaces only |

No party reads another party's database. Prime may call Shared Model Execution through its own
private execution contract. That internal call is not exposed to the website and is not defined by
this document.

## 6. Endpoint and transport

The provider exposes:

```http
POST /business/v1/guest/answer
```

- Transport **MUST** be HTTPS with TLS 1.2 or later.
- The endpoint **MUST** accept and return UTF-8 JSON.
- The website **MUST** call it from server-side code. Browsers **MUST NOT** receive Business Contract
  credentials or the provider's private origin when an application proxy can keep it private.
- Requests **MUST NOT** follow a redirect to another host.
- The provider **MUST** complete or fail each attempt within 15 seconds.
- The website consumer **MUST** bound the complete interaction, including one possible retry and
  backoff, to 22 seconds.
- Streaming is not part of v1.0. A later compatible capability version may add it.
- Successful response bodies **MUST NOT** exceed 64 KiB.
- Request bodies **MUST NOT** exceed 64 KiB. The byte limit and decoded character limits in §9 apply
  independently. The server-side consumer should serialize validated strings directly as UTF-8
  rather than expanding ordinary Unicode into `\\u` escape sequences.
- Responses **MUST** include `Cache-Control: no-store` and **MUST NOT** set cookies.

The browser-facing `/api/lucy` route is an application adapter and is not part of this service
contract. It may use a smaller public response shape but must preserve the semantic distinctions in
this contract.

## 7. Service authentication and authorization

### 7.1 Profile

The initial profile is `stoin-business-jwt-v1`:

- Ed25519 signature with `alg=EdDSA`;
- exact `kid` from the provider's allowlist;
- locally verified by Homes Prime without calling Stoin Control or an introspection service;
- a dedicated key that is not reused for Management Contract, deployment, model-provider,
  customer-authentication, or policy-notary operations; and
- a maximum nominal token lifetime of 300 seconds with at most 30 seconds of clock skew.

For each accepted key, Prime locally binds the exact issuer, subject, audience, deployment
environment, and permitted capabilities. Claimed identity cannot select or expand authorization.
Production and nonproduction keys are distinct and non-interchangeable. No guest request may trigger
key discovery, token issuance, introspection, rotation, or authorization through Stoin Control.

### 7.2 Initial caller claims

| Claim | Required value or rule |
| --- | --- |
| `iss` | `stoin:application:utopia-homes-web` |
| `sub` | `stoin:service:utopia-homes-web-guest-adapter` |
| `aud` | `stoin:business:utopia-homes-prime` |
| `scope` | Exact string `guest.answer` |
| `iat`, `nbf`, `exp` | Integer UTC epoch seconds; `nbf == iat`, `iat < exp`, `exp - iat <= 300`; neither `iat` nor `nbf` may be more than 30 seconds in the future |
| `jti` | UUID v4 one-time nonce unique to the issued token |

The credential grants only the public `guest.answer` capability. It grants no private record access
and cannot be expanded by a message, page context, claimed identity, or model interpretation.

Every future application caller receives its own `sub`, key, environment binding, and explicit
capability grant. It must not reuse the website guest adapter's identity.

The provider atomically records a content-free digest of each accepted `jti` until the latest
permitted acceptance instant and rejects replay. Each retry uses a fresh JWT and `jti`, while keeping
the same idempotency key and request payload. Duplicate, malformed, or conflicting security claims
are rejected. A token is rejected after `exp + 30 seconds`; skew is never widened dynamically.
The replay record uses the same Homes-owned, crash-tolerant, content-free coordination facility as
idempotency status, with a separate namespace and retention rule. It never stores a token or request
body.

Authentication and public authorization are established before reading or interpreting the body.
Untrusted signature, key, identity, audience, algorithm, or token-validity failures return generic
`401 authentication_failed`. An otherwise authenticated caller without `guest.answer` returns generic
`403 capability_forbidden`.

### 7.3 Browser boundary

The website adapter **MUST** enforce its own same-origin, method, body-size, rate, and session limits
before calling Prime. Browser-supplied names, email addresses, roles, ownership claims, property IDs,
and page context are untrusted context, never authorization.

## 8. Required request headers

```http
Authorization: Bearer <stoin-business-jwt-v1>
Accept: application/json
Content-Type: application/json
X-Request-ID: <UUID-v4>
Idempotency-Key: <UUID-v4>
```

- `X-Request-ID` is a content-free correlation value. The provider returns it unchanged.
- `Idempotency-Key` identifies one requested assistant turn, not a person or conversation.
- Query parameters are prohibited in v1.0.
- Unknown or malformed required headers return `400 invalid_request`, except authentication failures,
  which return `401 authentication_failed`.

## 9. Request schema

```json
{
  "contract_version": "1.0",
  "session_id": "27b20c7b-777e-4af3-8db1-5fe1fc2f3b7e",
  "message": {
    "turn_id": "056d5f10-ed13-44fa-b8bc-1af90d43dceb",
    "content": "Which home is best for 20 people, four cars, and a pool?"
  },
  "history": [
    {
      "turn_id": "f938d01b-0125-48ed-962b-9c739e43a24f",
      "role": "user",
      "content": "Tell me about the homes with pools."
    },
    {
      "turn_id": "12682577-2c4b-4889-8391-47dca4b38ad4",
      "role": "assistant",
      "content": "Buttercup Beauty and Central Ave Socialization have verified pool information."
    }
  ],
  "page_context": {
    "path": "/stays/buttercup-beauty",
    "subject_type": "property",
    "subject_id": "buttercup-beauty"
  },
  "locale": "en-US"
}
```

### 9.1 Request constraints

- `contract_version` is exactly `1.0`.
- `session_id` and every `turn_id` are UUID v4 values. They are random correlation identifiers, not
  customer identities, grants, ownership evidence, or sufficient abuse-control keys.
- `message.content` is required, after trimming is 1–2,000 Unicode characters, and is treated as
  untrusted text.
- `history` contains zero to 12 prior messages and at most 10,000 characters total.
- History roles are only `user` and `assistant`; `system`, `developer`, `tool`, or unknown roles are
  rejected.
- History must alternate roles, begin with `user`, and end with `assistant` when non-empty.
- The current `message.turn_id` cannot appear in history. All included turn IDs are unique.
- `page_context` is optional. `path` must be a normalized Utopia-relative path of at most 512
  characters. It cannot contain a scheme, host, credentials, query string, fragment, encoded external
  URL, or percent-encoded delimiter that would introduce a query string or fragment.
- `subject_type` is one of `property`, `destination`, `service`, `design`, or `none`.
- `subject_id` is an approved stable public identifier or null. The provider resolves it against
  Homes-owned public data; it never treats it as proof that the record exists or is public.
- `locale` is an approved BCP 47 tag. V1.0 initially guarantees only `en-US`.
- Unknown request members are rejected. This prevents a caller from silently sending identity,
  private context, tool instructions, or future fields to an older provider.

All supplied history, including entries labeled `assistant`, is untrusted browser content. The role
label describes alleged conversation order and establishes neither provenance nor authority. History
cannot establish prior approval, verified facts, policy, tool results, or permissions. Prime
preserves that trust boundary when assembling model context and independently retrieves and
revalidates supporting business facts for the current answer. Signing genuine assistant turns is an
optional later provenance improvement, not a substitute for current grounding.

## 10. Temporary conversation state

- The browser application owns the temporary history presented to Prime.
- History is held in browser memory, not local storage, cookies, analytics, or a durable transcript
  store.
- Same-tab Utopia page navigation preserves the history.
- Minimizing the panel preserves it.
- New-conversation, page refresh, tab close, or 30 minutes of inactivity clears it.
- The website sends only the bounded history required by §9, even if its UI temporarily holds more.
- Request and response content may exist only in volatile process memory for active execution and
  replay, for at most ten minutes from initial admission. Content must not enter persistent caches,
  queues, disks, backups, traces, crash dumps, or provider retention. Encryption alone does not make
  retained content content-free or satisfy this restriction.
- Content-free accounting and deduplication records may persist under an explicitly configured
  retention policy. Durable session telemetry must not be joined to a guest identity, marketing
  profile, or later authenticated session.
- Prime and Shared Model Execution do not create customer memory from public conversation content.

Future persistent or authenticated conversation continuity requires a separate identity, consent,
retention, deletion, and access-control design.

## 11. Idempotency and retry

The provider scopes `Idempotency-Key` to the authenticated service identity, deployment environment,
operation, and exact capability version. It atomically admits the key before paid execution.

One execution means one logical answer pipeline. The pipeline may use a bounded number of provider
invocations for generation, verification, or repair, but duplicate requests cannot start another
pipeline while execution or cost settlement remains unresolved.

- The same key and canonical request within ten minutes returns the same completed result only when
  that result remains in volatile memory and is still eligible under current public restrictions.
- The same key with a different canonical request returns `409 idempotency_conflict`.
- A duplicate while the original remains active returns `409 request_in_progress` with
  `Retry-After` and cannot start another execution.
- If durable content-free state shows completion or an unresolved outcome but volatile response
  content is unavailable, the provider returns `409 idempotency_recovery_unavailable`; it does not
  silently execute again under that key.
- If the original answer is no longer permitted because knowledge or an operational restriction was
  withdrawn or superseded, the provider returns `409 response_invalidated` and never replays it.
- Content-free state may include the scoped key digest, canonical request digest, status, timing, and
  cost/accounting reference. It never includes request or response content.
- Idempotency state expires after ten minutes. The consumer never intentionally reuses an expired key.

The consumer may make at most one automatic retry with the same canonical request and idempotency key
after a transport failure or an error explicitly marked retryable. It uses a fresh valid JWT and
`X-Request-ID` for the new attempt. For an HTTP response it honors `Retry-After`; for a transport
failure it uses a randomized 250–750 millisecond backoff. Both attempts and the backoff share the
22-second interaction deadline. The consumer dynamically limits the second attempt to the smaller of
15 seconds or the remaining interaction budget; it never starts an attempt after the total deadline
has elapsed. Validation, authentication, authorization, version, invalidation, and idempotency
conflicts are not retried automatically.

### 11.1 Initial replica profile

The initial v1.0 deployment uses exactly one active Prime answer coordinator per environment. Model
execution may scale behind that coordinator, but Business Contract admission, volatile replay, and
final response assembly do not load-balance across independent coordinator memories. This makes
same-process replay the normal case while preserving the no-persistent-content rule.

A horizontally scaled coordinator tier requires a separately reviewed replay profile before it may
claim conformance. That profile must either provide deterministic request affinity or use a shared,
memory-only, non-persistent replay cache with equivalent privacy and withdrawal enforcement. Without
one of those mechanisms, `idempotency_recovery_unavailable` would become an expected cross-replica
outcome and is not accepted silently as the v1.0 operating profile.

### 11.2 Canonical request identity

Before hashing, the provider:

1. decodes strict UTF-8 JSON and rejects duplicate member names;
2. validates the v1.0 request and rejects unknown members;
3. trims only `message.content` as specified by §9 while otherwise preserving string code points;
4. preserves omitted optional members as omitted and preserves the one explicitly allowed null
   (`page_context.subject_id`) as null; and
5. serializes the validated body with RFC 8785 JSON Canonicalization Scheme and hashes those bytes
   with SHA-256.

Implementations must use a maintained, reviewed RFC 8785 library with conformance vectors. Hand-
rolled number formatting, string escaping, or Unicode canonicalization is not accepted.

Authentication tokens, `X-Request-ID`, and other transport headers are excluded from request identity.
Reordered object members and insignificant JSON whitespace therefore remain the same request; Unicode
normalization, omitted-versus-null changes, array ordering, or content changes remain distinct.
Replayed `response_id` and `assistant_turn_id` remain unchanged, while the response header echoes the
current attempt's `X-Request-ID`.

## 12. Response schema

```json
{
  "contract_version": "1.0",
  "response_id": "a9ec2c26-cf3d-4a58-9939-cd421db25d71",
  "session_id": "27b20c7b-777e-4af3-8db1-5fe1fc2f3b7e",
  "assistant_turn_id": "ed1f1cfa-125c-4178-ae7d-dbc527a14863",
  "outcome": "answered",
  "answer": "Our public collection currently includes three homes. For 20 guests, four cars, and a pool, Buttercup Beauty is a verified match for those stated requirements.",
  "sources": [
    {
      "source_id": "public-property:buttercup-beauty",
      "title": "Buttercup Beauty",
      "url": "https://www.utopiahomes.com/stays/buttercup-beauty"
    }
  ],
  "actions": [
    {
      "action_id": "view-property:buttercup-beauty",
      "kind": "open_internal_link",
      "label": "Explore Buttercup Beauty",
      "url": "https://www.utopiahomes.com/stays/buttercup-beauty"
    }
  ],
  "limitations": []
}
```

### 12.1 Outcome values

| Outcome | Meaning |
| --- | --- |
| `answered` | The displayed answer addresses the question with sufficient support. |
| `partial` | A supported useful portion is answered and the missing or uncertain detail is explicit. |
| `clarification_needed` | A specific clarification is required before a responsible answer can be given. |
| `out_of_scope` | The request is unrelated or outside the public capability; the answer briefly redirects. |
| `refused` | An in-scope request is declined for a specific safety, privacy, or authority reason. |

Missing knowledge is not a service outage. A supported partial answer uses `200 partial`. Model,
knowledge-service, or execution failure uses the error contract and must not be presented as “we do
not know.”

### 12.2 Response constraints

- `answer` is 1–4,000 characters of display-ready plain text. Markdown and HTML are prohibited in
  v1.0; all links and actions use the structured fields below.
- The consumer renders the answer as text and never interprets model-produced markup.
- `sources` contains zero to eight unique approved public sources.
- Business factual claims require sufficient supporting evidence unless they are served directly
  from an authoritative structured record. Clarification, correction, conversational acknowledgment,
  and general guidance do not require decorative citations.
- A source URL must be selected from Homes-owned approved configuration. The model cannot create or
  modify it.
- `actions` contains zero to four unique approved actions. V1.0 permits only
  `open_internal_link`, `open_external_booking_link`, and `contact_utopia`.
- An external-booking action identifies its actual provider destination. It is never represented as
  a completed reservation, held inventory, or live price.
- `limitations` contains zero to four concise customer-relevant limitations. It must not reveal
  internal provider, prompt, policy, security, or infrastructure details.
- `session_id` exactly matches the request.
- `response_id` and `assistant_turn_id` are new UUID v4 values.
- Unknown response members may be ignored by a v1 consumer. Known members remain strict.

Prime validates every customer-visible field, including answer text, source titles, action labels and
destinations, and limitations. Every destination comes from approved Homes configuration; model-
authored URLs are prohibited. The website validates the response envelope, identifier matches, known
enums, bounds, source/action uniqueness, and action semantics before rendering. A malformed or
incompatible provider response becomes `temporarily_unavailable`.

The website may omit fields or format presentation, but it must not rewrite factual statements,
remove qualifications, change destinations, or truncate text so its meaning changes. Error and static
fallback copy are Homes-owned or Homes-approved.

The provider also returns content-free headers:

```http
X-Request-ID: <request value>
X-Utopia-Business-Release: <opaque release id>
X-Utopia-Knowledge-Release: <opaque approved projection id>
```

The website may retain these identifiers in restricted operational telemetry but must not show them
as customer content or forward them to browser analytics.

## 13. Knowledge, reasoning, and factual authority

Prime constructs the answer from the following precedence order:

1. an effective public operational restriction or withdrawal;
2. current structured public property and service facts;
3. approved descriptive knowledge and curated local-guide records; and
4. general model reasoning that does not claim a Utopia fact.

Effective public operational restrictions and withdrawals override structured facts, descriptive
knowledge, general reasoning, and cached responses.

Homes Prime owns and validates effective public restriction state. If the current state required for
an answer cannot be established, the affected portion fails closed. An expired unresolved restriction
becomes unknown pending review, not automatically resolved. Software rollback must not restore
withdrawn knowledge.

Future authenticated reservation exceptions and authoritative PMS availability, pricing, and stay
restrictions require separately versioned capabilities. Their precedence is defined when those
capabilities exist rather than being implied by `guest.answer@1.0`.

The provider must distinguish:

- **exact business facts** — capacity, beds, parking, locations, amenities, policies, URLs, dates,
  prices, and restrictions are validated against structured or authoritative records;
- **descriptions and explanations** — require supporting approved evidence and final-answer factual
  support checks; and
- **conversation and general guidance** — may use ordinary model reasoning but cannot imply an
  unverified Utopia benefit, supply, endorsement, distance, business hour, or current event.

Valid source IDs alone do not prove support. Prime validates the final displayed answer, including
numbers, negation, property identity, exceptions, comparisons, and limitations. Unsupported prose
cannot be preserved merely because claim metadata is valid.

When support is incomplete, Prime gives the supported portion and identifies what it cannot verify.
It does not substitute an arbitrary relevant property card, repeat the prior answer, or describe an
implementation restriction as a permanent inability.

## 14. Curated local recommendations

Local recommendations are allowed only from a Homes-approved guide or another explicitly approved
public source.

The provider treats these as separate claims:

- the business exists;
- Utopia recommends it;
- its location or relative proximity;
- its hours or current opening status; and
- suitability for a stated preference.

Each claim requires corresponding current support. If the guide supports a coffee shop's identity
but not current hours, Lucy may recommend it while advising the guest to verify hours. If no approved
recommendation exists, Lucy says she does not yet have a verified Utopia recommendation and offers
general destination help; she does not invent a business or issue a blanket refusal.

## 15. Model and execution requirements

- Ordinary relevant conversation **MUST** be handled by a functioning LLM path. A finite intent map,
  exact-question table, or passage echo is not conformant.
- Direct structured rendering **MAY** answer critical exact facts, but it remains part of a coherent
  conversational response.
- The model receives only the bounded context assembled by Prime. It does not receive database,
  provider, environment, or Control credentials.
- Shared Model Execution is stateless with respect to durable customer knowledge and prompt history by
  default. It may hold bounded request state for the active call, recovery, and idempotency window.
- Provider routes must satisfy the approved privacy and retention policy. Unapproved fallback routes
  are prohibited.
- Request, model, and execution limits are separate. Reaching one limit must not silently weaken
  another.
- Cost admission is evaluated before paid execution and settled or recovered through content-free
  accounting references.
- A model's self-reported confidence is not evidence.
- Serving-plane authentication, configuration, knowledge access, inference admission, retries, and
  accounting recovery operate without synchronous Stoin Control access. Shared Model Execution owns
  provider-neutral execution mechanics; Homes Prime owns model context, business retrieval,
  answer/refusal policy, factual validation, and customer-facing fallback selection.

Model/provider selection, token limits, and spending ceilings are deployment policy, not fixed by
this contract. They are selected from repeated quality, latency, privacy, and cost evaluations.

## 16. Privacy and logging

No transcript capture is enabled by this contract.

The website, Prime, reverse proxy, Shared Model Execution, provider route, error reporting, request
tracing, and analytics must all be checked before making that claim to visitors.

Allowed durable telemetry is content-free and may include:

- request, response, release, and idempotency identifiers;
- a one-way keyed digest of `session_id` for bounded troubleshooting and abuse correlation;
- timestamps and bounded latency stages;
- outcome and error categories;
- input/output size buckets;
- model/provider route identifier approved for internal use;
- token and cost totals;
- source/action counts; and
- policy, grounding, or validation pass/fail categories.

It must not include message text, answer text, source snippets, names, emails, IP-derived profiles,
page query strings, arbitrary URLs, or model prompts. Infrastructure access logs should minimize or
redact IP addresses and user agents according to approved retention policy.

Raw `session_id` must not be durably retained. Its keyed digest has an explicit maximum TTL of 24
hours, uses an environment-specific key unavailable to browser code, and is deleted when that TTL
expires. Neither the raw value nor its digest may be joined to a guest identity, authenticated
session, advertising identifier, or marketing profile. Deployments may choose a shorter TTL.

Security audit events record authentication failures and abuse categories without token contents or
body content.

## 17. Error contract

```json
{
  "contract_version": "1.0",
  "error": {
    "code": "temporarily_unavailable",
    "message": "Lucy is temporarily unavailable. Please try again shortly.",
    "correlation_id": "b139a2b0-61f2-4523-99ad-aa4c67db2cdc",
    "retryable": true
  }
}
```

| HTTP | Code | Retryable | Meaning |
| --- | --- | --- | --- |
| 400 | `invalid_request` | no | Malformed headers, body, history, or page context |
| 400 | `unsupported_version` | no | Requested capability version is not supported |
| 401 | `authentication_failed` | no | Generic service-authentication failure |
| 403 | `capability_forbidden` | no | Valid caller lacks `guest.answer` |
| 409 | `idempotency_conflict` | no | Key reused with different canonical request |
| 409 | `request_in_progress` | yes | Same request is already executing |
| 409 | `idempotency_recovery_unavailable` | no | Prior execution cannot be replayed without forbidden content retention |
| 409 | `response_invalidated` | no | Prior response is no longer eligible under current public state |
| 413 | `request_too_large` | no | Body or bounded-content limit exceeded |
| 429 | `rate_limited` | yes | Public or service limit reached |
| 503 | `temporarily_unavailable` | yes | Model, knowledge, policy, or execution dependency unavailable |
| 503 | `answer_validation_failed` | no | No supported final answer survived validation; no answer content is returned |
| 504 | `deadline_exceeded` | yes | Provider could not complete within its deadline |

- Errors contain no `observed_at`, stack trace, provider message, prompt fragment, rejected value,
  token, key ID, policy threshold, database detail, or internal hostname.
- `correlation_id` is provider-generated and distinct from `X-Request-ID`.
- Retryable responses include integer `Retry-After` seconds between 1 and 30.
- `answer_validation_failed` is intentionally a non-retryable `503`: the serving capability failed
  to produce a safe answer for this request, but an automatic identical retry is not permitted merely
  because generic HTTP tooling often retries 5xx responses.
- The website converts errors into a natural customer-facing state and preserves normal navigation,
  forms, contact routes, and booking links.

## 18. Abuse, safety, and content boundaries

- Limits are applied at browser/session, website adapter, Prime capability, and Shared Model Execution
  layers.
- The public endpoint does not accept files, images, URLs for retrieval, or tool instructions.
- Prompt injection in message, history, public content, or page context cannot change authority,
  expose hidden instructions, or activate private tools.
- Claims of being Ray, an owner, a guest, or staff do not alter public authority.
- Prime briefly redirects unrelated requests while remaining helpful on Utopia, hospitality, travel,
  property, owner-service, and Design topics.
- Policy refusals are specific and proportionate. Missing knowledge, unavailable tooling, and unsafe
  requests are not collapsed into one generic refusal.
- The answer must not provide access codes, private contact information, reservation identities,
  internal disputes, private owner records, or unapproved safety-critical instructions.

## 19. Versioning and compatibility

- The HTTP major version is `/business/v1`; the capability version is `guest.answer@1.0`.
- Management Contract capability discovery advertises `guest.answer` and its supported capability
  version, but does not proxy this endpoint or its payload.
- Additive optional response members are compatible within v1 and must be ignored by older consumers.
- Additive request members are not compatible until the provider and consumer negotiate support.
- Removing or changing a required member, enum meaning, limit, authentication claim, or error semantic
  requires a new capability version; a transport-breaking change requires `/business/v2`.
- Website and Prime releases are independently deployable. Each side pins the supported capability
  version and fails closed on incompatibility.
- Version compatibility is configured before serving traffic. Management discovery is not a
  request-time dependency. Unsupported versions fail before execution. Streaming requires explicit
  negotiation and is not silently compatible with the v1.0 JSON response.
- A knowledge release is independent from the capability version. Withdrawing a fact does not require
  a contract release and software rollback must not resurrect it.

## 20. Migration from the current implementation

### 20.1 Confirmed current website deltas

The website implementation inspected on 2026-09-16 has a narrower public contract:

| Current behavior | Target behavior |
| --- | --- |
| `/api/lucy` accepts only `{question}` with a 500-character limit | Accept bounded history, page context, stable turn IDs, and the current message through the application adapter |
| A one-hour `HttpOnly` session cookie supplies the upstream session ID | Browser-memory conversation state and random session ID clear on refresh, tab close, explicit reset, or inactivity |
| The server calls a configured upstream with a static bearer token | The server uses the dedicated short-lived `stoin-business-jwt-v1` service identity |
| The upstream timeout defaults to ten seconds | The Business Contract uses a measured bounded 15-second attempt / 22-second total interaction deadline |
| The server expects one answer, one source, version, and snapshot digest | The consumer validates outcome, bounded sources, approved actions, limitations, and content-free release headers |
| `/api/lucy` returns only answer text to the widget | The presentation adapter exposes useful source/action data while hiding internal release and correlation metadata |
| The widget displays messages locally but sends no prior turns | It sends only the bounded in-memory history needed for conversational continuity |

The existing same-origin check, hostname pin, request-size check, server-only upstream call, disabled
redirects, `no-store`, rate limits, generic outage response, and feature gate are useful controls to
preserve or strengthen.

The current session cookie is opaque and `HttpOnly`, but retaining it across refresh conflicts with
the accepted temporary-conversation behavior. The migration removes it from conversation continuity;
if a separate short-lived abuse-control cookie remains necessary, it must not link conversation text,
survive beyond its documented abuse-control purpose, or be described as chat memory.

### 20.2 Strangler sequence

The first cut is a strangler boundary, not a rewrite:

1. Freeze this contract and build an independent conformance bundle.
2. Have Homes wrap the accepted current guest-answer behavior behind this provider contract while
   retaining existing production behavior.
3. Exercise the wrapper as an explicitly preconformant compatibility preview using synthetic and
   staff-only traffic. It may prove schemas, authentication, isolation, and failure handling, but it
   must not advertise conformance or receive public guest traffic while carrying forward behavior
   that does not yet satisfy §§13–18.
4. Prove that Prime continues answering when Stoin Control is unavailable.
5. Move Homes prompts, knowledge projection, business validation, and curated local guide under Homes
   ownership without changing the website contract.
6. Extract provider-neutral model execution behind Prime's private execution boundary.
7. Change the website `/api/lucy` adapter to consume the candidate in an isolated conformance preview
   only after every normative provider requirement is implemented. Run the full protocol and semantic
   acceptance suites there.
8. Activate only after conversational, factual, privacy, failure, cost, and rollback acceptance pass.
9. Retire the former cross-realm guest request path only after rollback evidence and an observation
   window.

The migration must not create a second durable transcript store or a dual-write Homes database.
No migration stage may claim conformance or receive newly routed guest traffic until the serving
boundaries in §§5 and 15 hold. Legacy nonconformant behavior may remain only on the separately
identified existing path pending an approved cutover.
Schema conformance alone is never described as `guest.answer@1.0` capability conformance.

## 21. Acceptance criteria

### 21.1 Contract and isolation

1. Website and Prime run as independently deployed processes with separate repositories, secrets,
   release lifecycles, and no shared database access.
2. A Control outage has no effect on a healthy `guest.answer` request.
3. The browser never receives the Business Contract credential.
4. Wrong signature, issuer, subject, audience, algorithm, key, validity, environment, or malformed
   claim returns generic `401`; an authenticated caller without `guest.answer` returns generic `403`.
5. Oversized, malformed, unknown-role, tool-role, external-path, and unknown-member requests fail
   before model execution.
6. Repeating the same idempotent request does not cause a second paid execution; changing the body
   under the same key fails.
7. No request or answer content appears in infrastructure logs, traces, error reports, analytics, or
   provider-retained data contrary to the approved route policy.
8. No canonical Homes business record, DNS record, booking, payment, outbound message, reservation,
   or customer record is mutated. Content-free security, idempotency, accounting, and operational
   coordination state may be written only as explicitly permitted by this contract.
9. A preview token fails against production, a JWT `jti` cannot be replayed, and retries succeed with
   a fresh JWT while preserving the same canonical payload and idempotency key.
10. Simultaneous duplicates arriving from separate website replicas, response loss, coordinator
    restart before and after provider completion, late completion after timeout, and unresolved cost
    settlement never start an untracked duplicate answer pipeline.
11. Forged assistant history, copied session IDs, and purported prior approvals or tool results grant
    no authority and are independently regrounded.
12. Blocking all Stoin Control network access does not prevent cold authentication, configuration,
    knowledge access, cost admission, model execution, retry, or settlement.

### 21.2 Conversation and usefulness

13. “What makes a Utopia stay different?” answers directly with concrete verified benefits rather
   than only marketing language.
14. “How many properties do you manage?” begins with the direct count and correctly describes the
    public collection; no empty Sources heading is rendered.
15. “How long are Utopia stays?” answers about duration/minimum-stay knowledge or clearly says that
    current stay-length rules require the booking destination; it does not dump an arbitrary property.
16. “That doesn't make sense” acknowledges and repairs the prior misunderstanding instead of
    repeating it.
17. “Tell me about Buttercup” followed by “How many cars fit?” resolves the follow-up and retrieves
    the parking fact anew.
18. “Which homes have pools, and how do they differ?” compares only supported facts and distinguishes
    unknowns.
19. “We have 20 people, four cars, and want a pool” identifies only verified matches and explains any
    missing constraints.
20. “Is the pool open in November?” returns a supported seasonal answer or a precise unknown, not an
    inference from pool existence.
21. “How does your Design estimate work?” explains the published estimate process despite live
    booking prices being unavailable.
22. “Where is a good spot to get coffee in Wildwood?” uses the approved local guide; if hours are not
    current, it recommends without claiming current opening status.
23. A follow-up such as “Which is closest to Buttercup?” is answered only when approved location or
    distance evidence supports it.
24. Relevant unfamiliar wording, comparison, correction, and multi-requirement prompts succeed across
    repeated trials; acceptance is not limited to preset paraphrases.

### 21.3 Grounding and failure behavior

25. Wrong-property facts, unsupported numbers, inverted negation, expired restrictions, withdrawn
    facts, and unsupported claims attached to valid source IDs are rejected or repaired before display.
26. Exact structured facts cannot be overridden by descriptive copy or model prose.
27. Missing detail yields `partial` or `clarification_needed`; model/service failure yields a retryable
    error. The customer sees the distinction naturally.
28. Sources and actions are relevant, unique, approved, and working; empty source/action sections are
    hidden by the website.
29. An unapproved local business, current event, hour, distance, endorsement, booking URL, or live price
    is never invented.
30. Rate limiting, model failure, knowledge failure, and deadline expiry preserve the rest of the site
    and provide a useful contact or navigation fallback.
31. An invented Markdown link, misleading action label, malformed success response, unknown outcome,
    missing qualification, and unsupported claim attached to a valid source all fail before display.
32. A withdrawal, amenity closure, expired unresolved restriction, stale projection, cached replay,
    or software rollback cannot restore or expose superseded public information.
33. The website, reverse proxy, and generic HTTP middleware do not automatically retry
    non-retryable `answer_validation_failed`, even though its HTTP status is `503`.

## 22. Conformance artifacts

After design approval, Claude owns the Homes/provider artifacts and provider implementation; the
website consumer owns consumer fixtures. Protocol conformance and semantic product quality are two
separate evidence tiers.

### 22.1 Tier A — deterministic protocol bundle

This byte-reproducible bundle includes:

- JSON Schemas for request, success response, source, action, and error envelopes;
- positive and negative vectors for every schema rule;
- authentication claim vectors;
- request-canonicalization, idempotency, crash/recovery, and retry-state vectors;
- consumer and reverse-proxy vectors proving that `answer_validation_failed` is not automatically
  retried despite its `503` status;
- cross-field invariants for session, turns, outcomes, sources, actions, and retry semantics;
- paired provider/consumer fixtures;
- privacy-safe log and error fixtures; and
- a raw-byte canonical content digest reproducible without executing either implementation's code.

Strict provider schemas and tolerant additive response parsing must be tested separately so the
conformance validator is not mistakenly used as the runtime consumer parser.

### 22.2 Tier B — semantic and grounding evaluation suite

Acceptance criteria 13–32 require actual answer generation and cannot be certified by JSON Schema or
a deterministic validator. Their test definitions, approved knowledge fixtures, adversarial cases,
scoring rubrics, and evaluator configuration are versioned and digest-pinned, but a pass requires
recorded execution against the exact provider, model route, Homes behavior release, knowledge release,
and evaluation configuration.

The suite records repeated-trial factual correctness, support, correction quality, comparison quality,
clarification behavior, latency, cost, and failure handling. It distinguishes deterministic assertions
from human or model-graded judgments and preserves privacy-safe run metadata. A digest match proves
which evaluation was run; it does not prove that a model passed it. Production acceptance requires
the recorded run results and thresholds as separate evidence.

## 23. Settled freeze decisions

1. `guest.answer@1.0` is the first Business Contract capability. Live availability, booking actions,
   and authenticated guest access remain separate future capabilities.
2. The website guest adapter is the sole initial caller and has its own service identity. Future
   callers receive distinct identities and grants.
3. The 15-second attempt and 22-second total interaction limits are hard safety ceilings, not the
   desired customer-experience target. Production activation requires a separate latency SLO derived
   from repeated measured p95 and p99 evaluation results.
4. The single-coordinator and ten-minute volatile replay profile is accepted for the initial release
   as a deliberate privacy-versus-availability tradeoff. A coordinator restart may produce explicit
   `idempotency_recovery_unavailable`; it may not trigger an invisible duplicate pipeline.
5. Real local-guide selections are not a protocol-freeze dependency. Tier B may use clearly labeled,
   approved synthetic fixtures. Selecting and approving actual Wildwoods businesses is a Homes
   content and activation decision.

## 24. Review disposition

Claude's review of draft 0.1 and Lucy's review of draft 0.2 were accepted as follows:

| Finding | RC1 disposition |
| --- | --- |
| Protocol conformance and semantic model quality cannot share one deterministic certification claim | Split into deterministic Tier A and execution-dependent Tier B in §22 |
| Volatile response replay is ambiguous across replicas | Initial v1.0 profile now requires one active answer coordinator; horizontal replay requires a separately reviewed affinity or memory-only shared-cache profile |
| JWT replay state needs crash-tolerant coordination | Bound to the same Homes-owned content-free coordination facility as idempotency status, with separate namespace and retention |
| Character bounds could exceed the prior 32 KiB transport bound | Request bound raised to 64 KiB and independent decoded-character and encoded-byte enforcement made explicit |
| Preview conformance level was ambiguous | Split into explicitly preconformant compatibility preview and fully normative conformance preview |
| `iat`/`nbf`, JCS dependency, non-retryable 503, shrinking retry budget, and future caller identity needed precision | All stated explicitly in §§7, 11, and 17 |
| Criterion 8 prohibited the content-free coordination writes required elsewhere | Narrowed to canonical business/customer mutations while explicitly permitting contract-defined coordination state |
| Utopia Design information could imply Homes ownership | Cross-domain public information now requires an approved projection or contract and retains its canonical owner |
| Page context could carry query-string tracking or personal data | Query strings, fragments, and their encoded delimiters are prohibited |
| Durable raw session identifiers could create longitudinal pseudonymous tracking | Raw session IDs are prohibited from durable telemetry; keyed digests have a maximum 24-hour TTL and cannot join to identity or marketing data |
| V1 precedence modeled unavailable future capabilities | Normative precedence now includes only effective public restrictions, structured facts, approved knowledge, and general reasoning; future PMS/reservation rules are deferred |
| Middleware could retry non-retryable `answer_validation_failed` because it uses HTTP 503 | Added explicit website/reverse-proxy acceptance and Tier A vectors proving no automatic retry |

The selected capability, caller identity, hard deadlines, replay profile, and content-fixture boundary
are now recorded as settled freeze decisions in §23. The production latency SLO and real local-guide
content remain activation evidence and Homes content decisions, not protocol questions.

## 25. Explicit non-authorization

This design does not authorize code, schemas, migrations, services, keys, deployment, production
traffic, provider spending, database movement, DNS changes, transcript capture, or retirement of the
current guest path. Those follow only after the contract is reviewed, frozen, and assigned through
the agreed Lyra/Claude ownership boundary.
