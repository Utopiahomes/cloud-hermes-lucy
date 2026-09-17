# Tiamat Signed Release Format v1 — Draft 0.1

**Status:** implementation companion draft; not frozen and not production authority  
**Date:** 2026-09-17  
**Owner:** Tiamat / Stoin Control boundary  
**Review requirement:** independent review by the Homes implementation steward before freeze

## 1. Purpose and authority

This companion defines the offline-verifiable release objects used by Tiamat Shared Model Execution
for execution profiles, privacy policies, spending grants, and security/privacy revocations. It is a
reusable Control-to-Tiamat format and contains no Utopia Homes knowledge, prompt, transcript, or
business policy.

It implements the signed-policy and bounded-budget distribution required by Stoin Shared Model
Execution v1 RC1 §4, the profile-release rules in §8, the locally authoritative spending rules in
§13/§13.1, and acceptance criteria 73–74, 78, 80–81. It uses the established
`policy_notary_v13` signing-key purpose from Security v1.3/RC3 §6.2, but a release key is additionally
provisioned for the exact `tiamat-signed-release` use. A key accepted for that use MUST NOT be inferred
to authorize any other policy-notary operation.

No valid current release means no authority. In particular, no valid current spending grant means
Tiamat dispatches nothing.

## 2. Serialization and signature

Each release is one JWS Compact Serialization value:

```text
BASE64URL(UTF8(protected-header)) . BASE64URL(payload-bytes) . BASE64URL(signature)
```

- `alg` is exactly `EdDSA`; Ed25519 is the only accepted EdDSA curve in v1.
- `typ` is exactly `stoin-signed-release+jws`.
- `kid` is an exact, provisioned key identifier of 1–128 visible ASCII characters.
- The protected header has exactly `alg`, `kid`, and `typ`; unknown or duplicate members fail.
- Unprotected headers and detached or unencoded payloads are not accepted.
- All three compact segments use unpadded base64url and the value has exactly two `.` separators.
- The JWS signing input is the two exact received ASCII segments before the signature segment.
- Tiamat stores the exact compact JWS bytes and their SHA-256 digest. It verifies those exact bytes;
  it MUST NOT parse and reserialize a payload before signature verification.
- The payload is strict UTF-8 JSON: one object, no duplicate member names, no floats, and no unknown
  members for its release type.

RFC 8785 is not the signature container. It is used only to calculate `content_digest` as lowercase
hex SHA-256 over the RFC 8785 serialization of the exact `content` object. Tiamat verifies that digest
after verifying the JWS signature. This gives stable semantic release identity without changing the
standard JWS signing rules.

## 3. Common payload

Every payload has exactly these common members plus `content`:

| Member | Rule |
| --- | --- |
| `format_version` | Exact string `1`; unknown versions fail closed |
| `release_type` | `execution_profile`, `privacy_policy`, `spending_grant`, or `revocation` |
| `release_id` | 1–128 visible ASCII; unique within issuer/environment/type |
| `issuer` | Exact provisioned Control issuer |
| `environment` | Exact provisioned deployment environment |
| `caller_id` | Exact provisioned calling synth identity |
| `realm` | Lowercase realm identifier, 1–64 characters |
| `issued_at` | UTC RFC 3339 timestamp with seconds precision |
| `not_before` | UTC RFC 3339 timestamp with seconds precision |
| `not_after` | UTC RFC 3339 timestamp with seconds precision; later than `not_before` |
| `sequence` | Integer 1–9,007,199,254,740,991; strictly increases per release type/scope |
| `predecessor_release_id` | Null for the first activation; otherwise exact active predecessor |
| `content_digest` | Lowercase SHA-256 of RFC 8785 canonical `content` |
| `content` | Exact typed object from §4 |

The authorization scope is the tuple `(issuer, environment, caller_id, realm, release_type)`. A
claim cannot select or expand its trust scope. Valid signature time and current wall-clock validity
are both required for new admission.

`sequence` is the signed total-order field. A successor must name the exact active predecessor and
have a strictly larger sequence. Equal or lower sequence, a missing predecessor, two different
successors naming the same predecessor, or a gap from the active head fails closed. Lexical release
IDs and timestamps never break ties.

## 4. Typed content

### 4.1 `execution_profile`

The content contains the execution-profile ID and versioned provider mechanics required by RC1 §8:
route ID, model ID, permitted output modes, input/output/context ceilings, timeout ceiling, provider
privacy characteristics, data-collection and training flags, zero-data-retention requirement, rate
release ID, complete integer micro-USD rates, and maximum reservable charge. Provider credentials are
never embedded.

### 4.2 `privacy_policy`

The content contains a policy ID, approved provider-route IDs, required privacy characteristics,
data-collection/training/fallback prohibitions, region constraints, retention ceiling, and an integer
`eligibility_generation`. Activating a security/privacy successor strictly increases that generation.

### 4.3 `spending_grant`

The content contains exactly: partition ID, budget-period ID and boundaries, allowance in micro-USD,
maximum concurrency, largest per-call ceiling, contingency reserve, and optional signed notes-free
ordering metadata. The contingency reserve is at least
`2 × maximum_concurrency × largest_per_call_microusd`. A grant remains usable only while both its JWS
validity and budget period cover admission time. Crossing a period boundary never creates authority.

### 4.4 `revocation`

The content contains a target release type, target release ID or exact scoped key ID, reason code,
`effective_at`, and a strictly increasing eligibility generation. Revocation is separate from normal
rotation. Revoking a successor never restores its predecessor. A key revocation rejects every release
signed by that key at or after the declared compromise boundary. Historical verification for audit
does not make a revoked release live authority.

## 5. Trust inventory, rotation, and revocation

Each verification-key entry binds:

- exact `kid`, issuer, environment, purpose `policy_notary_v13`, and use
  `tiamat-signed-release`;
- Ed25519 public key;
- `valid_from`, `issuance_not_after`, and `verify_not_after`;
- status `staged`, `active`, `retired`, or `revoked`; and
- optional `compromise_suspected_from`.

Normal rotation stages the successor public key before issuance switches. Active and retired keys may
verify stored history during their verification windows, but only an active key may authorize a new
live activation. Retirement does not revoke releases already admitted under a valid release.
Revocation is fail-closed and distinct: it prevents live authorization according to its effective
boundary and advances eligibility where applicable.

The private signing key remains in the Control/policy-notary boundary. Tiamat receives only a reviewed
public trust inventory. Production and nonproduction inventories are disjoint.

## 6. Durable activation

Tiamat first verifies the exact JWS bytes, key scope, payload scope, format version, validity,
`content_digest`, and type invariants. Activation is then one fenced database transaction that:

1. locks the scoped release head and recovery gate;
2. confirms the deployment-owned storage epoch and recovery generation;
3. confirms predecessor and strictly increasing sequence;
4. stores the exact JWS bytes, JWS SHA-256, typed content digest, and content-free metadata;
5. marks the new release active and the predecessor superseded without deleting it;
6. advances the applicable eligibility generation; and
7. commits the new head.

No request may activate a release through the inference endpoint. Activation is an authenticated
management/offline operation. A failed, ambiguous, or partially observed activation does not select a
release by timestamp; Tiamat performs a fenced authoritative lookup.

Routine replacement permits an already admitted execution to finish under its pinned profile/rate,
subject to current security/privacy eligibility. It invalidates predecessor replay. Revocation before
the atomic completed commit suppresses delivery; revocation after commit affects replay only.

## 7. Restore and cold-start rule

A valid signature never proves database freshness and never restores spending capacity.

Every serving start requires the existing deployment-owned recovery witness: exact environment,
storage epoch, and monotonically increasing recovery generation stored outside PostgreSQL. Tiamat
compares it with the database restore gate before loading release heads or admitting work. It also
checks that stored active heads, consumed spending, reservations, pending reconciliation, forfeitures,
contingency use, and external liabilities belong to that witnessed generation.

If the witness is absent, unreadable, older/newer than the database, or cannot establish the latest
generation, cold start remains quarantined and dispatches nothing. Control may clear quarantine only
through the existing offline reconciliation procedure, which verifies release heads and settlement
position and advances the external recovery generation. Replaying signed releases into a stale
database is not reconciliation and cannot unblock it.

## 8. Required negative vectors

The conformance set must reject at least:

1. bad Ed25519 signature, unknown `kid`, wrong issuer/environment/use/purpose, and revoked key;
2. `alg` substitution, unknown/duplicate protected fields, unprotected headers, padding, malformed
   compact form, invalid UTF-8, duplicate JSON members, floats, and unknown payload members;
3. unknown `format_version` or `release_type`;
4. content digest mismatch while the signature remains valid;
5. wrong caller, realm, environment, partition, profile, route, or rate binding;
6. expired/not-yet-valid release and release outside the key issuance window;
7. missing/wrong predecessor, non-increasing sequence, competing successors, and predecessor
   resurrection after successor expiry or revocation;
8. grant outside its budget period, undersized contingency, or insufficient carried authority;
9. revocation-generation rollback and candidate completion racing an earlier revocation; and
10. valid releases on a stale restore, absent external witness, mismatched recovery generation, or
    unreconciled settlement position.

Positive vectors must include key rotation overlap, routine profile replacement with an in-flight
execution, next-period grant provision before an offline boundary crossing, exact-byte verification,
and stable RFC 8785 content digest across semantically identical content serialization.

## 9. Freeze and implementation gate

This draft does not authorize signing, activation, deployment, provider calls, or spending. Before
implementation it requires independent review by the Homes implementation steward, resolution of all
findings, an RC1 text digest, and a generated-plus-independently-verified negative-vector bundle.
