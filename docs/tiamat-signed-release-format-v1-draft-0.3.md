# Tiamat Signed Release Format v1 — Draft 0.3

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
§13/§13.1, and acceptance criteria 73–74, 78, 80–81. Reviewer-verifiable excerpts and source paths
are included in the companion packet. It uses the established `policy_notary_v13` signing-key purpose
from `src/lucy/contracts/security_v1_3.py`; Management Contract RC3 §6.2 reserves the broader
policy-notary purpose but does not define that exact versioned string. A release key is additionally
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
- The complete compact JWS is at most 131,072 bytes.
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
| `release_id` | 1–128 visible ASCII; unique within issuer/environment/type/subject |
| `subject_id` | Stable profile ID, policy ID, spending-partition ID, or revocation channel ID |
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

The release scope and sequence namespace is
`(issuer, environment, caller_id, realm, release_type, subject_id)`. Profiles, policies, and
spending partitions therefore rotate independently. Spending periods remain successors within one
partition subject. A claim cannot select or expand its trust scope. Valid signature time and current
wall-clock validity are both required for new admission.

Type binding is exact: `execution_profile.subject_id == content.profile_id`,
`privacy_policy.subject_id == content.policy_id`, and
`spending_grant.subject_id == content.partition_id`. Revocation `subject_id` identifies its dedicated
revocation chain, never the target key.

`sequence` is the signed total-order field. It need not be contiguous. A successor must name the
exact durable chain head—including an expired or revoked head—and have a strictly larger sequence.
Equal or lower sequence, a missing/wrong predecessor, or two candidates naming the same predecessor
fail closed; the first successfully fenced activation advances the head and makes the other stale.
Expiry, revocation, or failed activation never selects an older predecessor. Lexical release IDs and
timestamps never break ties.

Timestamp comparisons allow at most 30 seconds of clock skew for signature/key issuance checks.
Release `not_before`, `not_after`, budget-period boundaries, and revocation `effective_at` are business
cutoffs and receive no skew extension for admission.

## 4. Exact typed content

The normative machine-readable schemas are in
`contracts/tiamat-signed-release-v1-draft-0.3/schemas`. They set
`additionalProperties: false`, define every member, type, enum, and bound, and contain the cross-type
discriminators. Valid payload examples are in the bundle's `examples` directory. Strict schemas are
for release issuers/providers; future consumers may become tolerant only through a new recognized
format version. Unknown v1 members remain invalid.

### 4.1 `execution_profile`

The exact fields are `profile_id`, `provider_route_id`, `model_id`, `allowed_output_modes`,
`maximum_input_tokens`, `maximum_output_tokens`, `maximum_context_tokens`, `timeout_ceiling_ms`,
`privacy_policy_release_id`, `data_collection`, `training`, `zero_data_retention_required`,
`fallback_allowed`, `rate_release_id`, `rates`, and `maximum_reservable_microusd`. Rates are integer
micro-USD per million input, output, and reasoning tokens plus an integer per-request charge. Provider
credentials are never embedded.

### 4.2 `privacy_policy`

The exact fields are `policy_id`, `approved_provider_route_ids`, `required_provider_privacy`,
`data_collection`, `training`, `fallback_allowed`, `allowed_regions`,
`retention_ceiling_seconds`, and `eligibility_generation`. Privacy-policy and release-revocation
activation share one durable eligibility counter scoped by `(issuer, environment, caller_id, realm)`;
the signed value must equal the current generation plus one. A profile's
`privacy_policy_release_id` must identify the active
policy release for the same caller/realm and its route must be in that policy's approved set.

### 4.3 `spending_grant`

The exact fields are `partition_id`, `budget_period_id`, `period_start`, `period_end`,
`allowance_microusd`, `maximum_concurrency`, `largest_per_call_microusd`, and
`contingency_reserve_microusd`. There is no open-ended ordering metadata; common `sequence` is the
only successor tie-breaker. The contingency reserve is at least
`2 × maximum_concurrency × largest_per_call_microusd`. A grant remains usable only while both its JWS
validity and budget period cover admission time. Crossing a period boundary never creates authority.

The contingency reserve is additional to the ordinary allowance and is never dispatchable. A new
call's reservation is bounded by the smallest of the request ceiling, active profile maximum, and
grant largest-per-call ceiling. A new budget period renews ordinary allowance; settled ordinary spend
does not roll forward. Active reservations, pending reconciliation, forfeitures lacking authoritative
final cost, contingency use, and external liabilities do carry forward and reduce effective authority
until their contract-defined settlement, credit, or operator reconciliation.

### 4.4 `revocation`

An in-band revocation targets releases only. Its exact fields are `target_type` (constant `release`), `target_release_type`,
`target_release_id`, `reason_code`, `effective_at`, and `eligibility_generation`; the generation must
be the next value of the shared counter in §4.2. Revocation is separate from normal rotation and never
restores a predecessor. Key status changes are forbidden in release JWS objects and occur only through
the out-of-band trust inventory in §5. Historical verification for audit never makes a revoked release live.

## 5. Trust inventory, rotation, and revocation

Each verification-key entry binds:

- exact `kid`, issuer, environment, purpose `policy_notary_v13`, and use
  `tiamat-signed-release`;
- Ed25519 public key;
- `valid_from`, `issuance_not_after`, and `verify_not_after`;
- exact allowed scopes, each containing caller ID, realm, release type, and subject ID; wildcards are
  forbidden;
- status `staged`, `active`, `retired`, or `revoked`; and
- nullable `revoked_at` plus root-selected `active_release_policy` of `invalidate_immediately` or
  `honor_active_until_expiry`.

Normal rotation stages the successor public key before issuance switches. Active and retired keys may
verify stored history during their verification windows, but only an active key may authorize staging
or activation. Routine retirement does not invalidate a release that was already durably activated:
that release may authorize new inference admissions until its own expiry or supersession. It does not
permit activation of a merely staged release. Revocation is fail-closed and distinct.

At activation, `verify_not_after` must be no earlier than the release's `not_after`; otherwise the
release is rejected. A trust-inventory update may not shorten verification coverage beneath any
still-active release unless the same root-authorized update explicitly invalidates that release.

The release key cannot alter the trust inventory or revoke/unrevoke itself. Trust-inventory changes
and key revocations require a separately provisioned offline deployment trust-root key and monotonic
trust-inventory generation. The root public key is installed with the deployment witness, outside the
Tiamat database backup. A revoked release key is rejected for every new activation, including a
backdated payload. Previously active releases continue only when the root-authorized revocation record
explicitly permits that bounded behavior; otherwise they stop authorizing immediately.

The trust inventory is itself a compact JWS with `alg=EdDSA`, exact root `kid`, and
`typ=stoin-release-trust-inventory+jws`, subject to the exact-byte and 131,072-byte rules in §2. Its
strict payload schema is the packet's `trust-inventory.schema.json`. `inventory_generation` strictly
increases; `previous_inventory_digest` is null only for bootstrap and otherwise equals SHA-256 of the
exact prior compact JWS bytes. The installed root public key verifies the inventory before any release
key becomes trusted. Root-key replacement is a deployment recovery operation requiring an updated
external witness; neither a release JWS nor an inventory signed only by a release key can perform it.

The private signing key remains in the Control/policy-notary boundary. Tiamat receives only a reviewed
public trust inventory. Production and nonproduction inventories are disjoint.

## 6. Receipt, staging, and durable activation

Receipt verifies compact framing and bounded size and stores no authority. Staging verifies the exact
JWS bytes, key scope, payload scope, format version, signature, `content_digest`, typed invariants,
predecessor, and sequence, then stores the candidate as `staged`; staging may occur before
`not_before` or a future budget-period boundary and does not change the active head or permit dispatch.

At or after `not_before`, a local scheduler or authenticated offline management action may activate a
staged release without synchronous Control access. Activation still requires a currently active key,
current trust inventory, and all type-specific applicability rules. A future-period spending grant may
be staged in advance and activates no earlier than both `not_before` and `period_start`.

Activation is one fenced database transaction that:

1. locks the scoped release head and recovery gate;
2. confirms the deployment-owned storage epoch and recovery generation;
3. confirms predecessor and strictly increasing sequence;
4. stores the exact JWS bytes, JWS SHA-256, typed content digest, and content-free metadata;
5. marks the new release active and the predecessor superseded without deleting it;
6. advances the applicable eligibility generation; and
7. commits the new head.

No request may activate a release through the inference endpoint. Online activation calls require a
dedicated Ed25519 workload JWT with audience `tiamat-release-activation`, scope
`tiamat.release.activate`, exact environment/caller/realm binding, request digest, atomic scoped JTI
consumption, and a maximum 300-second lifetime. That client key is distinct from release-signing,
trust-root, inference-client, and provider keys. Offline recovery activation instead requires the
separately held recovery role and external witness. A failed, ambiguous, or partially observed activation does not select a
release by timestamp; Tiamat performs a fenced authoritative lookup.

Routine replacement permits an already admitted execution to finish under its pinned profile/rate,
subject to current security/privacy eligibility. It invalidates predecessor replay.

The authoritative revocation cutoff is the fenced atomic `completed` commit required by frozen Shared
Model Execution RC1 §11/§16 and acceptance criterion 81. Revocation ordered before that commit makes
the eligibility comparison fail and suppresses the candidate. Revocation ordered after that commit
cannot recall the committed original response and affects replay only. The implementation sends the
response immediately after commit and performs no blocking work between them. This companion does not
replace the frozen cutoff with a non-atomic pre-network-send promise.

## 7. Restore and cold-start rule

A valid signature never proves database freshness and never restores spending capacity.

Every serving start requires the deployment-owned recovery witness defined by
`docs/tiamat-execution-ledger-recovery-rc1.md`: exact environment, storage epoch, monotonically
increasing recovery generation, and dispatch authorization stored outside PostgreSQL and outside the
database host/VM and its snapshot boundary. Tiamat
compares it with the database restore gate before loading release heads or admitting work. It also
checks that stored active heads, consumed spending, reservations, pending reconciliation, forfeitures,
contingency use, and external liabilities belong to that witnessed generation.

Every supported restore MUST invalidate dispatch authorization outside the database before the
candidate backup is attached. If pre-invalidation cannot be proved after a disaster, the recovery
launcher creates a strictly newer quarantined external generation before any serving credential is
issued. Thus a backup and witness that formerly both said generation 7 cannot resume as generation 7:
the supported restore first creates quarantined generation 8, and the restored generation-7 database
fails comparison even when the backup came from generation 7.

When Control is reachable at startup, Tiamat MUST authenticate it and confirm the active release
heads, trust-inventory generation, budget-period heads, settled spend, reservations, pending
reconciliation, forfeitures, contingency use, and external liabilities before dispatch. Any mismatch
quarantines the environment. When Control is unreachable, the structurally separate witness may
support the bounded offline window only if it matches, is not quarantined, covers every intervening
budget period, and local authority is otherwise current. Control reachability never weakens the
external-witness requirement.

If the witness is absent, unreadable, not quarantined for the current restore attempt, older/newer
than the database, or cannot establish the latest generation, cold start remains quarantined and
dispatches nothing. Control clears quarantine only through the nine-step offline procedure in the
recovery checkpoint, which verifies release heads and settlement position before advancing the
database to the already-created external generation. The executable mechanism is
`src/lucy/shared_execution/recovery.py`; the physical stale-snapshot proof is
`tests/integration/test_tiamat_postgres_execution_ledger.py`. Replaying signed releases into a stale
database is not reconciliation and cannot unblock it.

## 8. Required negative vectors

The conformance set must reject at least:

1. bad Ed25519 signature, unknown `kid`, wrong issuer/environment/use/purpose, and revoked key;
2. `alg` substitution, unknown/duplicate protected fields, unprotected headers, padding, malformed
   or oversized compact form, invalid UTF-8, duplicate JSON members, floats, and unknown payload members;
3. unknown `format_version` or `release_type`;
4. content digest mismatch while the signature remains valid; this is a signed-pipeline
   self-consistency and Control/Tiamat RFC 8785 drift check, not a forgery defense;
5. wrong caller, realm, environment, partition, profile, route, or rate binding;
6. expired/not-yet-valid release and release outside the key issuance window;
7. missing/wrong predecessor, non-increasing sequence, competing successors, and predecessor
   resurrection after successor expiry or revocation;
8. grant outside its budget period, undersized contingency, or insufficient carried authority;
9. revocation-generation rollback and candidate completion racing an earlier revocation; and
10. valid releases on a stale restore, absent external witness, mismatched recovery generation, or
    unreconciled settlement position.
11. a same-generation stale backup after later spending, proving mandatory external
    pre-invalidation prevents it from serving.
12. a compromised release key attempting to revoke another key or alter the trust inventory.

Positive vectors must include key rotation overlap, routine profile replacement with an in-flight
execution, next-period grant provision before an offline boundary crossing, exact-byte verification,
and stable RFC 8785 content digest across semantically identical content serialization.

## 9. Freeze and implementation gate

This draft does not authorize signing, activation, deployment, provider calls, or spending. Before
implementation it requires independent review by the Homes implementation steward, resolution of all
findings, an RC1 text digest, and a generated-plus-independently-verified negative-vector bundle.
