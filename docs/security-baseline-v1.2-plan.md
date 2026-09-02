# Cloud Lucy Security Baseline v1.2 — review plan

Date: 2026-09-02

Status: **approved by Lucy/Ray and the owner on 2026-09-02 for staged
implementation under the sequence and gates in Section 15. This approval does
not authorize live Telegram transcript capture**.

Live Telegram transcript capture remains disabled. AWS and Render changes may
proceed only through the reviewed implementation gates and synthetic acceptance
scope. This document contains no credentials, account identifiers, service
identifiers, or transcript content.

## 1. Purpose and disposition

Security Baseline v1.1 separated routine/archive, policy, evidence, and deletion
workloads, but it left the final raw-evidence controls inside the services they
were intended to govern:

- `lucy-evidence` could enumerate PostgreSQL evidence and directly use DynamoDB
  wrapped-key reads plus KMS `Decrypt`.
- `lucy-deletion` could enumerate key references and directly delete wrapped
  keys and ciphertext.
- Application permit checks therefore protected the public API but did not
  contain a complete compromise of either service.

Version 1.2 retains the four Render responsibilities while moving final
cryptographic operations into two independently enforcing, on-demand AWS Lambda
executors. PostgreSQL becomes an execute-only exact-operation gate for the two
sensitive Render services. Neither request-facing service retains direct KMS,
wrapped-key, ciphertext-table, or key-deletion authority.

This plan also adopts the owner-approved Phase 1 deletion policy:

> Evidence becomes inaccessible to Lucy when deletion completes. Under normal
> operation it becomes cryptographically unrecoverable after the configured
> 30-day recovery window has aged out. Exceptional recoverable copies extend,
> but never shorten, that finality period. Finality is declared only after the
> system verifies that no recoverable wrapped-key copy remains. During the
> recovery window, an AWS security administrator may restore evidence only when
> an audited investigation determines that the deletion was unauthorized.

Security Baseline v1.2 inherits every v1.1 control not explicitly superseded by
this document. Where the two conflict, v1.2 governs, and the implementation
report must list the conflict and its migration disposition. Provider privacy,
secret filtering, KMS master-key protection, MFA, backup handling, structured-
memory limits, fail-closed behavior, and capture gating do not disappear merely
because v1.2 concentrates on evidence and deletion boundaries.

Baseline v1.2 does not supersede v1.1 until its contracts, implementation,
negative-permission tests, real-cloud recovery drill, and final owner acceptance
report all pass.

## 2. Scope and non-goals

### In scope

- Four private Render security/backend services and their exact responsibilities.
- Two versioned AWS Lambda executor functions.
- One operator-triggered, metadata-only finality-verification utility with no
  persistent endpoint or evidence/key access.
- Render OIDC caller roles and Lambda runtime/deployment roles.
- Execute-only PostgreSQL security-definer functions and runtime logins.
- Signed owner-interaction assertions, sensitive-action permits, post-claim
  execution grants, deletion target manifests, and executor receipts.
- Durable cross-cloud operation state, retries, receipts, and reconciliation.
- Wrapped-key recovery for unauthorized deletion during a 30-day protected window.
- Network isolation, observability, quotas, alarms, and acceptance evidence.
- A final capture-activation gate.

### Explicitly out of scope

- Ray Array, multi-human quorum, generalized StoinNet execution, or additional
  agent infrastructure.
- Encrypted semantic/structured memory. The documented plaintext structured-
  memory residual boundary remains.
- Moving Render PostgreSQL into AWS.
- A reverse AWS-to-Render private network bridge.
- A NAT gateway solely to let Lambda connect to Render PostgreSQL.
- Broadly enabling Render PostgreSQL's external endpoint.
- Full owner archive export.
- Automatic recovery during normal service startup.
- Claiming that quotas contain a fully compromised Lambda runtime.

### Known v1.1 controls explicitly superseded

- Direct evidence/deletion Render access to the evidence KMS key and wrapped-key
  registry is replaced by exact Lambda caller roles.
- Table-wide evidence/deletion SQL grants are replaced by direct, execute-only
  grants to exact service logins.
- `SensitiveActionPermitV1` is replaced in production by the incompatible,
  explicitly versioned V2 contract; V1 is never silently broadened.
- The wrapped-key registry changes from PITR disabled to a configured 30-day
  protected recovery window with verified rather than timestamp-assumed finality.
- “Deletion has zero KMS permissions” becomes the precise rule “deletion has
  zero permission on the evidence KMS key and only `kms:Sign` on its separate
  receipt key.”
- “Deleted” is split into claimed, executing, effective, and finality-verified
  states; an already executing retrieval is not falsely described as revoked.

## 3. Security objectives and invariants

The implementation must preserve all of the following:

1. No single Render runtime can enumerate and decrypt historical evidence.
2. No single Render runtime can enumerate and destroy wrapped evidence keys.
3. The policy signer cannot invoke either executor and has no AWS role.
4. The evidence and deletion workflows cannot call KMS or DynamoDB directly.
5. Each executor accepts only a signed, unexpired, exact-action operation and
   lacks PostgreSQL/archive enumeration.
6. PostgreSQL runtime identities cannot directly read evidence/permit tables or
   mutate ciphertext, keys, security functions, schemas, roles, or backups.
7. Deletion authority over per-record wrapped keys never grants authority to
   decrypt, disable, delete, rotate, or change policy on the KMS master key.
8. PostgreSQL restoration alone cannot make deleted raw evidence available.
9. Hermes `/opt/data` remains a retry/runtime cache, never the authoritative
   autobiographical store after PostgreSQL commit.
10. No plaintext, plaintext hash, DEK, wrapped DEK, permit private key, database
    password, or provider secret appears in application logs or receipts.
11. Missing, malformed, mismatched, expired, replayed, or ambiguously authorized
    operations fail closed.
12. Capture cannot be enabled by a deployment default, partial rollout, database
    migration, or infrastructure creation.
13. Render workflow services are untrusted messengers: Lambda authenticates a
    policy-notarized PostgreSQL claim, and PostgreSQL reconciles only a
    policy-attested, cryptographically authenticated executor receipt.
14. Development and production keys, tables, aliases, runtime roles, OIDC
    subjects, and storage epochs are disjoint.
15. New retrieval claims stop when deletion is claimed. Phase 1 does not claim
    revocation of plaintext already read or a retrieval already executing.

## 4. Target topology

```text
                                  AWS us-east-1
                      +----------------------------------+
                      | Evidence KMS key / wrapped keys  |
                      | Executor receipt-signing keys    |
                      | Grants, receipts, quotas, audit  |
                      +----------------+-----------------+
                                       ^ exact alias invocation
                                       |
+------------------ Render Virginia private environment ------------------+
|                                                                          |
| Hermes -> lucy-routine  -> private PostgreSQL + archive AWS role         |
|        -> lucy-policy   -> permit/manifest/grant/receipt notary, no AWS  |
|        -> lucy-evidence -> exact DB claim -> policy grant -> Lambda      |
|        -> lucy-deletion -> exact DB claim -> policy grant -> Lambda      |
|                                      |                    |              |
|                                      +<- policy-attested receipt --------+
|                                                                          |
| PostgreSQL external IP allowlist: empty                                  |
+--------------------------------------------------------------------------+
```

Render PrivateLink is not used for Lambda-to-PostgreSQL access. Both Lambdas
remain outside the Render private network and receive only bounded operation
packages through synchronous, authenticated `InvokeFunction` calls.

The Lambdas do not require VPC attachment for this design. Adding a VPC or NAT
is a material change requiring a separate cost and security review.

## 5. Component and permission matrix

### 5.1 Render services

| Service | Responsibility | PostgreSQL | AWS | Secrets | Explicitly denied |
| --- | --- | --- | --- | --- | --- |
| `lucy-routine` | Structured memory, budgets, approvals, capture state, ciphertext ingestion, archive key creation | Existing least-privilege routine/archive tables; no ciphertext reads | OIDC archive role: exact KMS `GenerateDataKey`, wrapped-key `PutItem`, bounded journal-head metadata read | Adapter token, commitment key; no permit private key | KMS `Decrypt`; wrapped-key reads/deletes; executor invocation; permit signing; IAM/KMS/Dynamo administration |
| `lucy-policy` | Verify owner assertions; issue permits; sign deletion manifests and post-claim execution grants; verify executor receipt signatures and persist content-free attestations | Individually granted permit, scope, claim-digest, grant, and receipt-attestation functions only | No AWS identity or AWS variables | Policy-notary Ed25519 private key; owner-broker and executor-receipt public keys | Evidence plaintext/ciphertext; wrapped keys; executor invocation; KMS/Dynamo/IAM access |
| `lucy-evidence` | Coordinate owner-authorized raw-evidence retrieval as an untrusted messenger | `CONNECT`, required schema `USAGE`, and `EXECUTE` on named retrieval claim/reconcile functions only | OIDC caller role: `lambda:InvokeFunction` on the qualified production decrypt alias only | Adapter/owner authentication; public contract metadata | Direct table access; KMS; DynamoDB; policy signing; unqualified Lambda, `$LATEST`, other functions, code/alias changes |
| `lucy-deletion` | Coordinate owner-authorized deletion as an untrusted messenger | `CONNECT`, required schema `USAGE`, and `EXECUTE` on named deletion claim/reconcile functions only | OIDC caller role: `lambda:InvokeFunction` on the qualified production deletion alias only | Adapter/owner authentication; public contract metadata | Direct table/ciphertext deletion; KMS; DynamoDB; policy signing; unqualified Lambda, `$LATEST`, other functions, code/alias changes |

`lucy-routine` includes archive ingestion; archive is not a fifth Render security
service. `lucy-policy` is the fourth boundary that is sometimes omitted when the
topology is described informally as normal/archive/evidence/deletion. Hermes is
a separate future gateway service and is not one of these four backend security
identities.

### 5.2 AWS identities

| Identity | Allowed | Explicitly denied |
| --- | --- | --- |
| Render archive caller | Existing exact KMS `GenerateDataKey`, wrapped-key `PutItem`, and projected deletion-head read | Decrypt, registry reads/deletes/scans/queries, executor invocation, administration |
| Render evidence caller | Invoke the qualified production decrypt alias ARN | All KMS/DynamoDB actions; other Lambda functions; unqualified function and `$LATEST`; code/version/alias administration |
| Render deletion caller | Invoke the qualified production deletion alias ARN | All KMS/DynamoDB actions; other Lambda functions; unqualified function and `$LATEST`; code/version/alias administration |
| Decrypt Lambda runtime | Exact wrapped-key `GetItem`; KMS `Decrypt` on the production evidence key with the exact record-bound context; `kms:Sign` on its dedicated receipt key; conditional execution-ledger/receipt read-write; content-free logs/metrics | Scan, Query, BatchGet, export, backup, table administration, evidence-key administration/GenerateDataKey, deletion, PostgreSQL/network enumeration, deletion-receipt signing |
| Deletion Lambda runtime | Exact wrapped-key `GetItem`/transactional `Delete`; `kms:Sign` on its dedicated receipt key; conditional immutable intent/receipt writes; bounded quota counters; content-free logs/metrics | Every action on the evidence KMS key, including decrypt; Scan, Query, BatchGet, export, backup, table administration, receipt update/delete, PostgreSQL/network enumeration, retrieval-receipt signing |
| One-off finality verifier | Read-only table/PITR/backup/export/restore metadata for the exact production registry and tagged quarantine copies | `GetItem`, Scan, Query, restore, export creation, writes/deletes, every KMS action, transcript access, normal runtime assumption |
| Lambda deployer | Publish reviewed versions and repoint only the controlled production aliases after acceptance | Runtime data access, KMS use, wrapped-key access, PostgreSQL access, Render secrets |
| `LucySecurityAdministrator` | MFA-protected infrastructure administration using the current AWS `AdministratorAccess` permission set | Not granted normal application-level transcript retrieval/decryption; nevertheless able to alter code, IAM, KMS policy, aliases, and infrastructure and therefore an ultimate audited Phase 1 human trust boundary |
| `LucyRecoveryAdministrator` | MFA-protected session role for manual PITR restore to quarantine; inspect/copy exact wrapped-key items during approved recovery; dispose of quarantine | Not granted KMS decrypt or normal application authority; separation from security administration is procedural/session-based while the same human may assume both roles |

Published Lambda versions are immutable code/configuration artifacts within AWS
limits. A production alias is a controlled mutable pointer; it must never be
described as immutable. Runtime and caller roles cannot publish, update, or
repoint it.

The executor receipt-signing keys are asymmetric KMS `SIGN_VERIFY` keys distinct
from the symmetric evidence-wrapping key and from each other. A receipt signature
authenticates the executor authority that produced it; it does not prove honest
behavior after complete compromise of that executor or its signing credentials.

## 6. PostgreSQL enforcement design

### 6.1 Role rules

The v1.1 table-wide grants for `lucy_evidence_reader` and
`lucy_evidence_deleter` must be revoked. Each exact production service `LOGIN`
receives direct grants rather than membership in a shared/inherited runtime
capability role. It receives only:

- database `CONNECT`;
- `USAGE` on the schema containing the reviewed API functions;
- `EXECUTE` on an explicit allowlist of versioned functions; and
- no membership in table-owner, migration, maintenance, backup, compatibility,
  or alternate runtime roles.

The implementation must also:

- revoke database/schema/table/function privileges from `PUBLIC`;
- revoke default `EXECUTE` on new functions from `PUBLIC` before deployment;
- prevent runtime roles from creating objects in every function resolution path;
- ensure runtime logins are not superusers, table owners, function owners, or
  `BYPASSRLS` roles;
- make runtime logins `NOINHERIT`, grant no alternate roles, and deny `SET ROLE`
  or `SET SESSION AUTHORIZATION` paths that could change the effective caller;
- keep migration and security-function ownership in separate `NOLOGIN` roles;
- grant functions individually, never `ALL FUNCTIONS IN SCHEMA`; and
- verify effective privileges with the actual production-shaped logins.

### 6.2 Security-definer requirements

Every sensitive function must:

- be versioned and `SECURITY DEFINER`;
- set a fixed safe `search_path` with `pg_catalog` first and no caller-writable
  schema;
- fully qualify application tables, functions, types, and operators where
  practical;
- avoid dynamic SQL, or strictly parameterize and independently review any
  unavoidable dynamic statement;
- obtain caller identity specifically from `session_user`, never a supplied
  parameter or `current_user` (`current_user` is the function owner inside a
  security-definer function);
- validate exact serialized permit/manifest material already stored by policy;
- use the database clock for expiry checks;
- take row/advisory locks in a documented order;
- bind permit ID, nonce, root evidence ID, action, reason, owner interaction,
  idempotency key, caller role, byte/record limits, and package digest;
- return only the minimum bounded encrypted operation package; and
- emit content-free audit/operation records without returning arbitrary rows.

Row-level security may be added as defense in depth, but it is not the principal
gate and must not rely on caller-set session variables. Direct table privilege
denial and hardened functions remain mandatory.

### 6.3 Planned database functions

Final names may change in implementation, but the privilege boundaries must map
one-to-one to functions equivalent to:

- `issue_sensitive_action_permit_v2(unsigned_request, signed_permit)` — policy
  only; persists the exact canonical signed capability and issuance operation.
- `prepare_deletion_scope_v1(root_evidence_id, owner_interaction_id)` — policy
  only; computes and persists a canonical unsigned content-free target manifest.
- `finalize_deletion_scope_v1(manifest_id, signed_manifest)` — policy only;
  verifies the immutable prepared digest/expiry fields and freezes the exact
  signed representation used by the database claim and AWS executor.
- `read_claim_digest_for_notary_v1(operation_id)` — policy only; reads the
  content-free digest and immutable bindings directly from a valid `CLAIMED`
  database operation. The workflow service cannot supply or alter that digest.
- `store_sensitive_execution_grant_v1(operation_id, signed_grant)` — policy
  only; freezes the exact post-claim grant against the database claim digest.
- `attest_executor_receipt_v1(operation_id, signed_receipt)` — policy only;
  persists a content-free attestation after policy verifies the pinned executor
  public key, signature, domain, operation bindings, and deadline.
- `claim_evidence_retrieval_v1(serialized_permit, idempotency_key,
  requested_bytes)` — evidence only; claims one exact record and returns one
  bounded ciphertext package.
- `reconcile_evidence_retrieval_v1(operation_id)` — evidence only; advances
  only from the matching policy-written receipt attestation and never trusts a
  receipt body supplied by the workflow.
- `record_evidence_delivery_v1(operation_id, transport_outcome)` — evidence
  only; records `DELIVERY_CONFIRMED` or `DELIVERY_UNKNOWN` using a reviewed
  content-free transport enum and never stores plaintext.
- `claim_evidence_deletion_v1(serialized_permit, signed_manifest,
  idempotency_key)` — deletion only; recomputes/verifies scope and persists
  pending deletion state without deleting ciphertext.
- `reconcile_evidence_deletion_v1(operation_id)` — deletion only; advances only
  from the matching policy-written receipt attestation, then finalizes
  tombstones/ciphertext removal and the full derived-data invalidation cascade.
- `record_finality_verification_v1(operation_id, metadata_evidence)` — a
  separate one-off finality-verifier login only; advances finality from reviewed,
  content-free AWS backup/restore metadata and cannot read evidence or keys.

Readiness/liveness functions must be separate and content-free. They must not
quietly grant sensitive table access merely to reuse a shared startup path.

## 7. Authorization contracts

### 7.1 Common signed-envelope rules

Every signed contract contains:

- `contract_version` and `canonicalization_version`;
- an `object_type` domain separator that makes a signature invalid for every
  other contract type;
- signature algorithm and stable `key_id`;
- issuer, environment, issue time, and expiration or execution deadline;
- maximum accepted clock skew of 30 seconds;
- `storage_epoch`, `registry_epoch`, `key_epoch`, and relevant `record_version`;
  and
- a signature over a deterministic, byte-for-byte canonical representation.

Unknown fields, algorithms, domains, canonicalization versions, key IDs,
environments, or epochs fail closed. Signed free text is prohibited; reason and
result fields use reviewed enums.

### 7.2 `OwnerInteractionAssertionV1`

The phrase “independently verified active owner interaction” becomes a concrete
contract issued by the reviewed owner-event broker. It binds:

- channel and broker identity;
- stable owner subject;
- source interaction/message ID;
- requested sensitive action and exact evidence ID where known;
- authentication method;
- creation time, maximum age, nonce, and anti-replay identifier; and
- the common signed-envelope environment/epoch fields.

`lucy-policy` trusts only pinned owner-broker public keys and durable anti-replay
state. A Telegram allowlist, bearer token, model assertion, supplied message ID,
or cron/background context alone cannot create this assertion. Defining and
accepting this broker is a capture blocker, not Ray Array implementation.

### 7.3 `SensitiveActionPermitV2`

The existing `SensitiveActionPermitV1` contract is not silently reinterpreted or
extended. Baseline v1.2 introduces `SensitiveActionPermitV2` as the production
owner-intent root capability because the new domain, canonicalization, owner-
assertion, environment, epoch, key-ID, and deadline fields are wire-incompatible
security changes. Production v1.2 executors reject V1 permits. V1 remains only a
historical/local migration input while capture is disabled.

`SensitiveActionPermitV2` binds:

- common signed-envelope fields and permit ID;
- retrieval or deletion action;
- stable owner subject and exact `OwnerInteractionAssertionV1` ID/digest;
- exact root evidence UUID;
- content-free reason code;
- record and byte limits;
- issue time and `permit_claim_deadline`, with a maximum five-minute claim
  lifetime;
- random nonce; and
- Ed25519 signature.

The policy private key exists only in `lucy-policy`. Render workflows and AWS
executors receive only the public verification key. A database issuance row must
match the exact canonical signed object; possession of a syntactically valid
signature alone is insufficient at the PostgreSQL gate.

### 7.4 `DeletionTargetManifestV1`

One root deletion can invalidate several separately encrypted derived evidence
records. A permit that signs only the root evidence ID does not authorize an
untrusted workflow service to supply arbitrary additional key references.

Introduce `DeletionTargetManifestV1`, containing at minimum:

- common signed-envelope fields and manifest ID;
- root permit ID, nonce, action, root evidence ID, owner interaction, and
  idempotency binding;
- immutable database scope/version, record, key, registry, and storage epochs;
- a canonical, sorted, unique sequence of target evidence IDs and key references;
- target count and total manifest digest;
- claim and execution deadlines; and
- Ed25519 policy signature over the canonical representation.

`lucy-policy` obtains the content-free scope only through
`prepare_deletion_scope_v1`; it does not receive ciphertext or plaintext. The
database persists the canonical unsigned manifest before signature, then
`finalize_deletion_scope_v1` freezes the exact signed representation against the
prepared digest. The deletion claim function recomputes or loads the immutable
scope and rejects any mismatch. The AWS deletion executor verifies the policy
signature and the complete manifest/package digest before deleting a key.

The manifest prevents a compromised `lucy-deletion` process from substituting
another known `key_ref`. Ordinary Phase 1 deletion is capped at 90 wrapped-key
targets in one DynamoDB transaction. If the exact closure is larger, PostgreSQL
fences it as `BULK_REQUIRED`, policy does not sign a truncated ordinary manifest,
and completion requires a separately owner-authorized bulk-deletion design or
manual governed reconciliation. The service may never silently truncate the
cascade or mint a broader target list.

### 7.5 `SensitiveExecutionGrantV1`

After PostgreSQL claims an operation, `lucy-policy` acts as a content-free
notary. The workflow supplies only the operation ID. Policy calls
`read_claim_digest_for_notary_v1` itself, signs the returned immutable claim, and
stores the exact grant through `store_sensitive_execution_grant_v1`.

The grant binds:

- common signed-envelope fields;
- root permit ID and nonce;
- PostgreSQL operation ID and `session_user` service identity;
- exact evidence ID or deletion manifest ID/digest;
- exact encrypted package digest;
- action, environment, idempotency key, and all record/key/storage epochs;
- exact executor identity, qualified production alias ARN, and approved
  published Lambda version;
- issue time, original `permit_claim_deadline`, and separate
  `execution_deadline`; and
- policy-notary signature.

Lambda requires the original owner permit, post-claim execution grant, and exact
package/manifest. A valid owner permit without this post-claim grant cannot
execute. The untrusted workflow cannot cause policy to sign a caller-supplied
digest.

### 7.6 `ExecutorReceiptV1`

Each Lambda produces a canonical receipt that binds:

- common signed-envelope fields;
- executor identity, qualified alias, and published Lambda version;
- operation, permit, execution-grant, and manifest IDs as applicable;
- package or manifest digest;
- exact result enum;
- Lambda request ID and KMS request ID for retrieval, or the durable
  `TransactWriteItems` client request token for deletion;
- completion timestamp; and
- the dedicated executor receipt-signing `key_id` and KMS signature.

Each receipt key is an asymmetric `ECC_NIST_P256` KMS key with
`KeyUsage=SIGN_VERIFY`. The executor signs the 32-byte SHA-256 digest of the
domain-separated canonical receipt using `ECDSA_SHA_256` and
`MessageType=DIGEST`; policy verifies with the pinned public key outside KMS.
The evidence-wrapping key is never used for signatures.

For retrieval, Lambda conditionally stores the signed non-plaintext receipt in
the AWS execution ledger before releasing plaintext in its response. If receipt
creation or signing fails, Lambda returns no plaintext.

For deletion, Lambda constructs and signs the receipt before the DynamoDB
transaction. The same transaction conditionally appends the accepted signed
intent, stores that exact signed receipt, and deletes the exact manifest keys.
The known client request token is the transaction identifier in the receipt;
the later AWS response request ID is telemetry, not part of the atomic proof.

The workflow carries the signed receipt to policy. Policy verifies it with the
pinned executor public key and writes a content-free attestation through
`attest_executor_receipt_v1`. PostgreSQL reconciliation accepts only that policy-
written attestation and the exact previously stored receipt digest. Unsigned
workflow JSON is never reconciliation authority.

Receipt signing authenticates the executor authority, not honest execution
after full executor compromise. A compromised runtime holding its scoped
`kms:Sign` permission can sign false statements for opaque identifiers it knows;
that residual risk is contained by non-enumeration, separation, CloudTrail,
deletion recovery, and the human trust boundary rather than misrepresented as
cryptographic attestation of correct code execution.

### 7.7 Key trust, rotation, and revocation

- The policy notary signs permits, manifests, and execution grants with explicit
  domain separation. Policy trusts the owner-broker assertion keys and both
  executor receipt public keys.
- Each executor trusts only the production policy-notary public-key set and its
  own environment/alias bindings. PostgreSQL stores exact signed objects and
  trusts only policy-written receipt attestations.
- Production and development use separate keys and key IDs. A production key is
  never accepted in development or vice versa.
- Normal rotation publishes the next public key before issuance switches. The
  previous public key remains verification-only for no longer than maximum
  clock skew plus the longest valid execution deadline, then is removed from the
  active acceptance set. Its public key, validity interval, algorithm, purpose,
  and retirement/revocation status remain in an immutable historical
  verification registry for deletion recovery, receipts, and audit; historical
  storage can never authorize a newly issued object.
- Emergency revocation immediately blocks new claims/grants from the affected
  key ID. Already fenced deletion operations do not reopen; they require a new
  owner-authorized continuation or explicit manual reconciliation. Retrieval
  operations that have not produced a valid receipt fail final. Objects signed
  during a suspected compromise interval are marked for manual review rather
  than silently trusted as historical authority.
- Rotation, overlap, revocation, and trusted-key inventories are audited and
  exercised in acceptance tests.

### 7.8 Hard Phase 1 limits

| Limit | Phase 1 maximum |
| --- | --- |
| Plaintext retrieval result | 65,536 bytes |
| Serialized encrypted retrieval package | 131,072 bytes |
| Serialized deletion invocation package | 131,072 bytes |
| Ordinary deletion targets | 90 exact wrapped-key records |
| Ordinary deletion chunks | 1 DynamoDB transaction |
| Canonical deletion manifest | 65,536 bytes |
| Permit claim lifetime | 5 minutes |
| Post-claim execution deadline | 10 minutes |
| Decrypt Lambda configured timeout | 60 seconds |
| Deletion Lambda configured timeout | 120 seconds |

The implementation must also assert AWS's 100-action/4-MB DynamoDB transaction
limits and 6-MB synchronous Lambda request/response limits. Lucy's smaller caps
are the application boundary; AWS service maxima are not permission to expand
them. Parameters differing under the same idempotency key always fail.

## 8. Retrieval transaction

### 8.1 State model

```text
ISSUED -> CLAIMED -> EXECUTING -> EXECUTOR_RECEIPTED
   |          |          |               |
   +-> EXPIRED+----------+               +-> DELIVERY_CONFIRMED
                         |               +-> DELIVERY_UNKNOWN
                         +-> FAILED_RETRYABLE
                         +-> FAILED_FINAL
```

States are monotonic except that `FAILED_RETRYABLE` may resume the same operation.
Every transition is bound to the original permit, evidence ID, action,
idempotency key, caller, execution grant, epochs, and package digest.

`DELIVERY_CONFIRMED` means the reviewed downstream transport accepted the
delivery; it is not proof that a human read it. Plaintext delivery is at-most-once
and best-effort. A network or process failure after Lambda returns plaintext can
produce `DELIVERY_UNKNOWN`; the system must not claim that the owner received it.

### 8.2 Flow

1. Policy validates one `OwnerInteractionAssertionV1` and issues one retrieval
   permit.
2. `lucy-evidence` calls the retrieval claim function.
3. PostgreSQL verifies issuance, signature material, expiry, exact record,
   tombstone state, byte limit, caller, and idempotency; it atomically moves the
   operation to `CLAIMED` and returns one encrypted package.
4. `lucy-evidence` asks policy to notarize only that operation ID. Policy reads
   the claim digest directly from PostgreSQL, signs `SensitiveExecutionGrantV1`,
   and freezes the exact grant in PostgreSQL.
5. `lucy-evidence` invokes only the qualified decrypt Lambda alias with the
   owner permit, execution grant, and exact package.
6. Lambda independently verifies both signatures, action, deadlines, evidence/
   environment/epoch binding, nonce, package digest, exact alias, durable AWS
   nonce state, and quotas.
7. Lambda performs one exact wrapped-key read, calls KMS with the required
   evidence-bound encryption context, decrypts the AES-GCM payload internally,
   and produces no more than the permit's byte limit. It never returns the DEK.
8. Lambda signs and conditionally persists `ExecutorReceiptV1`. Only after that
   durable write succeeds may it return the bounded plaintext and signed receipt.
9. `lucy-evidence` gives the signed receipt to policy. Policy verifies the pinned
   receipt key and stores the content-free attestation. PostgreSQL reconciliation
   advances to `EXECUTOR_RECEIPTED` only from that attestation.
10. `lucy-evidence` makes one delivery attempt without persisting plaintext. It
    records transport acceptance as `DELIVERY_CONFIRMED`; an ambiguous response
    becomes `DELIVERY_UNKNOWN`.

If the database claim succeeds but Lambda is not invoked, the same idempotency
key can resume before the execution deadline. If Lambda decrypts but any later
response or process state is lost, its receipt survives but plaintext is not
cached. A replay after the durable executor receipt exists returns only the
signed receipt/status, never plaintext. Delivering plaintext again always
requires a new owner assertion and permit. Exactly-once claims apply to permit
consumption, executor receipt, and logical reconciliation—not human plaintext
delivery.

## 9. Deletion transaction

### 9.1 State model

```text
ISSUED -> CLAIMED -> EXECUTING -> EXECUTOR_RECEIPTED -> EFFECTIVE
   |          |          |                                  |
   +-> EXPIRED+          +-> FAILED_RETRYABLE                +-> FINALITY_PENDING
              +-> BULK_REQUIRED                             +-> FINALITY_EXTENDED
                                                          -> FINALITY_VERIFIED
```

The user-visible meanings are distinct:

- **Deletion claimed:** the request is accepted and no new retrieval or memory
  use may begin. The user sees “deletion accepted,” not “forgotten.”
- **Deletion executing:** a retrieval claimed earlier may still finish; key
  deletion and reconciliation are pending.
- **Deletion effective:** the exact key-removal receipt exists and PostgreSQL
  reconciliation/cascade completed. Lucy may now report “forgotten.”
- **Deletion cryptographically final:** finality verification proves no
  recoverable wrapped-key copy remains.

Phase 1 explicitly accepts that a retrieval already executing when deletion is
claimed may finish. It does not promise revocation of already disclosed or in-
flight plaintext. All later retrieval claims are fenced immediately, and the
race is an explicit acceptance test.

Retrieval and deletion claim functions acquire the same per-evidence database
lock in the reviewed global lock order. A retrieval claim that commits first is
the previously authorized in-flight operation described above. A deletion claim
that commits first makes every later retrieval claim fail closed. There is no
unimplemented claim of a cross-cloud lease or atomic revocation.

### 9.2 Flow

1. Policy verifies owner interaction, prepares the exact deletion closure, and
   signs the root permit plus `DeletionTargetManifestV1`.
2. `lucy-deletion` calls the deletion claim function.
3. PostgreSQL validates the stored permit and manifest, recomputes target
   coverage, atomically claims the operation, records pending deletion, and
   fences the root and derivatives from normal retrieval/promotion.
4. If the closure exceeds 90 keys or the 65,536-byte canonical manifest limit,
   PostgreSQL leaves it fenced as `BULK_REQUIRED`; ordinary execution stops.
5. Otherwise `lucy-deletion` asks policy to notarize only the claimed operation
   ID. Policy reads the digest directly from PostgreSQL, signs
   `SensitiveExecutionGrantV1`, and freezes it in PostgreSQL.
6. `lucy-deletion` invokes only the qualified deletion Lambda alias with the
   owner permit, signed manifest, execution grant, and exact target package.
7. Lambda independently validates every signature, action, claim/execution
   deadlines, manifest/package/environment/epoch binding, nonce, exact alias,
   quotas, and durable prior receipt state.
8. Lambda signs `ExecutorReceiptV1`. One `TransactWriteItems` call atomically
   appends the accepted independent signed intent/manifest, stores that exact
   immutable signed receipt, updates bounded quota state, and deletes no more
   than the manifest's 90 exact wrapped-key items. The built-in ten-minute
   client-token window is supplemental; the durable signed intent and receipt
   are authoritative.
9. A lost response resumes only the same grant/manifest/transaction token. A
   matching receipt plus absent exact keys reconciles as success. Missing keys
   without that receipt and accepted manifest fail closed.
10. `lucy-deletion` gives the signed receipt to policy. Policy verifies the
    pinned receipt key and writes a content-free attestation. The database
    reconciliation function accepts only that attestation, then atomically
    writes tombstones, removes ciphertext, invalidates/redacts every derivative,
    appends audit, records `deletion_effective_at`, and advances to `EFFECTIVE`.

No startup path invents, accepts, or completes deletion authority. Interrupted
operations require the explicit reviewed reconciliation path. The owner permit
must be claimed before `permit_claim_deadline`; the same exact fenced operation
may execute only until `execution_deadline`. After that it requires a new owner-
authorized continuation or manual reconciliation and can never silently reopen.

## 10. Thirty-day protected recovery

### 10.1 User-visible semantics

After a deletion claim is accepted:

- new routine recall, memory promotion, and raw retrieval claims are fenced;
- an already executing retrieval may finish during the documented Phase 1 race;
- the user sees “deletion accepted” while execution/reconciliation is pending;
  and
- no fixed finality date is claimed before actual recovery-state verification.

At `EFFECTIVE`:

- receipt-backed wrapped-key removal and PostgreSQL cascade are complete;
- no Render or Lambda runtime can restore the evidence;
- Lucy may report “forgotten”; and
- finality remains pending during the protected recovery interval.

For 30 days, DynamoDB point-in-time recovery preserves a human-administrator
recovery path. During this interval deletion is operationally effective but not
yet cryptographically final. Finality requires positive verification that the
oldest restorable point no longer contains the key and that no exceptional copy
remains.

PostgreSQL stores at least:

- `deletion_effective_at` — exact logical completion time;
- `finality_not_before` — initial lower bound derived from effective key removal
  and the configured recovery period;
- `finality_verified_at` — null until a reviewed verifier proves finality; and
- `finality_status` — `PENDING`, `EXTENDED`, or `VERIFIED` with a content-free
  reason/evidence reference.

The system never declares finality merely by adding 30 days to a timestamp.

### 10.2 Registry controls

- Enable DynamoDB PITR on the wrapped-key registry with a 30-day recovery period.
- Keep deletion protection and retained infrastructure lifecycle controls.
- Prohibit normal table deletion. DynamoDB creates a separate 35-day system
  backup when a PITR-enabled table itself is deleted; if that exceptional event
  occurs, the affected deletion-finality clock extends until that additional
  recoverable copy expires and the incident is explicitly reconciled.
- Do not create on-demand backups, AWS Backup plans, exports, global replicas,
  streams containing wrapped-key values, or application logs that extend the
  recovery period.
- Inventory account-level backup/export mechanisms before activation and alarm
  on changes that can create an unreviewed copy.
- Store deletion receipts/journal longer than the key recovery window so an
  authorized deletion remains distinguishable from an unauthorized deletion.
- Finality verification checks the registry's actual
  `EarliestRestorableDateTime` is later than the key-removal transaction,
  inventories on-demand/AWS Backup recovery points, deleted-table system
  backups, exports, replicas, and quarantined/restored tables, and records a
  content-free evidence digest. Any exceptional copy changes status to
  `EXTENDED` and moves the lower bound later; it can never shorten finality.

Phase 1 finality verification is an audited, operator-triggered one-off utility
inside the Render private environment, not a fifth continuously running backend
service and not normal startup work. Its exact database login can execute only
`record_finality_verification_v1`; its exact OIDC role can read only backup,
restore, export, table, and PITR metadata. It receives no `GetItem`, Scan, Query,
restore, write/delete, KMS, transcript, or wrapped-key permission. A false
operator verification remains an audited availability/assurance risk but cannot
itself recover or decrypt evidence.

### 10.3 Manual recovery procedure

Only the MFA-protected `LucyRecoveryAdministrator` may perform recovery:

1. Disable sensitive operations and quarantine normal services without using
   ordinary startup repair.
2. Open an incident and record why the suspected deletion was unauthorized.
3. Restore the registry to a new isolated quarantine table at the appropriate
   pre-deletion time. Before anyone inspects or copies an item, apply restrictive
   IAM/resource policy, quarantine tags, logging, and deletion controls. Do not
   assume source-table IAM policies, alarms, tags, streams, TTL, or PITR settings
   were carried into the restored table.
4. Validate the independent journal, manifest, CloudTrail events, operation
   ledger, record identity, registry identity, and absence of a valid owner-
   authorized deletion.
5. Copy only the exact wrapped-key item proven to have been deleted without
   authority. Never replace or roll back the production table wholesale.
6. Reconcile PostgreSQL under a new controlled recovery operation/storage epoch.
7. Verify service denial/allow behavior, retain content-free evidence of the
   decision, and remove the quarantine table according to the runbook.

If a valid owner-authorized deletion exists, policy prohibits restoration even
though the administrator can technically restore the historical table during
the window. Phase 1 uses one strongly authenticated human administrator; it does
not claim two-person or Ray Array authorization. That is an accepted residual
risk. Because the same owner can assume both security and recovery roles, their
separation is procedural and session-based, not containment of a fully
compromised or coerced human administrator.

## 11. Network and secret controls

- Render services and PostgreSQL must share the same protected production
  environment and Virginia private network.
- PostgreSQL's external IP allowlist must be explicitly empty. An acceptance
  test from outside Render must fail before any real data exists.
- Render OIDC trust must bind exact workspace, environment, service subject, and
  `sts.amazonaws.com` audience. Permanent AWS access keys are forbidden.
- Development and production use separate evidence-wrapping and receipt-signing
  KMS keys, DynamoDB tables, Lambda functions/aliases, runtime and caller roles,
  Render service subjects, database logins, registry/key/storage epochs, and
  trusted-key inventories. No development principal can address a production
  resource, and no production contract validates in development.
- The policy service must have no `AWS_ROLE_ARN`, web-identity token path,
  DynamoDB/KMS variables, or Lambda invocation permission.
- Caller roles invoke only qualified production alias ARNs. No function URL is
  created. Lambdas accept no unauthenticated HTTP path.
- Lambda runtime roles, caller roles, deployer, security administrator, and
  recovery administrator remain separate.
- Secrets must be service-specific and rotated after any environment cloning,
  staff/access change, suspected exposure, or failed acceptance involving logs.
- Production aliases point only to artifact-digest-verified, tested published
  versions. Rollback points to a previously accepted version, never `$LATEST`.
- Evidence KMS operations require the exact approved encryption-context key set,
  not merely one present field. The set binds `application`, `environment`,
  opaque evidence ID, record version, key epoch, and registry epoch; fixed values
  use exact IAM conditions, dynamic fields are required and verified by the
  executor, and unexpected context keys are denied. Context values contain no
  transcript or semantic text because KMS records them in audit logs.

## 12. Quotas, observability, and alarms

### 12.1 Quotas

Reserved concurrency limits simultaneous Lambda executions but is not a daily
security boundary. Each executor also uses durable conditional counters for
reviewed per-minute and per-day ceilings.

Initial numerical ceilings must be chosen from synthetic acceptance traffic and
recorded before deployment. Exceeding a ceiling denies the operation and alerts;
it never falls back to direct KMS/Dynamo access.

A fully compromised Lambda runtime can attempt to bypass quota code using its
runtime AWS permissions. Phase 1 containment then depends on lack of enumeration,
opaque UUIDs, exact database gating, signed permits/manifests, short-lived role
credentials, KMS context, receipts, recovery, and detection. Quotas must not be
described as hard containment of that total compromise.

### 12.2 Required records and alerts

- CloudTrail management events and KMS cryptographic events remain enabled.
- DynamoDB data events cover wrapped keys, executor ledgers, deletion receipts,
  and recovery actions.
- CloudWatch metrics distinguish accepted, denied, expired, replayed, throttled,
  retried, executor-receipted, delivery-confirmed, delivery-unknown, deletion-
  effective, finality-extended/verified, and failed operations without content.
- Immediate alerts cover unexpected KMS decrypt volume, multiple deletion
  attempts, assertion/grant/receipt/manifest mismatch, receipt-signing failure,
  direct denied runtime API calls, signing-key/function/alias changes, IAM/KMS
  policy changes, PITR/backup changes, and recovery/finality-verifier use.
- CloudTrail/KMS encryption context contains only opaque evidence identifiers;
  it never includes transcript text or semantic labels.
- Audit delivery and alert receipt are tested with non-destructive synthetic
  events before activation.

## 13. Threat matrix after v1.2

| Single compromised boundary | Expected maximum consequence | Still blocked |
| --- | --- | --- |
| Hermes | Current conversation/runtime history and allowed routine calls | Permit signing, DB exact gate, executor authority |
| `lucy-routine` | Current processing, plaintext structured memory, new ciphertext ingestion disruption | Historical raw decrypt; key reads/deletes; permit signing |
| Owner-broker assertion key | Forged owner-interaction assertions for known identifiers | Policy/database issuance rules, executor invocation, ciphertext/key access |
| `lucy-policy` | Forged permits/manifests/grants/receipt attestations and authorization metadata | Executor invocation, evidence ciphertext/plaintext, KMS/Dynamo actions |
| Policy private signing key | Forged policy-signed contracts outside the service for identifiers the attacker knows | Database issuance/claim state, exact caller role, executor invocation, ciphertext/key enumeration |
| `lucy-evidence` | Every plaintext record legitimately passing through it while compromised; delivery suppression/duplication attempts | Table enumeration, direct wrapped-key access, direct KMS, policy forgery |
| `lucy-deletion` | Workflow disruption and replay attempts for packages it legitimately receives | Table enumeration, arbitrary manifest substitution, direct key/ciphertext deletion |
| Evidence caller AWS role | Invoke decrypt alias with attacker-supplied requests | KMS/Dynamo access; valid permit/database package creation |
| Deletion caller AWS role | Invoke deletion alias with attacker-supplied requests | KMS/Dynamo access; valid signed manifest/database claim creation |
| Decrypt Lambda runtime and receipt-signing authority | Decrypt/exfiltrate any exact opaque package/key reference already known to it, forge its receipts, and bypass its own quotas | Enumeration through granted PostgreSQL/Dynamo APIs, policy signing, key deletion |
| Deletion Lambda runtime and receipt-signing authority | Delete any exact opaque key references already known to it, forge its receipts, and bypass its own quotas | Enumeration through granted PostgreSQL/Dynamo APIs, evidence-key KMS use; protected recovery remains |
| Sensitive PostgreSQL login | Invoke only named functions with valid stored authorization | Direct table enumeration/mutation, AWS actions |
| PostgreSQL migration/function-owner role | Read/alter database state and security functions, forge claim state, or disrupt/fence service | AWS caller/executor roles, policy keys, KMS/Dynamo authority unless another boundary is crossed |
| PostgreSQL theft/backup | Ciphertext, metadata, plaintext structured memory | Raw transcript decryption without AWS key path |
| One-off finality verifier | Falsely delay or claim finality and expose backup inventory metadata | Evidence/key item reads, restores, writes, KMS use, transcript access |
| Render workspace administrator | Alter deployments/configuration and potentially compromise several Render services/secrets together | AWS account administration and recovery copies, absent additional compromise; nevertheless an ultimate Phase 1 platform trust boundary |
| AWS security/deployment administrator | Change Lambda code, IAM/KMS policy, aliases, tables, audit, or recovery controls | Not contained by Phase 1 runtime separation; MFA-protected audited human trust boundary |
| Recovery administrator | Restore wrapped keys during the protected window | Normal KMS decrypt and application authority when used alone; separation from security administration is procedural for one human |
| Retrieval already executing when deletion is claimed | Previously authorized plaintext may still be returned before key deletion wins the race | Every new retrieval/memory claim; “forgotten” status until deletion is effective |

Coordinated compromise of policy plus the matching workflow/caller boundary can
defeat single-service separation. AWS administrator, Render administrator,
software supply-chain, owner-account, coercion, and multi-boundary compromise
remain explicit Phase 1 residual risks.

## 14. Acceptance plan

All tests use synthetic evidence. No denial test performs KMS master-key
disable/deletion, production-table deletion, or other destructive administration.

### 14.1 Static and build acceptance

- Contract canonicalization/signature vectors pass across Render and Lambda
  implementations for owner assertions, permits, manifests, execution grants,
  and receipts, including wrong domains, algorithms, key IDs, environments,
  epochs, clock skew, rotation overlap, and emergency revocation.
- One migration head; clean-cluster upgrade and documented rollback/forward fix.
- Lambda artifacts are dependency-locked, scanned, digest-recorded, and published
  as versions; production aliases reference accepted versions.
- Infrastructure templates have no direct KMS/Dynamo permission on evidence or
  deletion caller roles and no Lambda invoke permission on policy/routine roles.
- Production/development keys, tables, aliases, roles, OIDC subjects, and
  contract trust stores are disjoint; every cross-environment attempt fails.
- Render template keeps capture explicitly false and PostgreSQL external access
  is separately verified empty.

### 14.2 PostgreSQL permission acceptance

As each real production-shaped login:

- allowed named functions succeed only for their service;
- direct `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `COPY`, function alteration,
  schema/object creation, role changes, extension creation, and backup operations
  fail as specified;
- sensitive functions are not executable by `PUBLIC` or another runtime role;
- functions identify callers with `session_user`; runtime `SET ROLE`, inherited
  role, and session-authorization escalation attempts fail;
- wrong caller, permit, action, ID, reason, expiry, nonce, byte count,
  idempotency key, manifest, grant, receipt, environment, epoch, scope version,
  or package digest fails;
- policy reads the claim digest directly; a workflow-supplied digest is never
  signed or accepted;
- reconciliation rejects unsigned, incorrectly signed, wrong-executor, wrong-
  version, wrong-alias, wrong-operation, or unattested receipts;
- concurrent claims produce one durable claim; and
- readiness does not require broad data privileges.

### 14.3 AWS permission acceptance

- Evidence/deletion Render caller roles can invoke only their qualified
  production alias.
- Those roles cannot invoke `$LATEST`, unqualified functions, the other
  executor, or any KMS/Dynamo/IAM/backup API.
- Decrypt runtime denies Scan, Query, BatchGet, export, DeleteItem,
  GenerateDataKey, administration, unrelated evidence contexts, and the deletion
  receipt-signing key. It may sign only with its dedicated receipt key.
- Deletion runtime denies every action on the evidence KMS key, the retrieval
  receipt key, Scan, Query, BatchGet, export, table deletion, backup, receipt
  mutation/deletion, and unrelated tables. It may sign only with its dedicated
  receipt key.
- Policy has no callable AWS identity.
- Runtime roles cannot change Lambda code, versions, aliases, policies, logs,
  alarms, PITR, or CloudTrail.

### 14.4 Retrieval acceptance

- One synthetic owner assertion, permit, DB claim, policy-notarized execution
  grant, exact Lambda invocation, KMS decrypt, signed/durable non-plaintext
  receipt, policy attestation, reconciliation, and bounded delivery succeeds.
- Forged, expired, replayed, wrong-action, wrong-record, wrong-reason,
  wrong-owner-interaction, over-byte, tampered-ciphertext, swapped-key,
  mismatched-context, altered-package, wrong-environment/epoch/alias, and forged-
  grant/receipt requests all fail independently at the appropriate boundaries.
- Claim-then-crash resumes only the same idempotent operation.
- Receipt-signing or durable-receipt failure returns no plaintext.
- Decrypt-response or delivery loss produces `DELIVERY_UNKNOWN`, records no
  plaintext, makes no human-delivery claim, and requires a new assertion/permit
  for another attempt.
- Logs, traces, metrics, receipts, and error bodies contain no plaintext or key.

### 14.5 Deletion acceptance

- One root record with multi-hop/multi-source derived artifacts produces the
  canonical signed manifest and deletes only its exact key closure.
- Adding, removing, reordering, duplicating, or substituting a target/key
  invalidates the manifest or database scope check.
- Wrong permit/action/record/manifest/grant/receipt/idempotency key fails.
- Crash before AWS execution leaves the operation resumable and data fenced.
- The accepted signed intent, exact key deletions, bounded quota update, and
  immutable signed receipt commit in one DynamoDB transaction of no more than
  100 actions/4 MB; an over-90-target closure becomes fenced `BULK_REQUIRED`.
- Lost DynamoDB response and crash before PostgreSQL reconciliation complete
  exactly once logically without broader deletion.
- A matching immutable receipt plus absent key reconciles as success; an absent
  key without that receipt fails closed.
- Derived claims, relationships, proposals, corrections, approvals, working
  context, embeddings/summaries if present, and Hermes/runtime residues follow
  the reviewed cascade and cannot repopulate memory after restart.
- A deliberately raced earlier retrieval may finish, no later retrieval begins,
  the user sees “deletion accepted” while pending, and “forgotten” appears only
  after receipt attestation and PostgreSQL reconciliation establish `EFFECTIVE`.

### 14.6 Compromise-oriented acceptance

- Stolen evidence DB credentials cannot enumerate evidence, permits, ciphertext,
  key references, or claims.
- Stolen evidence caller credentials plus DB credentials cannot bulk-decrypt or
  bypass a valid exact permit.
- Stolen deletion DB credentials cannot enumerate or directly delete ciphertext.
- Stolen deletion caller credentials plus DB credentials cannot delete a key
  without the exact signed manifest, post-claim execution grant, and matching
  claim.
- A compromised policy identity can create signed authorization but cannot invoke
  either executor or read ciphertext.
- Executor roles cannot enumerate the archive or registry even when normal
  application checks are deliberately bypassed in a synthetic harness.
- A forged workflow package cannot obtain a policy grant; a forged workflow
  receipt cannot obtain a policy attestation.
- Complete executor compromise is tested/documented as abuse of already-known
  opaque identifiers, not incorrectly described as access to exactly one ID.

### 14.7 Recovery and finality acceptance

- Wrapped-key PITR reports a 30-day recovery period and no unreviewed backup,
  export, replica, or stream extends it.
- Render PostgreSQL external access fails from outside Render.
- An unauthorized synthetic deletion is restored from a quarantined PITR table
  by the recovery administrator only; restrictive policy/logging/tags are
  applied before inspection, and normal runtimes cannot restore it.
- A valid owner-authorized synthetic deletion is identified by the independent
  journal and is not restored.
- PostgreSQL backup restoration does not bypass the AWS receipt/journal fence.
- Recovery creates a new controlled storage epoch and never rolls the production
  registry back wholesale.
- `deletion_effective_at`, `finality_not_before`, `finality_verified_at`, and
  `finality_status` behave monotonically; time passage alone never verifies.
- The finality verifier uses actual earliest/latest restorable times and backup/
  export/quarantine inventory. A synthetic exceptional copy extends status to
  `EXTENDED`; only absence of every recoverable copy permits `VERIFIED`.

## 15. Implementation sequence and gates

1. **Design review:** Lucy and owner review this plan, including the signed
   deletion manifest and accepted residual risks.
2. **Contract first:** define canonical `OwnerInteractionAssertionV1`, operation
   package, permit, deletion manifest, `SensitiveExecutionGrantV1`,
   `ExecutorReceiptV1`, quota, finality, and state-transition contracts plus
   cross-language test vectors and rotation/revocation rules.
3. **PostgreSQL gate:** add migrations, function-owner roles, execute-only
   claim/notary/attestation/reconciliation functions, revocations, state tables,
   and real-login negative tests.
4. **AWS executors:** implement locally testable pure handlers, durable ledger/
   signed-receipt adapters, exact KMS/Dynamo calls, quotas, and sanitized
   telemetry.
5. **Infrastructure v1.2:** replace direct workload roles with exact caller and
   executor roles; add separate executor receipt-signing keys, Lambda versions/
   aliases, PITR, recovery/deployer identities, alarms, environment separation,
   and outputs. Do not mutate the v1.1 production template in place without a
   reviewed migration/rollback path.
6. **Render v1.2:** remove KMS/Dynamo variables from evidence/deletion, add exact
   alias invocation configuration, use distinct execute-only DB logins, and
   keep capture false.
7. **Local acceptance:** run static checks, complete synthetic tests, PostgreSQL
   concurrency/crash tests, and policy-template negative tests.
8. **Synthetic cloud acceptance:** provision only reviewed resources, test real
   OIDC, actual IAM denials, synthetic retrieval/deletion, alarms, ambiguity,
   and restart behavior.
9. **Recovery drill:** perform a quarantined synthetic PITR recovery and record
   RPO, RTO, permissions, costs, and cleanup.
10. **Final report:** Lucy reviews exact deployed identities, digests, tests,
    exceptions, residuals, rollback, and cost projection.
11. **Owner activation:** only the owner may separately authorize live Telegram
    transcript capture after accepting the final report.

No clean intermediate step silently advances to capture activation.

## 16. Cost and operational impact

Version 1.2 retains the four planned Render backend services. It adds two
low-volume on-demand Lambda functions, DynamoDB execution/receipt/quota items,
two asymmetric KMS receipt-signing keys, 30-day PITR for the wrapped-key table,
Lambda/CloudWatch telemetry, and additional CloudTrail data events.

It deliberately avoids:

- two additional continuously running Render executor services;
- a Lambda VPC/NAT gateway solely for reverse PostgreSQL connectivity; and
- moving the authoritative database into AWS during this security pass.

Expected request/compute/storage volume is small, but no fixed dollar promise is
part of this plan. Before provisioning, use current AWS and Render pricing to
record monthly low/expected/alert-threshold projections. CloudTrail data events,
log retention, PITR storage, and alert delivery must be included rather than
assuming Lambda compute is the only cost.

## 17. Rollback and upgrade rules

- Capture remains false during every rollout and rollback.
- Database changes are forward-fix by default; destructive downgrade is not an
  automatic rollback strategy.
- The prior Lambda version remains published and recorded until the new version
  passes acceptance; alias rollback requires the separate deployer.
- A rollback may never restore direct KMS/Dynamo authority to Render evidence or
  deletion services.
- IAM broadening, PostgreSQL external access, disabling PITR/audit, or bypassing
  permits to restore availability requires a new security review.
- Ambiguous deployment state fails closed and is reconciled before reopening
  sensitive operations.

## 18. Approved decisions

On 2026-09-02 Lucy/Ray and the owner confirmed the following twelve decisions
and accepted the documented Phase 1 residual risks:

1. `OwnerInteractionAssertionV1` makes owner-event verification concrete, and
   the incompatible new security fields use `SensitiveActionPermitV2` rather
   than silently changing the existing V1 wire contract.
2. Policy reads PostgreSQL claim digests directly and signs
   `SensitiveExecutionGrantV1`; an untrusted workflow cannot authenticate its own
   package.
3. Each executor signs `ExecutorReceiptV1` with its separate asymmetric receipt
   key; policy verifies and attests it; PostgreSQL never trusts an unsigned
   workflow receipt.
4. Receipt signing authenticates executor authority but is not described as
   proof of honest behavior after total executor compromise.
5. Retrieval delivery is at-most-once/best-effort and may become
   `DELIVERY_UNKNOWN`; plaintext is never cached and no plaintext is released
   before the executor receipt is durable.
6. New retrievals are fenced at deletion claim, an already executing retrieval
   may finish, and “forgotten” is reported only at `EFFECTIVE`.
7. Finality uses actual recoverable-copy verification and the four stored
   finality fields; a metadata-only one-off verifier records it, and exceptional
   copies extend the normal 30-day window.
8. Ordinary Phase 1 deletion is one signed transaction of at most 90 wrapped-key
   targets; larger closures remain fenced as `BULK_REQUIRED` for separately
   authorized handling.
9. PostgreSQL uses `session_user`, denies runtime role switching, and preserves
   the reviewed security-definer hardening.
10. Contract domains, canonicalization, algorithms, key IDs, clock skew,
    rotation/revocation, claim/execution deadlines, size/time bounds,
    environment separation, and epoch bindings are explicit.
11. AWS/Render/human administrator trust, known-identifier executor abuse,
    migration-owner compromise, signing-key compromise, and the retrieval/
    deletion race appear candidly in the threat matrix.
12. V1.2 inherits every v1.1 control not expressly superseded. Ray Array,
    two-person recovery, encrypted semantic memory, and broader cloud migration
    remain out of scope unless implementation exposes a material vulnerability.

## 19. Reference basis

Repository sources being revised or preserved:

- [Security Baseline v1.1](security-baseline-v1.1.md)
- [Expanded Phase 1 gap review](phase1-gap-review-2026-08-31.md)
- [Independent deletion recovery checkpoint](deletion-recovery-2026-08-31.md)
- [Current Render/AWS acceptance plan](render-aws-kms-acceptance.md)
- [Current production database grants](../deploy/postgres/production_roles.sql.example)
- [Current AWS template](../deploy/aws/security-baseline-v1.1.yaml)

Authoritative platform behavior used by this plan:

- [Render PostgreSQL internal/external connectivity and IP allowlists](https://render.com/docs/postgresql-creating-connecting)
- [Render PrivateLink direction and limitations](https://render.com/docs/private-link)
- [PostgreSQL safe `SECURITY DEFINER` functions and default `PUBLIC` execution](https://www.postgresql.org/docs/current/sql-createfunction.html)
- [DynamoDB PITR periods, pricing behavior, and deleted-table system backups](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html)
- [DynamoDB point-in-time restoration to a new table](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_RestoreTableToPointInTime.html)
- [DynamoDB transactional writes](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html)
- [Lambda synchronous invocation payload limits](https://docs.aws.amazon.com/lambda/latest/api/API_Invoke.html)
- [Lambda reserved concurrency](https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html)
- [AWS KMS asymmetric `Sign`](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)
- [AWS KMS encryption-context policy conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html)
- [AWS KMS CloudTrail logging](https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html)

Current platform documentation must be rechecked immediately before production
provisioning; this draft records the behavior reviewed on 2026-09-02.

## 20. Activation gate

Live Telegram transcript capture remains prohibited until all of the following
are true:

- Lucy and the owner approve the final v1.2 design.
- The implementation and infrastructure diffs receive review.
- All database, IAM, contract, crash, compromise, observability, restore, and
  finality acceptance tests pass against production-shaped synthetic resources.
- Owner-event verification, clean Hermes history/reset, provider privacy, budget,
  backup, and remaining Phase 1 capture blockers also pass.
- The final acceptance report lists every deployed identity and permission,
  artifact digest, test result, exception, cost, RPO/RTO, rollback route, and
  residual risk without including secrets.
- The owner separately and explicitly enables capture.

Until then, the safe expected state is a functioning development system with
capture disabled—not a partially trusted production archive.
