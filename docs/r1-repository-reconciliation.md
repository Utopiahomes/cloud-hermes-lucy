# R1 repository reconciliation

Status: R1-0 and the R1-1 synthetic local slice are complete. R1-2 contracts,
single-realm process sessions, authenticated admission, scoped memory, sensitive
operations, deletion recovery, and scoped off-record enforcement are implemented
locally. A repeatable per-realm AWS template and validated AWS-to-PostgreSQL stamp
handoff are prepared locally. R1-2 deployed verification and commissioning remain
outstanding; production provisioning remains disabled.

## Frozen baseline

- Inspected source: `aa157bded743976e934887b996ea8d79a5ebacef`, a documentation-only
  successor to accepted runtime `52527fa9d8eaa3be766986101b6a8f51c1b1c208`.
- Accepted v1.2 PostgreSQL head: `0021_recovery_capture_safety`; additive R1 local
  head: `0039_r1_scoped_capture_runtime`.
- Accepted AWS executor source: `0020aaaf1add48feb7e083c22d4770b3415a2e51`.
- Signed contracts remain `SensitiveActionPermitV2`, `SensitiveExecutionGrantV1`, and
  `ExecutorReceiptV1`, using Ed25519, `lucy-cjson-1`, a 30-second skew allowance, and
  the existing ten-minute workflow execution window.
- The deployed executor sequence remains PostgreSQL claim, policy-signed grant,
  Lambda AWS effect, policy-attested receipt, PostgreSQL reconciliation. Lambdas do
  not connect to PostgreSQL.
- Live Telegram capture remains disabled. R1 work does not alter this gate.

The complete v1.2 acceptance evidence and cloud identities are recorded in
`docs/security-baseline-v1.2-final-acceptance-2026-09-08.md`. Evidence remains valid
because R1-1 is additive and does not change the accepted contracts, executors,
archive, deletion, recovery, or deployment templates.

## Actual repository map

| Boundary | Current authority | R1 disposition |
| --- | --- | --- |
| Signed sensitive operations | `contracts/security_v1_2.py`, `security_workflows.py`, migrations 0017-0021 | Frozen through R1-1 |
| AWS effects | `executors/handlers.py`, v1.2 CloudFormation | Frozen; realm parameterization begins R1-2 |
| Memory/evidence | `memory.py`, `archive.py`, `evidence.py`, `provenance.py` | Single-realm today; scope migration begins R1-2 |
| Model cost | `model_execution.py`, `actions.py`, `budget_accounts` | Single fixed model/reservation today; replaced for paid traffic in R1-3 |
| Runtime admission/recovery | `readiness.py`, `recovery.py`, `authorized_deletion_recovery.py` | Preserve v1.2; authority/cost overlays begin R1-4 |
| Local PostgreSQL | digest-pinned pgvector/PostgreSQL 16 in `compose.test.yaml` | R1 migrations proven here |
| Render PostgreSQL | PostgreSQL 18 in the reviewed Blueprint | Version/extensions and price must be verified before provisioning |
| Tenant/public directory | None before R1 | Added by migration `0022_r1_tenant_public` |

## R1-1 change record

Migration `0022_r1_tenant_public` is additive. It introduces accounts, stable nodes,
append-only tenures, realms and active realm bindings, issuer/subject principals,
workspaces, memberships, trusted hostname bindings, Lucy instance identities, and
one `REGISTERED_NONSPENDABLE` wallet registration per node. Composite foreign keys
prevent a workspace or channel from mixing node and tenure identifiers.

The public projection is physically distinct from private memory tables. A candidate
contains canonical FAQ JSON and its digest. Approval binds the reviewed digest;
publication copies those exact bytes into an immutable version and updates only a
small active route pointer. Website lookup resolves scope from the registered,
normalized hostname and queries only the active public version. It has no private
memory fallback. Withdrawal immediately clears the pointer. Durable independent
withdrawal acknowledgement and protected recovery handoff remain R1-4 gates, so
withdrawal is currently a local implementation primitive rather than a production
durability claim.

## Authority and unresolved deployment facts

- R1-1 local provisioning uses the existing migration/application identity. Website
  reads use a dedicated `lucy_public_runtime` login with execute-only access to the
  exact lookup function and no projection-table enumeration. Separate production
  publisher/approver logins and their rendered grant template remain required before
  deployment; the current slice does not claim that final credential blast radius.
- Customer authentication will bind stable issuer/subject pairs. AWS operator SSO is
  not customer authentication. The production IdP, audience, and strong-auth claim
  remain an activation decision.
- No production DNS, databases, KMS keys, Render services, customer records, paid
  inference, or transcript capture are authorized by this implementation pass.
- The production hosting quote and exact continuously deployed realm set remain
  R1-5 commissioning inputs. These do not block the synthetic slice.

## Verification ledger

| Check | Evidence | Invalidated by |
| --- | --- | --- |
| Clean migration 0001 through `0039` | Disposable pgvector/PostgreSQL 16 tmpfs cluster | Migration or bootstrap change |
| Post-0034 cumulative V1.3 contracts, scoped deletion chain, and three-realm recall boundaries; 20 tests passed | Three focused unit/integration files on the clean PostgreSQL 16 cluster | V1.3 contracts, migrations 0030-0034, deletion chain, or scoped-memory search rules |
| Cumulative V1.3 contracts, scoped permit/archive/grant/receipt/deletion, internal admission, and three-realm memory boundaries; 27 distinct tests passed | Four focused unit/integration files on the clean PostgreSQL 16 cluster; the initially omitted synthetic Alpha login variable was supplied and its two-test file passed | Any covered contract, migration 0022-0031, realm login bootstrap, or scoped service change |
| Host normalization and snapshot digest | `tests/unit/test_r1_tenancy_publication.py` | Canonicalization/input change |
| Utopia approved FAQ, Alpha isolation, spoof denial, immutable bytes, withdrawal | `tests/integration/test_r1_tenant_public_slice.py` | Tenancy/publication/schema change |
| Wallet uniqueness and tenure immutability | same integration test | Identity/schema change |
| V1.3 scope, KMS context, permit deadlines, purpose-pinned signature | `tests/unit/test_security_contracts_v1_3.py` | V1.3 contract/canonicalization change |
| One process holds exactly one fixed private-realm credential; verified workload and scope conflicts fail closed | `tests/unit/test_realm_sessions.py` | Realm binding/session selection change |
| Raymond/Utopia/Alpha execute-only memory isolation, direct-table denial, idempotent replay/conflict, unbound-login denial | `tests/integration/test_r1_scoped_memory.py` on disposable PostgreSQL 16; 2 passed | Scoped-memory schema/functions, bootstrap roles, or client change |
| Realm-specific audience/strength admission, content-free directory contracts, foreign decision rejection, complete context digest | `tests/unit/test_internal_admission.py` | Identity verifier/directory interface, runtime binding, or context-digest change |
| Utopia/Raymond authenticated workspace resolution, foreign channel/stale binding denial, monotonic membership/channel/service/node authority, directory SQL least privilege | `tests/integration/test_r1_internal_admission.py` on disposable PostgreSQL 16; 6 passed | Directory function/grants, authority-generation schema, tenancy, or admission client change |
| Authenticated Utopia memory write/read, Raymond isolation, and current-authority recheck before every effect | `tests/integration/test_r1_internal_admission.py` on disposable PostgreSQL 16; 7 passed total | Admission gateway, realm session binding, scoped-memory client/function, or authority transition change |
| Policy-only V3 permit issue, workflow-only exact-once claim, canonical permit digest, cross-realm and direct-table denial, revocation before issue/claim | `tests/integration/test_r1_sensitive_permit_claim.py` on disposable PostgreSQL 16 | V3 permit contract, migration 0025, actor/service bindings, authority generations, or bootstrap roles |
| Realm-scoped encrypted evidence registration and replay, archive/workflow direct-table denial, foreign-scope rejection, exact claimed-package freeze/replay, and Python/PostgreSQL package-digest parity | `tests/integration/test_r1_sensitive_permit_claim.py` on disposable PostgreSQL 16; 3 passed in the file | Encrypted evidence/package V2 contract, migration 0026, actor/service bindings, or authority generations |
| Policy-only post-claim V2 grant storage/replay, exact executor/caller/package binding, wrong-alias rejection, current-authority recheck, and Python/PostgreSQL grant-digest parity | `tests/integration/test_r1_sensitive_permit_claim.py` on disposable PostgreSQL 16; 3 passed in the file | Execution-grant V2 contract, migration 0027, executor/actor bindings, or authority generations |
| Policy-only V2 receipt attestation/replay, exact grant/package/key-purpose binding, wrong-package denial, historical receipt acceptance after executor revocation, and digest parity | `tests/integration/test_r1_sensitive_permit_claim.py` on disposable PostgreSQL 16; 3 passed in the file | Executor-receipt V2 contract, migration 0028, receipt trust/bindings, or deadline rules |
| Workflow-only receipt reconciliation/replay, foreign-workflow denial, terminal state/digest persistence, and no caller-supplied receipt body | `tests/integration/test_r1_sensitive_permit_claim.py` on disposable PostgreSQL 16; 3 passed in the file | Migration 0029, workflow binding, receipt attestation, or operation-state rules |
| Same-scope evidence-derived memory provenance, exact replay, foreign/missing evidence denial, and execute-only backing-table isolation | `tests/integration/test_r1_sensitive_permit_claim.py` on disposable PostgreSQL 16; 3 passed in the file | Migration 0030, scoped archive or memory provenance rules |
| Exact deletion closure, incomplete-closure denial, manifest replay, durable evidence fence, and post-fence derivation denial | `tests/integration/test_r1_sensitive_permit_claim.py` on disposable PostgreSQL 16; 3 passed in the file | Migration 0031, deletion-manifest V2 contract, provenance, or fence locking |
| Policy-signature verification before scoped deletion storage; invalid signature produces no store call | `tests/unit/test_security_contracts_v1_3.py`; 15 passed in the file | V1.3 verifier, policy trust keys, or scoped deletion admission service |
| Manifest-bound deletion grant, wrong-manifest denial, exact qualified executor/caller binding, and replay | `tests/integration/test_r1_sensitive_permit_claim.py` on a clean PostgreSQL 16 database; 3 passed in the file | Migration 0032, deletion manifest, permit ceilings, or executor binding |
| Deletion receipt exact grant/manifest/package binding, action-specific fields and key purpose, substitution denial, and replay | `tests/integration/test_r1_sensitive_permit_claim.py` on PostgreSQL 16; 3 passed in the file | Migration 0033, deletion receipt V2 contract, grant, manifest, or executor binding |
| Receipt-only deletion reconciliation to 30-day `FINALITY_PENDING`, foreign/wrong-reconciler denial, recall suppression, and post-fence retrieval-package denial | `tests/integration/test_r1_sensitive_permit_claim.py` after clean migration 0001-0034; 3 passed in the file | Migration 0034, reconciliation state, deletion effects, memory search, or package/grant fence guards |
| Realm-bound metadata-only finality observation, database-derived `EXTENDED` result while PITR can recover the deleted key, exact replay, foreign-operation denial, and no direct deletion-effect access | `tests/integration/test_r1_sensitive_permit_claim.py` after clean migration 0001-0035; 3 passed in the file; finality and deployment-boundary unit checks included in a separate 14-test pass | Migration 0035, finality collector, finality actor bindings, production grants, or recovery-inventory contract |
| Historical V1.3 deletion recovery proof verifies retired-but-uncompromised policy/receipt keys and binds realm scope, permit, exact closure, grant, caller, executor, receipt, outcome, and digests; revoked keys and substituted callers fail closed | `tests/unit/test_security_contracts_v1_3.py` plus unchanged v1.2 recovery tests; 20 passed | V1.3 contracts/verifier, historical-key semantics, recovery-proof binding, canonicalization, or v1.2 recovery compatibility |
| Quarantined V1.3 restore replay revalidates scope/target/recovery digests and exact restored artifacts, creates one immutable recovery fence, suppresses restored recall, blocks new derivation, and replays exactly once; wrong scope and ready storage fail closed | `tests/integration/test_r1_sensitive_permit_claim.py` after clean migration 0001-0036; 3 passed in the file | Migration 0036, recovery contract/proof, capture-off admission, scoped archive/provenance, or recall/package fence logic |
| Production-scoped recovery utility pins the expected realm/workspace, caller, qualified executor and historical trust inventories before acquiring maintenance/admission locks and invoking only the quarantined V2 database gate | `tests/unit/test_scoped_authorized_deletion_replay.py`, V1.3 contract tests and deployment-boundary tests; 28 passed; Ruff and mypy passed | Scoped recovery utility/configuration, V1.3 historical verifier, Docker deployment contents, or recovery database gate |
| Realm-scoped OTR transitions and immutable per-turn decisions prevent both off-record turns and pre-transition accepted turns from entering the archive after capture is disabled; re-enabling capture does not revive old receipts, while a newly accepted turn archives successfully | `tests/integration/test_r1_sensitive_permit_claim.py` after clean migration 0001-0037; 4 passed; Ruff and mypy passed | Migration 0037, archive actor/service authority, scoped capture functions/tables, or capturable archive wrapper |
| An issued grant may still produce one exact receipt after executor revocation; substitution fails and exact replay remains idempotent, while revocation prevents new grant admission | Existing retrieval chain in `tests/integration/test_r1_sensitive_permit_claim.py`; exercised in the same 4-test clean-schema pass | Executor binding/grant/receipt migrations 0027-0029 or revocation semantics |
| Realm role renderer requires four distinct namespace-bound, non-elevated, membership-free LOGINs and replaces prior privileges with exact execute-only R1 grants; the routine role receives the staged capture protocol but cannot call the legacy direct registration function | `tests/unit/test_postgres_deployment_renderer_v1_3.py`, `tests/integration/test_r1_production_realm_roles.py`; rendered SQL applied to disposable PostgreSQL 16 | V1.3 role template/renderer, scoped function signatures, Docker contents, or PostgreSQL role attributes |
| A canonical content-free realm security stamp pins one foundation, four PostgreSQL/service identities, and distinct qualified retrieval/deletion AWS bindings; its quarantined provisioner is atomic, rejects partial state, and replays exactly without writes | `tests/unit/test_realm_provisioning.py`, `tests/unit/test_realm_binding_provisioner.py`, `tests/integration/test_r1_realm_binding_provisioning.py`; clean migration 0001-0037; 12 focused checks passed plus Ruff and mypy | Realm-stamp contract/provisioner, directory/binding tables, role attributes, Docker contents, or migration head |
| Additive V2 retrieval/deletion Lambda invocation and result types accept only V1.3 permit/grant/package/manifest/receipt objects, lock each route to its action, bind the receipt digest, and prohibit plaintext on deletion or replay | `tests/unit/test_security_contracts_v1_3.py`; 18 passed plus Ruff and mypy | V1.3 executor wire models, signed contracts, canonicalization, or result semantics |
| The effect-free V1.3 executor admission boundary historically verifies the already-claimed permit, live-verifies the post-claim grant and deletion manifest, and pins exact realm/workspace/binding/caller/alias/version/package/closure/deadline/ceiling fields before any AWS operation | `tests/unit/test_security_contracts_v1_3.py`; 20 passed plus Ruff and mypy | V1.3 executor admission, contracts/verifier, identity configuration, canonical sizing, or grant timing semantics |
| The additive V1.3 AWS adapter loads one exact strongly consistent receipt, signs scoped receipts with the configured purpose key, conditionally persists retrieval receipts, and atomically records deletion authority/outcome/quota while removing only archive targets' exact wrapped keys | V1.3 contract and unchanged V1.2 executor unit suites; 41 passed plus Ruff and mypy | AWS adapter, V1.3 contracts, DynamoDB transaction shape/limits, KMS signing, or V1.2 compatibility |
| The additive V1.3 executor core admits scope before any effect, performs one authenticated retrieval decrypt with no plaintext on replay, produces exact scoped KMS-signed receipts, and commits deletion without evidence-key/decrypt authority | V1.3 contract/core and unchanged V1.2 executor unit suites; 43 passed plus Ruff and mypy | V1.3 executor admission/core, AWS backend protocol, receipt construction/replay, AES-GCM binding, quota semantics, or V1.2 compatibility |
| Separate V1.3 Lambda entry points parse only V2 invocations, pin one realm/workspace/deployment/caller/qualified alias from environment, reject `$LATEST` or cross-scope configuration, emit content-free metrics, and scrub unexpected failure text | V1.3 handler and unchanged V1.2 executor unit suites; 45 passed plus Ruff and mypy | V1.3 handler/runtime configuration, environment contract, log/metric behavior, or V1.2 compatibility |
| The repeatable V1.3 CloudFormation stamp is derived only from the exact accepted V1.2 template digest, requires one explicit realm identity, creates separate physical keys/tables/roles/executors per stack, pins realm scope and caller identity in Lambda configuration, and enforces the complete V2 realm context in KMS and IAM | `tests/unit/test_aws_security_v1_3_template.py`; 5 passed plus Ruff and mypy | Frozen V1.2 template, V1.3 renderer/template, executor environment, KMS context, IAM policies, or realm output contract |
| The content-free stamp builder accepts exactly one complete termination-protected stack, cross-checks every realm parameter/output against the PostgreSQL binding description, rejects unknown fields and cross-account AWS bindings, and emits a validated canonical `RealmSecurityStampV1` with its digest | `tests/unit/test_realm_security_stamp_builder_v1_3.py`; 5 passed plus Ruff and mypy | CloudFormation realm outputs, stamp builder/model, AWS binding formats, or PostgreSQL realm-binding input contract |
| The V1.3 realm archive encryptor pins one deployment-owned scope and exact evidence key, obtains a 256-bit DEK, authenticates bounded plaintext with the exact header, emits validated payload/wrapper contracts, and registers the wrapped DEK only after KMS response validation; it exposes no decrypt or delete capability | `tests/unit/test_realm_archive.py`; 5 passed plus Ruff and mypy | Realm archive encryptor/identity, V1.3 payload/wrapper/context contracts, AES-GCM binding, or commitment behavior |
| The realm archive AWS adapter permits only exact-key `GenerateDataKey`, strongly consistent exact-key `GetItem`, and conditional wrapped-key/envelope `PutItem`; it exposes no scan, query, batch-read, decrypt, or delete surface | `tests/unit/test_realm_archive_aws.py`; focused adapter checks passed plus Ruff and mypy | Realm archive AWS adapter, KMS response validation, DynamoDB item/condition shape, or wrapped-key/envelope metadata |
| Realm archive construction fails before AWS client creation unless the V1.3 backend, `us-east-1`, account-bound key ARN, exact scope JSON, positive record version, table, and 32-byte commitment key are deployment-pinned | `tests/unit/test_realm_archive_aws.py`; 10 cumulative checks passed plus Ruff and mypy | Realm archive environment factory, deployment variables, scope contract, or AWS client construction |
| Archive capture durably separates PostgreSQL intent, AWS outcome, and PostgreSQL reconciliation; exact retries reuse stable IDs and a persisted DynamoDB envelope, a crash after DynamoDB does not generate a second DEK, withdrawal before reconciliation fails closed, and the production role cannot bypass the protocol | Clean migration 0001-0038; `tests/integration/test_r1_sensitive_permit_claim.py`, `tests/integration/test_r1_production_realm_roles.py`, and realm archive unit tests; 37 affected checks passed plus Ruff and mypy | Migration 0038, staged archive store/service, realm archive backend/envelope, scoped capture gate, or production realm grants |
| The V1.3 realm runtime preserves the existing Hermes accept-turn, capture-mode, and message-ingestion contract while routing archive writes through the staged protocol; the global activation gate returns capture-disabled without database/AWS writes, and the exact backend selector cannot silently switch other deployments | Clean migration 0001-0039; runtime/API, archive, role-renderer, and scoped PostgreSQL tests; 56 affected checks passed plus Ruff and mypy | Migration 0039, realm runtime adapter/factory, API backend selection, capture functions, or archive commit protocol |
| The read-only V1.3 deployed-state verifier pins one realm's CloudFormation identity, termination protection, qualified executor versions and configuration, public-only trust stores, KMS keys, DynamoDB protections, and absence of static AWS credentials | `tests/unit/test_realm_security_v1_3_deployment_verifier.py` plus unchanged v1.2 verifier tests; 9 passed plus Ruff and mypy | V1.3 verifier, realm template parameters/outputs, executor environment, or inherited v1.2 deployed-resource rules |
| V1.3 container admission selects schema head 0039 explicitly, binds each HTTP process to its expected realm database LOGIN, permits only content-free admission/revision reads, rejects direct customer-table authority, and never consults the V1.2 deletion journal | `tests/unit/test_runtime_readiness.py`, `tests/unit/test_postgres_deployment_renderer_v1_3.py`, and `tests/integration/test_r1_production_realm_roles.py`; 25 focused checks passed, including four real PostgreSQL boundary admissions; Ruff and mypy passed | Readiness/runtime selection, V1.3 realm grants, schema head, database LOGINs, or admission tables |

## R1-2 checkpoint

`contracts/security_v1_3.py` adds new wire identities rather than extending or
reinterpreting v1.2 JSON: origin scope, current execution binding, resolved execution
context, owner assertion V2, permit V3, encrypted evidence package V2, deletion target
manifest V2, sensitive execution grant V2, executor receipt V2, KMS encryption context V2, and v1.3
verification keys. New signatures retain the
already reviewed `lucy-cjson-1`
canonicalizer, include their object type/version as a domain separator, and pin a
distinct v1.3 key purpose. Permit admission is at most 60 seconds while execution
completion remains a separate bounded deadline. A historical realm/storage mismatch
requires an exact restore-mapping ID.

`SensitiveExecutionGrantV2` preserves the corrected, deployed ordering: the workflow
claims in PostgreSQL before policy signs a post-claim grant. It binds the permit
digest, claim/admission times, operation and idempotency identity, target and active
scope, exact qualified executor alias/version/caller, package digest, and action-
specific record/byte ceilings. The additive database gates and local executor path
now implement this contract; no v1.3 cloud route has been deployed.

`ExecutorReceiptV2` preserves ECDSA P-256 for KMS-compatible executor signing while
owner, permit, and grant contracts remain Ed25519. The v1.3 trust store pins the
algorithm and action-specific receipt-key purpose. Receipts bind the exact permit and
grant digests, scope/active execution binding, qualified executor and caller, package,
deadline, outcome, content-free journal reference, and operational deletion state.
Cryptographic finality remains a later independently verified record; an executor
receipt cannot claim it.

The executor wire boundary now has additive V2 invocation and result types. They
accept only the V1.3 permit, post-claim grant, scoped package or deletion manifest,
and scoped receipt contracts; action confusion, receipt-digest substitution,
deletion plaintext, and replayed plaintext fail validation. The frozen V1 invocation
and result types remain unchanged. Separate V1.3 Lambda entry points and a local
per-realm CloudFormation stamp now exist; neither has been deployed.

`executors/admission_v1_3.py` adds the pure pre-effect admission layer. A claimed
permit is verified as historical authorization evidence because its 60-second
admission deadline may legitimately precede Lambda execution; the post-claim grant
is live-verified through the separate completion deadline. Retrieval then binds the
exact current wrapper/KMS scope, record, canonical package digest, and byte size.
Deletion additionally live-verifies the signed closure and binds its owner evidence,
idempotency identity, target count, digest, and canonical size. No AWS operation is
implemented by this layer, and the deployed handler remains V1-only.

The shared AWS adapter now has additive V1.3 receipt and deletion operations while
its accepted V1 methods remain unchanged. V1.3 receipts are exact-key, strongly
consistent reads and conditional writes with realm/epoch metadata. Deletion stores
the signed permit, post-claim grant, frozen closure and scoped receipt together with
both quota reservations in one DynamoDB transaction, deleting only exact wrapped-key
references carried by encrypted-archive targets. Derived-memory targets cannot name
or delete AWS key material. The adapter exposes no scan, query, or batch-read method.

`executors/core_v1_3.py` composes the pure admission boundary with those exact AWS
operations. Retrieval admits the signed chain and realm identity before quota or KMS,
authenticates the payload with its V2 header/context, bounds plaintext, persists a
purpose-scoped receipt, and returns plaintext only for the winning first execution.
An exact retry replays the durable receipt without decrypting or returning plaintext.
Deletion constructs a content-free operational-deletion receipt and commits through
the atomic adapter path; its core has no evidence key or decrypt capability.

`executors/handlers_v1_3.py` exposes separate V1.3 retrieval and deletion entry
points. Each runtime derives one target scope, workspace, deployment binding, caller,
executor identity, published version, and qualified alias from deployment-owned
environment. Request JSON cannot select those values. The handler accepts only V2
invocations, rejects unqualified/moving execution, emits content-free V1.3 metrics,
and never logs exception text. The derived per-realm CloudFormation stamp references
these handlers through distinct functions and `realm-v13` aliases, but no Lambda
version or realm stack has been deployed.

`deploy/aws/security-baseline-v1.3.yaml` preserves the accepted V1.2 resource
boundary while making one stack equal one realm security stamp. Its fail-closed
renderer pins the exact V1.2 input digest and requires every expected transformation
count. Deployment-owned scope JSON, execution binding, workspace, caller role,
executor identity, and alias are injected into each executor. KMS and IAM require
the full `KmsEncryptionContextV2` realm context, including the realm and tenant IDs;
the evidence ID remains dynamic but mandatory. A validated handoff builder combines
the stack's read-only outputs with the reviewed PostgreSQL realm description and
produces the canonical `RealmSecurityStampV1` plus digest. Deployed verification and
synthetic cloud acceptance remain open gates.

`realm_archive.py`, `realm_archive_aws.py`, and `realm_archive_commit.py` provide
the encryption-only new-capture ingestion path. The process receives one deployment-owned realm scope and
exact KMS key, generates a data key, validates the KMS response, encrypts with
AES-256-GCM and the supplied authenticated header, emits validated V2 payload and
wrapper bindings, and conditionally stores the wrapped key with realm metadata. It
has no decrypt or delete method. The environment factory requires the explicit V1.3
backend and matches region/account/key before constructing AWS clients. Migration
`0038_r1_archive_commit_protocol` durably separates the intent, AWS outcome, and
reconciliation because PostgreSQL, KMS, and DynamoDB cannot share one transaction.
It allocates stable object IDs before AWS, recovers an exact durable DynamoDB envelope
after an ambiguous failure, and rechecks capture authorization during reconciliation.
The request commitment is keyed, so PostgreSQL does not retain a guessable plaintext
hash. The production realm login can execute only the staged functions and cannot
call the legacy direct evidence-registration function.

Migration `0039_r1_scoped_capture_runtime` adds a realm-derived, execute-only
capture-state read and connects the staged archive service behind Hermes' existing
internal conversation API contract when the backend is exactly
`aws-kms-dynamodb-v13`. The global transcript-capture flag remains an independent
fail-closed gate: while false, turn acceptance and message preservation perform no
database or AWS write. This compatibility path has been exercised against disposable
PostgreSQL with a synthetic KMS/DynamoDB effect boundary; it has not been activated
or deployed.

`EncryptedEvidencePackageV2` separates an immutable payload binding from its
replaceable key-wrapper binding. The payload commits to original realm scope,
ciphertext bytes, nonce, authenticated header, record version, and ciphertext digest.
The wrapper commits to the current wrapping scope, exact wrapped-key reference and KMS
context. New ingestion requires matching scopes; moving only the wrapper requires an
exact migration-receipt ID while leaving the ciphertext digest unchanged. This is a
local typed boundary and does not migrate the accepted v1.2 archive.

`DeletionTargetManifestV2` freezes one canonical root-evidence closure across encrypted
archive representations and derived artifacts. Archive targets require the exact
representation and wrapped-key reference; memory, embedding, result and projection
cleanup targets cannot carry wrapped-key destruction authority. The signed manifest
binds the realm/workspace, permit and owner assertion, closure and policy versions,
canonical target digest, and separate claim/execution deadlines. It reports
operational deletion policy only; cryptographic finality remains independent.

`realm_sessions.py` holds exactly one deployment-owned private-realm credential per
process and selects it only after workload identity has been verified. A request may
supply a realm/workspace hint only for conflict detection; it cannot select a
credential. Unknown subjects/actions, conflicting hints, and any attempt to configure
multiple realm bindings in one process fail closed. A content-free directory/admission
interface may resolve metadata for several realms, but it cannot hold or return these
content credentials.

Migration `0023_r1_scoped_memory` adds immutable content-scope and service-binding
rows plus append-only scoped claims/events. PostgreSQL resolves the caller from
`session_user`; the application cannot supply a realm selector. Three synthetic
logins receive execute-only access to named write/search functions and cannot select
the backing tables. Cross-realm reads return no rows, unknown bindings fail closed,
and idempotency conflicts do not write data. Legacy v1.2 rows remain in their
explicit enclave.

`internal_admission.py` now defines the realm-local side of authenticated admission.
Only a verifier may produce identity facts; the verifier is required to bind the
configured issuer and realm-specific audience. The directory request and decision
contain authorization metadata only—no bearer token, database credential, prompt,
query, response, or private content. The realm process cross-checks every returned
scope/binding/action before constructing a server-only, canonically digest-bound
`ResolvedExecutionContextV1`. No production IdP implementation or network broker is
claimed yet.

Migration `0024_r1_internal_admission` and
`PostgresDirectoryAdmissionAuthorizer` implement the database-backed directory
decision. A dedicated login has execute-only access to one security-definer function;
its distinct function owner can read only authorization metadata and has no scoped-
memory table or function authority. Utopia and Raymond use separate single-binding
process fixtures and realm-specific audiences. Membership, channel, service-binding,
principal, and node authority changes are monotonic: revocation/disable cannot be
reversed, and generation or epoch changes invalidate stale admission.

`authenticated_memory.py` places that admission decision directly in front of the
scoped-memory effect. The caller supplies identity proof and operation content but no
realm, workspace, or database selector. The workspace is fixed deployment
configuration, and the memory session is derived from the same admission object's
single realm binding rather than injected separately. A fresh directory decision is
required before every read or write; a revoked membership therefore cannot reach the
memory client. The resolved context remains server-only and is never accepted as a
bearer credential.

Migration `0025_r1_sensitive_permit_claim` begins sensitive-chain scope
parameterization without changing the accepted v1.2 path. A policy-notary login may
store only a signed V3 permit whose exact owner, channel, workspace, service binding,
realm, storage epoch, deployment, and current authority generations match its fixed
realm binding. The permit now binds both the channel ID and generation, and the
target service-binding ID and generation. A separate workflow login can claim only
that pre-issued permit in its own fixed realm. Claim is idempotent, rechecks current
authority, and records an immutable scoped event; neither login can select or write
the backing tables directly. PostgreSQL recomputes the same canonical unsigned
contract digest used by the application. The policy process remains responsible for
cryptographic signature verification before calling the issue gate; its scoped
credential is therefore an explicit policy trust boundary.

Migration `0026_r1_scoped_archive_package` makes the encrypted object referenced by a
V3 permit concrete before an execution grant can exist. A fixed archive-writer login
can register only new-capture payload/wrapper pairs in its own active content scope;
PostgreSQL validates the AES-GCM payload digest, exact KMS context, lineage, realm and
storage epochs, and idempotent replay. Neither the archive writer nor workflow login
can enumerate the backing tables. After an exact V3 permit is claimed, the workflow
can freeze only that active evidence version and current wrapper into an immutable
`EncryptedEvidencePackageV2`; PostgreSQL and Python produce the same canonical
package digest. Migration/rehost wrappers remain deliberately outside this initial
slice and require their later receipt-gated path.

Migration `0027_r1_execution_grant` adds an immutable realm executor registry and a
policy-only post-claim V2 grant gate. The gate rechecks current owner, channel, node,
tenure, realm, service, policy and executor authority immediately before admission;
binds the exact claimed permit and frozen package; and pins the qualified Lambda
alias, published version, caller identity, byte ceiling and completion deadline.
Grant replay is exact and neither the policy nor workflow login can enumerate grant
or package tables.

Migration `0028_r1_executor_receipt` adds immutable, content-free V2 receipt
attestations. Policy admits only a preverified receipt matching the exact stored
grant, package, qualified executor, caller, receipt-key purpose, record version and
deadline. Executor revocation blocks future grants but does not suppress an exact
receipt for a grant already issued, preserving an auditable revocation race instead
of losing its outcome.

Migration `0029_r1_receipt_reconcile` adds the workflow-only terminal transition.
The reconciliation function accepts only an operation ID, locks that exact scoped
operation, and derives the outcome solely from the immutable policy-written receipt
attestation. Foreign workflows fail closed; successful and rejected executor results
become distinct terminal states; exact retries return the stored outcome without a
second event.

Migration `0030_r1_scoped_provenance` makes evidence-derived scoped memory explicit.
Every derived claim commits its same-scope source evidence IDs atomically, and the
archive service cannot enumerate either the evidence or provenance backing tables.
Derivation and deletion use the same per-evidence transaction lock; a deletion fence
therefore prevents a later derivation from committing, while any derivation that wins
the lock is included in the closure computed by the following deletion increment.

Migration `0031_r1_deletion_closure` freezes a policy-signed V2 manifest only when it
exactly equals PostgreSQL's current same-scope closure: the active archive
representation and every provenance-linked scoped memory claim. The fence, immutable
manifest, normalized targets, and content-free event commit in the same transaction.
An incomplete or stale representation fails closed, and exact replay cannot create a
second fence or event. The policy application must cryptographically verify the
manifest before invoking this execute-only database gate.

`VerifiedScopedDeletionService` is that application-side admission gate. It verifies
the policy-notary key purpose, issuer, environment, live key window, authorization
deadline, and signature before any store call. It then compares the database result
to the verified manifest identifiers and digests, rejecting a storage-binding
mismatch.

Migration `0032_r1_deletion_grant` admits deletion grants through a deletion-only
function. The signed grant must bind the claimed permit, exact frozen manifest ID and
digest, current realm authority, qualified deletion executor and caller identity,
canonical manifest byte size, and permit record/byte ceilings. Its package digest is
the frozen manifest digest, matching the established deletion-executor contract;
retrieval grants remain on their narrower function and cannot name a manifest.

Migration `0033_r1_deletion_receipt` adds the deletion-only attestation function.
It accepts a policy-preverified receipt only when its deletion key purpose, executor,
caller, permit, grant, manifest, package digest, transaction token, record version,
deadline, result, and operational-finality fields exactly match stored authority.
The receipt is content-free and immutable; the historical executor binding may have
been revoked after grant admission without erasing the exact completed outcome.

Migration `0034_r1_deletion_reconcile` separates deletion reconciliation from the
retrieval terminal path. A successful or idempotent deletion receipt creates one
immutable operational effect and advances the operation to `FINALITY_PENDING` with a
fixed 30-day not-before time; a rejected receipt creates no deletion effect. Exact
replay is read-only. Once the deletion fence exists, provenance-linked claims are
excluded from ordinary scoped recall and no new retrieval package or retrieval grant
can be admitted for that evidence. Cryptographic finality remains a later,
independently verified record rather than a claim made by the executor receipt.

Migration `0035_r1_scoped_finality` gives a realm-bound finality verifier one
execute-only metadata operation. PostgreSQL resolves its scope from `session_user`,
accepts no caller-supplied finality verdict, requires the scoped deletion to have an
attested operational effect, and derives `EXTENDED` or `VERIFIED` from the actual
PITR and exceptional-copy inventory. Observations are immutable and monotonic; an
identical retry is replayed without another row, a foreign operation is invisible,
and time alone cannot make a still-recoverable deletion cryptographically final.
The operator finality utility now calls this scoped gate while the v1.2 gate remains
granted for compatibility with the frozen enclave.

`verify_authorized_deletion_recovery_v2` is the content-free recovery admission
boundary for the scoped chain. It historically verifies every signature, allowing a
retired verification key only for evidence issued during its valid issuance window;
revoked keys and contracts in a declared suspected-compromise interval fail closed.
It then binds the permit, canonical deletion closure, post-claim grant, exact
realm-bound caller and qualified executor, and successful operational-deletion
receipt into one recovery digest. The proof does not itself mutate a restored
database; migration 0036 consumes it only through a quarantined replay gate.

Migration `0036_r1_scoped_deletion_recovery` consumes that proof only while storage
is quarantined and the centralized transcript-capture boundary is off. It rederives
the realm, scope, manifest-target and recovery digests; requires every restored
archive and derived-memory artifact to match the authorized closure; and writes one
immutable recovery record, target set, and root-evidence fence. A simulated older
restore made the derived claim visible after its newer ordinary fence was removed;
the recovery replay suppressed it again, blocked subsequent derivation, and an exact
retry made no second write. Ciphertext remains immutable in PostgreSQL, while the
externally destroyed wrapped key and enforced fence preserve crypto-shredding and
ordinary-recall deletion semantics.

`deploy/postgres/replay_authorized_deletion_cloud_v1_3.py` is the production
operator bridge for that gate. It accepts no command-line values, requires the exact
reviewed authorization marker, production Render, capture-off state, the private
migration login, an explicit realm/workspace scope, caller and qualified executor
bindings, and historical V1.3 trust inventories. It verifies the signed chain before
opening PostgreSQL, then requires TLS, quarantine, the database-owned capture boundary
and both maintenance/admission locks. The container includes this utility, but no R1
production deployment or replay has been performed.

Migration `0037_r1_scoped_capture` separates capture state and immutable turn
receipts by database-derived content scope. An off-record transition increments the
conversation generation under a scope-specific lock. Archive admission requires a
previously accepted, enabled receipt whose generation still equals the current
conversation generation. Consequently, disabling capture invalidates both future
turns and any earlier accepted-but-not-yet-archived turn; returning on-record never
revives them. The archive login has execute-only access and cannot enumerate or
rewrite the supporting tables. This is the local R1 path; live Telegram capture is
still disabled.

`render_security_v1_3_sql.py` and `production_realm_roles_v1.3.sql.example`
provide the first production parameterized stamp. They bind four distinct LOGINs to
one explicit realm namespace and remove all table/function authority before granting
the exact routine/archive, policy, workflow, and finality entry points. The rendered
stamp was applied to the disposable PostgreSQL environment and its effective grants
were queried. It does not create realm directory rows, AWS identities, Render
services, or an activation decision.

`realm_provisioning.py` and `provision_realm_bindings_v1_3.py` make the next
commissioning boundary deterministic. One strict, content-free, canonical manifest
pins the tenant/node/tenure/realm/workspace, four namespace-bound PostgreSQL and
service identities, authority generations, and distinct same-account/same-region
qualified retrieval/deletion executor aliases and receipt keys. The production
utility requires the private migration identity, TLS, quarantined admission,
capture-off state, and both maintenance locks. It applies the entire stamp in one
transaction, rejects conflicting or partial prior state, and treats an exact replay
as read-only. The path has been proven on disposable PostgreSQL only; no production
realm has been provisioned.

The scoped retrieval, deletion, and new-capture chains are complete locally through
reconciliation, finality observation, quarantined restore replay, scoped OTR
enforcement, ambiguous archive-write recovery, and the documented post-grant
revocation race. The next exact R1-2 action is to prepare and perform synthetic
deployed verification of one realm stamp with capture still disabled. Realm-specific AWS and
Render commissioning remains required before R1-2 can be activated.
Durable revocation acknowledgement and protected recovery handoff remain R1-4 gates
and are not pulled forward into R1-2.

R2 jobs/wallet spending and R3 consulting, local runners, portability, transfer,
rehosting, and StoinNet execution are explicitly deferred.
