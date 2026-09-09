# R1 repository reconciliation

Status: R1-0 and the R1-1 synthetic local slice are complete. R1-2 contracts,
single-realm process sessions, authenticated admission, scoped memory, sensitive
operations, deletion recovery, and scoped off-record enforcement are implemented
locally. R1-2 production stamps and commissioning remain outstanding; production
provisioning remains disabled.

## Frozen baseline

- Inspected source: `aa157bded743976e934887b996ea8d79a5ebacef`, a documentation-only
  successor to accepted runtime `52527fa9d8eaa3be766986101b6a8f51c1b1c208`.
- Accepted v1.2 PostgreSQL head: `0021_recovery_capture_safety`; additive R1 local
  head: `0037_r1_scoped_capture`.
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
| Clean migration 0001 through `0037` | Disposable pgvector/PostgreSQL 16 tmpfs cluster | Migration or bootstrap change |
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
| Realm role renderer requires four distinct namespace-bound, non-elevated, membership-free LOGINs and replaces prior privileges with exact execute-only R1 grants; the routine role receives only the capture-enforcing archive entry point | `tests/unit/test_postgres_deployment_renderer_v1_3.py`, `tests/integration/test_r1_production_realm_roles.py`, scoped integration and deployment-boundary tests; rendered SQL applied to disposable PostgreSQL; 19 checks passed across the focused passes | V1.3 role template/renderer, scoped function signatures, Docker contents, or PostgreSQL role attributes |
| A canonical content-free realm security stamp pins one foundation, four PostgreSQL/service identities, and distinct qualified retrieval/deletion AWS bindings; its quarantined provisioner is atomic, rejects partial state, and replays exactly without writes | `tests/unit/test_realm_provisioning.py`, `tests/unit/test_realm_binding_provisioner.py`, `tests/integration/test_r1_realm_binding_provisioning.py`; clean migration 0001-0037; 12 focused checks passed plus Ruff and mypy | Realm-stamp contract/provisioner, directory/binding tables, role attributes, Docker contents, or migration head |

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
specific record/byte ceilings. This is a typed local contract only at this checkpoint;
no v1.3 database gate, deployed executor, or cloud route claims implementation yet.

`ExecutorReceiptV2` preserves ECDSA P-256 for KMS-compatible executor signing while
owner, permit, and grant contracts remain Ed25519. The v1.3 trust store pins the
algorithm and action-specific receipt-key purpose. Receipts bind the exact permit and
grant digests, scope/active execution binding, qualified executor and caller, package,
deadline, outcome, content-free journal reference, and operational deletion state.
Cryptographic finality remains a later independently verified record; an executor
receipt cannot claim it.

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

The scoped retrieval and deletion chains are complete through reconciliation, finality
observation, quarantined restore replay, scoped OTR enforcement, and the documented
post-grant revocation race. The R1-2 local behavioral exit evidence is complete, and
its realm-parameterized PostgreSQL role stamp and deterministic directory/binding
provisioner are implemented. Realm-specific AWS and Render stamps remain before R1-2
can be commissioned.
Durable revocation acknowledgement and protected recovery handoff remain R1-4 gates
and are not pulled forward into R1-2.

R2 jobs/wallet spending and R3 consulting, local runners, portability, transfer,
rehosting, and StoinNet execution are explicitly deferred.
