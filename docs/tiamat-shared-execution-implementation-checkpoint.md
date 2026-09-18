# Tiamat Shared Model Execution — implementation checkpoint

**Date:** 2026-09-18
**Contract:** Stoin Shared Model Execution v1.0 RC1  
**Contract digest:** `a010c2cd5d501dd5586be3e1c54753ed7bf82505b9971d19c007e227bb9a75a8`  
**Conformance-bundle digest:** `5185680e2cb9ac9aff6006c9abc6a582b67933db077d5c7bd5dcc596f574cb85`

## Completed locally

- Recovery-anchor foundation: root-signed, predecessor-linked anchor transitions bind the verified
  recovery witness, environment/ledger/epoch, continuity state and PostgreSQL continuity beacon.
  A local in-memory adapter proves only transition semantics: it is explicitly not a deployment
  store. The linked recovery-witness Draft 0.5 and companion-amendment draft define the remaining
  external-store, launcher, PostgreSQL checkpoint and migration work.

- Frozen Tier A bundle with strict provider schemas, all 29 exact error tuples, positive and
  negative vectors, cross-field invariants, header/JWT/state fixtures, complete acceptance-criteria
  classification, an independent verifier, and a reproducible raw-content digest.
- Strict Pydantic request and response models for the RC1 message, output, usage, and cost shapes.
- Initial restricted-JSON-Schema admission validator.
- Profile-pinned local execution service with atomic in-memory create/reserve, dispatch-before-send,
  scoped canonical-identity conflict, single dispatch, terminal replay, and synchronous settlement.
- Fake-provider unit tests including concurrent same-key admission.
- Private local FastAPI endpoint with bounded raw-body handling, required request headers, exact
  authenticated response headers, no cookies, and release-header suppression on authentication and
  unknown-route failures.
- EdDSA workload JWT verification with provisioned key/issuer/subject/profile binding, fixed
  audience/scope, temporal limits, request binding, and scoped atomic in-memory `jti` replay state.
- Focused ordered-gate tests for invalid-token versus replay-store failure, step-6 digest mismatch,
  malformed request identity, fresh-token idempotent replay, and release-information disclosure.
- Executor-side provider-output enforcement for text/JSON byte bounds, the restricted caller schema,
  combined generated-token ceilings, usage arithmetic, response-envelope size, and cost overrun,
  with distinct fail-closed RC1 error codes.
- The restricted JSON-output evaluator is differentially checked against the independent
  `jsonschema` implementation across every supported value class and constraint family. Additional
  adversarial cases enforce the RFC 8785 numeric domain, reject invalid Unicode scalars, preserve
  JSON numeric equality without conflating booleans, and turn a post-dispatch noncanonical provider
  number into a durable paid `provider_response_invalid` failure rather than an uncaught exception.
- Topology-neutral local spending-partition reference model covering grant validity and budget-period
  applicability, predecessor/successor activation, no predecessor fallback, active versus pending
  exposure, the `2N` bound, contingency-reserve sizing, carried obligations, settlement, and
  forfeiture.
- Runtime RFC 8785 canonicalization for idempotency identity, requested-schema byte bounds, and JSON
  candidate byte bounds, verified against all five already-vendored official reference vectors.
- Content-free fenced transition reference model with lease epochs, record generations, CAS-style
  owner checks, admitted/dispatched reaping, stale-owner rejection, outcome uncertainty, and final
  eligibility suppression.
- Dedicated Tiamat PostgreSQL migration lineage through `0006_render_recovery_rls`; Cloud Lucy remains at
  `0071` and does not consume migration `0072`.
- Migration `0005` creates one immutable database-owned UUID inside each newly migrated Tiamat
  ledger. The migration/recovery-only day-zero initializer refuses any existing execution, replay,
  release, or settlement state; creates a blocked generation-one restore gate; and emits the exact
  non-authorizing `not_installed` checkpoint needed for later signed-anchor commissioning. It has an
  explicit exact confirmation argument, performs no AWS request, and cannot enable dispatch.
- Content-free PostgreSQL adapters for durable scoped JWT replay, coordinator-generation fencing,
  atomic create/reserve, durable-before-send dispatch, terminal settlement, outcome uncertainty,
  authoritative lease reaping, and 24-hour reservation forfeiture.
- Forced row-level security for caller, realm, environment, and spending-partition isolation; the
  serving-role template is a non-owner with `NOBYPASSRLS`. The separately held recovery role is
  excluded from serving processes and has an explicit, exact-role recovery policy rather than
  `BYPASSRLS`, which Render's managed owner cannot mint.
- Restore quarantine uses deployment-owned storage epoch and recovery generation plus a database
  coordinator generation. A stale restore cannot resume against a newer witness until an offline
  reconciliation explicitly advances and unblocks the gate.
- A disposable PostgreSQL 16 integration environment proves migration, durable JWT replay,
  concurrent single admission, dispatch-before-send, settlement, non-owner RLS isolation,
  coordinator failover/takeover, admitted/dispatched reaping, recovery-generation mismatch, and a
  stale physical database snapshot failing closed under a newer external witness.
- Durable unclear-dispatch resolution aborts at zero cost only for the exact live owner epoch. If a
  newer reaper result exists, the lookup preserves `outcome_unknown` and its held reservation.
- Exact provider route and rate releases are pinned on every durable execution. A synchronous or
  asynchronously discovered overrun records the full external charge, spends contingency only for
  the excess, quarantines that exact pair, invalidates replay, and blocks the partition when the
  remaining contingency cannot cover the liability.
- Content-free financial events survive eligible idempotency-row expiry. Ordinary settled records
  retain the ten-minute contract window; unresolved forfeitures retain a 30-day tombstone before
  expiry, while their accounting event remains.
- Real PostgreSQL backend termination while dispatch and settlement transactions are open proves
  that execution state, spend, contingency, quarantine, and financial-event writes roll back as one
  unit. The separately tested unclear-commit resolver covers the case where commit may have landed.
- Frozen Tiamat Signed Release Format v1 RC1 plus a 71-file conformance bundle containing 55
  deterministic synthetic vectors, strict payload schemas, root/release Ed25519 fixtures, an
  independent verifier, a coverage map, and a reproducible raw-content digest.
- Executor-side compact-JWS verification preserves and hashes the exact received bytes, rejects
  duplicate JSON members and nonconformant headers, validates root-signed trust inventory and exact
  release-key scope, checks RFC 8785 content identity, and enforces time, subject, privacy-route,
  contingency, and budget-period relationships.
- A complete signed execution authority now requires one current profile, its exact privacy-policy
  release, and one applicable current spending grant. Missing trust inventory or grant fails closed
  before a service capable of dispatch can be constructed.
- Migration `0003_signed_release_authority` separates immutable exact-JWS artifacts from small
  monotonic activation heads and root-signed trust-inventory generations. Forced RLS applies to all
  three tables; the runtime role receives read-only authority while a separate non-bypass release
  manager receives staging/activation writes.
- The PostgreSQL authority adapter now provides idempotent exact-byte staging, conflict detection,
  root-inventory successor activation, scoped release-head locking, predecessor/sequence checks,
  atomic supersession, and exact active-JWS loading. Activation and loading both lock against the
  restore gate and fail closed when no reconciled environment row is open.
- Active signed revocations now apply transactionally to the exact current target. The release head
  becomes a revoked tombstone with an incremented eligibility generation; active loading fails and
  no predecessor can reappear. Applying the same revocation is idempotent, while an ambiguous,
  non-head, or conflicting target fails closed.
- Verified spending grants stage an immutable ledger projection. Activation advances the signed
  release head and the partition's active grant, period, allowance, contingency, concurrency, and
  per-call ceiling in one transaction; a missing partition or invalid predecessor rolls the entire
  change back.
- Active inventories and release heads are now stamped with the restore-gate recovery generation.
  Offline recovery requires an exact externally supplied inventory generation/digest and the exact
  set of release-head digest/state pairs before restamping them for the next generation and opening
  dispatch. Database contents alone cannot self-authorize after quarantine or restore.
- The cold-start authority loader reads only recovery-generation-bound active records, reverifies
  the root-signed inventory and every exact compact JWS, follows the execution profile's exact
  privacy-policy release ID, resolves the current partition grant, and constructs dispatch-capable
  authority only after the complete relationship set passes. A revoked linked policy remains
  unavailable after a correctly reconciled restore.
- The private HTTP boundary now implements ordered route/method rejection with no release
  disclosure, validates transfer framing before authentication, streams through a 1 MiB gross hard
  cap instead of buffering an unbounded body, and preserves the separate authenticated 256 KiB
  contract-size gate. Missing or duplicate binding headers remain generic authentication failures.
- Every step-3 rejection—including missing bindings, invalid JWTs, replay, and unavailable replay
  state—now passes through one fixed 50 ms minimum timing class with up to 10 ms of cryptographic
  jitter. The delay is injectable for deterministic proof, and the later raw-body digest mismatch
  remains explicitly outside that class as required by RC1.
- Step 8 and step 9 are now distinct in the running boundary: an unknown or unauthorized profile is
  `403 capability_forbidden`, while a valid authorized profile that cannot enforce the requested
  output mode is `422 output_contract_unsupported` before provider dispatch.
- Direct ASGI failure injection proves a disconnect while the request body is streaming fails at
  the transport gate with no authentication or release disclosure. A separate lost-response test
  disconnects after the provider result was durably committed, then retries with the same
  idempotency key and receives the stored response without a second provider call.
- A boundary-sized 65,536-byte provider text result produces a complete strict-schema success under
  the 131,072-byte raw response cap. A one-byte-larger provider result becomes a bounded, strict,
  paid `provider_response_too_large` failure with no oversized content reflected to the caller.
- A single adversarial cross-product walks route, method, framing, authentication, request-header,
  media, response-media, contract-size, raw-digest, strict-request, and capability gates while every
  later layer is also malformed; each request returns only the earliest RC1-defined failure and no
  provider call occurs.
- All 29 RC1 error codes are present with exact status, message, and retryability constants; a test
  checks the complete implemented code/message/retry set against the frozen positive vectors.
- The live success envelope, all 29 generated error envelopes, and all four cost-receipt variants
  are now validated directly against the frozen strict provider schemas with an independent
  JSON-Schema implementation.
- Post-dispatch validation failures now persist and return the stable execution ID, failed state,
  and authoritative settled, pending-reconciliation, or overrun cost receipt. Same-key duplicates
  replay that terminal content-free failure without another provider call. Invalid provider usage or
  cost arithmetic cannot become a success receipt and retains the full reservation pending
  reconciliation.
- The real FastAPI/JWT boundary has been exercised with `PostgresJtiReplayStore`: the first signed
  request dispatches once, reuse of the same `jti` returns the generic no-release-header `401`, and
  the dedicated database retains only issuer, subject, realm, environment, `jti`, and expiry.
- Workload-key rotation is proven through the same PostgreSQL-backed HTTP boundary: old and successor
  Ed25519 keys both work during overlap, removing the old key rejects it before replay-state
  insertion or release disclosure, and the successor continues to dispatch normally.
- Idempotency-digest-key rotation now uses a current key plus bounded predecessors to derive
  versioned HMAC-SHA256 identities. Every newly admitted execution atomically stores aliases for all
  configured overlap keys; per-digest advisory locks and alias lookup make old and successor
  processes converge on one execution even when they race. Migration `0004` backfills the legacy
  digest as an alias, applies forced RLS, and exposes a retention check so a key version cannot be
  retired while a retained execution still depends on it.

No provider credentials, real model route, spending grant, provider call, deployment, migration, or
production change was created.

### DynamoDB external recovery-anchor increment

The approved single-provider deployment choice is now represented locally without provisioning:

- `DynamoDbExternalRecoveryAnchor` stores exact signed transition and witness bytes, uses strongly
  consistent exact-key reads, re-verifies signed bytes on every read and before every write, and
  conditionally replaces only the exact predecessor digest/version. DynamoDB metadata cannot
  establish authority on its own.
- `RecoveryAnchorRecordDecoder` provides the production exact-byte seam: it first verifies the
  recovery witness against a separately accepted witness-inventory key/scope, then verifies the
  root-signed anchor transition and its exact witness digest/identity binding. The environment
  factory supplies only table and region settings; AWS credentials remain in the SDK machine
  identity chain.
- `RecoveryAnchorRuntimeGate` makes the approved outage behavior executable: startup requires the
  external anchor; a running process may retain only its last verified authority until signed
  expiry; a newly observed quarantine blocks immediately; recovery updates fail closed.
- `deploy/aws/tiamat-recovery-anchor-v1.yaml` defines one retained, deletion-protected, encrypted,
  PITR-enabled PAY_PER_REQUEST table and separate read-only runtime versus conditional-update
  coordinator policies. Neither role receives scan, query, delete, restore, or table-mutation
  permissions.
- `docs/tiamat-dynamodb-recovery-anchor-deployment-review-v1.md` records topology, AWS-unavailable
  behavior, permissions, cost assumptions, activation procedure, and rollback. The isolated AWS
  staging table and exact Render OIDC roles are commissioned; both inert identities remain
  suspended and provider dispatch remains disabled.

## Deliberately not yet claimed

The in-memory store is a test adapter. It does not establish durable or multi-replica conformance.
Before any deployment or real provider activation, Tier B must add and prove:

1. connect the implemented offline exact inventory/release-head reconciliation input to an
   independently authenticated Control witness in a deployment; local witness enforcement,
   recovery-generation binding, cold-start reverification, monotonic activation, atomic grant
   projection, signed no-fallback revocation, and exact active-byte loading are done;
2. add caller-side differential proof that Homes Prime produces the same RFC 8785 identity;
3. complete caller-side tolerant-consumer tests against the bundle;
4. deadline, disconnect, crash, stale-owner, late-result, recovery, reconciliation, and rollback
   failure injection;
5. a separately authorized provider adapter and provider/model/rate selection;
6. independently deployed Homes Prime ↔ Tiamat network conformance and privacy evidence.

The existing Homes corpus remains local-test-only and is not authorized for provider use.

## Verification ledger

At local commit preparation on 2026-09-18:

- DynamoDB recovery-anchor boundary: 44 focused tests passed across the portable state machine,
  exact-byte witness and transition JWS verifiers, DynamoDB adapter, runtime outage gate, and
  CloudFormation assertions.
  The suite covers strong reads, bootstrap and successor CAS, signature re-verification, unsigned
  metadata corruption, conditional races, ambiguous-write resolution, AWS-unavailable
  startup/write behavior, bounded cached
  operation through an outage, signed expiry, and immediate known-quarantine blocking. Ruff passed
  for all touched Python files and strict mypy passed for both recovery-anchor source modules.
  CloudFormation was structurally parsed and policy-asserted locally; AWS-side `validate-template`
  remains part of the pre-provisioning activation review because no AWS call was authorized.
- Complete unit suite after the DynamoDB environment factory and concrete witness decoder: 1,200
  passed with two existing dependency deprecation warnings. An initial run placed pytest's import
  fixture inside the repository and correctly triggered three intake-boundary failures; rerunning
  unchanged code with the temporary root outside the repository passed completely.
- AWS pre-provisioning review: the template passed the AWS CloudFormation validator in account
  `429870640638`, `us-east-1`. Change set `review-20260918-01` reached `CREATE_COMPLETE` and remains
  unexecuted/available. The stack shell is `REVIEW_IN_PROGRESS`; AWS enumerated zero provisioned
  resources. The proposed dedicated Tiamat reader/updater roles do not yet exist, and no existing
  Lucy/Utopia identity was reused or changed. Exact content-free evidence is recorded in
  `docs/evidence/tiamat-recovery-anchor-aws-change-set-review-2026-09-18.json`.

- AWS/Render staging commissioning: stack `tiamat-staging-recovery-anchor-v1` reached
  `CREATE_COMPLETE`; table `stoin-staging-tiamat-recovery-anchor-v1` is active with deletion
  protection and PITR enabled. Exact Render identities `srv-damkn2bm8hqs73dh1abg` and
  `srv-damko3m7bikc73c1b510` are separately bound to dedicated reader/updater roles, configured
  without static AWS credentials, auto-deploy disabled, and manually suspended. IAM simulation
  allowed the reader's `GetItem` while denying `PutItem`, allowed the coordinator's `GetItem` and
  `PutItem`, and denied both identities against a foreign-environment leading key. Live Render OIDC
  assumption was subsequently proven for both services using startup-time STS identity output; each
  assumed exactly its own expected role, then both services were re-suspended. Root-signed anchor
  bootstrap remains separate; no signed history or provider dispatch was created. Evidence is in
  `docs/evidence/tiamat-recovery-anchor-staging-commissioning-2026-09-18.json`.

- Render OIDC proof: `docs/evidence/tiamat-recovery-anchor-oidc-role-assumption-2026-09-18.json`
  records the executor and coordinator STS assumed-role ARNs, account match, cross-role isolation,
  and post-proof suspended state. The scoped proof performed zero DynamoDB writes, created no root
  key or signed history, and did not dispatch a provider request.

- Render PostgreSQL staging provisioning and bootstrap: dedicated database `tiamat-staging-ledger`
  (`dpg-damo6cp42hec73bp5nug-a`) is available in `cloud-lucy` /
  `management-contract-staging`, Virginia, on PostgreSQL 16 with the 0.1c-256mb plan and 1 GB storage.
  The selected dashboard price was $6.30/month, storage autoscaling and HA are disabled, and no
  credentials or connection strings were recorded. Render confirms that all internet traffic is
  blocked by PostgreSQL's resource-specific inbound rules; the inherited workspace and environment
  `0.0.0.0/0` rules remain unchanged. The independent lineage reached
  `0006_render_recovery_rls`; the runtime and recovery logins were successfully verified, and
  dispatch remains disabled. Temporary bootstrap secrets still require removal, while initialization
  and the capability probe remain pending. Content-free evidence is
  `docs/evidence/tiamat-render-postgres-staging-provisioning-2026-09-18.json`.

- Disposable bootstrap boundary: private Render service `tiamat-staging-bootstrap`
  (`srv-damoneajnfac73ai6ucg`) ran one successful exact-confirmation job at commit `d7c8335`.
  It migrated through `0006_render_recovery_rls`, created all three database roles, and verified only
  the runtime and recovery logins; the release-manager remains `NOLOGIN` until its own service
  boundary exists. The temporary owner and bootstrap-password secrets must now be removed and the
  runner suspended. No ledger initialization, anchor write, or provider dispatch has occurred.

- Cryptographic commissioning path: the strict recovery-witness inventory verifier now binds one
  active purpose-distinct witness key to the exact environment and ledger under the offline root.
  The offline builder creates and self-verifies the root-signed inventory, quarantined witness and
  predecessor-null version-one transition. Separate deployment tools generate ignored local key
  material, create a public signed package, and verify/dry-run before any network use. The online
  installer accepts no private key, requires an exact ledger-bound execution confirmation, uses the
  ambient SDK identity, conditionally writes only an empty anchor and strong-reads the result. No
  staging root key or signed history has been generated or installed.

- Verification after the cryptographic commissioning increment: 42 focused recovery-anchor tests
  passed, including offline package construction, inventory/root/scope validation, package tamper
  rejection, independent root trust pinning, exact signed-byte decoding, conditional bootstrap,
  strong reads, CAS collision and outage behavior. The complete unit suite passed 1,221 tests with two existing dependency
  deprecation warnings. Ruff passed across `src`, `deploy/aws` and unit tests; strict mypy passed
  across 144 source files plus all three new commissioning tools. `git diff --check` passed.

- Recovery-anchor unit boundary: 15 passed, including root-signed transition binding, signature/type
  substitution, predecessor-chain tampering, witness renewal, witness-inventory rotation,
  quarantine/recovery-pending lifecycle, PostgreSQL control/timeline/flush-LSN beacon query,
  stale-WAL beacon rejection, expiry and missing-anchor fail-closed behavior. Ruff and strict mypy
  passed for the two new modules and their tests.

- Signed-release RC1 bundle: 106 independent checks passed after fresh archive extraction; raw
  content digest `51b0f943c59b685f261bf0c58abad79a92f7c9fae5074517036c18e0884978d9`.
- Signed-authority and neighboring Shared Execution unit boundary: 76 passed. A broader `-k` run
  was discarded because pytest imported unrelated deployment tests without the repository root on
  `PYTHONPATH`; the explicit affected-file run is the valid evidence.
- Dedicated PostgreSQL 16 authority-store proof: all 17 integration tests passed against a fresh,
  loopback-only, tmpfs-backed disposable container, including blocked-before-recovery behavior,
  idempotent staging, inventory activation, release activation/loading, and missing-predecessor
  rejection. The container was stopped and removed after the run.
- The same 17-test PostgreSQL suite passed again after adding signed revocation, proving an active
  privacy-policy head becomes an idempotent revoked tombstone and is no longer loadable, without
  predecessor fallback. Its disposable container was also removed.
- The 17-test suite passed again after grant coupling, proving bootstrap and successor grants update
  the active signed head and budget projection atomically while the earlier missing-predecessor
  attempt leaves the partition unchanged. The disposable container was removed.
- The same fresh PostgreSQL 16 suite passed all 19 tests after recovery binding, cold-start loading,
  HTTP replay-store wiring, and workload-key rotation were completed. It proves recovery rejects
  unconfirmed database
  authority, accepts only
  an exact external inventory/head-set witness, restamps authority to the new recovery generation,
  still refuses a profile whose linked privacy policy is a revoked tombstone, and proves the real API
  consumes durable scoped replay state before dispatch, and enforces old/successor key overlap and
  retirement. The loopback-only disposable container was stopped and removed.
- A fresh PostgreSQL 16 suite then passed all 20 tests after migration `0004`, including a
  concurrent mixed-generation race in which the successor knew digest keys `v2` and `v1` while the
  predecessor knew only `v1`. Both admissions resolved to one execution and the durable alias set
  preserved both key versions; no second reservation or dispatch was created.
- Focused HTTP/service ordered-gate, receipt, and frozen-error-table suite: 41 passed. This includes
  cross-product precedence through the raw-digest gate, terminal paid-failure replay, provider
  accounting rejection, exact 404/405,
  malformed and duplicate `Content-Length`, the unauthenticated 1 MiB cap, duplicate binding
  headers, and proof that the authenticated replay gate precedes the 262,144-byte contract cap.

- Recovery-bootstrap hardening after independent review: bootstrap now accepts a complete validated
  checkpoint and independently computes RFC 8785/SHA-256 component and combined digests. The sole
  day-zero inventory is the non-authorizing `not_installed` sentinel, constrained to generation-one
  quarantine with no release heads or settlement positions. Witness verification binds component
  digests and signing-key authorization windows; offline root/witness keys must be distinct and the
  generator refuses unverified Windows plaintext storage. No key, signed history, DynamoDB write,
  Render resume, or provider dispatch occurred. Focused recovery tests: 55 passed; complete unit
  suite: 1,225 passed with two existing dependency deprecation warnings. Strict mypy passed across
  142 source files. Repository-wide Ruff remains blocked by 204 pre-existing violations in vendored
  conformance bundles; touched recovery files passed Ruff.

- Day-zero ledger initializer: 22 focused recovery, checkpoint, commissioning, and execution-ledger
  tests passed. Ruff passed for the touched source, migration, and test files; strict mypy passed for
  the two touched source modules. Alembic rendered the independent PostgreSQL SQL migration chain
  through `0005_ledger_identity` without connecting to a database. No Tiamat PostgreSQL instance,
  ledger row, root key, signed package, DynamoDB record, provider route, or production resource was
  created by this increment.

- RC1 conformance bundle: 130 independent checks passed; digest remained
  `5185680e2cb9ac9aff6006c9abc6a582b67933db077d5c7bd5dcc596f574cb85`.
- Complete unit suite: 1,167 passed with two dependency deprecation warnings. The first run exposed
  an unrelated probabilistic Private Lucy test nonce that began with `_` despite its alphanumeric
  first-character schema; the focused rerun and unchanged complete suite passed. No Private Lucy
  code was changed in this branch.
- Ruff: passed for `src`, unit tests, the Tiamat migration lineage, and the new integration test.
- Strict mypy: passed across 135 source files.
- Alembic: the independent migration lineage through `0002_route_settlement_retention` rendered successfully as PostgreSQL
  offline SQL.
- Focused durable-ledger tests: nine unit tests and 20 real PostgreSQL integration tests passed using
  a loopback-only, tmpfs-backed PostgreSQL 16 container with synthetic credentials. This establishes
  local database behavior, not production replication or failover.
