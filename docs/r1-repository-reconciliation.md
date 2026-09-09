# R1 repository reconciliation

Status: R1-0 and the R1-1 synthetic local slice are complete. R1-2 contract and
realm-session implementation has begun. Production provisioning remains disabled.

## Frozen baseline

- Inspected source: `aa157bded743976e934887b996ea8d79a5ebacef`, a documentation-only
  successor to accepted runtime `52527fa9d8eaa3be766986101b6a8f51c1b1c208`.
- Accepted PostgreSQL head: `0021_recovery_capture_safety`.
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
| Clean migration 0001 through `0022` | Disposable pgvector/PostgreSQL 16 tmpfs cluster | Migration or bootstrap change |
| Host normalization and snapshot digest | `tests/unit/test_r1_tenancy_publication.py` | Canonicalization/input change |
| Utopia approved FAQ, Alpha isolation, spoof denial, immutable bytes, withdrawal | `tests/integration/test_r1_tenant_public_slice.py` | Tenancy/publication/schema change |
| Wallet uniqueness and tenure immutability | same integration test | Identity/schema change |
| V1.3 scope, KMS context, permit deadlines, purpose-pinned signature | `tests/unit/test_security_contracts_v1_3.py` | V1.3 contract/canonicalization change |
| Verified workload selects one fixed private-realm credential | `tests/unit/test_realm_sessions.py` | Realm binding/session selection change |

## R1-2 checkpoint

`contracts/security_v1_3.py` adds new wire identities rather than extending or
reinterpreting v1.2 JSON: origin scope, current execution binding, resolved execution
context, owner assertion V2, permit V3, KMS encryption context V2, and v1.3
verification keys. New signatures retain the already reviewed `lucy-cjson-1`
canonicalizer, include their object type/version as a domain separator, and pin a
distinct v1.3 key purpose. Permit admission is at most 60 seconds while execution
completion remains a separate bounded deadline. A historical realm/storage mismatch
requires an exact restore-mapping ID.

`realm_sessions.py` selects database credentials only from a deployment-owned mapping
after workload identity has been verified. A request may supply a realm/workspace hint
only for conflict detection; it cannot select a credential. Unknown subjects/actions,
conflicting hints, duplicate subjects, and shared private-realm credentials fail
closed. The next R1-2 increment is the parallel scoped-memory schema and execute-only
PostgreSQL operations for Raymond/Utopia/Alpha test logins; legacy v1.2 rows remain in
their explicit enclave.

R2 jobs/wallet spending and R3 consulting, local runners, portability, transfer,
rehosting, and StoinNet execution are explicitly deferred.
