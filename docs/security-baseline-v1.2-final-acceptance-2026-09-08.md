# Security Baseline v1.2 final deployed acceptance

Date: 2026-09-08 (completed 2026-09-09 02:24:27Z)

Disposition: **the single-tenant Security Baseline v1.2 implementation,
deployment, synthetic cloud path, and authorized-deletion recovery fence have
passed their technical acceptance gates.** Live Telegram transcript capture is
still disabled. This report is for Lucy/owner review and is not capture
activation approval. Multitenancy and StoinNet integration remain outside this
gate.

## Accepted release

- Render/runtime commit:
  `52527fa9d8eaa3be766986101b6a8f51c1b1c208`.
- PostgreSQL migration head: `0021_recovery_capture_safety`.
- AWS executor source revision:
  `0020aaaf1add48feb7e083c22d4770b3415a2e51`.
- Executor ZIP SHA-256:
  `6029965bf5631c9e0d47f775654025984841e5418f3eb07ec82a1d8b78981357`.
- Executor AWS `CodeSha256`:
  `YCmWW/VjHJ4NR/d1ZUAlmEhB5UGPPrB+yCodi3iYE1c=`.
- Executor manifest SHA-256:
  `6c38efbacedb1f5dee7861371d9356a06b1f0f3e9413d8c8a2a76f7ce9222acd`.
- CloudFormation template SHA-256:
  `3acff006d2268ef03001e48caaf3e6ea4f9b510fb802aaac0337517e1b71c3df`.
- Base image: `python:3.12.11-slim` pinned to
  `sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f`.
- The current production image was built by Render from the exact commit. Render
  exposes the commit/deployment identity used below, but the collected API
  evidence does not expose a portable OCI manifest digest. The commit and pinned
  base image are therefore the recorded rollback identity for this release.

## Deployed boundaries

AWS account `429870640638`, region `us-east-1`, stack
`lucy-security-baseline-v1-2`; termination protection is enabled. Operator access
was the short-lived IAM Identity Center `LucySecurityAdministrator` session via
the `lucy-dev` CLI profile. No long-lived AWS credentials were created or found
in a runtime environment.

| Boundary | Deployed identity | Effective authority |
| --- | --- | --- |
| Routine/archive | Render `srv-daca8gafngtc73clva90`; DB `lucy_routine_workflow`; AWS role `lucy-prod-v12-render-archive` | Structured memory and ciphertext ingestion; exact data-key creation and wrapped-key creation; no decrypt, registry enumeration/deletion, executor invocation, or administration |
| Policy/notary | Render `srv-daca8gafngtc73clva80`; DB `lucy_policy_notary`; no AWS identity | Exact permit/grant/receipt-attestation functions and signing material; no evidence data, executor invocation, KMS, DynamoDB, or administration |
| Evidence workflow | Render `srv-dacab5afngtc73cm99m0`; DB `lucy_evidence_workflow`; AWS role `lucy-prod-v12-render-evidence-caller` | Execute-only PostgreSQL retrieval functions and invocation of the qualified retrieval alias; no direct tables, KMS/DynamoDB, enumeration, or other Lambda authority |
| Deletion workflow | Render `srv-dacab52fngtc73cm99l0`; DB `lucy_deletion_workflow`; AWS role `lucy-prod-v12-render-deletion-caller` | Execute-only PostgreSQL deletion functions and invocation of the qualified deletion alias; no direct ciphertext/key deletion, KMS/DynamoDB, enumeration, or other Lambda authority |
| Finality verifier | Render `crn-daca8gafngtc73clvaag`; DB `lucy_finality_verifier`; AWS role `lucy-prod-v12-finality-verifier` | Content-free recovery metadata only; no item reads, writes, restore, export, or KMS authority |
| Retrieval executor | `lucy-evidence-executor-v12:production`, published version 7; runtime role `lucy-prod-v12-retrieval-runtime` | Exact-key lookup, record-bound evidence-key decrypt, dedicated receipt signing, bounded immutable ledger/receipt writes; no Scan/Query/BatchGet/export/deletion/administration |
| Deletion executor | `lucy-deletion-executor-v12:production`, published version 7; runtime role `lucy-prod-v12-deletion-runtime` | Exact-key transactional deletion, dedicated receipt signing, bounded immutable intent/receipt/quota writes; no evidence-key KMS action, enumeration, export, backup, or administration |
| Human recovery | `lucy-prod-v12-recovery-administrator` | MFA/session-bound quarantined PITR recovery and exact controlled recovery operations; no evidence decrypt or normal application authority |

The evidence KMS key is
`arn:aws:kms:us-east-1:429870640638:key/9ac76d13-191f-48d7-8197-45b95f019f48`.
Separate receipt-signing keys are
`147b517c-8b1d-449b-acf9-0d7e8c9ff14a` (retrieval) and
`b87ef3db-edf7-411f-b6d1-35d01282312e` (deletion). Deployment verification
confirmed that all three are enabled, single-region keys with their exact
reviewed purposes.

The authoritative wrapped-key, intent, receipt, journal and quota tables are
the `lucy-prod-v12-*` DynamoDB tables emitted by the stack. They are encrypted,
on-demand, deletion-protected where specified, and have the reviewed PITR or TTL
configuration. PostgreSQL has an empty external allow-list; every service uses
the Render private database host. Current storage epoch is
`c768a554-ba36-4902-be09-3a682a203910`.

## Acceptance evidence

| Check | Result | Evidence |
| --- | --- | --- |
| Focused recovery code | 70 tests passed | Current `52527fa` work leading to the final gate |
| PostgreSQL recovery boundary | Passed | Real PostgreSQL migration `0020` to `0021`; exact synthetic receipt admitted, ordinary enabled receipt rejected; replay applied once and was idempotent thereafter |
| Runtime readiness | 26 tests passed | Expected migration `0021`, exact identity/binding checks |
| Production packaging | 13 tests passed | Recovery replay utility present in production image; local pinned Linux image built successfully |
| Synthetic archive/retrieve/delete | Passed | `render-synthetic-acceptance-v1.2-75c1134c-bab7-48e7-b279-0b632eaa5ab6-resume.json` |
| Authorized-deletion restore fence | Passed | `authorized-deletion-restore-fence-v1.2-04e6c6fa-fb3f-4a6c-8105-ee25c0b5dda2.json` |
| AWS deployed state | Passed | `aws-deployment-v1.2-52527fa-a7cc3d36.json`; 50 boundary checks passed |
| IAM and audit planes | Passed, reused after no relevant AWS change | Digests recorded in `security-v1.2-independent-evidence-ad5e8630.json` |
| Privacy log scrub | Passed | 1,048 AWS messages and the relevant Render messages scanned; zero plaintext, credential, or unsafe-fragment matches |
| Final Render audit | Passed | `render-live-audit-v1.2-52527fa-a7cc3d36.json`; all five identities live on the exact commit, capture false, no static AWS credentials, no temporary database authority |
| Consolidated gate | Passed | `security-v1.2-final-52527fa-a7cc3d36-1b09-428a-ab1a-e9a5624f0f47.json` |

The recovery drill restored an isolated PostgreSQL point, established
quarantine, bootstrapped all five exact runtime logins, and reapplied the two-key
authorized deletion. The first replay removed the resurrected payloads and the
second replay was idempotent. The temporary recovery database was deleted,
temporary environment authority was removed, and all continuous services were
resumed. No live transcript was used.

## Recovery objectives and observed result

- Protected recovery window: 30 days for the governed stores, subject to the
  documented exceptional-copy extension.
- Observed recovery point: `2026-09-08T21:21:37Z`, intentionally one second
  after the synthetic archive job completed and before its authorized deletion.
- Observed RPO result: zero loss for the intended two-record synthetic recovery
  set; both exact records were present in the restored point and then deleted by
  the signed replay fence. This is a correctness result, not a general uptime
  guarantee.
- The runner did not persist the recovery-request timestamp, so a clean
  infrastructure-only RTO cannot be reconstructed. The conservative wall-clock
  upper bound from the selected restore point through successful replay and
  cleanup was 4h 55m 45s; it includes the required PITR age wait, deployment
  waits, troubleshooting and operator interruptions and is not a production RTO
  target. Precise request-to-ready and ready-to-replay timing should be added to
  the next scheduled recovery exercise without reopening this acceptance gate.

## Cost and alerts

- AWS Cost Explorer returned USD `0.194273` account-wide unblended cost for
  2026-09-06 through 2026-09-08. Billing is delayed and was not tag-isolated to
  Lucy, so this is observed account cost, not a Lucy invoice or monthly forecast.
- Render cost was not exposed by the collected service API evidence and is not
  represented as measured here.
- The CloudWatch recovery-administrator alarm successfully published to
  `arn:aws:sns:us-east-1:429870640638:lucy-prod-v12-security-alerts`.
- Ray confirmed receipt of a real security-administration EventBridge email.
  Human receipt of the later synthetic CloudWatch test email was not separately
  confirmed; AWS records its SNS action as `Succeeded`. This is an observability
  exception, not an authorization-path failure.

## Finality, exceptions and residual risks

Operational deletion is effective immediately after signed reconciliation, but
cryptographic finality remains `EXTENDED` while a recoverable copy exists. The
last measured inventory contained one reviewed DynamoDB deleted-table `SYSTEM`
backup, created 2026-09-03 and expiring 2026-10-03. Time passage alone does not
mark deletion final; the finality verifier must observe that no governed or
exceptional copy remains.

Accepted Phase 1 residual risks remain:

- one strongly authenticated human is the ultimate AWS/platform trust boundary;
- structured semantic memory is plaintext to normal Lucy, with credential
  rejection/quarantine controls;
- a completely compromised executor can abuse opaque identifiers it already
  knows, although it cannot enumerate the archive;
- a retrieval already executing when deletion is claimed may finish;
- Render and AWS platform administrators remain privileged boundaries;
- operational and cryptographic deletion differ during the 30-day/extended
  recovery window; and
- this is a single-tenant acceptance. Tenant isolation and per-customer keys,
  identities and data boundaries require the separately reviewed tenancy work.

Reporting exceptions are the non-isolated steady-state RTO, non-isolated AWS
cost, unavailable Render cost, unavailable Render OCI digest, and unconfirmed
human receipt of the synthetic CloudWatch email. None changes the tested
authorization, encryption, deletion, quarantine or recovery behavior. They must
remain visible rather than being described as passed measurements.

## Rollback route

Capture remains false during rollback. Database schema changes are forward-fixed;
they are not destructively downgraded. A runtime rollback uses a coordinated
deployment to the recorded prior application revision and rebinds the database
executor versions/epochs as one quarantined operation. Lambda rollback requires
the separate deployer to repoint each production alias to its recorded prior
published version; runtime identities cannot change aliases. A rollback must not
restore direct KMS/DynamoDB authority to the Render evidence or deletion service,
open PostgreSQL externally, disable PITR/audit, or bypass permits. Ambiguous state
stays quarantined until reconciled.

## Decision still required

Lucy and the owner may now review this report. Security Baseline v1.2 technical
acceptance is complete, but live Telegram transcript capture remains exactly
`false`. Enabling it requires a separate, explicit owner activation decision.
