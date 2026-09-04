# Cloud Lucy Security Baseline v1.2 — implementation checkpoint

Date: 2026-09-02

Status: **local implementation and production-shaped PostgreSQL enforcement
pass. AWS/Render provisioning, synthetic cloud acceptance, and the quarantined
recovery drill remain open. Live Telegram transcript capture is disabled and is
not authorized.**

## Implemented

- Canonical signed owner assertion, V2 permit, encrypted package, deletion
  manifest, post-claim grant, KMS-signed receipt, quota, state, verification-key,
  recovery-inventory, and finality-record contracts.
- Execute-only PostgreSQL service identities and versioned security-definer
  issue/scope/claim/notary/attestation/reconciliation/finality functions.
- Direct table privilege revocation and startup admission checks that reject
  accidental direct application-table grants to policy, evidence, or deletion.
- Independently enforcing retrieval and deletion Lambda executors with exact
  environment/epoch/record/session/alias/version bindings, immutable receipts,
  bounded quotas, and content-free errors.
- Render coordinators that can call only a private policy endpoint, their exact
  qualified Lambda alias, and their named PostgreSQL functions.
- Four private Render backends plus a separate non-continuous finality utility;
  policy has no AWS identity, while evidence/deletion have no KMS/DynamoDB
  variables or authority.
- A Blueprint-managed PostgreSQL 18 instance in the same protected, network-
  isolated production environment, with no external IP allowlist. Its generated
  owner is migration-only; each runtime receives a distinct post-bootstrap URL.
- A metadata-only finality utility. It reports observed recovery facts; it
  cannot supply a finality verdict. PostgreSQL derives `EXTENDED` or `VERIFIED`
  from its authoritative deletion time and the observed PITR/backup/export/
  import/replica/quarantine/stream inventory.
- A separate v1.2 CloudFormation stack with three disjoint KMS keys, retained
  protected DynamoDB ledgers, exact Render OIDC callers, published Lambda
  versions and aliases, deployer/recovery/finality identities, CloudTrail,
  alarms, and owner alerts.
- Hash-pinned Linux AMD64 Lambda dependencies and deterministic zip packaging,
  plus hash-pinned Linux runtime dependencies for the Render Docker image.
- Exact production-login and post-stack epoch/executor binding SQL templates.

## Local evidence

- Ruff: passed across `src`, `tests`, and the artifact builder.
- Strict MyPy: passed for 41 source files.
- CloudFormation schema/lint validation: passed.
- Unit tests: 210 passed locally and again inside the exact Linux deployment
  image.
- PostgreSQL integration tests: 175 passed, 1 explicitly quarantined backup
  drill skipped. This includes real separate LOGINs and the metadata-derived
  `EXTENDED` to `VERIFIED` transition.
- Combined suite: 385 passed, 1 explicitly quarantined backup drill skipped.
- The clean executor artifact was rebuilt twice byte-for-byte identically from
  commit `0f25e85c9b1da5b0bf87ad15b954dcd6d0e76fa0` (`source_state=clean`):
  SHA-256 hex `05236e5e19cb92ba57600c59ebb0b24d0df9b62d0730a0f7dcbe5d9b27183e8e`
  and base64 `BSNuXhnLkrpXYAxZ67CyTQ35ti0HMKD33L5dmycYPo4=`. The Linux AMD64 ZIP is
  23,567,559 bytes with 2,506 files. Upload/version identity and the final
  deployed Lambda version remain cloud acceptance evidence, not local claims.
- After the executor outcome metrics, deployed-state verifiers, and audit-plane
  hardening were completed, the release artifact was refreshed twice
  byte-for-byte identically from clean commit
  `b8056897cec063d3ee593d10178b78956593a949`: SHA-256
  `235bd12254a61433e81e767b5a686561aff8ad48533cc52d7786a02d2b42b9ce`
  (`I1vRIlSmFDPoHnZ7WmhlYa/4rUhTPMUtd4agLStCuc4=`), 23,568,213 bytes and
  2,506 files. The artifact manifest SHA-256 is
  `bdfbf88350d21a6d44f90631c03ed0778f86e216fec5f991aa995feebfe3d8a4`;
  the reviewed CloudFormation template SHA-256 is
  `99922ee906da2de847a24bcf0c914eeb24f85c825fc23ec63f4131a23abdd8be`.
  This refreshed candidate has not yet been represented as uploaded or
  deployed evidence.
- The hash-locked Render dependency inventory has SHA-256
  `29dcc6d96c8ad72d2db123a78dc02333df2207119c8483935f5b04a372f4e8e0`.
  A local Linux AMD64 preflight build ran as UID/GID 10001 and passed all 210
  unit tests; its local BuildKit manifest digest is
  `sha256:b6c8ea0c9e1f33cd8c5470798f0d2810bfc53100aecbd7d99f1a047089a98528`.
  This is build evidence, not the final Render-deployed artifact digest.

No test used a real transcript, Telegram capture, production database, AWS key,
or Render secret.

## Narrow implementation finding

The initial finality function accepted a caller-supplied `VERIFIED` status even
though a metadata-only verifier does not know PostgreSQL's authoritative
deletion timestamp. The implementation corrected this without expanding the
architecture: the utility now submits only content-free AWS recovery facts, and
PostgreSQL derives the monotonic verdict. This closes a false-finality path.

## Cloud gate still required

Read-only preflight confirmed account `fortisanima` in `us-east-1` through the
`LucySecurityAdministrator` Identity Center assignment and a Render Pro
workspace. No v1.2 CloudFormation stacks, customer KMS keys, DynamoDB tables,
Lambda functions, S3 buckets, or Render OIDC provider existed at that check.

1. Create the protected Render production environment, private PostgreSQL
   database, and immutable IDs for the four private services plus the finality
   utility base.
2. Generate the policy-notary key, retain its private seed only as the Render
   policy secret, and use only its reviewed public inventory in AWS executors.
3. Upload the clean release artifact to a private versioned S3 bucket and record
   the object version together with the verified local SHA-256 representations.
4. Deploy `deploy/aws/security-baseline-v1.2.yaml` in `us-east-1`; confirm the
   alert subscription and record all stack outputs.
5. Obtain the two KMS receipt public keys, construct the pinned policy receipt
   trust inventory, and populate only the matching Render service variables.
6. Apply migrations, exact production LOGIN grants, and
   `deploy/postgres/configure_security_v1.2.sql.example`. Keep admission
   quarantined.
7. Run positive, negative, crash/retry, permission, cost, log-scrub, and network
   acceptance using synthetic evidence only.
8. Perform the quarantined unauthorized-deletion PITR recovery drill and prove
   that an authorized deletion is not restored. Measure RPO/RTO.
9. Produce the final deployed acceptance report and request a separate owner
    decision. Do not set `LUCY_TRANSCRIPT_CAPTURE_ENABLED=true` before that
    approval.

## Rollback before activation

- Keep all Render services stopped or failing closed with storage admission
  quarantined.
- Repoint neither production Lambda alias unless its reviewed previous version
  and digest are recorded.
- If the v1.2 stack creation fails, preserve retained KMS/DynamoDB/audit
  resources, inspect the failed change set, and use a reviewed forward repair;
  never delete retained evidence keys to make a retry convenient.
- The v1.1 deployment is not modified in place. No runtime traffic or live
  transcript exists to migrate at this gate.

## Accepted residual risks carried forward

- One strongly authenticated human remains the ultimate AWS trust boundary.
- Structured semantic memory remains plaintext to normal Lucy, with credential
  rejection/quarantine controls.
- A fully compromised executor can abuse already-known opaque identifiers.
- Retrieval already executing when deletion is claimed may finish.
- Render/AWS platform administrators remain privileged trust boundaries.
- Operational deletion becomes effective before cryptographic finality; the
  protected recovery window is 30 days and exceptional copies can extend it.
