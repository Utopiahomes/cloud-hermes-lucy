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
- A metadata-only finality utility. It reports observed recovery facts; it
  cannot supply a finality verdict. PostgreSQL derives `EXTENDED` or `VERIFIED`
  from its authoritative deletion time and the observed PITR/backup/export/
  import/replica/quarantine/stream inventory.
- A separate v1.2 CloudFormation stack with three disjoint KMS keys, retained
  protected DynamoDB ledgers, exact Render OIDC callers, published Lambda
  versions and aliases, deployer/recovery/finality identities, CloudTrail,
  alarms, and owner alerts.
- Hash-pinned Linux AMD64 Lambda dependencies and deterministic zip packaging.
- Exact production-login and post-stack epoch/executor binding SQL templates.

## Local evidence

- Ruff: passed across `src`, `tests`, and the artifact builder.
- Strict MyPy: passed for 41 source files.
- CloudFormation schema/lint validation: passed.
- Unit tests: 208 passed.
- PostgreSQL integration tests: 175 passed, 1 explicitly quarantined backup
  drill skipped. This includes real separate LOGINs and the metadata-derived
  `EXTENDED` to `VERIFIED` transition.
- Combined suite: 383 passed, 1 explicitly quarantined backup drill skipped.
- Dirty-tree local executor artifact was rebuilt twice byte-for-byte identically:
  SHA-256 `05236e5e19cb92ba57600c59ebb0b24d0df9b62d0730a0f7dcbe5d9b27183e8e`.
  It is labeled `dirty-local-test` and is **not deployable**. A clean committed
  source tree must produce the release digest recorded in the final report.

No test used a real transcript, Telegram capture, production database, AWS key,
or Render secret.

## Narrow implementation finding

The initial finality function accepted a caller-supplied `VERIFIED` status even
though a metadata-only verifier does not know PostgreSQL's authoritative
deletion timestamp. The implementation corrected this without expanding the
architecture: the utility now submits only content-free AWS recovery facts, and
PostgreSQL derives the monotonic verdict. This closes a false-finality path.

## Cloud gate still required

1. Sign in through IAM Identity Center as the user assigned the
   `LucySecurityAdministrator` permission set; do not use root for routine work.
2. Create/confirm the protected Render production environment and immutable IDs
   for the four private services plus the finality utility base.
3. Generate the policy-notary key, retain its private seed only as the Render
   policy secret, and use only its reviewed public inventory in AWS executors.
4. Build the clean release artifact, upload it to a private versioned S3 bucket,
   and record the object version and both SHA-256 representations.
5. Deploy `deploy/aws/security-baseline-v1.2.yaml` in `us-east-1`; confirm the
   alert subscription and record all stack outputs.
6. Obtain the two KMS receipt public keys, construct the pinned policy receipt
   trust inventory, and populate only the matching Render service variables.
7. Apply migrations, exact production LOGIN grants, and
   `deploy/postgres/configure_security_v1.2.sql.example`. Keep admission
   quarantined.
8. Run positive, negative, crash/retry, permission, cost, log-scrub, and network
   acceptance using synthetic evidence only.
9. Perform the quarantined unauthorized-deletion PITR recovery drill and prove
   that an authorized deletion is not restored. Measure RPO/RTO.
10. Produce the final deployed acceptance report and request a separate owner
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
