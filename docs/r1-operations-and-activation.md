# R1 operations and bounded activation

## Accepted operating state

Utopia is the only commissioned production-ready R1 realm. Raymond and Alpha are
synthetic isolation proofs; SC Consulting and Cloud Lucy Service are registered-only.
The ordinary Utopia services are suspended, runtime admission is quarantined, paid
inference is fail-closed, auto-deploy is off, the database public allow-list is empty,
and transcript capture is disabled.

This state is intentionally useful as a secure technical foundation without claiming
that a customer-facing product is live. R2 jobs/wallet settlement and R3 consulting,
local runners, portability, transfer, rehosting, and StoinNet execution are absent.

## Identities and blast radii

| Process | Database authority | AWS authority | Network/content boundary |
| --- | --- | --- | --- |
| `lucy-routine` / `lucy_routine` | Scoped semantic-memory operations | None | Realm-private; no raw evidence decrypt |
| `lucy-policy` / `lucy_policy` | Exact policy claim/grant/attestation operations | None | Realm-private; no archive body access |
| `lucy-evidence` / `lucy_evidence_reader` | Exact permit-bound retrieval functions; no table enumeration | Invoke exact retrieval alias through its realm caller role | Realm-private; bounded evidence release |
| `lucy-deletion` / `lucy_evidence_deleter` | Exact governed-deletion functions; no direct key/ciphertext tables | Invoke exact deletion alias through its realm caller role | Realm-private; no KMS master-key administration |
| `lucy-finality-utility` | Content-free finality metadata | Exact finality-verifier reads | Scheduled metadata-only observation |
| `lucy-authority-writer` | Pending authority events and exact acknowledgements | Append only the typed Utopia authority journal | Private recovery plane |
| `lucy-cost-writer` | Pending cost events and exact acknowledgements | Append only the typed Utopia cost journal | Private recovery plane |
| `lucy-recovery-coordinator` | Exact replay/activation functions through four recovery logins | Strongly consistent exact-key recovery reads and scoped pause operations | Private recovery plane; cannot reopen without protected handoff |

AWS execution remains: PostgreSQL workflow claim, policy-signed grant, Lambda AWS
effect, policy-attested receipt, PostgreSQL reconciliation. Lambda does not connect to
PostgreSQL. Ordinary processes do not hold static AWS credentials.

## Routine operation

1. Keep deployments pinned to a reviewed commit, auto-deploy disabled, and capture false.
2. Keep the PostgreSQL public allow-list empty. Use a temporary exact `/32` entry only
   for an approved operator procedure, require TLS, and remove it in guaranteed cleanup.
3. Treat missing identity, binding, policy, cost, journal, or recovery-head facts as a
   denial. Do not substitute defaults.
4. A restriction is locally blocked immediately but reported durable only after its
   exact journal/head acknowledgement. An ambiguous effect stays pending or quarantined.
5. Review content-free alarms and finality state. Never put transcript plaintext,
   decrypted evidence, bearer tokens, or secret values in logs or acceptance artifacts.

## Emergency quarantine and rollback

1. Disable public routing and suspend ordinary services.
2. Set runtime admission to `quarantined`; keep transcript capture false and paid
   inference disabled.
3. Do not downgrade the database or delete journal/KMS resources. Preserve evidence of
   ambiguous operations.
4. Roll application services only to an exact previously accepted commit and preserve
   the current schema until compatibility is proved.
5. Before reopening, run the deployed AWS verifier, the read-only PostgreSQL verifier,
   Render identity/config inspection, and the protected recovery handoff if any restore
   or journal divergence occurred.
6. Reopen only after the live authority and cost heads equal the replayed heads under a
   protected writer pause/barrier. Otherwise remain quarantined.

Detailed recovery evidence is in
`docs/evidence/utopia-r1-4-protected-recovery-2026-09-11.json`; deployment procedures
are in `deploy/aws/README.md` and `deploy/postgres/README.md`.

## Separate activation manifest

No live activation is authorized by R1 acceptance. A later activation change must name
and review all of the following in one bounded manifest:

- exact realm, service names, source commit, image/base-image digest, schema revision,
  AWS stack/template digests, and rollback commit;
- customer authentication issuer, audience, subject mapping, strong-auth requirement,
  owner identities, and session/channel bindings (AWS operator SSO is not customer auth);
- exact DNS names, public/private ingress, forwarded-host/origin trust, rate limits,
  request/session/IP limits, request bytes, token limits, and timeouts;
- model/provider/rate version, provider credential scope, global/realm/site daily caps,
  outstanding exposure and concurrency caps; missing values keep paid calls disabled;
- approved initial public snapshot and source lineage, permitted data classes/actions,
  operational contacts, and rollback/quarantine owner;
- an explicit, separate decision for transcript capture. Capture remains false unless
  that decision is approved after the encryption/deletion boundary review.

Start from `deploy/render/utopia-r1-activation-manifest.v1.json.example` and keep the
populated manifest in the ignored operator evidence store. Validate it with
`python deploy/render/validate_activation_manifest_v1_3.py <manifest>`; the validator
prints only a content-free result and rejects moving revisions, undeclared origins,
forwarded-host trust, incomplete paid-inference limits, and capture enablement.

Immediately before activation, verify drift against the accepted evidence, deploy the
same exact reviewed revision to the selected services, prove negative authentication,
cross-realm, direct-SQL, and AWS-role controls, then perform a protected handoff. No
other logical node becomes production-ready through Utopia's approval.
