# Security Baseline v1.2 cloud bootstrap checkpoint

Date: 2026-09-04

Status: **AWS control-plane deployment and bootstrap accepted. Render runtime,
synthetic cloud behavior, and recovery/finality acceptance remain. Live
Telegram transcript capture is disabled and not authorized.**

## Completed cloud controls

- The reviewed CloudFormation repair reached `UPDATE_COMPLETE` with termination
  protection enabled.
- The deployment, IAM/KMS-policy, and audit verifiers all passed after the
  repair. Both qualified production executor aliases target immutable published
  version `2`.
- The two asymmetric KMS receipt public keys were obtained with `GetPublicKey`,
  validated as `ECC_NIST_P256` / `SIGN_VERIFY` / `ECDSA_SHA_256`, and encoded as
  production `VerificationKeyV1` records. No private KMS material was exported.
- The independent deletion-journal head was absent and was conditionally
  initialized exactly once at sequence zero. A consistent reread proved its
  exact approved journal and registry binding.
- Exact non-secret Render bindings and PostgreSQL role/binding SQL were rendered
  from live stack outputs. No marker remains unresolved and the receipt trust
  inventory validates against Lucy's contract model.
- Focused contract, infrastructure, and PostgreSQL renderer tests pass: 62
  tests. The generated controlled artifacts have these SHA-256 values:

  - receipt trust inventory:
    `ba4b462dce0ec2464fa432c7eafd8e5a2ea20f6be1d086a1b1dd794a767f10e1`
  - Render bindings:
    `c3e9ffd4608f58f14b3dbedbd35b42bdd02b6eda9b0a800a18cffbe30fcd118e`
  - PostgreSQL direct-role grants:
    `bc57b4c0124326362fbb6eb9f6e7e0f68bdc1bb79e95e561017d400eab24a1db`
  - PostgreSQL immutable executor bindings:
    `d88b584add9469e3fd8ac46408d38a59a8efb83b18afa28ee8b6ad22378cfe90`

All detailed reports and generated deployment artifacts remain under the
git-ignored controlled acceptance directory. They contain no transcript or
private signing material.

## Render observation and prepared transition

The existing Render project contains the four private backends, the inert
finality cron base, and PostgreSQL 18 in the protected production environment.
The four services are still running the resource-ID provisioning hold from
commit `1358417`; the finality utility has never run. PostgreSQL reports
`Available`, and its database-specific inbound rules block all internet
traffic.

The connected Blueprint uses
`deploy/render/security-baseline-v1.2.yaml.example` on `main` with manual sync.
That source now removes the four provisioning-hold command overrides and
markers, while preserving:

- capture explicitly `false`;
- short-lived Render OIDC with no static AWS credential variables;
- the inert scheduled finality sentinel; and
- manual deployment control.

Pushing the source does not deploy it because Blueprint auto-sync remains off.
The manual sync must occur only after production database logins, migrations,
direct grants, immutable executor bindings, and matching service environment
values are ready.

## Reprioritized completion path

Only release-blocking security work remains before returning to feature
development:

1. **Database and Render wiring.** Create five distinct `NOINHERIT` database
   logins, apply migrations through `0019`, apply the reviewed direct grants and
   immutable version-2 bindings, and populate each Render service with only its
   matching database URL, OIDC role, and public/non-secret AWS bindings. Runtime
   admission stays quarantined and capture stays false.
2. **One synthetic runtime bundle.** Manually sync the Blueprint to the reviewed
   commit, then prove startup, actual OIDC, one end-to-end synthetic archive →
   retrieval → deletion path, the highest-value cross-role/API denials, and
   idempotent crash/retry recovery. This replaces many small checkpoints with
   one evidence-producing acceptance run.
3. **One recovery/finality bundle.** Restore only an unauthorized synthetic
   deletion into quarantine, prove an authorized deletion is not restored,
   measure RPO/RTO and cost, dispose of quarantine safely, and verify monotonic
   finality.
4. **Final report.** Record deployed identities, effective permissions, artifact
   digests, test evidence, actual costs, exceptions, rollback, and residual
   risks for Lucy/owner review.

Passing these gates does not itself enable live capture. Activation remains a
separate owner decision.
