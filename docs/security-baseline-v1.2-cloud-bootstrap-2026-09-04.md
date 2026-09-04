# Security Baseline v1.2 cloud bootstrap checkpoint

Date: 2026-09-04

Status: **AWS control-plane deployment and the private Render PostgreSQL
boundary are accepted. Render runtime, synthetic cloud behavior, and
recovery/finality acceptance remain. Live Telegram transcript capture is
disabled and not authorized.**

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

## Private Render database acceptance

The private migration utility built and ran on Render from reviewed commit
`f30de15`. Its successful run reported:

- migration head `0019_security_v1_2_reconcile`;
- TLS-protected connections for the migration identity and all five runtime
  identities;
- five distinct `NOINHERIT` runtime logins with no elevated flags or inherited
  role memberships;
- two active immutable production executor bindings;
- runtime admission `quarantined`;
- transcript capture `false`;
- direct-role SQL digest
  `bc57b4c0124326362fbb6eb9f6e7e0f68bdc1bb79e95e561017d400eab24a1db`;
  and
- executor-binding SQL digest
  `d88b584add9469e3fd8ac46408d38a59a8efb83b18afa28ee8b6ad22378cfe90`.

The initial verifier incorrectly attempted to read `runtime_admission` through
the finality identity. That access was correctly denied by PostgreSQL. Commit
`f30de15` changed the verifier to require that denial while continuing to
require the four request-processing identities to observe the quarantined
state. The subsequent idempotent run passed.

Each generated database URL was then saved only to its matching permanent
service: routine, policy, evidence, deletion, or finality. No service received
the migration URL and no credential was shared between services. Settings were
saved without deploying the still-quarantined services.

The temporary cron resource `crn-dadcccv10e5c73ea7m7g`, including its migration
credential and bootstrap environment, was deleted after the successful run.
The protected environment returned to its six permanent resources. Generated
credentials were never written to the repository or local filesystem.

The post-fix local regression is also green: 273 unit tests, Ruff, and strict
MyPy across 44 source files.

## Render observation and next transition

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

The database remained private during that transition. The reviewed deployment
path used a temporary migration-only Render resource with no AWS identity.
`deploy/postgres/bootstrap_cloud_v1_2.py` validates the private Render host and
disabled-capture authorization, creates or safely rotates the five exact
`NOINHERIT` logins, migrates through `0019`, applies the reviewed grants and
version-2 executor bindings, then verifies TLS, quarantine, disabled capture,
and every runtime login. It emits no credential material. The temporary
resource and its migration-owner environment were removed immediately after
the verified run; no normal Lucy service received migration authority.

Read-only inspection also reconciled the Blueprint with the database's
immutable generated identity: the existing production database is
`lucy_6tns`. The source now names that exact database, avoiding an invalid rename
attempt during manual sync. Its service ID remains
`dpg-daca8gafngtc73clvafg-a`, and its PostgreSQL-specific inbound rule set is
empty, overriding the broader workspace and environment defaults and blocking
all public database traffic.

## Reprioritized completion path

Only release-blocking security work remains before returning to feature
development:

1. **Complete runtime configuration.** Rotate the policy-notary acceptance key
   as one coordinated AWS/Render change, verify each service's exact OIDC role
   and public binding inventory, and keep runtime admission quarantined and
   capture false.
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
