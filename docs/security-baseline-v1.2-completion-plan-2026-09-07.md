# Single-tenant Security Baseline v1.2 completion

Status: **single-tenant technical acceptance complete** on runtime commit
`52527fa9d8eaa3be766986101b6a8f51c1b1c208`. The final deployed report is
[`security-baseline-v1.2-final-acceptance-2026-09-08.md`](security-baseline-v1.2-final-acceptance-2026-09-08.md).
Live Telegram transcript capture remains disabled and requires a separate owner
activation decision. Customer isolation and multitenancy are outside this gate.

## Evidence recovered after the interruption

- Reviewed, pushed application release: `ace5aba2996f63a26099c3511fe51f024b4d32b0`.
- Previous local full gate: 490 tests passed, zero skipped, including PostgreSQL
  backup/restore tests. Ruff and strict MyPy passed.
- Release locks contain cryptography 50.0.1. The September 5 dependency reports
  record zero known vulnerabilities; this is a dated scan, not a future guarantee.
- Reproducible Lambda ZIP SHA-256:
  `959ef15012c6c9f6a7d30b4e6bad4b5f7a45ee17b6067bad57167149b2cbd576`.
- September 7 Render read-only check: four continuous services running, capture
  false, executor bindings at version 5, no static AWS credentials, and no
  temporary database authority.

## Finite execution sequence

1. Preserve the reviewed release and verify operator tooling before cloud writes.
   Correct permanent-epoch cleanup, CloudFormation API use, property-level change
   validation, and fail-closed suspension. Run offline regression checks.
2. Obtain one process-local AWS Identity Center authorization. Upload and verify
   three exact release objects. Create and inspect the seven-resource update
   plus two verified unchanged dynamic ARN dependencies:
   two Lambda functions, two retained versions, two aliases, and the recovery
   administrator's quarantine restore policy. Preserve all unrelated parameters.
   AWS also reports AuditTrail.EventSelectors and LambdaDeployerPolicy.PolicyDocument
   because they reference the updated functions. Accept these only with unchanged
   tagged YAML definitions, no replacement, and exclusively dynamic references to
   the two exact function ARNs; reject direct changes to either resource.
3. Suspend the data path, quarantine database admission, deploy the update, verify
   AWS permissions, advance database executor bindings and policy configuration,
   rotate the runtime UUID epoch, prepare admission, remove temporary authority,
   and deploy the reviewed Render release. Preserve bigint security epochs.
4. Run fresh synthetic archive/retrieve/delete acceptance. Feed its exact report
   into the quarantined PITR recovery and deletion-finality drill. Record recovery
   times, authorized-deletion preservation, audit evidence, and complete cleanup.
5. Collect final AWS/Render/PostgreSQL identity and permission evidence, privacy
   checks, non-destructive alert receipt, actual available costs and projections,
   artifact identities, rollback route, exceptions, and residual risks. Produce
   the final report for Lucy/owner review.

Existing reports from older releases remain historical evidence. They cannot
substitute for deployed checks on this release. Any missing required evidence
must remain visibly open; the operator runner alone does not grant acceptance.

## Interruption and rollback

Operator scripts and detailed state are under ignored `secrets/generated/`.
They retain no AWS credentials. Before resuming an interrupted mutation, inspect
the saved state and the live cloud state. An ambiguous database transition keeps
the data path suspended. Temporary database authority is removed independently
of suspension cleanup. Do not blindly replay a synthetic operation.

Retain previous artifact/version identities. After database executor bindings
advance, rollback requires a coordinated forward deployment and rebind, not an
isolated alias change. Preserve capture=false through rollback and recovery.

Acceptance review and live-capture activation are separate owner decisions.

## September 8 execution checkpoint

- Identity Center authentication works again. AWS release preflight passed and
  the three reviewed release objects were uploaded. No stack update had occurred
  when the first change-set guard rejected the two dependency entries above.
- Read-only comparison verified unchanged audit-trail, deployer-policy, and Lambda
  function definitions. AWS change details identify only dynamic ARN references
  for the two extra entries. The operator guard now enforces that exact boundary.
- Three focused operator regression checks passed, including rejection of direct
  dependency edits, unrelated ARN causes, unexpected resources, and role changes.
- The active operator keeps authorization only in process memory for diagnosis;
  it does not persist credentials. Exact progress remains in the ignored completion
  state file.
- Run `25eb57b5-8e45-4b6b-922d-23ff84531f8e`: reviewed change set executed;
  CloudFormation UPDATE_COMPLETE. Deployment, IAM, and audit verifiers passed
  (`secrets/generated/aws-{deployment,iam,audit}-v1.2-post-rollout-25eb57b5.json`).
  PostgreSQL bindings advanced from 5/5 to 6/6 with historical operation rows
  preserved and capture disabled. Fresh runtime epoch prepared successfully.
  Render rollout completed on the reviewed release for all five identities.
- Fresh synthetic cloud acceptance passed:
  `secrets/generated/render-synthetic-acceptance-v1.2-f4018628-9946-41f7-b27b-376fbad515e9.json`.
  Archive and deletion replayed exactly once; retrieval replay released no
  plaintext; opposite-executor invocation and wrapped-key enumeration were denied;
  executor receipts verified; two synthetic evidence records were deleted.
  Temporary trust cleanup succeeded, all five deployments were live, capture false.
  Recovery drill was attempted but did not pass; see the blocker below.

## Recovery blocker and safe handoff, September 8

Drill `b18d4fae-d339-4fbf-8c37-b8560b0bf507` failed before restoration.
CloudTrail records RestoreTableToPointInTime at 15:11:22Z denied because the
Recovery Administrator lacks dynamodb:Scan on the exact quarantine target.
AWS documents that point-in-time restoration also requires target-table read/write
permissions: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/backuprestore_IAM.html.
This conflicts with the planned exact-record-only recovery identity. Do not add
enumeration/write permissions silently or rerun the full completion workflow.

Evidence: `secrets/generated/recovery-finality-drill-v1.2-b18d4fae-d339-4fbf-8c37-b8560b0bf507.json`.
The failed report incorrectly marked services resumed despite skipping resume
after a cleanup error. The operator reporting condition has been corrected for
future runs; that original report is retained and must not be read as successful
service-resume evidence.

Subsequent operator reconciliation verified: exact synthetic source item absent;
exact quarantine table returns ResourceNotFoundException; original CloudTrail
selectors restored; all five runtime epochs match; temporary database authority
absent; capture false. Services were then resumed and a fresh Render preflight
confirmed all four continuous services running with executor bindings 6/6.
No AWS permissions were broadened in response to the restore failure.

Proposed owner decision: authorize a narrowly bounded restore phase with temporary
target-table read/write rights on only the exact quarantine table. Remove those
rights before exact-record inspection, verify enumeration is denied again, and
retain existing source-table and KMS boundaries. Review this permission change
before implementation. If approved, rerun the affected recovery drill using the
passing synthetic acceptance report; do not repeat unrelated passing tests.
Final clean audit, alert receipt, cost/RPO/RTO evidence, and acceptance report
remain open. Live capture remains unapproved and disabled.

### Approved recovery correction, September 8

Ray approved the exact-quarantine-table temporary restore grant in the current
task. The operator now binds seven DynamoDB target-table read/write actions to
one recovery session, one exact quarantine ARN, and a one-hour expiry. It removes
the inline grant before inspection, checks policy propagation, and retains the
deployed enumeration-denial check. Interrupted-drill cleanup removes the same
grant; source-table and KMS permissions remain unchanged.

Focused policy construction checks passed (exact target and action set; wildcard,
subresource and empty target rejected). Existing AWS session was verified with
STS. Previous synthetic key and quarantine table were reconfirmed absent; the old
marker was preserved as `recovery-finality-drill-v1.2-state-reconciled-b18d4fae.json`.
Recovery-only rerun started using the passing `f4018628` acceptance report.
This is an in-progress check, not a passed recovery result. No full-suite or
functional acceptance replay is required by this operational correction.

### Rerun result and alert correction

Recovery `f2561966-62d9-4274-af61-99cb22d3d99e` did not pass. The temporary
exact-session policy simulated as allowed, but RestoreTableToPointInTime still
returned AccessDeniedException for target Scan. Do not repeat the same restore.
The cause of the simulator/live-service mismatch is not yet established; IAM
propagation or restore-internal condition evaluation must be distinguished before
changing permissions. No broader target/source/KMS grant has been made.

The grant was removed and absence of the synthetic source key and quarantine
table reverified. Services were resumed; preflight confirmed capture false,
versions 6/6, matching runtime epoch, no static AWS credentials, no temporary DB
authority. The failed drill marker remains for reconciliation, not blind replay.
Evidence: `security-v1.2-post-failed-recovery-f2561966.json` and the matching
`recovery-finality-drill-v1.2-f2561966-62d9-4274-af61-99cb22d3d99e.json` under
`secrets/generated/`.

Independent alert validation found actual CloudWatch action failures: the SNS
policy allowed EventBridge only. Added CloudWatch Publish scoped by source account
and this stack's alarm ARN prefix. Live SNS policy was updated and read back;
repository template and verifier match the correction. **CloudFormation's stored
template still needs this targeted update**; preserve this known policy drift
until reconciled, rather than overwriting the live fix with the old template.
Rollback policy is recorded in `sns-alarm-policy-repair-20260908.json`.

Seven affected audit-verifier tests passed and focused Ruff passed. Five offline
restore-grant safety tests passed. A synthetic alarm transition produced a
CloudWatch action result of `Succeeded` to the correct SNS topic; confirmed email
subscription and corrected deployed SNS policy checks passed. Human inbox receipt
is not yet confirmed (`security-v1.2-alert-delivery-20260908.json`). This is real
alert-path evidence, not merely a policy simulation.

Cost Explorer returned USD 0.194273 for September 6–8 (query end September 9),
account-wide, delayed and not Lucy-isolated. Saved `security-v1.2-cost-20260908.json`.
Not a complete invoice or future cost projection.

Next: confirm inbox receipt; isolate the restore permission mismatch without
replaying functional acceptance; reconcile the SNS-only CloudFormation change;
finish recovery and then the final clean-state/privacy/report checks. Live capture
remains disabled and has no activation approval.

### Owner email evidence, September 8

Ray confirmed receipt and supplied the SNS email for EventBridge event
`b09ada54-c5b6-06c1-bb6e-853221a19906`: S3 PutBucketPolicy at 14:47:33Z.
Attachment reference: `9965f620-d2b2-4dd2-aee9-05305cfcca80/pasted-text.txt`.
This confirms the security-administration EventBridge → SNS → owner inbox path.
It is not the later CloudWatch synthetic alarm email. CloudWatch → SNS delivery
has separately succeeded per saved action history; receipt of that specific test
email remains unconfirmed. Do not conflate the two messages or repeat the test
merely because this attachment is the earlier administration alert.

### Live permission diagnosis and SNS reconciliation

The bounded live IAM diagnostic against the verified nonexistent quarantine target
returned AccessDenied twice, then ResourceNotFound (authorization accepted) after
about ten seconds. This proves IAM simulation led the DynamoDB authorizer in this
session; it supports propagation as the prior restore failure cause, but successful
restore remains to be demonstrated. No restore/data read occurred during diagnosis;
the exact-session, exact-target temporary policy was removed afterward.
Evidence: `restore-iam-live-diagnostic-20260908.json`.

Operator now requires this live authorization-readiness probe before issuing a
restore. Seven focused operator tests pass, including delayed authorization and
unexpected-existing-target rejection. No permission widening was needed.

CloudFormation SNS-only change set completed UPDATE_COMPLETE. Reviewed exactly one
Modify/no-replacement resource, SecurityAlertTopicPolicy; all parameters retained
and all other resource definitions unchanged. Stored deployed template matches the
prepared correction, SHA-256 beginning `3acff006d226`; full digest and change-set ARN
in `sns-template-reconciliation-20260908.json`. SNS template drift is resolved.
Do not replay the previous full rollout using its obsolete template hash.

The SSO token cannot refresh, although previously issued STS credentials remain
usable. Prepare a fresh session for the longer recovery/cleanup path rather than
risk expiry during suspension. Exact next session work: verify current safety
state, preserve reconciled f2561966 marker, run recovery only with f4018628
acceptance evidence and the live propagation probe, then final evidence collector.
No extra functional suite, Lambda rollout, alert re-send, or capture activation.

### Latest approved-session result: ad5e8630

Fresh authorization verified. Before the recovery-only run, reconfirmed old source
marker absent, quarantine absent, no temporary inline grant, capture false,
versions 6/6, and all four continuous services running. Preserved the previous
marker as `recovery-finality-drill-v1.2-state-reconciled-f2561966.json`.

Drill `ad5e8630-70b4-492a-9cb3-184b4d9bf4af` stopped at the live permission
readiness check: all twelve attempts remained denied within its approximately
one-minute bound. **No restore request was issued.** The earlier ten-second
diagnostic does not establish a sufficient readiness interval or fully explain
this failure. Do not claim the permission problem is solved or repeat the full
drill unchanged.

Automatic cleanup passed with no errors: synthetic source item absent,
quarantine absent, temporary grant removed, original CloudTrail selectors
restored, all five identities redeployed on ace5aba, capture disabled. The clean
runner removed its active drill marker. Exact report:
`recovery-finality-drill-v1.2-ad5e8630-70b4-492a-9cb3-184b4d9bf4af.json`.

Independent checks completed with this session: AWS deployment/IAM/audit, Render
identity/private-network/deployment/capture audit, and synthetic plaintext /
credential-pattern log scrub all passed. Evidence index:
`secrets/generated/security-v1.2-independent-evidence-ad5e8630.json`.
These are passing checks, **not** a passing recovery or final acceptance report.
Reuse where unchanged; a future recovery epoch change invalidates the epoch-
dependent portion of the Render audit, not the unchanged application tests.

Next diagnostic must run with normal services up, against a verified nonexistent
exact target, before any fresh synthetic deletion or suspension. Distinguish
cached credentials/client/authorizer state from policy conditions with content-free
per-attempt evidence; preserve the approved exact-target/session/expiry constraints.
Do not widen permissions or start another full drill merely to test a longer wait.
Once readiness is demonstrated reliably, run only recovery, its affected final
checks, and the acceptance report (including remaining cost projections).

### Client comparison isolates a reproducible difference

With services running, the same exact-target/session grant produced this result:
at 0 seconds all clients denied; at 16.4, 31.9 and 47.5 seconds the original
client still denied while a new client with the same credentials and a fresh STS
session both reached ResourceNotFound (authorized against the absent target).
Evidence: `restore-client-comparison-20260908.json`. This demonstrates a
client/connection-associated difference, not its undocumented internal AWS cause.
The grant was removed and no restoration/data read occurred.

The runner now creates a fresh client for each readiness attempt, retains the
authorized client for restore, and refreshes again after revocation. The denial
probe uses COUNT rather than retrieving item contents. Eight focused operator
tests passed, including distinct stale/ready clients. Recovery-only execution
resumed using the same valid authorization and prior functional evidence.

Fresh-client correction reached a new confirmed milestone: drill
`106e3086-fc74-4cd8-aa83-99a186725c50` successfully issued the restore request at
2026-09-08T16:15:40.242163Z and observed quarantine CREATING. This clears the
request-time permission blocker for this run; recovery/cleanup are still in
progress and are not yet passed. Do not interrupt the active restore or remove
its temporary target grant while it is creating.

That restore reached ACTIVE, then stopped on GetResourcePolicy PolicyNotFoundException
immediately after attachment. Cleanup passed with no errors. AWS explicitly documents
this eventual-consistency response after PutResourcePolicy:
https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_GetResourcePolicy.html.
The operator now retries that response within its existing 120-second control
verification deadline, uses a fresh client per attempt, and still requires the exact
policy digest, tags and deletion protection before inspection. Nine focused tests
passed. Recovery-only rerun started with the same valid authorization; no permissions
were broadened and previously passed functional acceptance is still reused.

### Latest recovery milestone and unresolved finality count

Drill `27c1aec5-9d50-4f07-91d6-5ab8a123404f` restored successfully, verified
quarantine controls, removed the temporary grant, and completed finality job
`job-dag3h3fqj5pc738raj30`. Returned status EXTENDED with recoverable_copy_count=2,
not the expected 1. The runner stopped before exact-key recovery and cleaned up.
Do not loosen this assertion without identifying the additional category/copy.

Post-cleanup administrator metadata showed zero quarantine tables, backups,
exports, imports, global tables and source AWS Backup recovery points, with no
source stream/replicas. That does not reconstruct the inventory while the restored
table existed. The historical CLI result contains only the aggregate and digest,
not category counts; cause remains unestablished.

A read-only finality-identity category diagnostic job `job-dag3jup594qs73fno3j0`
succeeded, but neither job-ID nor parent-service text-filtered CLI log retrieval
returned its stdout. No additional job or restoration was launched to work around
this. Evidence: `secrets/generated/finality-count-mismatch-20260908.json` and
`recovery-finality-drill-v1.2-27c1aec5-9d50-4f07-91d6-5ab8a123404f.json`.

Current handoff: restore authorization and quarantine-policy propagation are now
demonstrated in cloud. Exact-key recovery and finality disposition are still NOT
passed. Next isolate the aggregate=2 using category-level metadata from the
finality identity (resolve the successful diagnostic job's output first), without
another blind full drill or permission widening. All cleanup completed; capture
remains disabled. Nine focused operator regression tests passed. Keep prior
passing application/audit evidence; final acceptance remains open.

### Finality diagnostic publication gate

The standard finality command returned EXTENDED/copy_count=1 after cleanup
(`job-dag3n9p594qs73fo33ng`), versus 2 with the quarantine table present.
Saved `finality-post-cleanup-20260908.json`. The persistent category is still
unidentified. Two custom read-only category jobs succeeded but yielded no logs
through CLI or explicit-time API queries; stop repeating that custom path.

Added content-free category counts to the standard finality CLI JSON output,
without changing collection, DB verdict or aggregate arithmetic. Five targeted
finality tests and focused Ruff passed. Local commit `a2468a0` includes this
diagnostic, the already-deployed SNS fix, verifier tests and checkpoint. All five
Render services have autoDeploy=no. No diagnostic deployment occurred.

Pushing this commit to origin/main was rejected by tool auto-review because
explicit authorization for that external/default-branch publication and repository
trust was not established. Do not bypass. Next required owner decision: approve
publishing this tested commit to Lucy's origin/main and deploying only finality
to obtain the category breakdown. Other services and Lambda versions stay put;
capture stays disabled. The local changes are complete but not published.

### 2026-09-08 recovery and epoch evidence

Commit `a2468a0` was explicitly approved, pushed to `origin/main`, and first
deployed only to finality. Its standard output identified the persistent copy as
one DynamoDB deleted-table `SYSTEM` backup created 2026-09-03 and expiring
2026-10-03. It reports zero bytes and no AWS Backup vault or lifecycle. This is
the exceptional deleted-table recovery window already described in Section 10.2;
finality correctly remains `EXTENDED`. No backup plan, export, import, replica,
stream, on-demand backup, or quarantine table remains.

Recovery drill `7a1bf879-285d-4227-ab9b-37a1393cffb7` reached hardened
quarantine and exposed a false-positive KMS denial probe. IAM simulation and the
live KMS authorization-only dry run (`DryRun=true`,
`DryRunModifiers=IGNORE_CIPHERTEXT`) both proved `kms:Decrypt` is denied to the
Recovery Administrator. The operator probe now uses that AWS-supported mode.

Drill `1f33e5a8-ce47-4403-8011-a7b0ccd1452cd` then proved the synthetic PITR
restore, exact recovered item, owner-authorized target absence, normal-role
denials, KMS denial, and CloudTrail `DeleteItem`/`GetItem` delivery. It stopped
at PostgreSQL maintenance because the operator command incorrectly requested
legacy v1 deletion replay in a v1.2 deployment. Cleanup removed the exact
temporary grant, synthetic item, quarantine table, CloudTrail selector, and
temporary database authority.

The already-passed recovery evidence was reused. A focused controlled epoch
transition omitted legacy replay, waited for suspended-service PostgreSQL
sessions to drain, and succeeded on retry job `job-dag4stv40ujc73eam7j0`.
All five Render identities now share storage epoch
`90c8860d-a48c-4f0e-90d9-a1986db94e42` on commit `a2468a0`; all four private
services passed `/ready` in job `job-dag5045bedkc73fisd6g`; capture is false;
temporary maintenance authority is absent. Finality job
`job-dag50f9594qs73fskaf0` returned `EXTENDED`, aggregate 1, with only the
reviewed deleted-table system backup category nonzero.

One activation blocker remains: this controlled epoch transition used current
PostgreSQL state. It does not prove forward reapplication of v1.2 deletion
receipts/manifests to a PostgreSQL backup taken before that deletion. The legacy
journal cannot provide that proof and must not be silently reused. Live capture
therefore remains disabled. Do not repeat the PITR drill; next either implement
the v1.2 PostgreSQL deletion-replay fence and test a pre-deletion restore, or
record it as an explicit failed activation gate. Astra read-only review confirmed
that suppressing verification for nonempty legacy history would weaken the
baseline; empty legacy history alone is not v1.2 completeness.

### Authorized-deletion restore fence implementation, September 8

Work started on the single remaining activation blocker without repeating any
passing AWS or Render checks. Future deletion transactions now commit the exact
signed permit and execution grant into the immutable DynamoDB deletion-intent
record alongside the already-persisted manifest and executor receipt. The new
`authorized_deletion_recovery` verifier checks all four historical signatures,
their environment and epoch bindings, every permit/manifest/grant/receipt ID and
digest, and the exact reviewed deletion executor before producing a content-free
recovery contract.

Migration `0020_authorized_delete_recovery` adds a quarantined, migration-only
PostgreSQL gate. It refuses active capture, non-quarantined storage, changed
targets, duplicate or conflicting operation IDs, malformed digests, and target
cardinality changes. An accepted recovery records immutable authority/target
metadata, reapplies the deletion cascade, deletes exactly the restored payloads,
writes tombstones, and is idempotent only for the same recovery and authority
evidence digests. Normal Lucy, policy, evidence, deletion, and finality logins
receive no execute or table authority for this path.

Focused Ruff and mypy passed. The complete unit suite passed: 313 tests, with
one pre-existing Starlette deprecation warning. Alembic reports exactly one head,
`0020_authorized_delete_recovery`. Docker Desktop failed before its engine became
available with the known `sailor-ingest.sock` startup error, so no container,
volume, or database was changed and the PostgreSQL integration test is still
not executed. Do not deploy this migration or executor change until that exact
integration test passes. Live capture remains disabled.

Follow-up added recovery-runner boundary and idempotency tests; the complete unit
suite now passes 315 tests. The PostgreSQL 18 grammar parser accepts both SQL
blocks in migration 0020 (22,521 bytes), and Alembic still reports exactly one
head. This is syntax evidence only, not database-execution evidence.

Docker diagnosis found normal ACLs but stale Windows socket/reparse points dated
August 31. The original `Docker/run` directory was preserved as
`Docker/run.stale-20260908-1445`; a second failed-start `Docker/run` directory was
preserved as `Docker/run.failed-20260908-1458`; and the separate stale
`docker-secrets-engine` directory was preserved as
`docker-secrets-engine.stale-20260908-1458`. Empty runtime directories were
recreated, but Docker still did not expose its engine pipe after the bounded
restart and was stopped to prevent further popups. Images, containers, volumes,
settings, project files, and database state were not moved. Do not repeat socket
cleanup; the next Docker step is an application/WSL diagnostic or host reboot.

### Authorized-deletion restore fence database gate, September 8

Docker Desktop was upgraded in place from 4.88.1 to 4.90.0. The engine then
started normally (Engine 29.7.2). This matches Docker's 4.89.0 release note for
the stuck-socket startup fix. Local diagnostic bundle
`lucy-docker-afunix-20260908.zip` remains in the Windows temporary directory and
was not uploaded. No factory reset was performed.

The disposable PostgreSQL 16 role-test cluster exposed and prevented one real
migration defect: migration 0019 had correctly closed schema `CREATE`, so 0020
now grants it temporarily to the dedicated no-login security function owner and
revokes it again after installation. Test setup was also corrected to establish
the explicit operation -> evidence -> restored-payload foreign-key order and to
enter quarantine before replay.

The focused database gate now passes. It proves migration 0020 installs through
the non-superuser migration identity, removes exactly the resurrected payload,
writes one tombstone and one recovery target, replays the same authority
idempotently, denies the recovery function to routine, policy, evidence,
deletion, and finality logins, and leaves the security function owner without
schema `CREATE`. Focused Ruff, `git diff --check`, recovery unit tests, and the
database gate passed together: 22 tests. The two warnings are pre-existing
Starlette and Alembic deprecations.

This completes the previously blocked local PostgreSQL execution gate. Prior
AWS/Render evidence remains valid because deployed commit, configuration, and
environment were not changed. Live Telegram transcript capture remains disabled.
Next: publish the reviewed restore-fence revision, deploy the affected
quarantined components, run one synthetic pre-deletion PostgreSQL restore replay,
then assemble the final v1.2 acceptance report. Do not repeat the already-passed
AWS identity, DynamoDB PITR, KMS denial, CloudTrail, readiness, or exceptional
backup inventory checks unless deployment drift invalidates them.
