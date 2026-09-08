# Single-tenant Security Baseline v1.2 completion

Status: execution in progress; cloud acceptance is not yet complete.
Live Telegram transcript capture remains disabled. Customer isolation and
multitenancy are outside this completion gate.

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
