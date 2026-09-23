# Tiamat Gate 2 — staging cutover checklist

Scope: deploy the M4 anchor writer, move the anchor's write boundary to it, and then — in a
separate, later phase on a disposable ledger — run one synthetic execution through signed
configuration on Render. **The commissioned ledger stays dispatch-blocked from start to finish,
and neither phase changes its database or its anchor record. No real provider is configured or
called.** Reconciliation and re-quarantine through M4, which complete Gate 2, come after this
checklist and are not part of it.

Account `429870640638`, region `us-east-1`. Every step records its evidence in
`docs/evidence/tiamat-gate2-staging-cutover-<date>.json`.

The two phases are approved separately:

- **Phase A (steps 1–6): the writer and the boundary.** AWS only. No database is touched.
- **Phase B (steps 7–9): the disposable ledger.** Its own approval. Signed-configuration
  activation belongs here, not in Phase A: activation refuses a blocked gate
  (`recovery_gate_blocked`), and the commissioned ledger's gate stays blocked.

## 0. Preconditions

| Item | Value or owner |
| --- | --- |
| Writer artifact | `dist/aws/tiamat-anchor-writer-v1.zip`, built from a clean tree; digest and commit in its `.manifest.json` |
| Final writer roots | `deploy/aws/tiamat-staging-anchor-writer-roots.json`, exact bytes, SHA-256 `d641fe3b70eeca4f3973749880e99d7d18d8cccab7bb9b199665ddd38398a948` |
| Staging anchor key | `ENV#staging#LEDGER#6177502f-3a93-429c-b68b-0ed726d1447f` |
| Pinned anchor root | `tiamat-recovery-root.staging.1`, public key SHA-256 `54865ab6738e51177c2880f1fc31baf86afb4f0f4b58bc415c943d0def39d996` |
| Current anchor head | `transition_version` 2, `39a929956738360d7d9f5bcdd77f9c00473a3b57c481af195c0b55f2938bb459`, quarantined (installed from the "successor v3" package; the package name is not the transition version) |
| Coordinator role | `tiamat-staging-recovery-coordinator` (Render OIDC, one service) |
| Runtime role | `tiamat-staging-executor` (Render OIDC, one service) |
| Alarm destination | an operator address Ray chooses for the SNS topic |
| Staging release root and signed profile, privacy policy and grant | **Control**, needed in Phase B only (step 9) |

# Phase A — the writer and the boundary

## 1. Alarm topic

Create SNS topic `stoin-staging-tiamat-anchor-alarms`, subscribe the chosen address, confirm the
subscription. Its policy must accept `cloudwatch.amazonaws.com` publications from this account.

## 2. Artifact upload

Upload the zip to the versioned executor artifact bucket. Record the S3 object version. The
`WriterArtifactCodeSha256` parameter is the manifest's `artifact_sha256_base64`.

## 3. Deploy `tiamat-anchor-writer-v1`, with two probe keys, and prove it runs

Run `deploy/aws/prepare_anchor_writer_probe.py --environment staging --final-roots-file
deploy/aws/tiamat-staging-anchor-writer-roots.json --final-roots-sha256 <digest above>
--output-directory <dir>`; it refuses roots that are not the reviewed bytes. It writes
`writer-roots-with-probes.json` — the final roots plus two disposable probe keys, each with its own
throwaway root, as exact bytes — and one signed event per probe (`before-boundary`,
`after-boundary`). It prints the merged digest, each probe's expected transition digest and its
`witness_not_after` (12 hours; after it the writer refuses the witness and the probes must be
prepared, and the stack redeployed, again).

Pass the roots and their digest through a CloudFormation parameters file, never through shell
`--parameter-overrides`: the digest covers exact bytes, and shell quoting of JSON is where they
change. Deploy with `aws cloudformation deploy --stack-name stoin-staging-tiamat-anchor-writer-v1
--template-file deploy/aws/tiamat-anchor-writer-v1.yaml --capabilities CAPABILITY_NAMED_IAM
--parameter-overrides file://<parameters.json>`, the file setting `ResourceNamespace=stoin`,
`EnvironmentName=staging`, `AnchorTableName=stoin-staging-tiamat-recovery-anchor-v1`,
`CoordinatorRoleName=tiamat-staging-recovery-coordinator`, the artifact bucket, key and object
version, `WriterArtifactCodeSha256`, `WriterRootsJson` (the content of
`writer-roots-with-probes.json`), `WriterRootsSha256` (the printed digest) and `AlarmTopicArn`.

The writer role trusts `lambda.amazonaws.com` with no condition — Lambda does not supply
`aws:SourceArn` when it assumes an execution role, so a trust condition on it would stop the
function from running. The role is bound to its function instead: its DynamoDB grant requires
`lambda:SourceFunctionArn` to equal the function's unqualified ARN, a key Lambda places in the
credentials it issues to this function, so the grant works only with those credentials. That
another principal's use of the role is refused rests on AWS's documented semantics; this
checklist does not test it.

Verify, all before step 4:

1. **The version's pinned configuration.** `aws lambda get-function-configuration --function-name
   stoin-staging-tiamat-anchor-writer-v1 --qualifier live > live.json`, then
   `deploy/aws/verify_anchor_writer_version.py --function-configuration live.json --manifest
   dist/aws/tiamat-anchor-writer-v1.zip.manifest.json --roots-file <dir>/writer-roots-with-probes.json
   --table stoin-staging-tiamat-recovery-anchor-v1 --namespace stoin --environment staging
   --account-id 429870640638` reports `verified: true`: the alias resolves to a published version
   of the writer function; its code digest is the manifest's and nothing adds code outside it (zip
   package, no layers, no file systems, exactly the writer's three environment variables); its
   roots are byte-for-byte the reviewed file and hash to its pinned digest; its description names
   both digests; it runs as the writer role, whose name is derived, not supplied; the writer
   accepts that configuration, and every root's key matches its pin.
2. **The alias executes, assumes its role and loaded those roots.** Invoke the `live` alias with
   `probe-event-before-boundary.json`: `installed`, with the digest the preparer printed. Invoke it
   again: `already_installed`, with no second write. A valid install is reachable only after the
   roots have loaded and the role's credentials have read and written the table, so it proves what
   a malformed request cannot (the handler validates a request before it loads its roots).
3. **The deployed role.** `aws iam get-role --role-name stoin-staging-tiamat-anchor-writer-v1`
   shows the trust above. `aws iam get-role-policy --role-name
   stoin-staging-tiamat-anchor-writer-v1 --policy-name stoin-staging-anchor-writer-v1` shows the
   `StrongReadAndConditionalWriteOnly` statement exactly as in the template, including its
   `lambda:SourceFunctionArn` condition: the install in 2 shows the binding admits the function,
   only this shows the binding is there. `aws cloudtrail get-trail-status` shows logging.

If 1 or 2 fails, stop: do not run step 4. Rollback before step 4 is deleting this stack.

## 4. Update `tiamat-recovery-anchor-v1` — the boundary moves

Only after step 3 passed. First save the stack's current template and parameters
(`aws cloudformation get-template` and `describe-stacks`) into the evidence: that is the only
template break-glass may restore. Then update with the revised template and `AnchorWriterRoleName`
set to the writer stack's role. This removes the coordinator's PutItem and adds the table's writer-only
resource policy.

Verify:
- `aws dynamodb get-resource-policy --resource-arn <table arn>` returns the deny statement exactly;
- the coordinator's policy grants only `GetItem` and `DescribeTable` on the table.

If this update fails, CloudFormation returns the stack to its pre-step-4 template — the state in
force before this checklist, not a relaxation of a boundary already in place. The table policy
and the coordinator's policy are separate resources, so check both afterwards. If the stack ends
in `UPDATE_ROLLBACK_FAILED`, stop, run `continue-update-rollback`, and re-check
`get-resource-policy` before anything else.

## 5. Prove the boundary with real credentials

IAM simulation cannot evaluate the table's resource policy for these roles, so each principal
attempts real writes. `deploy/aws/probe_anchor_write_boundary.py --table
stoin-staging-tiamat-recovery-anchor-v1 --environment staging` attempts PutItem, UpdateItem,
DeleteItem, BatchWriteItem, TransactWriteItems and a PartiQL insert on a fresh disposable key.
Every one must be denied (`all_denied: true`, exit 0). Run it:

1. as the administrator, from a workstation;
2. as the coordinator, from its Render service (one-off job or shell);
3. as the runtime, from its Render service.

Each run's `caller` field must name the expected role, which also proves each Render service
assumes its intended machine role.

Then the writer, through the new boundary and on the coordinator's own path, before the
`after-boundary` probe's `witness_not_after`. From the coordinator's Render service, run
`deploy/aws/invoke_anchor_writer_probe.py --function-name stoin-staging-tiamat-anchor-writer-v1
--event-file probe-event-after-boundary.json`: `caller` names the coordinator role and the answer
is `installed`, with the printed digest. Run it again: `already_installed`, with no second write.
After step 4, invoking the alias is the coordinator's only way to write the anchor; this exercises
it end to end on a disposable key.

Then alarms, recorded as observations rather than as the boundary's pass condition, which is the
denied writes above. Step 4's changes to the table policy should raise `AnchorBoundaryChanges`;
step 3's own events largely precede its trail and are not expected to. Whether the denied
attempts raise `ForeignAnchorWrites` depends on denied data events carrying `resources[].ARN` for
every write API, which the synthetic filter test cannot establish: record which did. Confirm what
reached the SNS subscription.

## 6. Remove the probe keys

Redeploy the writer stack with `WriterRootsJson` set to the content of
`deploy/aws/tiamat-staging-anchor-writer-roots.json` and `WriterRootsSha256` to its digest above.
Verify:
- a new version was published and the `live` alias moved to it;
- `verify_anchor_writer_version.py` with `--roots-file deploy/aws/tiamat-staging-anchor-writer-roots.json`
  reports `verified: true`, with only the staging anchor key;
- invoking the alias with `probe-event-before-boundary.json` now answers
  `recovery_anchor_writer_key_not_configured`: the roots loaded and the probe's is gone. (A valid
  request for the staging key itself would be a real anchor transition, which this checklist
  never makes.)

The probe items stay in the table, inert: no ledger reads their keys and nothing can delete them.

**Phase A ends here.** The commissioned ledger's anchor record, database and gate are unchanged.

# Phase B — the disposable ledger (not yet approved)

The served process dispatches only under an anchor whose continuity is `continuity_established`
for its own ledger. The commissioned ledger stays quarantined and blocked, so Phase B runs
entirely on a disposable ledger, through the single truthful ceremony of Draft 0.5 section 7 with
the empty-ledger checkpoint projection. The library operations, the offline signer and the
beacon read are exercised end to end on the disposable test database
(`tests/integration/test_tiamat_gate2_reconciliation.py`), including the commissioned ledger's
shape; the `first-inventory` and `authorize` subcommands and the installer script are thin
wrappers over those tested functions and are not themselves run by a test. Phase B still needs its
own deployment approval. No two-ceremony walk, and no placeholder checkpoint, is used.

Tools: `deploy/postgres/tiamat_reconciliation_ledger_v1.py` (recovery login: `report`, `beacon`,
`first-inventory`, `authorize`), `deploy/aws/prepare_tiamat_reconciliation_step_v1.py` (offline:
`pending`, `established`) and `deploy/aws/install_tiamat_reconciliation_step_v1.py` (verify, then
one write through the M4 writer with strong reads before and after). Every mutating command
previews by default and needs its exact digest confirmed.

## 7. The disposable ledger reaches established continuity

1. **Ledger.** A separate disposable Postgres ledger, migrated to head, with roles from
   `deploy/postgres/tiamat_roles.sql.example`; `initialize_environment` at recovery generation 1,
   blocked. The commissioned staging database is not changed.
2. **Anchor bootstrap.** A disposable identity with its own throwaway root, added to
   `WriterRootsJson` as a further reviewed version (verified as in step 6); its version-one
   quarantined bootstrap installed through the writer.
3. **First release inventory, dispatch still blocked.** Control signs the generation-1 RELEASE
   trust inventory. `first-inventory` verifies it against the pinned release root and, in one
   transaction, requires the gate blocked, of this epoch and of the generation `report` read back,
   on this ledger and never reconciled (no retained checkpoint, no claimant ever issued), no prior
   activated inventory (a staged copy of the same bytes is allowed), and an empty financial and
   release history; it activates the inventory and leaves dispatch blocked. One time only.
4. **Checkpoint.** `report --checkpoint-generation 2`: the empty-ledger checkpoint — the installed
   inventory, no release heads, no settlement positions. It refuses a ledger with any history.
5. **Pending.** Offline `pending` signs a reconciled witness for generation 2 under a successor
   witness inventory, and the `recovery_pending` transition; install through the writer.
6. **Authorize (the gate opens, no serving authority yet).** The authorization itself
   strong-reads the anchor (its head must be exactly the pending step) and, in one transaction:
   target generation equal to
   the witness's and above the ledger's; all three checkpoint digests equal the witness's; the
   installed inventory equal to the ledger's single active one; no history; checkpoint bound
   immutably; anchor floor advanced to the pending transition; gate open at generation 2.
   Between this and 7.7 the database gate is open while the anchor is only pending: nothing can
   serve, but release activation would be accepted, so Control activates nothing until 7.7 is
   installed.
7. **Established.** `beacon` reads the continuity beacon for the checkpoint now bound; offline
   `established` signs `continuity_established` with the identical witness bytes and that beacon,
   and writes the launcher's trust file (commit it); install through the writer.

## 8. Render: the served process, synthetic only

A serving process that never holds the recovery credential:

- start command: `uvicorn --factory lucy.shared_execution.served_environment:create_app_from_environment --host 0.0.0.0 --port $PORT --workers 1`;
- environment: every variable `served_environment.py` requires, with
  `TIAMAT_PROVIDER_TRANSPORT=synthetic`, `TIAMAT_EXPECTED_ENVIRONMENT` and `TIAMAT_EXPECTED_LEDGER_ID`
  pinned to the disposable ledger independently of the trust file, `TIAMAT_RECOVERY_GENERATION=2`,
  `TIAMAT_RUNTIME_DATABASE_ROLE=tiamat_runtime`, and **no** `TIAMAT_RECOVERY_DATABASE_URL`. Its
  presence refuses startup, and the process also checks the runtime URL's `current_user`, so a
  recovery credential in the runtime slot refuses too;
- the launcher (`deploy/postgres/issue_tiamat_startup_attestation_v1.py`) runs separately, with
  the disposable ledger's recovery credential and the step 7 trust file, immediately before the
  service starts. Startup consumes its claimant.

The step 7 witness and its inventory are valid for at most 24 hours from the pending signing
(12 by default); steps 7.5 to 9 run inside that window, and the launcher's trust file expires
with them. Renewal, which needs a new witness inventory and so a new trust file, is not part of
this checklist.

## 9. Signed configuration (Control), then one synthetic request

With the gate open and the service started, Control stages and activates, through the release
manager, the signed profile, privacy policy and spending grant for the served profile; Draft 0.5
section 4 allows release activation to advance from the checkpoint. Open: activating the grant
projects it onto a spending partition and grant row that only test helpers create today; that
seeding needs its own reviewed operator step before Phase B. Then one synthetic request
through the signed configuration returns 200 with the signed profile release, makes one synthetic
provider call, and leaves the settled receipt in the disposable ledger.

The launcher compares the anchored witness with the retained checkpoint, not with the ledger's
current heads, so a restart after activation is expected to re-attest within the witness's
validity. That is not yet tested; record one restart as evidence.

## Commissioned ledger (not part of this checklist)

Reconciling the commissioned ledger is the final Gate 2 proof. It uses the same tools with a
generation jump: its anchor head is the v2 continued-quarantine successor at witness generation 2,
so the pending witness must be at least generation 3. That head's witness has expired, which
needs no further quarantine successor: the signer and the writer verify a head at its own signed
issue time (the disposable test reproduces exactly this shape). Nothing touches it until its
actual database state and current external anchor are read back and reviewed. The deployed role
template predates migrations 0007 and 0011, so the recovery login's grants on
`startup_attestations` and `recovery_checkpoints` are confirmed in that readback; `report` and
`first-inventory` fail
closed on a permission error. No anchor reset and no two-ceremony walk.

## Rollback — fail closed

Rollback never widens who can write the anchor.

- **Before step 4:** delete the writer stack. Nothing depended on it; the table, the anchor record
  and the coordinator's existing access are as they were.
- **From step 4 on, containment:** stop the writer —
  `aws lambda put-function-concurrency --function-name stoin-staging-tiamat-anchor-writer-v1
  --reserved-concurrent-executions 0`. The anchor is then writable by no one. That is safe:
  the commissioned ledger is quarantined and dispatch-blocked, and stays so without any anchor
  write. The table's writer-only policy stays in place. Do not delete the writer stack or its
  role while the policy names it. The change is a Lambda configuration change, so
  `AnchorBoundaryChanges` alarms: expected, and recorded. The 0 is drift from the template's 1 and
  stays until an operator deliberately lifts it, by `put-function-concurrency` back to 1 or by a
  writer-stack deploy that changes the function, which re-applies the template's 1. A deploy that
  leaves the function unchanged does not. Verify as in step 6 immediately after lifting it.
- **From step 4 on, a faulty writer version:** redeploy the writer stack with a previously reviewed
  artifact and roots. That deploy changes the function and so lifts containment: at once run step
  6's checks (the pinned configuration and the `key_not_configured` answer) and step 3's item 3,
  and contain again if any fails.
- **Break-glass, not a rollback step:** redeploying the `tiamat-recovery-anchor-v1` template
  saved at step 4 removes the writer-only policy and restores the coordinator's direct `PutItem`. It
  needs its own explicit authorization from Ray and Lyra, recorded with its reason, and is
  followed by re-running step 5 once the boundary is restored.
- **Phase B:** the Render service can be suspended at any time; suspension is local containment
  and needs no anchor write. The disposable ledger and its anchor item are left inert.
