# Tiamat Gate 2 — staging cutover checklist

Scope: deploy the M4 anchor writer, move the anchor's write boundary to it, and run one synthetic
execution through signed configuration on Render. **The commissioned ledger stays dispatch-blocked
from start to finish. No real provider is configured or called.** Reconciliation and re-quarantine
through M4, which complete Gate 2, come after this checklist and are not part of it.

Account `429870640638`, region `us-east-1`. Every step records its evidence in
`docs/evidence/tiamat-gate2-staging-cutover-<date>.json`.

## 0. Preconditions

| Item | Value or owner |
| --- | --- |
| Writer artifact | `dist/aws/tiamat-anchor-writer-v1.zip`, built from a clean tree; digest and commit in its `.manifest.json` |
| Staging anchor key | `ENV#staging#LEDGER#6177502f-3a93-429c-b68b-0ed726d1447f` |
| Pinned anchor root | `tiamat-recovery-root.staging.1`, public key SHA-256 `54865ab6738e51177c2880f1fc31baf86afb4f0f4b58bc415c943d0def39d996` |
| Current anchor head | v3, `39a929956738360d7d9f5bcdd77f9c00473a3b57c481af195c0b55f2938bb459`, quarantined |
| Coordinator role | `tiamat-staging-recovery-coordinator` (Render OIDC, one service) |
| Runtime role | `tiamat-staging-executor` (Render OIDC, one service) |
| Staging release root and signed profile, privacy policy and grant | **Control** (needed from step 8) |
| Alarm destination | an operator address Ray chooses for the SNS topic |

Final `WriterRootsJson` (exact bytes; its SHA-256 is
`d641fe3b70eeca4f3973749880e99d7d18d8cccab7bb9b199665ddd38398a948`):

```json
{"ENV#staging#LEDGER#6177502f-3a93-429c-b68b-0ed726d1447f":{"root_key_id":"tiamat-recovery-root.staging.1","root_public_key_b64":"DM9S8adJAaB/qvc4zQWorAFIRKDKqJ8WR4FxgIUuWjo=","root_public_key_sha256":"54865ab6738e51177c2880f1fc31baf86afb4f0f4b58bc415c943d0def39d996"}}
```

## 1. Alarm topic

Create SNS topic `stoin-staging-tiamat-anchor-alarms`, subscribe the chosen address, confirm the
subscription. Its policy must accept `cloudwatch.amazonaws.com` publications from this account.

## 2. Artifact upload

Upload the zip to the versioned executor artifact bucket. Record the S3 object version. The
`WriterArtifactCodeSha256` parameter is the manifest's `artifact_sha256_base64`.

## 3. Deploy `tiamat-anchor-writer-v1` — first with the probe key

Run `deploy/aws/prepare_anchor_writer_probe.py --environment staging --output-directory <dir>`.
Merge its `probe-roots-entry.json` into the final roots JSON above and compute the merged
document's SHA-256 over its exact bytes. Pass both through a CloudFormation parameters file, never
through shell `--parameter-overrides`: the digest covers exact bytes, and shell quoting of JSON is
where they change. Deploy with `aws cloudformation deploy --stack-name
stoin-staging-tiamat-anchor-writer-v1 --template-file deploy/aws/tiamat-anchor-writer-v1.yaml
--capabilities CAPABILITY_NAMED_IAM --parameter-overrides file://<parameters.json>`, the file
setting `ResourceNamespace=stoin`, `EnvironmentName=staging`,
`AnchorTableName=stoin-staging-tiamat-recovery-anchor-v1`,
`CoordinatorRoleName=tiamat-staging-recovery-coordinator`, the artifact bucket, key and object
version, `WriterArtifactCodeSha256` (the manifest's `artifact_sha256_base64`), `WriterRootsJson`,
`WriterRootsSha256` and `AlarmTopicArn`.

Verify:
- the `live` alias points at a version whose `CodeSha256` equals the manifest digest and whose
  description names both digests;
- invoking the alias with a malformed event answers `recovery_anchor_writer_request_invalid`, not
  `recovery_anchor_writer_misconfigured`. A roots JSON and digest that disagree fail closed either
  way, but only this shows the deployed version is the reviewed one;
- `aws cloudtrail get-trail-status` shows logging.

## 4. Update `tiamat-recovery-anchor-v1` — the boundary moves

Update with the revised template and `AnchorWriterRoleName` set to the writer stack's role. This
removes the coordinator's PutItem and adds the table's writer-only resource policy.

Verify:
- `aws dynamodb get-resource-policy --resource-arn <table arn>` returns the deny statement exactly;
- the coordinator's policy grants only `GetItem` and `DescribeTable` on the table.

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

Then the positive test, through the writer only, before the `witness_not_after` the preparer
printed (after it, the writer refuses the witness and the probe must be prepared again):
- invoke the `live` alias with `probe-event.json`: `installed`, and the digest the preparer printed;
- invoke it again: `already_installed`, with no second write.

Then alarms, recorded as observations rather than as the boundary's pass condition, which is the
denied writes above. Step 4's changes to the table policy should raise `AnchorBoundaryChanges`;
step 3's own events largely precede its trail and are not expected to. Whether the denied
attempts raise `ForeignAnchorWrites` depends on denied data events carrying `resources[].ARN` for
every write API, which the synthetic filter test cannot establish: record which did. Confirm what
reached the SNS subscription.

## 6. Remove the probe key

Redeploy the writer stack with the final roots JSON and its digest above. Verify a new version was
published and the `live` alias moved to it. The probe item stays in the table, inert: no ledger
reads its key and nothing can delete it.

## 7. Staging database grants

Apply the release-manager grants from `deploy/postgres/tiamat_roles.sql.example` (grant staging
and projection on `grant_releases` and `spending_partitions`). This step changes grants only; the
gate stays blocked. (Step 8 does write authority rows, through the release manager.)

## 8. Signed configuration (Control)

Control stages and activates, through the release manager, the staging trust inventory and the
signed profile, privacy policy and spending grant for the served profile.

## 9. Render: the served process, synthetic only

A serving process that never holds the recovery credential:

- start command: `uvicorn --factory lucy.shared_execution.served_environment:create_app_from_environment --host 0.0.0.0 --port $PORT --workers 1`;
- environment: every variable `served_environment.py` requires, with
  `TIAMAT_PROVIDER_TRANSPORT=synthetic`, `TIAMAT_EXPECTED_ENVIRONMENT` and `TIAMAT_EXPECTED_LEDGER_ID`
  pinned independently of the trust file, `TIAMAT_RUNTIME_DATABASE_ROLE=tiamat_runtime`, and **no**
  `TIAMAT_RECOVERY_DATABASE_URL`. Its presence refuses startup, and the process also checks the
  runtime URL's `current_user`, so a recovery credential in the runtime slot refuses too;
- the launcher (`deploy/postgres/issue_tiamat_startup_attestation_v1.py`) runs separately, with
  the recovery credential, immediately before the service starts.

**Open, and blocking staging sign-off.** The served process dispatches only under an anchor whose
continuity is `continuity_established` for its own ledger. The commissioned ledger's anchor is
quarantined and must stay so, and no other ledger has an anchor record in the staging table. The
synthetic execution therefore needs a disposable staging ledger identity with its own throwaway
root in `WriterRootsJson` (as the probe key has), taken through quarantined, then
`recovery_pending`, then `continuity_established` by the writer. The offline builders today sign
only quarantined transitions; building the pending and established transitions for that
disposable identity is the remaining local work for this step, and it is the same ceremony Gate 2
then runs for real reconciliation. It also needs, unscheduled today: the disposable identity's
root back in `WriterRootsJson` after step 6 removed the probe's (a further reviewed version), a
committed trust file for it, a separate disposable Postgres ledger, and the launcher's placement
on Render.

With that in place: one synthetic request through the signed configuration returns 200 with the
signed profile release, makes one synthetic provider call, and leaves the settled receipt in the
disposable ledger. The commissioned ledger's gate is not touched.

## Rollback

- Before step 4: delete the writer stack's function and alias; nothing depended on them.
- After step 4: re-deploy the previous `tiamat-recovery-anchor-v1` template. That restores the
  coordinator's PutItem and removes the table policy; the anchor's contents are unchanged, since
  every write so far was either denied or went through the writer on a disposable key.
- The Render service can be suspended at any time; suspension is local containment and needs no
  anchor write.
