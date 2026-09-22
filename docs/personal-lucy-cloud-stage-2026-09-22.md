# Raymond cloud stage: scoped credentials installed

The correction release has been packaged and checked locally. Ray approved credential
installation on the two named suspended Raymond services and the quarantined schema
migration. Both completed on 2026-09-22. No service activation, personal import or Telegram
change was performed.

## Applied stage and fresh verification

The exact `stage-raymond-synthetic-suspended-v1` command completed with status
`staged_suspended`. Independent Render GET requests then confirmed, for both `policy` and
`routine`: exact service ID, byte-for-byte environment equality with the saved stage
artifact, saved rollback snapshot, `suspended`, auto-deploy `no`, and false capture,
product ingress, executor and intake flags. OpenRouter and Telegram credentials are absent.
Secret values were compared in memory and were not printed. The gitignored state and
rollback files are `secrets/generated/raymond-synthetic-stage-v1.json` and
`secrets/generated/raymond-synthetic-stage-rollback-v1.json`.

## Staging boundary

Run the prepared operator tool to install Raymond's own scoped credentials on these existing
Render private services, keeping both suspended and auto-deploy disabled:

| Destination | Resource | Credentials staged |
|---|---|---|
| `raymond-lucy-policy` | `srv-dak5bd5g1s2s7389ml7g` | Raymond policy database login, Raymond policy signing key/trust, new private gateway token |
| `raymond-lucy-routine` | `srv-dak5bc2d0e5s73b2c8vg` | Raymond routine database login and the same private gateway token; no signing key |

Both services belong to `evm-dak5bboae00c73fnvu4g`. Their database is
`dpg-dak5bqad0e5s73b2e3d0-a` / `lucy_raymond`. Fresh GET-only inspection confirmed both
services are suspended with auto-deploy off. The tool rechecks those predicates before writing.

Local preparation succeeded and printed only configuration key names. It reads neither the
personal export nor its pilot authorization. It installs no OpenRouter or Telegram credential.
Capture, product ingress, pilot executor and pilot intake flags are all false. It does not
change service commands, branches, schema or deployment state, or create cloud resources.
This is inert credential staging; it is not a ready-to-serve runtime or completed cloud demo.

The authorized command that was executed:

```powershell
.\.venv\Scripts\python.exe -m deploy.render.stage_raymond_synthetic --apply --authorization stage-raymond-synthetic-suspended-v1
```

The operator saves the exact previous environments to the gitignored
`secrets/generated/raymond-synthetic-stage-rollback-v1.json` before mutation, saves the new
values separately, reads back each write, and verifies that services remain suspended.
On a failed or uncertain write it attempts restoration for every attempted service, including
the failing one. Saved state prevents an automatic second attempt after an ambiguous failure;
inspect remote state and the rollback snapshot before any retry. No credentials enter logs or Git.

## Release and verification

- Local image: `lucy-personal-memory:0073-20260922`.
- Image ID: `sha256:27a97777d68d895de6811055015cf71cfac4b44f8fd8807bdb79c0da2061e782`.
- Network-disabled image smoke test passed: migrations, bootstrap, head verifier and synthetic
  commissioning agree on `0073_memory_candidate_correction`; executor/proxy modules import;
  `/app/secrets` and `/app/.env` are absent.
- Fixed two stale `0072` pins in the head verifier and commissioning tool. Their 34 focused
  unit tests, Ruff and strict mypy pass. The earlier 99 passing checks remain applicable to
  unchanged portions of this increment.
- Three new staging tests pass: local preparation without network/provider/pilot dependencies,
  authorization before cloud access, and restoration of both environments after an uncertain
  second write. Ruff and strict mypy pass for the staging operator.
- Schema/runtime sources in this image are based on `a04eef6` plus the current local increment;
  source is locally committed as `92c75b6fac5dabe795dafc15716637e8440d35a8` on
  `codex/personal-lucy-memory-20260922`. The image is locally built, not deployed. The
  staging tool is a local operator utility, not copied into the service image.

Ray explicitly approved publishing the branch after the initial automatic approval rejection.
`codex/personal-lucy-memory-20260922` is published at verified remote commit
`d126f7064c58acdb644fbf14f4def78353f49996`. The credential stage and rollback files
remain ignored by Git.

## Completed quarantined migration

The local, gitignored operator `secrets/generated/_migrate_raymond_memory_0073.py` pins that
commit and the Raymond database ID. Its read-only preflight passed on 2026-09-22: the two
existing services are still suspended, their environments match the saved stage, no temporary
migration service existed, and the private migration URL targeted `lucy_raymond` as
`lucy_migration`. Ruff, strict mypy and compilation passed.

The first authorized attempt created a temporary Render service, but Windows Application
Control blocked the local Render CLI before deployment. The operator deleted that service;
an independent GET found none and the saved state had no job ID. The retry used the Render
API to deploy the pinned commit. Its migration job and separate read-only six-check head
verifier job both reported `succeeded`. The migration command verifies revision `0073`,
quarantined admission, a safe capture boundary and no residual schema CREATE authority before
exiting successfully. The head verifier runs all six predicates in a read-only transaction.
The saved job state is gitignored at `secrets/generated/raymond-memory-migration-0073-state.json`.
Render's logs API returned 403 for this token, so the evidence is the two terminal job
statuses and the independent post-run GET, not the job's printed JSON receipts. That GET
confirmed no temporary service remains and both policy/routine services are suspended.
The executed invocation was:

```powershell
.\.venv\Scripts\python.exe secrets/generated/_migrate_raymond_memory_0073.py --apply --authorization migrate-raymond-quarantined-memory-0073-v1
```

Next prepare the bounded synthetic cloud execution. Preserve
the additive correction ledger on rollback; suspend services and quarantine admission rather
than downgrading it. Public intake, actual history and Telegram cutover remain later steps.

## Disabled pilot configuration and renewed proposal

On 2026-09-22, a fresh **non-authorizing** pilot proposal was built locally from the same
11 selected conversations. The local ZIP commitment and every selected manifest record match
the prior approved bundle; destination, route and limits are unchanged. It has a new campaign
ID and exact bundle digest `15b2d1f70e50920d4605862d5c6772a8e28b24003681b5101671648813312b24`,
expires 2026-09-29 23:25 UTC, and retains the $2 cumulative spend ceiling and 20-attempt
limit. Files are in Ray's protected `chatgpt/2026-09-22-renewal` intake directory. The
proposal grants **no authority** to upload or process real history. The model route is still
listed by [OpenRouter](https://openrouter.ai/google/gemini-3.1-flash-lite); endpoint policy and
price must be rechecked immediately before any real provider request.

Ray approved use of the existing shared OpenRouter billing key for **synthetic demonstration
only**. A local operator prepared the two exact Raymond service environments from that
proposal, the prior scoped-credential stage and Raymond AWS bindings. The executor startup
configuration parsed successfully with activation simulated locally. Three focused staging
tests, Ruff and strict mypy passed. The disabled config was then applied to the two existing
suspended services using `stage-raymond-disabled-pilot-suspended-v1`. Independent Render GETs
confirmed exact environment equality and that both services remain suspended, with capture,
product ingress, pilot executor and pilot intake all false. A gitignored rollback snapshot and
stage receipt are saved under `secrets/generated/raymond-disabled-pilot-*20260922.json`.
No service command, branch, deployment, provider request, personal-data import or Telegram
route changed.

Next prepare the bounded synthetic cloud runner and its exact rollback, then commission only
the synthetic boundary. Real-history execution requires a fresh exact owner authorization
for the new digest and a separate decision on the provider credential; this shared-key
approval does not cover real history.

## Deployment boundary found during preparation

The two existing Raymond services are still on `codex/r1-tenant-foundation`; a read-only GET
found their latest deploys canceled. Ray approved an exact attempt to deploy commit
`39d285924dd5caa91d85ebea05479cee446ad3b8` while both remained suspended. The
operator saved the prior branch and commands and tried the policy deploy first. Render
returned HTTP 400, `cannot deploy suspended service`, before any new build started. The
operator restored both prior configurations, and an independent GET confirmed both services
remain suspended on their original branch and commands, with no new deployment. The
gitignored receipt is `secrets/generated/raymond-synthetic-deploy-state-v1.json`.

Ray subsequently authorized a bounded synthetic activation. On 2026-09-22, the temporary
Raymond-only Render job verified the quarantined `0073` head, ran the audited empty-realm
recovery, and opened admission with capture disabled. An initial recovery job failed because
the new command was absent from the Docker image's explicit copy list; commit `188f9d1`
added it, and the corrected job succeeded. The existing policy and routine services then
deployed exact commit `188f9d1a00a81f297d991e3ad447c5f8aada3350` and reached Render
`live`. A same-network one-off check of both private `/ready` endpoints succeeded. The two
services were suspended again, the quarantine job succeeded, and the temporary utility was
deleted. Independent Render GETs confirmed both services suspended, capture, product ingress,
pilot executor and pilot intake all `false`, and no temporary utility remaining. The
gitignored job and deploy receipts are `secrets/generated/raymond-synthetic-activation-state-v1.json`
and `secrets/generated/raymond-live-deploy-state-v1.json`.

This is deployed startup/admission evidence, not a cloud import/remember/correct/forget
acceptance. The local synthetic memory flow passed separately; the cloud synthetic import
still needs its purpose-built runner. No Telegram route, real-history import or provider call
was part of this activation. The lifecycle is now `ready` after audited recovery, while
runtime admission is quarantined; the former offline-head verifier's lifecycle predicate is
therefore intentionally stale. A future opening must recheck admission and service state.

## Authorization and blockers

Automatic approval review rejected execution of the historical mixed-purpose commissioning
helper, even in its requested preflight mode, because it can persist secrets and Render service
configuration without explicit destination authorization. It was not executed. Ray then
explicitly approved the two destination services and a narrower operator staged them. The
subsequent independent read-only verification passed.

The saved real-history pilot authorization expired at `2026-09-21T16:09:00Z`. It cannot be reused
for real import. It was inspected only for authorization metadata; no conversation data was read.
Synthetic preparation is independent of that authorization. A real pilot needs a fresh exact
authorization after the cloud demonstration, with the existing $2 budget proposal revalidated.
