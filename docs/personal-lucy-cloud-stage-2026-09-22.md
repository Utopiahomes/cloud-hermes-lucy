# Raymond cloud stage: scoped credentials installed

The correction release has been packaged and checked locally. Ray approved credential
installation on the two named suspended Raymond services. The stage was applied on
2026-09-22. No schema migration, service activation, personal import or Telegram change
was performed.

## Applied stage and fresh verification

The exact `stage-raymond-synthetic-suspended-v1` command completed with status
`staged_suspended`. Independent Render GET requests then confirmed, for both `policy` and
`routine`: exact service ID, byte-for-byte environment equality with the saved stage
artifact, saved rollback snapshot, `suspended`, auto-deploy `no`, and false capture,
product ingress, executor and intake flags. OpenRouter and Telegram credentials are absent.
Secret values were compared in memory and were not printed. The gitignored state and
rollback files are `secrets/generated/raymond-synthetic-stage-v1.json` and
`secrets/generated/raymond-synthetic-stage-rollback-v1.json`.

## Exact next action

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

The branch is **not published**. The existing origin is
`https://github.com/Utopiahomes/cloud-hermes-lucy.git`, and its shared branch resolves to
the exact base commit `a04eef6`. All 16 committed paths are code, tests or documentation;
the credential stage and rollback files are ignored by Git. Automatic approval review still
rejected the push because the remote was not independently verified as a trusted private
organization repository and Ray has not explicitly authorized export of this branch's code
and documentation. Do not try another route to publish without that authorization.

After a specifically authorized branch push, pin the release, advance the quarantined Raymond database through 0073
using the existing migration-only operator, and re-run the content-free head verifier. Preserve
the additive correction ledger on rollback; suspend services and quarantine admission rather
than downgrading it. Prepare the bounded synthetic cloud execution before opening private
runtime admission. Public intake, actual history and Telegram cutover remain later steps.

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
