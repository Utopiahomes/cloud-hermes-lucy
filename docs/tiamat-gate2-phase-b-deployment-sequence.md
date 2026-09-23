# Tiamat Gate 2 Phase B — deployment sequence (for review, not approved)

Scope: one synthetic request served through signed configuration on a **disposable** staging
ledger. The commissioned ledger (`tiamat-staging-ledger`, anchor
`ENV#staging#LEDGER#6177502f-…`) is not touched. No real provider. Every mutating command below
previews by default and needs its exact digest or identity confirmed.

Status of the tooling: every command in steps 7–9 was run through its real `main()`, in this
order, on a disposable test ledger with only the AWS transport simulated
(`tests/integration/test_tiamat_gate2_operator_cli.py`, commit `f24cef7`). What has **not** been
exercised anywhere is provisioning a brand-new database end to end (section 2).

## 1. Decisions needed before this can be exact

| # | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | Where the disposable ledger's credentials live on Render | (a) new services — a disposable recovery runner and a served service — with new IAM roles trusting only them, and the writer's invoke permission extended to the new runner's role (the writer template takes one `CoordinatorRoleName` today, so this needs a template change); (b) temporarily re-point the existing coordinator's `TIAMAT_RECOVERY_DATABASE_URL` at the disposable database | (a). (b) puts two ledgers' credentials through one slot; every tool checks the expected ledger ID, but a mistake would still be a live commissioned-ledger command. |
| D2 | Environment name | must be `staging`: the writer's grant is scoped to `ENV#staging#LEDGER#*` | `staging`, with the new database's own ledger ID; the anchor key cannot collide. |
| D3 | How the fresh database reaches the current schema | the existing Render bootstrap job migrates only to `0006`; 0007–0017 and the D1 finalizer have only been applied to the test database, incrementally | Prove the full fresh path locally first (a disposable Postgres 16 container: bootstrap → `alembic upgrade head` → finalizer → initialize → the whole Phase B command sequence), then run the same steps on Render. |
| D4 | Control's release-manager boundary | the role template creates `tiamat_release_manager` as NOLOGIN ("its separately deployed boundary … when that boundary exists"); no Render path exists for Control to stage and activate releases | Needs a decision from Control/Lyra: a release-manager login held only by a Control-operated one-off runner, or another boundary. Blocks section 9. |
| D5 | Runtime grant gap | the template grants the runtime no access to `execution_idempotency_aliases`, which admission writes (`postgres_ledger.py:617`); the test fixture grants it | Fix the template before provisioning; reviewed change. |
| D6 | Release-root pin | `deploy/postgres/tiamat-staging-release-root-pin.json` | From Control's independently approved key ID and fingerprint; never derived from a candidate key. |

## 2. Provision the disposable ledger (Render)

2.1 Create Render Postgres 16 in `management-contract-staging` (Virginia), e.g.
`tiamat-staging-gate2b`, database `tiamat_gate2b`; clear its IP allow list (internal only).
Record its ID and owner name. (Free plan is already used by the test database: paid plan.)

2.2 Bootstrap runner (secrets on the runner only: `TIAMAT_ENVIRONMENT=staging`,
`TIAMAT_BOOTSTRAP_DATABASE_URL`, `TIAMAT_RUNTIME_PASSWORD`, `TIAMAT_RECOVERY_PASSWORD`):

    python deploy/postgres/bootstrap_tiamat_staging_v1.py --confirm-bootstrap bootstrap:staging:tiamat_gate2b

2.3 Migrate to head as the owner (D3; no script today):

    TIAMAT_MIGRATION_DATABASE_URL=<owner url> python -m alembic -c tiamat_alembic.ini upgrade head

2.4 Runtime grant fix (D5), then the D1 finalizer (not yet in the image):

    python deploy/postgres/finalize_tiamat_d1_v1.py --environment staging --expected-ledger-id <id> --confirm-blocked-ledger finalize-d1:staging:<id>

2.5 Initialize, blocked at generation 1 (recovery login):

    python deploy/postgres/initialize_tiamat_ledger_v1.py --environment staging --storage-epoch <uuid4> --recovery-generation 1 --confirm-initialize initialize:staging:<epoch>

2.6 `verify_tiamat_render_capabilities_v1.py` as recovery; `tiamat_reconciliation_ledger_v1.py
readback --environment staging` (expects revision `0017_revocation_generation`, gate blocked at 1,
all history counts 0). Remove the owner URL; suspend the bootstrap runner.

## 3. Anchor identity and writer roots (offline + AWS)

3.1 Offline (Linux host): `generate_tiamat_recovery_identity_v1.py` (root
`tiamat-recovery-root.staging-gate2b.1`, bootstrap witness), then
`prepare_tiamat_recovery_bootstrap_v1.py` with the day-zero checkpoint from 2.5.

3.2 Writer roots: add the new anchor key and root to `WriterRootsJson` as a reviewed file
(`deploy/aws/tiamat-staging-anchor-writer-roots.json` gains one entry; new digest), redeploy the
writer stack by change set, verify with `verify_anchor_writer_version.py`, and check the
commissioned key's answer is unchanged.

3.3 Bootstrap through the writer, from the disposable recovery runner (D1):

    python deploy/aws/install_tiamat_recovery_bootstrap_v1.py --package <bootstrap.json> --expected-root-public-sha256 <root pin> --execute --confirm-empty-bootstrap bootstrap:staging:<id> --writer-function <live alias ARN>

## 4. Checklist steps 7.3–7.8 (disposable recovery runner, plus offline signing)

    python deploy/postgres/tiamat_reconciliation_ledger_v1.py first-inventory --environment staging --expected-ledger-id <id> --expected-storage-epoch <epoch> --expected-recovery-generation 1 --inventory-jws-file <control inventory> --release-root-key-id <id> --release-root-public-key-b64 <key> --release-root-pin deploy/postgres/tiamat-staging-release-root-pin.json   # then --execute --confirm-jws-sha256 <digest>
    python deploy/postgres/tiamat_reconciliation_ledger_v1.py report --environment staging --checkpoint-generation 2        # checkpoint.json
    # offline: prepare_tiamat_reconciliation_step_v1.py pending --head-package <bootstrap.json> --checkpoint checkpoint.json --witness-private-identity … --root-private-identity … --expected-root-public-sha256 <pin> --output pending.json
    python deploy/aws/install_tiamat_reconciliation_step_v1.py --package pending.json --ceremony recovery_pending --expected-root-public-sha256 <pin>   # then --execute --confirm-transition-sha256 … --writer-function <ARN>
    python deploy/postgres/tiamat_reconciliation_ledger_v1.py authorize --environment staging --pending-package pending.json --expected-root-public-sha256 <pin> --source-recovery-generation 1   # then --execute --confirm-target-generation 2 --confirm-checkpoint-sha256 …
    python deploy/postgres/tiamat_reconciliation_ledger_v1.py beacon --environment staging            # beacon.json
    # offline: prepare_tiamat_reconciliation_step_v1.py established --pending-package pending.json --beacon beacon.json --trust-output trust.json --root-private-identity … --expected-root-public-sha256 <pin> --output established.json
    python deploy/aws/install_tiamat_reconciliation_step_v1.py --package established.json --ceremony continuity_established --expected-root-public-sha256 <pin>   # then --execute … --writer-function <ARN>
    python deploy/postgres/tiamat_reconciliation_ledger_v1.py create-partition --environment staging --expected-ledger-id <id> --expected-storage-epoch <epoch> --expected-recovery-generation 2 --caller-id <c> --realm <r> --partition-id <p>   # then --execute --confirm-partition-id <p>

Commit `trust.json` before section 5. Steps 4.2–5 must finish inside the pending witness's
validity (12 h default, 24 h maximum).

## 5. Served process and launcher (Render)

A served service (D1) with `uvicorn --factory
lucy.shared_execution.served_environment:create_app_from_environment --host 0.0.0.0 --port $PORT
--workers 1`, `TIAMAT_PROVIDER_TRANSPORT=synthetic`, `TIAMAT_RECOVERY_GENERATION=2`, the pinned
environment and ledger ID, the runtime URL and role, and no recovery URL. Immediately before it
starts, the recovery runner runs the launcher:

    python deploy/postgres/issue_tiamat_startup_attestation_v1.py --trust-package trust.json --expected-ledger-id <id>

## 6. Section 9 — signed configuration and one synthetic request (blocked on D4)

Control stages and activates the signed profile, privacy policy and spending grant through the
release manager; then one synthetic request, and one restart recorded.

## 7. Image changes needed

The Render image must also copy `finalize_tiamat_d1_v1.py`, `issue_tiamat_startup_attestation_v1.py`,
`prepare/install_tiamat_reconciliation_step_v1.py` (install only; prepare stays offline) and the
committed trust and pin files. `tiamat_reconciliation_ledger_v1.py` is added in `0794e61`.
