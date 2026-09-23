# Tiamat Gate 2 Phase B — deployment sequence (for review, not approved)

Scope: one synthetic request served through signed configuration on a **disposable** staging
ledger. The commissioned ledger (`tiamat-staging-ledger`, anchor
`ENV#staging#LEDGER#6177502f-…`) is not touched. No real provider. Every mutating command below
previews by default and needs its exact digest or identity confirmed.

Control-side design choices for D1, D4 and D6 are recorded in
`docs/tiamat-gate2-proof2-control-decisions-2026-09-23.md`. That record does not authorize
provisioning, shared-writer deployment, signing or activation. D6 is a prerequisite for the
first-inventory step in section 4, not merely for section 6.

Status of the tooling: every command in steps 7–9 was run through its real `main()`, in this
order, on a disposable test ledger with only the AWS transport simulated
(`tests/integration/test_tiamat_gate2_operator_cli.py`, commit `f24cef7`). A full fresh-database
path through migration 0017 and the empty-ledger ceremony then passed twice on local PostgreSQL 16
with TLS (`docs/evidence/tiamat-gate2-proof1-fresh-ledger-2026-09-23.json`, commit `788f388`).
This does not establish the hosted Render path or real AWS writer behavior for the disposable key.

## 1. Decisions needed before this can be exact

| # | Decision | Resolution or next action | State |
|---|---|---|---|
| D1 | Where the disposable ledger's credentials live on Render | Separate disposable recovery runner and synthetic served service, each pinned to its own ledger and IAM role; never re-point the commissioned coordinator. Shared-writer policy extension requires its own reviewed change set and execution approval. | Control design chosen; provisioning pending. |
| D2 | Environment name | Use `staging` with the disposable database's own ledger ID and a noncolliding anchor key, within the writer's `ENV#staging#LEDGER#*` scope. | Chosen. |
| D3 | Fresh schema path | Reuse the Proof 1 sequence: bootstrap to `0006`, owner migration to `0017`, finalizer, initialize blocked, capability check, then empty-ledger ceremony. | Passed locally twice; Render execution pending. |
| D4 | Control's release-manager boundary | Activate the narrowly granted login only on the disposable ledger and use a separate Control-operated one-off runner with exact signed artifacts, current verification and readback. No recovery or signing credentials in that runner. | Runner and owner login step implemented and tested locally (`src/lucy/shared_execution/release_runner.py`, `deploy/postgres/tiamat_release_runner_v1.py`, `deploy/postgres/enable_tiamat_release_manager_login_v1.py`); review pending. |
| D5 | Runtime grant gap | Grant the runtime only the access admission needs on `execution_idempotency_aliases` (`postgres_ledger.py:617`), then review and test it before provisioning. | Implemented: the role template grants the runtime `SELECT, INSERT` only; proven on a fresh bootstrap. Review pending. |
| D6 | Release-root pin | `deploy/postgres/tiamat-staging-release-root-pin.json` | Offline RELEASE-root candidate, Control approval of its exact key ID and raw-public-key fingerprint, then a committed pin. No approved pin exists yet; blocks first-inventory. |

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

## 6. Section 9 — signed configuration and one synthetic request

6.1 Owner boundary, disposable ledger only (D4): give the release manager a login, verified
over TLS; its password goes only to the release runner's secret.

    TIAMAT_MIGRATION_DATABASE_URL=<owner url> TIAMAT_RELEASE_MANAGER_PASSWORD=<secret> python deploy/postgres/enable_tiamat_release_manager_login_v1.py --expected-ledger-id <id> --confirm-disposable-login release-manager-login:<database>:<id>

6.2 Control's one-off release runner (`TIAMAT_RELEASE_MANAGER_DATABASE_URL` only), after checklist step 7.7 has
installed `continuity_established`: stage then activate, in this order, the privacy policy, the
execution profile, then the spending grant. Each command previews first; `--execute` needs the
release's exact digest. Before activation the runner re-reads the active inventory, verifies it
against the approved RELEASE-root pin (D6) and the release under it now, requires the exact staged
bytes, succession, an open gate and, for the grant, active policy and profile heads, then reads
the head back.

    python deploy/postgres/tiamat_release_runner_v1.py stage|activate --environment staging --expected-ledger-id <id> --issuer <issuer> --caller-id <c> --realm <r> --release-root-pin deploy/postgres/tiamat-staging-release-root-pin.json --release-root-key-id <id> --release-root-public-key-b64 <key> --release-jws-file <file>   # then --execute --confirm-jws-sha256 <digest>

A grant's release ID must be unique across every environment of the database (`grant_releases`
is keyed by release ID alone), and a grant stages only once its partition exists (checklist step 7.8).

6.3 One synthetic request through the signed configuration; one restart and re-attestation
recorded. The runner's credential is then removed and the runner suspended.

## 7. Image changes needed

The Render image must also copy `finalize_tiamat_d1_v1.py`, `issue_tiamat_startup_attestation_v1.py`,
`prepare/install_tiamat_reconciliation_step_v1.py` (install only; prepare stays offline) and the
committed trust and pin files. `tiamat_reconciliation_ledger_v1.py` is added in `0794e61`; the
release runner and the owner's login step are added with D4.
