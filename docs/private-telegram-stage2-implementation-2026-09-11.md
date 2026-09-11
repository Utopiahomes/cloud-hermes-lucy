# Private Telegram Stage 2 implementation checkpoint

Date: 2026-09-11. Status: **local implementation complete; production capture remains
disabled and uncommissioned**.

## Deliverable and boundary

Stage 2 adds default encrypted evidence retention to the already accepted private Utopia
Telegram gateway. It does not add automatic memory writes, raw-evidence retrieval, governed
deletion, or any policy/evidence/deletion credential to the gateway. Those authorities remain
behind their existing services and later owner-controlled workflows.

The Stage 2 gateway continues to expose one read-only memory tool. Every retained exchange
must complete this path before its substantive assistant response can be delivered:

`accept turn -> encrypt user evidence -> infer/settle budget -> encrypt assistant evidence ->
commit the linked two-message turn -> deliver`

The `off the record` command atomically disables capture and accepts its control turn. The
`back on the record` command first rotates the ephemeral Hermes session, then atomically
enables capture and accepts the new control turn. This prevents an off-record exchange from
remaining in model history and influencing a later retained answer.

## Implemented increments

1. Migration `0054_stage2_scoped_turn_commit` adds immutable authoritative turn commits and
   atomic capture-transition receipts. The realm routine login receives execute-only access to
   the two exact functions; normal application and public roles do not.
2. The companion requires the assistant archive to include the current retained user evidence
   in its bounded provenance set. Delivery fails closed unless PostgreSQL confirms both AWS
   archive reconciliations and the authoritative turn commit.
3. The pinned Hermes overlay serializes each chat, preserves lease/dedup/budget handling,
   removes the fallback post-call writer, and rotates Hermes history before capture resumes.
4. `Dockerfile.hermes-telegram-stage2` remains pinned to Hermes v0.20.5 and the reviewed image
   digest. Its plugin exposes only `lucy_memory_lookup` and the three required lifecycle hooks.
5. A separate Stage 2 activation manifest requires capture encryption, two-message commit,
   history rotation, one gateway, and the continued absence of automatic memory writes, raw
   evidence retrieval, and sensitive gateway tools.
6. The production migration entry point is quarantine-only, targets `0054` explicitly, never
   enables capture, and emits a content-free permission receipt. The older V1.3 migrator now
   targets its explicit reviewed revision instead of moving Alembic `head`.

## Verification ledger

| Check | Result | Evidence / environment | Invalidated by |
|---|---|---|---|
| Focused Stage 2 unit/API/archive tests | Passed, 82 tests | Windows local Python 3.11 | Relevant source/dependency change |
| Complete unit suite | Passed, 734 tests | Windows local Python 3.11 | Shared source/dependency change |
| Ruff and strict mypy | Passed | 82 source files before migration entry point; 83 after it | Relevant source/config change |
| Fresh migration chain | Passed, `0001 -> 0054` | Disposable PostgreSQL on `127.0.0.1:54329` | Migration/role change |
| Execute-only production realm roles | Passed | Disposable PostgreSQL | Migration/role template change |
| Atomic off/on receipt, encrypted replay, two-message commit, bad-lineage rejection | Passed | Disposable PostgreSQL with synthetic ciphertext and KMS backend | Archive/migration change |
| All five V1.3 service identities at Stage 2 revision | Passed | Disposable PostgreSQL | Readiness/role/schema change |
| Same-chat concurrency serialization | Passed | Focused async test | Gateway overlay change |
| Pinned Stage 2 Docker build | Passed | Docker Desktop; local manifest list `42c44f9f...` | Dockerfile/context/base-image change |
| Hermes config and plugin doctor | Passed | Isolated tmpfs container, synthetic credentials, no Telegram/companion connection | Profile/plugin/base-image change |

The `.pytest_cache` directory is not writable in the current workspace; pytest emitted a cache
warning only. Test execution and results were unaffected.

## Production finish line (not yet executed)

1. Commit and push the reviewed Stage 2 implementation while Stage 1 remains live and capture
   remains false.
2. Deploy the bridge-compatible routine service with Stage 1 settings; confirm the current
   Stage 1 acceptance checks remain valid.
3. Quarantine admission, run the exact `0053 -> 0054` migration/grant job, and retain its
   content-free receipt. Do not enable capture.
4. Build the exact production Stage 2 gateway artifact and populate/validate the ignored
   activation manifest with source, rollback, image, profile, realm, and service identities.
5. Commission the routine and gateway Stage 2 settings with exactly one bot consumer. Reopen
   only after readiness succeeds at `0054`.
6. Exercise one synthetic retained turn, retry/restart replay, budget settlement, owner denial,
   off/on-record history rotation, archive recovery, and content/secret-free logs in the cloud.
7. Produce the deployed acceptance report. Live capture is accepted only after that evidence
   passes; rollback may return the application to Stage 1 but must not undo archive, deletion,
   revocation, or authority history.

## Current blocker

None for source implementation. Production commissioning and live encrypted capture have not
been performed in this checkpoint.
