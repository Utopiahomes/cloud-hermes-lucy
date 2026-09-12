# Private Telegram Stage 2 implementation checkpoint

Date: 2026-09-11; accepted 2026-09-12. Status: **Stage 2 production acceptance
passed; encrypted private-Telegram evidence capture is active**.

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
| Corrective release static/focused checks | Passed, 89 focused tests plus Ruff and strict mypy | Commit `3f18ed8d52763be61d90843891d963b3c9212dbe` | Relevant source/dependency change |
| Exact corrective gateway and routine Docker builds | Passed | Local Docker, commit `3f18ed8d52763be61d90843891d963b3c9212dbe` | Dockerfile/context/base-image change |
| Corrective Render deployment and private readiness | Passed | Routine deploy `dep-dai9qqlg1s2s738lnce0`; gateway deploy `dep-dai9s88ae00c73dq9a9g`; readiness job `job-dai9s75g1s2s738lshpg` | Render service/environment/deploy change |
| Exact deployed hook, replay, and registration paths | Passed | Synthetic Render jobs on corrective gateway; pre/direct/transform/ambiguous/registration all true | Gateway image/profile/plugin/config change |
| Concurrent archive admission | Passed, 24/24 | Render job `job-dai9t3h5efls73chf1rg` | Routine/gateway/archive/database/network change |
| Single-gateway startup and lease | Passed | Corrective gateway resumed; configuration, profile, Hermes, Lucy plugin, RAM boundary, preflight, lease, and startup events present; old gateway suspended | Gateway service/environment/deploy/lease change |
| Startup archive-boundary validation | Passed | Commit `e6f66d3c2aa1b2b17bedcae1b67a4cd613346067`; 52 focused tests, Ruff, and strict mypy; routine readiness job `job-daia8pu743jc73ebpjp0` | Runtime/archive configuration or source change |
| Corrected production deployment | Passed | Routine deploy `dep-daia8b61egvs739fige0`; gateway deploy `dep-daia8s3l550s73flh4l0`; both live at `e6f66d3c2aa1b2b17bedcae1b67a4cd613346067` | Render environment or deployment change |
| Serving-worker archive boundary | Passed | Existing-gateway authenticated private-network probe `job-daia9u2d0e5s73fu4fog` | Routine/gateway credential, network, or deployment change |
| Exact archive hooks and replay | Passed | Jobs `job-daiaasjl550s73flodj0`, `job-daiaasqd0e5s73fu7g1g`, `job-daiaasqd0e5s73fu7g6g`, `job-daiaasrl550s73floe10`, and `job-daiaat6743jc73ec16kg` | Hook/profile/archive source or configuration change |
| Live owner retained round trip | Passed | 2026-09-12 10:11-10:12 ET; substantive response delivered only after the fail-closed retention path completed | Gateway/routine/archive/database/model bridge change |
| Live durable turn and budget predicates | Passed | Content-free in-Render verifier `job-dailtuoae00c73f2bc80`: terminal delivery, exactly one successful model settlement, enabled receipt, user and assistant archive success/reconciliation, linked turn commit, two encrypted evidence records, and zero scoped/legacy memory writes | Database rows, schema, gateway/routine/archive/model bridge change |
| Recent production log privacy | Passed | One-hour routine/gateway scan at `2026-09-12T14:19:54Z`: no configured secrets or conversation payload fields emitted | Logging or deployment change |
| One production bot consumer | Passed | Active `srv-dai4k467bikc73bhs6r0`; prior gateway `srv-dai3hmu743jc73do9ebg` suspended; both enumerated through Render | Gateway service state or bot-token assignment change |

The `.pytest_cache` directory is not writable in the current workspace; pytest emitted a cache
warning only. Test execution and results were unaffected. A final local Docker rebuild was not
repeated because Docker Desktop's engine was unavailable. The exact source was built and
started by Render, and the serving worker plus deployed hook paths were checked there instead.

## Production finish line — completed

All seven commissioning steps passed. The accepted deployed source is
`e6f66d3c2aa1b2b17bedcae1b67a4cd613346067`, running as routine service
`srv-daca8gafngtc73clva90` and Telegram gateway `srv-dai4k467bikc73bhs6r0`.
The gateway has no static AWS credential, policy, evidence-reader, or deletion authority.
Automatic memory writes and raw-evidence retrieval remain disabled. The active interface is the
existing allowlisted UtopiaLucy private Telegram bot; ordinary owner messages are retained as
encrypted evidence by default, while the documented off-record control disables Lucy archive
capture until the owner returns on record.

## Corrective incident and resolution

Initial live Stage 2 canaries failed closed because the long-lived routine had an invalid
effective `AWS_REGION`, so construction of the realm archive boundary was rejected before the
inbound receipt could be admitted. Earlier job probes exercised short-lived paths and did not
prove the effective configuration of the serving worker. The final correction sets the reviewed
`us-east-1` region and makes a Stage 2 routine construct and type-check its archive boundary
before opening Uvicorn. A deployment with future configuration drift therefore fails readiness
instead of accepting traffic and returning a late archive error.

The live canary, authoritative database predicates, budget settlement, encrypted evidence
counts, log-privacy scan, and single-gateway enumeration all passed after that correction. No
acceptance blocker remains. Rollback may disable capture or return application behavior to the
reviewed Stage 1 release, but it must not undo archive, deletion, revocation, or authority
history already committed under Stage 2.
