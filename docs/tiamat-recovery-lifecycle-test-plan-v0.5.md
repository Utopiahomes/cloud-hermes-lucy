# Tiamat staging recovery lifecycle — test plan v0.5

Author: Claude (Homes side). Reviews: Fable (v0.1, v0.3), Lyra (v0.2, v0.4), Lucy (v0.3).
Status: revised for review. Documentation only. Nothing in this plan has been executed.
Tiamat revision reviewed: `e2e294d` on `codex/management-contract-v1`.
Normative source: `docs/tiamat-control-recovery-witness-v1-draft-0.5.md` (cited as §N).
v0.3 and v0.4 are retained in `docs/` for diffing.

**Changes from v0.4** (Lyra's review):

- **V7 — C1-T(ii) no longer overpromises.** A same-timeline restore can keep an unconsumed
  attestation, and its WAL can later catch up. C1-T(ii) now tests **both** the rejection and the
  negative control, and states that the supported restore procedure — not the database function —
  is what forces quarantine. (Lyra 1; ties to G11 and C6(i))
- **V8 — the attestation has an exact claimant.** At most one unconsumed attestation may exist per
  environment, enforced by a partial unique index, and a new launcher gate supersedes any earlier
  one. C1-T(vi) tests two simultaneous starts. (Lyra 2)
- **V9 — C1 is marked partial against §8.4**, not passing, until the launcher runs automatically on
  the ordinary-restart path or a reviewed contract change is made. New case C1-A. (Lyra 3)
- **V10 — the Render restore claims are hypotheses.** That a point-in-time restore preserves role
  passwords and changes the timeline is recorded as a test hypothesis, to be settled by the
  disposable restore. Render's documentation promises neither. P2 step 4 is written so it stays
  correct whichever way each resolves. (Lyra)
- **V11 — P1(f) refined.** `pg_current_wal_flush_lsn()` is documented as read-only and needs no
  superuser, so `tiamat_runtime` can very likely call it today. The probe now asks whether a revoke
  is *possible*, and V2 stands unless it is. (Lyra)

**Changes from v0.3** (Lucy's review, then Fable's review of v0.3 plus Lucy's comments):

- **V1 — D1 TOCTOU closed.** A single `SECURITY DEFINER` consume function rechecks the live
  database identity when the attestation is consumed. A non-consuming variant rechecks it while
  running. Runtime `UPDATE` on `restore_gate` is revoked. New migration 0007. (Lucy §1; Fable a)
- **V2 — R1 restated honestly.** PostgreSQL may not be able to stop `tiamat_runtime` from calling
  `pg_control_*`. R1 is a design rule — the executor never interprets raw beacon values — unless the
  P1 probe proves a revoke works. (Fable a3)
- **V3 — D2 is not the production model.** A production trust-model decision is required before
  commissioning operational renewal. The one constraint on any future delegation is recorded here;
  it is not designed. (Lucy §2; Fable b)
- **V4 — M4 is kept, with a full writer contract.** (Lucy §3; Fable c)
- **V5 — P2 rotates the runtime credential** before LOGIN is ever restored, on every instance that
  will serve again, including restored ones. The reason is that a physical restore is expected to
  copy roles *with their passwords* — a hypothesis under V10, and the procedure is written to be
  correct either way. (Lucy §4; Fable d)
- **V6 — C1's auto-restart block is a labelled v1 policy, not an invariant.** C1b now quarantines
  instead of only refusing. (Lucy §5; Fable d, e4)

## 0. Ground truth today (verified 2026-09-18)

- DynamoDB `stoin-staging-tiamat-recovery-anchor-v1` holds one record: predecessor-null version 1,
  `quarantined`, transition `ce352339…7f7b`, ledger `6177502f-…447f`, epoch `63d24f64-…b4e6b2`.
- Render Postgres `tiamat-staging-ledger` is at `0006`, restore-gate generation 1, dispatch blocked.
- All three `tiamat-staging-*` services are suspended. The executor and coordinator both run the
  inert `lucy.tiamat_identity_service:app`.
- The coordinator last ran `52c3ff4`; `e2e294d` is not deployed.
- **Commissioned-ledger reconciliation is on hold** until §6 step 6.

## 1. Gaps

"Confirmed" means Lyra has independently confirmed the defect.

| # | Gap | Evidence | Blocks |
|---|---|---|---|
| G1 | **Confirmed.** The executor is the inert stub. Serving code never consults the anchor: `RecoveryAnchorRuntimeGate` is used only in tests, and the executor checks only `restore_gate`. The fence identity comes from a static `RecoveryWitness`; it must be derived from the verified anchor transition. | `recovery_anchor.py:213`; `postgres_ledger.py:40-47,186-195,1499-1514`; `postgres_authority.py:558-570` | C1–C3, C5, C7, C8 |
| G2 | Missing: refresh polling (≤30 s), a local latch, a trusted-clock bound, and an explicit `botocore.config.Config` for the 5 s timeout. | `recovery_anchor_dynamodb.py:187-188` | C3, C5, C7 |
| G3 | **Resolved (R1, restated in V2).** The launcher reads the beacon under `tiamat_recovery`. The executor learns only yes/no, through D1's functions. | provisioning review `:116` | C1, C1b, C6 |
| G4 | **Confirmed.** `authorize_reconciled_state` is still old-style: exactly `+1`, a bare liability count, no `ledger_id` or checkpoint-digest check, and no checkpoint table. `quarantine_environment` doesn't record the anchor transition. | `recovery.py:104-124,143,167-177` | C8, commissioned reconciliation |
| G5 | No launcher. Under R2 it doesn't sign; it installs and strong-rereads pre-signed transitions, reads the beacon, runs DB authorize, writes the attestation (D1), and runs P2. The **offline** boundary needs a successor-transition builder (quarantine, pending, established, renewal). | `recovery_anchor_commissioning.py:153` | C4, C6–C8 |
| G6 | No witness renewal. Validity ≤24 h. | — | C1c, C5 |
| G7 | `e2e294d` not deployed. | Render `dep-damqe9jm8hqs73aesjig` @ `52c3ff4` | any successor write |
| G8 | **Confirmed.** `refresh()` replaces a newer cached transition with an older valid one. | `recovery_anchor.py:231-240` | C4(vi), C7 |
| G9 | **Confirmed.** Successor rules allow `quarantined → continuity_established` without `recovery_pending`. | `recovery_anchor.py:312-345` | C4(x), C8 |
| G10 | No verified way to revoke old-worker DB access. Probed first in P1. `tiamat_runtime`'s `UPDATE` on `restore_gate` is removed by D1. | `tiamat_roles.sql.example:7,11,27` | C7, C8 |
| G11 | LSN staleness detection is not a guarantee: a restored snapshot can catch up. This is a stated v1 boundary. | `recovery_anchor.py:82-90` | C6(i) |
| G12 | **Closed (R2).** | — | — |
| G13 | **Confirmed.** IAM scopes keys but can't require the conditional-write protocol. Closed by M4. | `tiamat-recovery-anchor-v1.yaml:76-84` | commissioned established transition |
| G14 | **New.** Migration 0007 is needed for the attestation table, the D1 functions, and the revoke of runtime `UPDATE ON restore_gate`. It must follow the separate Tiamat lineage and 0006's RLS model. | `0006_render_recovery_rls.py:41-49` | D1, C1, C8 |

### F1 — anchor rollback by overwrite

The coordinator role has unconditional `PutItem`, and readers hold no floor across restarts. Anyone
who can act as the coordinator service can overwrite the record with an older validly signed
transition. That includes anyone with Render deploy or job access to that service.

- **Worst variant:** an old `continuity_established` record is replayed while a restored snapshot
  also rewinds the DB gate, on the same timeline.

| Mitigation | Kind | Protects | Does not protect |
|---|---|---|---|
| M1 — monotonic floor in `refresh()`; latch closes with `recovery_anchor_rollback_observed` | prevention | a running process | a newly started process |
| M2 — anchor version and digest recorded in `restore_gate` at quarantine and authorize; startup rejects a lower anchor | prevention | an **intact ledger and runtime only** (R4) | a restored or rewound DB |
| M3 — DynamoDB Streams alarm on any image that isn't `old + 1` with the correct predecessor | **detection only** | makes a rollback visible | stops nothing; Streams can't see the writing principal |
| M4 — validating sole writer (contract below) | prevention at storage | every reader, including after a restore, and F2 | table-admin writes; table PITR (both listed in the boundary) |

**Gate (R5):** M4 is deployed and proven on staging before any `continuity_established` transition on
the commissioned ledger. Disposable-ledger evidence without M4 proves protocol behaviour only.
Rejected: S3 Object Lock, because one junk write would become permanent.

**M4 writer contract (V4).** The writer is the only principal that may write the anchor. For each
request it:
1. **Strong-reads the current head itself.** It never trusts a head supplied by the caller.
2. **Verifies the candidate independently.**
   - It checks exact-byte signatures, including the `inventory_jws` bytes carried in the request.
   - It verifies them against a **root public key held in its own configuration, keyed per
     `anchor_key`**. The disposable ledger has a different root. Changing that configuration is a
     reviewed change and is listed in the boundary.
   - It applies `valid_at(now)` using its own clock.
   - It applies `validate_anchor_successor` against the head it just read, **including the G9
     continuity-state rules**.
3. **Makes a conditional write against the exact prior version and digest.**
4. **Strong-rereads**, and returns the reread digest.
5. **Makes retry idempotent.** If the head is already byte-identical to the candidate, it returns
   success. Today `install()` would instead fail with `transition_chain_invalid` on a retry after an
   ambiguous response (`recovery_anchor_dynamodb.py:102-103`).

Identity:
- **Remove `dynamodb:PutItem` from the coordinator policy** in CloudFormation. Don't just stop
  using it.
- The Lambda execution role is the only `PutItem` principal. The function's resource policy allows
  `InvokeFunction` only from the coordinator role ARN.
- Turn on CloudTrail data events on the table, with an alarm on any `PutItem` from a principal other
  than the writer. This is detection; it covers the principal that M3 can't see.

Pinning and coupling:
- The writer packages the same `lucy.shared_execution` revision as the executor. Evidence records
  its code digest, because reader/writer verification drift is a new failure class.
- Emergency quarantine now also depends on the writer. It fails closed; that is accepted and stated.

### F2 — raw malformed write denies service

Readers fail closed with `recovery_anchor_record_invalid`. Until M4, recovery is to re-put the latest
signed bytes or restore with PITR.

## 2. Design decisions

### D1 — the startup attestation, with a live identity check (V1, V2)

**Why it's needed.** The executor must not interpret beacon values itself (R1), and Render restarts
a crashed service without the launcher. The v0.3 attestation also had a time-of-check/time-of-use
gap. It proved the database looked right when the launcher checked it, not when the executor
started. Two concrete cases:
- a Render HA failover promotes a standby behind the **same URL** with a new timeline;
- a snapshot taken after the attestation was written restores with an unconsumed attestation in it.

**The design** (migration 0007):

1. **The table.** `tiamat.startup_attestations` holds:
   - `attestation_id uuid`;
   - the anchor transition sha256 and version;
   - `system_identifier`, `timeline_id`, `flushed_lsn`, `checkpoint_digest`;
   - the full composite fence;
   - `expires_at` and `consumed_at`.

   Only the recovery role and the definer functions can insert or update it, and the runtime cannot
   read it directly. RLS follows the 0006 `current_user = 'tiamat_recovery'` model.

   **Exactly one claimant (V8).** A partial unique index allows at most one unconsumed attestation
   per environment: `UNIQUE (environment) WHERE consumed_at IS NULL`. A launcher gate that runs
   again — a retry, or a second concurrent launch — first marks any earlier unconsumed attestation
   superseded in the same transaction, so a digest lookup can never find two rows. Two executors
   starting at once therefore see exactly one winner; the loser finds no attestation and stays
   blocked until a launcher gate runs for it (C1-T(vi)).
2. **The launcher's gate**, under `tiamat_recovery`:
   - read the anchor and the beacon;
   - verify `covers()` and witness validity;
   - insert one attestation;
   - expiry is proposed as `min(witness not_after, 10 min)`.
3. **`tiamat.consume_startup_attestation(anchor_transition_sha256 text) RETURNS bigint`.**
   `SECURITY DEFINER`, owned by `tiamat_recovery`. The executor passes the digest of the anchor
   transition it has just strong-read with its own read-only role. No attestation-ID handoff is
   needed, and the database check is tied to the executor's own anchor read. In one transaction the
   function:
   - selects the one unconsumed, unexpired, unsuperseded attestation carrying that digest
     (`FOR UPDATE`; uniqueness is guaranteed by the partial index above);
   - reads the live `system_identifier`, `timeline_id` and flushed LSN;
   - requires identity and timeline to be equal to the attested values, and the LSN to be at or
     ahead of the attested one;
   - requires the attested anchor version to be at or above the `restore_gate` anchor floor (M2);
   - marks the attestation consumed and acquires the coordinator generation;
   - **returns the new `coordinator_generation`**, which the fence needs, or raises.
4. **`tiamat.verify_attestation_current(coordinator_generation bigint) RETURNS boolean`.** A
   non-consuming recheck. It compares live identity and timeline with the attestation consumed for
   that generation, and returns false once a newer generation exists. It runs at every anchor
   refresh and at the final dispatch gate. This bounds the **running** window (failover after start)
   to the 30 s poll. A consume-time check alone would miss it.
5. **`tiamat.block_dispatch(reason text)`.** A one-way definer function: it can only set
   `dispatch_blocked = true`. This is the §6 latch-to-DB path.
6. **Revoke `UPDATE ON tiamat.restore_gate` from `tiamat_runtime`.** Coordinator acquisition and
   blocking now go only through the functions above. This closes the "compromised runtime clears the
   gate" caveat on M2 and G10.
7. **Hardening for all three functions:**
   - `SET search_path = pg_catalog, pg_temp`, with every reference schema-qualified;
   - `REVOKE EXECUTE … FROM PUBLIC`, then `GRANT EXECUTE … TO tiamat_runtime`;
   - no dynamic SQL.

   The runtime has no `CREATE` on `tiamat`, so objects can't be shadowed.
8. **Ownership mechanics.** `tiamat_recovery` has only `USAGE` on schema `tiamat`
   (`tiamat_roles.sql.example:17`), so the migration creates the functions as the Render owner, then
   runs `ALTER FUNCTION … OWNER TO tiamat_recovery`. In PG16 that may first need
   `GRANT tiamat_recovery TO <owner> WITH SET TRUE`. This is a P1 probe item.

**R1 restated (V2).** `pg_control_*` are likely PUBLIC-executable in PG16, and the Render owner may
not be able to revoke `pg_catalog` function grants. Unless P1 proves such a revoke works, R1 is a
**design rule** (the executor never obtains or interprets raw beacon values), not a
Postgres-enforced restriction. Provisioning review line 116 should be reworded to match. The executor
only ever receives an integer or a boolean.

### D2 — offline pre-signing is a test mechanism, not the production model (V3)

- **For the disposable proof:** every successor transition is pre-signed offline and bound to its
  exact predecessor digest. That covers quarantine, recovery-pending, established, and every
  renewal and beacon refresh. This is a test mechanism.
- **Production trust-model decision required before commissioning operational renewal.**
  - Today it would need one offline ceremony per day, because witnesses last ≤24 h.
  - Each ceremony must produce **both** the renewal and a fresh break-glass quarantine chained to it.
    The break-glass quarantine goes stale after **every** head change, including renewals, and its
    own witness also expires within 24 h (`recovery_anchor_dynamodb.py:83-84`).
- **The spec as written forbids delegation for anchor transitions.** Every transition is
  "root-signed", and the root authorizes the exact use `tiamat-recovery-anchor` (Draft 0.5 §2,
  lines 48-55). The *witness* layer already delegates through a root-signed inventory (§3), and
  signed-release RC1 §5 gives a pattern for exact-use keys (`tiamat-signed-release-format-v1-rc1.md`
  lines 21-22, 149-189). Delegation would need a Draft 0.6 amendment.
- **The one constraint to carry into that decision.** The *verifier* selects the required signer
  by transition class, as a rule, not as policy.
  - A delegated key may sign only transitions that **cannot raise authority**:
    - renewal (same generation and checkpoint, revision + 1);
    - quarantine.
  - These stay root-only: `recovery_pending`, `continuity_established`, epoch change, and changes to
    the inventory reference.
  - A delegated key must be:
    - bound to `(environment, ledger_id, storage_epoch)`;
    - limited by `issuance_not_after`;
    - revocable through the root-signed inventory chain.
  - Renewal would still need Control's witness key, so delegation removes only the root from the
    daily loop.
- **Not designed now.** The tests should show where the model actually hurts first.

## 3. Tiers and the disposable ledger

- **Tier L** — disposable PG16 plus DynamoDB Local. Runs the full matrix and fault injection.
  DynamoDB Local applies AWS request validation but not IAM.
- **Tier S** — real AWS and Render, as bounded jobs under the exact OIDC identities, re-suspended
  after each run.

The disposable staging ledger:
- its own Render Postgres instance (point-in-time restore needs a paid plan);
- its own `ledger_id` and anchor key;
- its own offline root and witness keys;
- the same image revision, roles, table, region and configuration shape;
- tooling that hard-asserts `ledger_id != 6177502f-…` before any write;
- a scoped test identity with an explicit Deny on the commissioned key, for raw-write cases;
- residue deleted by an admin or documented.

## 4. Case matrix

Evidence for each case records:
- the tested revision and environment;
- anchor digests before and after, and the strong-reread digest;
- the restore-gate row and the attestation row;
- beacon values and rejection codes;
- the suspension state;
- whether M4 was present, and the writer's code digest when it was.

| Case | Stimulus | Expected | §8 | Tier | Blocked by |
|---|---|---|---|---|---|
| **C1** Startup + ordinary restart — **PARTIAL against §8.4 (V9)** | Launcher gate, then executor start. Executor crash with Render auto-restart. Start while Control is unreachable. | Serves after a fresh consumed attestation. After the gate: no generation or coordinator reset, and no spending change. A Control outage doesn't block. **An auto-restart without a new launcher run stays blocked. This is a v1 conservative startup policy, and it does NOT satisfy §8.4's requirement that a supported ordinary restart succeeds while continuity is established.** C1 is recorded as partial, never as passing, until C1-A passes or a reviewed contract change is made. Production availability semantics: TBD. | 4 (partial) | L, S | G1, G4, G5, G7, G14 |
| **C1-A** Automatic ordinary restart | The launcher gate runs automatically on the restart path, without human action: the executor crashes, Render restarts it, the gate runs, the executor consumes a fresh attestation. | Serving resumes unattended while continuity holds, with no generation or coordinator reset and no spending change. A beacon or anchor failure on that path still quarantines (C1b). **This is what closes §8.4.** It needs no trust-model change, because attestations are not root-signed. | 4 | L, then S | G5, G14, C1-T(vi) |
| **C1-T** Attestation TOCTOU | (i) Change timeline or identity between attestation and consumption. (ii) Restore a snapshot containing an unconsumed attestation, in two sub-cases: (ii-a) the restored WAL is behind the attested LSN, or identity or timeline changed; (ii-b) **negative control** — a same-timeline, same-identity restore whose WAL has caught up past the attested LSN. (iii) Fail over after consumption while serving. (iv) Consume twice. (v) Consume an expired attestation. (vi) Two executors start at once against one attestation. | (i) Consume raises; the executor never serves. (ii-a) Consume raises. **(ii-b) Consume succeeds — this is the documented boundary (G11), not a defect.** The database function cannot identify every silent restore; what forces quarantine on a restore is the supported procedure (P2 and §7 step 1), and the evidence must say so rather than claiming the function covers it. (iii) `verify_attestation_current` is false at the next refresh or dispatch gate: the latch closes and `block_dispatch` runs. (iv), (v) Rejected. (vi) Exactly one consumes; the loser finds no attestation and stays blocked (V8). | 4, 6 | L all; S (iii) if Render HA is available, otherwise L only | G14 |
| **C1b** Beacon rejection | Launcher gate against: an older LSN; a changed system_identifier; a changed timeline; a checkpoint mismatch. | The launcher writes no attestation **and installs the pre-signed quarantine** (§2: continuity that can't be established after a crash leads to quarantine). If none is available, it records why and stays blocked. | 4 | L all; S via C6 | G5, D2 |
| **C1c** Renewal | Install a pre-signed renewal while serving with spending in flight. | No interruption. Spending and generation are unchanged; the anchor goes up by 1. A renewal that changes the checkpoint, status or inventory is rejected. | 4, 2 | L, S | G6 |
| **C2** AWS unavailable at startup | (i) Bad endpoint. (ii) Role not assumable. (iii) Wrong table. (iv) A key that was never installed. | The executor and the launcher each fail with `recovery_anchor_unavailable`. Nothing is admitted and readiness fails. | 4 | L, S | G1 |
| **C3** Outage while running | Anchor unreachable mid-run, with a short-validity witness. A second process starts mid-outage. | The first process continues until `not_after`, then blocks with zero grace. The second process can't start. Disposable ledger only. | 5, 9 | L, S | G1, G2 |
| **C4** CAS and chain attacks | (i) Concurrent N+1. (ii) Stale predecessor. (iii) Branch. (iv) Conflicting equal version. (v) Raw malformed bytes. (vi) Raw replay of an older valid transition. (vii) Ambiguous write, then retry with the same bytes. (viii) Epoch change without quarantine. (ix) Renewal that changes the checkpoint or status. (x) Skipping `recovery_pending`. (xi) With M4: coordinator raw `PutItem`. | (i) One wins; the loser gets `compare_failed` and stops. (ii)–(iv) Chain rejection codes. (v) `record_invalid`, failing closed. (vi) Without M4: a running process is rejected by M1; a restart on an intact DB is rejected by M2 and by the consume floor check; a restart after a restore is **not prevented**, M3 alarms, and it is recorded as the residual. With M4: refused at the writer. (vii) Resolved by reread; with M4, the byte-identical retry returns success. (viii) `recovery_epoch_change_requires_quarantine`. (ix) `recovery_witness_invalid_renewal`. (x) Rejected (G9). (xi) AccessDenied, and the CloudTrail principal alarm fires. | 2, 10 | L; S without M4; S with M4 | G5, G7, G8, G9, M4 |
| **C5** Expiry and clock | Cross `not_after` while running. Start after expiry. Install a not-yet-valid or expired witness. Renew after expiry. Clock rollback or uncertainty over 1 s. | `recovery_dispatch_not_authorized`: unsent work isn't sent and sent work stays a liability. `recovery_witness_not_current` for the install. A renewal after expiry is prospective only and never covers a budget period that wasn't covered. A clock fault blocks. | 5 | L (clock), S | G1, G2, G6 |
| **C6** Stale restore | (i) Crash recovery from a PGDATA copy of a same-generation, pre-spending snapshot. (ii) Render point-in-time restore to a new instance. (ii-b) Logical restore. (iii) Crash, then restore with no notice. | (i) Blocked only while the restored LSN is behind the signed LSN. A negative control drives WAL past it and shows it passes (G11). (ii) **Hypotheses to be settled by this test, not assumptions (V10):** that a Render point-in-time restore keeps the system_identifier, changes the timeline, and restores roles with their passwords. Render's documentation promises none of these. Record what actually happens for each of the three, and which field produced the mismatch. If a restore turns out to preserve identity *and* timeline, it falls back to the LSN comparison, with the G11 boundary. The credential fence in P2 step 4 runs on the restored instance either way. (ii-b) Expected new system_identifier. Record whether Render's logical backup includes globals (roles). (iii) The launcher quarantines before any attestation, and the floor is not rewound. | 6 | L (i), S (rest) | G5, G11, G14 |
| **C7** Quarantine race | Admitted work; an in-flight request; a worker paused between commit and send. The launcher installs the pre-signed quarantine. | Observed within 35 s + 1 s. The latch closes first, then `block_dispatch`. A DB failure doesn't reopen the latch. Unsent work isn't sent; sent and paused work become liabilities. Isolation follows P2. A reconnecting old worker is fenced by the composite fence **and** by the rotated credential. | 7, 9 | L, S | G1, G2, G5, G10, D2 |
| **C8** Recovery crash and negatives | A crash after each §7 step 1–7. An ambiguous commit at DB authorize and at each anchor install. The DB unblocked while the anchor is pending. Negatives: wrong checkpoint, wrong settlement position, duplicated liabilities, incomplete liabilities. | Always blocked. Resume is by readback, with no blind increment. **DB unblocked + anchor pending → the launcher writes no attestation, so the executor refuses.** Pending to established carries the same witness bytes (`recovery_anchor.py:333-335`). A concurrent quarantine defeats the final CAS. Every negative case is rejected. | 8, 2 | L all, S selected | G1, G4, G5, G9, G10 |

§8 items covered outside the matrix:
- **8.4 is closed by C1-A, not by C1.** C1 alone leaves the ordinary-restart criterion open (V9).
- 8.1 and 8.2: the existing unit tests, plus C4 (viii)–(ix).
- 8.3: an independent RFC 8785 and digest implementation from the Homes side.
- 8.10: configuration and credential evidence.

## 5. Old-worker isolation (V5)

**The real owner-credential boundary is Render dashboard access.** The owner URL was removed from
service environments after bootstrap, but it stays readable in the Render dashboard. That same
access is also F1's threat actor, and the evidence states this.

### P1 — capability probe, first

Run a bounded job with a temporarily re-issued owner credential. It is removed afterwards and
recorded like the bootstrap credential handoff. **No capability is assumed until P1 records it.**
P1 records whether the owner can:
- (a) `ALTER ROLE tiamat_runtime NOLOGIN` and `… PASSWORD`;
- (b) self-grant `tiamat_runtime WITH INHERIT TRUE` (for session termination), or hold
  `pg_signal_backend`;
- (c) `pg_terminate_backend` a probe session running as `tiamat_runtime`;
- (d) see runtime sessions in `pg_stat_activity`;
- (e) run `GRANT tiamat_recovery TO <owner> WITH SET TRUE` and `ALTER FUNCTION … OWNER TO
  tiamat_recovery` (needed by D1);
- (f) `REVOKE EXECUTE` on `pg_control_system()`, `pg_control_checkpoint()` and
  `pg_current_wal_flush_lsn()` from PUBLIC (decides V2). PostgreSQL 16 documents
  `pg_current_wal_flush_lsn()` as read-only and not superuser-restricted, so the expected answer is
  that `tiamat_runtime` can call these today and that a revoke is not available to the managed
  owner. The probe asks whether a revoke is *possible*; V2 stands unless it is.

It also records:
- whether Render offers a database restart or connection reset that drops all sessions;
- whether Render's logical backup includes globals.

### P2 — procedure, in order

Record evidence at every step.

1. Close the local latch (automatic). Install the pre-signed quarantine (§7 step 1).
2. Suspend the old executor service. Verify it is suspended with no running instances.
3. The launcher sets the DB gate with `quarantine_environment`.
4. **Credential fence, on every instance that will ever serve again.** That means the same instance
   for an in-place quarantine, **and any restored instance**, because a physical restore is expected
   to bring back `tiamat_runtime` with its old password (V10: verify in C6(ii); the fence runs
   regardless of the answer).
   - Set `tiamat_runtime` to NOLOGIN.
   - Terminate its sessions using the mechanism P1 proved. Verify zero runtime sessions in
     `pg_stat_activity`.
   - Run `ALTER ROLE tiamat_runtime PASSWORD <new>`.
   - If P1 proves no way to terminate sessions: use the database restart P1 found, or else document
     that in-place recovery is **not supported** and recovery must use a new instance, which still
     gets this credential fence.
5. Revoke provider credentials. In staging there are none; the evidence proves the executor
   environment contains no provider secret.
6. Complete recovery (§7 steps 3–7).
7. Put the new credential **only** into the authorized executor's Render secret. This is a deploy;
   record its deploy ID. The old service must never receive the new URL.
8. Set LOGIN, then run the launcher gate, then the executor consumes its attestation (D1).
9. Only after that may the launcher declare restore-safe (§6). A witness receipt alone never
   satisfies this.

## 6. Sequencing

0. **Decisions and probes.**
   - Run P1.
   - Confirm the D1 shape.
   - Confirm the PITR plan for the second instance.
   - Queue these Draft 0.5 amendments:
     - §2: the beacon reader is the launcher (R1), and R1 is a design rule (V2);
     - §2: verification is reader-side until M4 exists;
     - §2: the boundary list (table PITR, table-admin writes, G11, dashboard access);
     - §6: the one-way latch-to-DB path;
     - §7 steps 6–7: the attestation.
1. **Harden locally:**
   - G1, G2, G4, G5 (launcher without a signer), G6, G8, G9, M1, M2, D1 plus migration 0007 (G14),
     including the single-claimant index (V8) and the automatic launcher-on-restart path (C1-A);
   - the offline successor-transition builder;
   - deploy `e2e294d`.
2. **Tier L:** the full matrix, including C1-T (with its negative control) and C1-A. Evidence JSON
   named by revision. C1 is reported as partial against §8.4 until C1-A passes.
3. **Provision the disposable staging ledger.** Deploy the real executor and launcher with dispatch
   disabled and a synthetic provider, and prove no provider secret is present.
4. **Tier S, disposable ledger:** the full lifecycle without M4. Evidence is labelled "protocol
   behaviour; writer security not proven".
5. **Build and prove M4** to the §1 contract, including removing coordinator `PutItem` from
   CloudFormation, the CloudTrail principal alarm, and the M3 alarm. Re-run C4, including (vii) and
   (xi).
6. **Revisit the commissioned ledger.** Real reconciliation, then `recovery_pending`, then DB
   authorize, then `continuity_established` **through M4**, then C1.
7. Evidence and rollback review. D2's production decision comes before operational renewal on a live
   ledger. Provider activation remains a separate gate.

**Provable today with no new code:** only the executor role's live `PutItem` denial, and C4(v) on
the disposable key.
