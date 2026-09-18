# Tiamat staging recovery lifecycle — test plan v0.3

Author: Claude (Homes side). Independent review: Fable (v0.1). Owner review: Lyra (v0.2).
Status: revised for Lyra's line-level review. Nothing in this plan has been executed.
Tiamat revision reviewed: `e2e294d` on `codex/management-contract-v1`.
Normative source: `docs/tiamat-control-recovery-witness-v1-draft-0.5.md` (cited as §N).

**Changes from v0.2** (all from Lyra's review):
- R1 — The beacon is read by the recovery coordinator/launcher, never by `tiamat_runtime`.
  The spec conflict in G3 is resolved in favour of the provisioning review. See §1 G3 and D1.
- R2 — Root custody is fixed for staging: the root seed stays offline, and the launcher installs
  and verifies *pre-signed* transitions but never signs. G12 is closed; its operational
  consequences are recorded in D2.
- R3 — DynamoDB Streams alarms are labelled detection only.
- R4 — The DB anchor floor is labelled as protection for an intact ledger/runtime only.
- R5 — A validating sole-writer boundary is now a prerequisite before any `continuity_established`
  transition on the commissioned ledger. The disposable ledger proves protocol behaviour only.
- R6 — Old-worker isolation is a concrete procedure (§5), preceded by a capability probe of what
  the managed Render owner can actually do. `pg_signal_backend` is no longer assumed.

## 0. Ground truth today (verified 2026-09-18)

- DynamoDB `stoin-staging-tiamat-recovery-anchor-v1` holds one record: predecessor-null, version 1,
  `quarantined`, transition `ce352339…7f7b`, ledger `6177502f-…447f`, epoch `63d24f64-…b4e6b2`.
- Render Postgres `tiamat-staging-ledger` is at migration `0006`, restore-gate generation 1,
  dispatch blocked.
- All three `tiamat-staging-*` services are suspended. The executor and coordinator both run the inert
  `lucy.tiamat_identity_service:app`, not an execution service.
- The coordinator last ran `52c3ff4`. The successor-path fix `e2e294d` is not deployed.
- **Commissioned-ledger reconciliation is on hold** until this plan's step 6 (agreed with Lyra).

## 1. Gaps

"Confirmed" means Lyra has independently confirmed the defect.

| # | Gap | Evidence | Blocks |
|---|---|---|---|
| G1 | **Confirmed.** The deployed executor is the inert stub. Serving code never consults the external anchor: `RecoveryAnchorRuntimeGate` is used only in unit tests, and the executor checks only `restore_gate`. Its fence identity comes from a statically configured `RecoveryWitness`. It must be derived from the verified anchor transition. | `recovery_anchor.py:213`; `postgres_ledger.py:40-47,186-195,1499-1514`; `postgres_authority.py:558-570` | C1–C3, C5, C7, C8 |
| G2 | No refresh polling (≤30 s), local latch, or trusted-clock bound. The boto3 client uses default timeouts and retries, so §6's 5 s timeout and 35 s + 1 s bound need an explicit `botocore.config.Config`. The clock-uncertainty check could use the DynamoDB response `Date` header. | `recovery_anchor_dynamodb.py:187-188` | C3, C5, C7 |
| G3 | **Resolved (R1).** `tiamat_runtime` gets no control or WAL functions (the provisioning review line 116 stands). The launcher reads the beacon under `tiamat_recovery` during the mandatory startup/recovery gate. New work: the **startup attestation** in D1, and a Draft 0.5 §2 amendment, which currently says the executor verifies the beacon. | `tiamat-render-postgres-provisioning-review-v1.md:116` | C1, C1b, C6 |
| G4 | **Confirmed.** `authorize_reconciled_state` requires exactly `+1`, trusts a bare liability count, and checks neither `ledger_id` nor any checkpoint digest. There is no checkpoint table in 0001–0006. `quarantine_environment` records nothing about the anchor transition that caused it. | `recovery.py:104-124,143,167-177` | C8, commissioned reconciliation |
| G5 | No recovery launcher. The only transition builder is `build_quarantined_bootstrap`. Under R2 the launcher needs no signer. It needs: install + strong reread of a pre-signed transition; a beacon read; a DB authorize; the attestation (D1); and the isolation procedure (§5). The **offline** boundary needs a successor-transition builder for quarantine, recovery-pending, established and renewal. | `recovery_anchor_commissioning.py:153` | C4, C6–C8 |
| G6 | No witness renewal (§5). Validity is ≤24 h. Under R2 every renewal is an offline signing event (D2). | — | C1c, C5 |
| G7 | `e2e294d` not deployed. | Render `dep-damqe9jm8hqs73aesjig` @ `52c3ff4` | any successor write |
| G8 | **Confirmed.** `refresh()` replaces a newer cached transition with an older valid one. | `recovery_anchor.py:231-240` | C4(vi), C7 |
| G9 | **Confirmed.** `validate_anchor_successor` allows `quarantined → continuity_established` without `recovery_pending`. | `recovery_anchor.py:312-345` | C4(x), C8 |
| G10 | No verified way to revoke old-worker DB access (§7 step 2). All Tiamat roles are `NOCREATEROLE` and the owner URL was removed after bootstrap. What the managed owner can do is **unverified** and is probed first (§5, P1). Separately, `tiamat_runtime` holds `UPDATE` on `restore_gate`. | `tiamat_roles.sql.example:7,11,27` | C7, C8 |
| G11 | LSN staleness detection is not a guarantee: `covers()` passes once a restored snapshot's WAL catches up to the signed LSN. This is a stated v1 boundary (§2). | `recovery_anchor.py:82-90` | C6(i) |
| G12 | **Closed (R2).** The root seed stays offline and the launcher never signs. | — | — |
| G13 | **Confirmed.** The DynamoDB IAM policy scopes keys but cannot require the conditional-write protocol. Addressed by F1. | `tiamat-recovery-anchor-v1.yaml:76-84` | commissioned established transition |

### F1 — anchor rollback by overwrite

The coordinator role has unconditional `PutItem`, and readers hold no floor across restarts. Anyone
who can act as the coordinator service can overwrite the record with an older validly signed
transition. That includes anyone with Render deploy or job access to that service.

- **Worst variant:** an old `continuity_established` record is replayed while a restored snapshot also
  rewinds the DB gate, on the same timeline.

Mitigations, labelled by what each actually gives:

| Mitigation | Kind | What it protects | What it cannot protect |
|---|---|---|---|
| M1 — monotonic floor inside `refresh()` (fixes G8); latch closes with `recovery_anchor_rollback_observed` | prevention | a **running** process | a newly started process |
| M2 — anchor version and digest recorded in `restore_gate` at quarantine and authorize; startup rejects an anchor below it | prevention | an **intact ledger and runtime** only (R4) | a restored or rewound database, which rewinds the floor with it; a compromised runtime (it holds `UPDATE` on `restore_gate`) |
| M3 — DynamoDB Streams alarm on any image that isn't `old + 1` with the correct predecessor | **detection only (R3)** | makes a rollback visible after the fact | stops nothing; the time to respond is a human loop |
| M4 — **validating sole-writer boundary**: a Lambda (or equivalent) that alone holds `PutItem`, reuses `install()` verification, and gives the coordinator only invoke permission | prevention at storage | every reader, including after a restore, and F2 | writes by table administrators or table PITR (listed in the boundary statement) |

**Gate (R5):** M4 is deployed and proven on staging **before any `continuity_established`
transition on the commissioned ledger**. The disposable ledger may run the protocol without M4, but
its evidence proves protocol behaviour only, never writer security. Evidence records note this
explicitly. Rejected: S3 Object Lock, because a junk write into slot N+1 would become permanent.

### F2 — raw malformed write denies service

Readers fail closed with `recovery_anchor_record_invalid`. Until M4, recovery is to re-put the latest
signed bytes or restore with PITR.

## 2. Design decisions this plan depends on

**D1 — the startup attestation (a consequence of R1).** Every serving start must pass the beacon
check, but the executor may not read the beacon itself. And Render restarts a crashed service on its
own, without involving the launcher. Proposal:
- The launcher, under `tiamat_recovery`, reads the anchor and the beacon and verifies
  `covers()` and witness validity.
- It then writes one row to a new table, writable only by `tiamat_recovery` and readable by
  `tiamat_runtime`. The row holds: anchor transition sha256 and version, the observed beacon, the
  full composite fence, and a single-use `attestation_id`.
- At startup the executor reads the anchor itself (read-only role) and requires an unconsumed
  attestation whose anchor digest equals the anchor it just read. It then consumes the attestation
  atomically while acquiring its coordinator generation.
- A Render auto-restart without a new launcher run therefore finds no fresh attestation and stays
  blocked.

To decide: whether the attestation also expires (proposal: at `min(witness not_after, 10 min)`).
Whether a crashed executor restarting on the same database may reuse a launcher gate run is covered
by C1 (proposal: no — always a fresh attestation).

**D2 — offline signing cadence (a consequence of R2).** Every successor transition must be
pre-signed offline and bound to its exact predecessor digest: quarantine, recovery-pending,
established, every renewal, and every beacon refresh.
- **For the disposable proof:** acceptable. Tests are short and transitions are prepared ahead of
  each step.
- **Recorded for later (not needed for the disposable proof, per Lyra):**
  - Renewal at ≤24 h means at least one offline ceremony per day on a live ledger.
  - An emergency quarantine needs a quarantine transition that has **already been pre-signed against
    the current head**, otherwise quarantining waits for a signing ceremony. Proposal: after each
    install, the offline boundary also prepares a break-glass quarantine successor for the new head,
    and the launcher holds it ready.

## 3. Tiers and the disposable ledger

- **Tier L (local)** — disposable PG16 plus DynamoDB Local. Runs the full matrix and fault
  injection. DynamoDB Local applies AWS request validation but not IAM.
- **Tier S (staging)** — real AWS and Render, run as bounded jobs under the exact OIDC identities and
  re-suspended after each run.

**The disposable staging ledger:**
- Its own Render Postgres instance. Point-in-time restore needs a paid plan.
- Its own ledger_id and its own anchor key in the same table.
- Its own offline root and witness keys, generated in the same offline boundary as the
  commissioned ones.
- The same image revision, roles, table, region and configuration shape as the commissioned ledger.
- Tooling hard-asserts `ledger_id != 6177502f-…` before any write.
- Raw-write cases use a scoped test identity with an explicit Deny on the commissioned key.
- Residue in the table is deleted by an admin or documented.

## 4. Case matrix

Evidence for each case records:
- the tested revision and environment
- the anchor digests before and after, and the strong-reread digest
- the restore-gate row and the attestation row
- the beacon values
- the rejection codes
- the suspension state
- whether M4 was present

| Case | Stimulus | Expected | §8 | Tier | Blocked by |
|---|---|---|---|---|---|
| **C1** Startup + ordinary restart | Launcher gate then executor start; executor crash and Render auto-restart; start while Control is unreachable. | Serves after a fresh attestation. **An auto-restart with no new launcher run stays blocked (D1).** After the launcher re-runs: no generation or coordinator reset and no spending change. A Control outage doesn't block. | 4 | L, S | G1, G4, G5, G7, D1 |
| **C1b** Beacon rejection | Launcher gate against: an older LSN; a changed system_identifier; a changed timeline; a checkpoint mismatch. | The launcher refuses with `recovery_continuity_beacon_mismatch` and writes no attestation, so the executor cannot start. | 4 | L all; S via C6 | G5, D1 |
| **C1c** Renewal | Install a pre-signed renewal while serving with spending in flight. | No interruption. Spending and recovery generation are unchanged; the anchor version goes up by 1. A renewal that changes the checkpoint, status or inventory is rejected. | 4, 2 | L, S | G6 |
| **C2** AWS unavailable at startup | (i) Bad endpoint. (ii) Role not assumable. (iii) Wrong table (AccessDenied). (iv) A key that was never installed. | The executor and the launcher each fail with `recovery_anchor_unavailable`. Nothing is admitted and readiness fails. | 4 | L, S | G1 |
| **C3** Outage while running | The anchor becomes unreachable mid-run, with a short-validity witness. A second process starts during the outage. | The first process continues until `not_after`, then blocks with zero grace. The second process cannot start. Disposable ledger only. | 5, 9 | L, S | G1, G2 |
| **C4** CAS and chain attacks | (i) Two concurrent N+1 installs. (ii) Stale predecessor. (iii) Branch. (iv) Conflicting equal version. (v) Raw malformed bytes. (vi) Raw replay of an older valid transition. (vii) Ambiguous write. (viii) Epoch change without quarantine. (ix) Renewal that changes the checkpoint or status. (x) Skipping `recovery_pending`. | (i) One wins; the loser gets `recovery_anchor_compare_failed` and stops. (ii)–(iv) The chain rejection codes. (v) `record_invalid`, failing closed. (vi) Without M4: a running process is rejected by M1; a restart on an intact DB is rejected by M2; a restart after a restore is **not prevented**, M3 alarms, and this is recorded as the residual. **With M4:** the write is refused at the writer. (vii) Resolved by reread. (viii) `recovery_epoch_change_requires_quarantine`. (ix) `recovery_witness_invalid_renewal`. (x) Rejected (G9). | 2, 10 | L; S without M4; S with M4 | G5, G7, G8, G9, M4 |
| **C5** Expiry and clock | Cross `not_after` while running. Start after expiry. Install a not-yet-valid or expired witness. Renew after expiry. Clock rollback, or clock uncertainty over 1 s. | `recovery_dispatch_not_authorized`: unsent work is not sent, sent work stays a liability. `recovery_witness_not_current` for the install. A renewal after expiry is prospective only and never covers a budget period that wasn't covered. A clock fault blocks. | 5 | L (clock), S | G1, G2, G6 |
| **C6** Stale restore | (i) Crash recovery from a PGDATA copy of a same-generation, pre-spending snapshot. (ii) Render point-in-time restore to a new instance. (ii-b) Logical restore with pg_dump. (iii) Crash, then restore with no notice. | (i) Blocked only while the restored LSN is behind the signed LSN. A negative control drives WAL past it and shows it passes, documenting G11. (ii) Same system_identifier but a new timeline, so mismatch; record the field. (ii-b) New system_identifier, so mismatch. (iii) The launcher quarantines before issuing any attestation, and the floor is not rewound. In (ii) and (iii), old credentials do not exist on the new instance (§5). | 6 | L (i), S (rest) | G5, G11, D1 |
| **C7** Quarantine race | Admitted work; an in-flight request; a worker paused between commit and send. Then the launcher installs a pre-signed quarantine (D2). | Observed within 35 s + 1 s. The latch closes first, then the DB gate. A DB failure does not reopen the latch. Unsent work is not sent; sent and paused work are recorded as liabilities. Isolation follows the §5 procedure. A reconnecting old worker is fenced by the full composite fence. | 7, 9 | L, S | G1, G2, G5, G10, D2 |
| **C8** Recovery crash and negative cases | A crash after each §7 step 1–7. An ambiguous commit at DB authorize and at each anchor install. The DB unblocked while the anchor is still pending. Negatives: wrong checkpoint, wrong settlement position, duplicated liabilities, incomplete liabilities. | Always blocked. Resume is by readback, with no blind increment. **With the DB unblocked and the anchor pending, there is no attestation and the executor refuses.** Pending to established carries the same witness bytes (`recovery_anchor.py:333-335`). A concurrent quarantine defeats the final CAS. Every negative case is rejected. | 8, 2 | L all, S selected | G1, G4, G5, G9, G10 |

**§8 items covered outside the matrix:**
- **8.1 and 8.2:** the existing unit tests, plus C4(viii)–(ix).
- **8.3:** an independent RFC 8785 and digest implementation, supplied from the Homes side.
- **8.10** (Control has no DB writes): configuration and credential evidence.

## 5. Old-worker isolation procedure (R6)

**P1 — capability probe, run first and read-only where possible.** Use a bounded job with a
temporarily re-issued owner credential, removed afterwards and recorded like the bootstrap
credential handoff. It records whether the managed owner can:
- (a) `ALTER ROLE tiamat_runtime NOLOGIN` and change its password;
- (b) grant itself membership in `tiamat_runtime`, or hold `pg_signal_backend`;
- (c) `pg_terminate_backend` a runtime session, tested against a probe session under `tiamat_runtime`;
- (d) observe runtime sessions in `pg_stat_activity`.

It also records whether Render offers a database restart or connection reset that drops all sessions.
**No capability is assumed until P1 records it.**

**P2 — procedure, in order.** Each step's evidence is recorded:
1. Close the local latch (automatic on an observed quarantine), and install the pre-signed quarantine
   transition (§7 step 1).
2. Suspend the old executor service. Verify it is suspended and has no running instances.
3. The launcher sets the DB gate with `quarantine_environment`.
4. **In-place quarantine, same DB instance:** set `tiamat_runtime` to NOLOGIN, then terminate its
   sessions, using whichever mechanism P1 proved. Verify with `pg_stat_activity` that zero runtime
   sessions remain. If P1 proves no termination mechanism, then the database restart P1 found, or
   else a documented block: in-place recovery is **not supported** and recovery must go through a new
   instance.
5. **Restore paths, new instance:** isolation comes from the new instance. Old credentials were never
   created there, and new scoped credentials are issued only after the launcher's attestation.
6. Revoke the provider credentials. In staging there are none: the evidence proves the executor
   environment contains no provider secret.
7. Only then may the launcher declare restore-safe (§6). A witness receipt alone never satisfies this.

## 6. Sequencing

0. **Decisions:** D1 (the attestation shape), then P1, and the capability probe for the
   second-instance PITR plan. Also queue the Draft 0.5 amendments: §2 beacon reader (R1), §2
   reader-side verification until M4, and the boundary list (table PITR, G11).
1. **Harden locally:**
   - G1, G2, G4, G5 (launcher without a signer), G6, G8, G9, M1, M2, D1;
   - the offline successor-transition builder;
   - deploy `e2e294d` (G7).
2. **Tier L:** the full matrix, with evidence JSON named by revision.
3. **Provision the disposable staging ledger** (§3), then deploy the real executor and launcher
   with dispatch disabled and a synthetic provider. The Render environment is proven to hold no
   provider secret.
4. **Tier S, disposable ledger:** the full lifecycle without M4. Evidence is labelled
   "protocol behaviour; writer security not proven".
5. **Build and prove M4 plus the M3 alarm on staging.** Re-run C4 against it.
6. **Revisit the commissioned ledger:** the real reconciliation, `recovery_pending`, DB authorize,
   then `continuity_established` through M4, then C1. This is the gate from R5.
7. Evidence and rollback review. Provider activation remains a separate gate.

**Provable today with no new code:** only the executor role's live `PutItem` denial, and C4(v) on
the disposable key.
