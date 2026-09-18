# Tiamat Control Recovery Witness v1 — Draft 0.5

Status: review candidate; documentation only. Implementation and deployment proof remain pending.
Replaces Draft 0.4. Drafts 0.2–0.4 remain historical review material.

## 1. Purpose and relationship to existing contracts

Control issues signed, content-free recovery checkpoints. Tiamat verifies them before using its
locally authoritative ledger. A signature establishes issuer authority, not database freshness.
No witness independently authorizes inference, grants spending, or activates a release.

This companion implements the external recovery requirement in
`tiamat-signed-release-format-v1-rc1.md` §7 and formalizes the deployment witness and nine-step
procedure in `tiamat-execution-ledger-recovery-rc1.md`. Section 7 below expands that procedure;
it does not create an alternative route around its accounting reconciliation. Existing local
tests prove the earlier database mechanism only, not this companion's external storage or lifecycle.

The established `policy_notary_v13` purpose is defined in `src/lucy/contracts/security_v1_3.py`;
Management Contract RC3 §6.2 reserves the broader policy-notary purpose. Recovery uses a separately
authorized key use and inventory, as specified below.

Two coordinated document amendments are required before this draft can freeze:

1. Signed-release RC1 §7 currently requires online startup confirmation of current accounting with
   Control. Replace that requirement with checkpoint verification plus deployment continuity for
   ordinary restart; retain full accounting reconciliation for recovery. Its cold-start wording
   must distinguish a quarantined recovery attempt from an ordinary reconciled restart.
2. The ledger recovery checkpoint must reference this companion, its external anchor and composite
   fence, and replace the old exact `current + 1` authorization interface with section 7's rule.

The frozen RC1 text and bundle are unchanged by this candidate. The amendments require review and
versioned artifact updates together; implementations must not claim simultaneous conformance to
contradictory startup rules. Shared Model Execution wire contracts remain unchanged.

## 2. External anchor and supported deployment

One independently recoverable ledger has one deployment-provisioned `(environment, ledger_id)`.
That identity comes from the launcher configuration, never from whichever database is attached.
Multiple ledgers in one environment use separate anchor records and identities.

The supported deployment MUST provide a durable, strongly consistent external anchor store on
infrastructure separate from both PostgreSQL and its host/VM snapshot boundary. It cannot be a
PostgreSQL table, an executor image, an executor-local disk cache, or a file restored with the
database host. The host adapter/product for that store is a deployment selection still to be proved.
Its required behavior is concrete: atomic compare-and-swap, read-after-write consistency, durable
acknowledgment, separate access controls, and no rollback through database recovery operations.

Each anchor record is an exact root-signed compact-JWS **anchor transition**, not mutable transport
metadata. It contains deployment identity, storage epoch, monotonically increasing transition version,
SHA-256 of the exact predecessor transition, the exact witness SHA-256 and tuple, witness-inventory
floor, continuity state, and optional continuity beacon. The signed envelope binds every one of those
members. The anchor service verifies it before compare-and-swap; TLS and workload credentials only
authenticate transport and cannot change a floor or mark an attachment established.

The root authorizes the exact use `tiamat-recovery-anchor`. Control may publish witness candidates,
but only the recovery launcher may submit an anchor transition signed for that use. The anchor service
accepts only the unique next transition version whose predecessor hash equals its durable current
record. It rejects unsigned writes, lower/branching transitions and conflicting equal versions.
Serving executors receive read-only anchor credentials. Neither they nor the restored database can
lower a floor, switch epoch, or clear continuity/quarantine. Recovery credentials are separately held;
Control has no direct Tiamat database write access.

Epochs are UUID identities with explicitly authorized successors; UUID lexical or numeric order is
never succession. Replacing an epoch creates a higher anchor transition in `quarantined` state and
requires recovery under the new identity. A backup from a retired epoch may be evidence/source for
that recovery, but can never resume as the retired epoch. An older validly signed anchor export cannot
replace the current authoritative record. Restoring the anchor store itself requires independent
recovery of its latest signed chain; uncertainty blocks service.

Every serving start MUST read this external anchor. A management outage may permit restart when
this separate anchor store remains reachable and valid; loss of both does not. A running process
may retain verified bytes in memory for the bounded authority interval, but that memory cannot
bootstrap another process. No per-inference Control network call or second live spending ledger is
required.

An ordinary restart means the same authoritative database attachment with a signed continuity beacon.
The beacon contains PostgreSQL `system_identifier`, timeline ID, a durable flushed-WAL LSN, and the
immutable checkpoint digest. The launcher periodically reads those values from the attached database,
then submits a signed next anchor transition. On restart, the database must report the same system ID,
same timeline, the checkpoint digest, and a flushed LSN at or ahead of the signed beacon. A stale
snapshot therefore fails continuity even when its local restore gate is self-consistent.

Executor crashes alone do not invalidate continuity. A restore, clone, rollback, endpoint replacement,
or potentially data-losing failover MUST pass through a deployment launcher which first invalidates
continuity in the external anchor before granting serving access. Stable hostnames and database-local
UUIDs are not proof. A supported database service must supply a deployment-verifiable attachment or
failover history; otherwise the launcher treats the event as recovery. If continuity cannot be
established after a crash, it quarantines.

The operational controls must prevent recovery paths from bypassing this launcher. A silent snapshot
substitution by an actor bypassing all deployment controls is not independently detectable from a
matching checkpoint. This is an explicit v1 boundary, not a claim that signed checkpoints detect
arbitrary storage rollback. The deployment is ineligible until its actual restore/failover paths
enforce and test the gate, including crash-then-restore without prior notification.

## 3. Signing and strict witness format

Use compact Ed25519 JWS with protected header exactly
`{"alg":"EdDSA","kid":"...","typ":"stoin-tiamat-recovery-witness+jws"}`.
The key has purpose `policy_notary_v13` and exact use `tiamat-recovery-witness`, scoped to the
environment and ledger. A release-signing key is not implicitly a witness key.

A distinct root-signed recovery-witness trust inventory has type
`stoin-tiamat-recovery-witness-trust-inventory+jws`. It follows the signed-release inventory's
generation, predecessor-digest, key-scope and revocation rules, with this distinct type/use.
Its root and monotonic inventory floor live outside the database boundary. Rotation may overlap
authorized keys. A routine witness renewal may use a successor inventory under the same checkpoint
when the root-signed inventory chain is valid; it increments witness revision and anchor transition
version without stopping work. Revocation rejects new acceptance and blocks continued use of affected
witnesses unless the root-authorized revocation explicitly permits bounded continuation. Root
replacement is a deployment recovery action. Release trust inventory and witness trust inventory are
distinct.

Verify and retain exact received compact bytes. Do not reserialize before signature verification.
Apply the existing 131,072-byte limit, strict unpadded base64url, duplicate-member rejection, and
rejection of unknown protected members, payload members and format versions. Illustrative values
below stand for values satisfying the types; the example is not a signed fixture.

```json
{
  "format_version": "1",
  "witness_id": "11111111-1111-4111-8111-111111111111",
  "issuer": "stoin:control",
  "environment": "staging",
  "ledger_id": "22222222-2222-4222-8222-222222222222",
  "storage_epoch": "33333333-3333-4333-8333-333333333333",
  "recovery_generation": 8,
  "witness_revision": 1,
  "status": "reconciled",
  "issued_at": "2026-09-18T12:00:00Z",
  "not_before": "2026-09-18T12:00:00Z",
  "not_after": "2026-09-19T00:00:00Z",
  "inventory_generation": 12,
  "inventory_jws_sha256": "<64 lowercase hex characters>",
  "release_heads_sha256": "<64 lowercase hex characters>",
  "checkpoint_settlement_position_sha256": "<64 lowercase hex characters>",
  "checkpoint_digest": "<64 lowercase hex characters>"
}
```

UUIDs are lowercase canonical UUID v4. Digests are exactly 64 lowercase hexadecimal characters.
Identity strings obey their existing signed-release contract bounds and must equal the deployment
binding. Generations/revisions are integers in `1..9007199254740991`; monetary values and counts
are integers in `0..9007199254740991`. Booleans, floats, overflow, and rounded large integers reject.
Timestamps are whole-second UTC `YYYY-MM-DDTHH:mm:ssZ`, without leap seconds. Require
`issued_at <= not_before < not_after` and validity no longer than 24 hours.

There is zero acceptance grace at expiry or before `not_before`: require
`not_before <= trusted_now < not_after`. Deployment clock uncertainty must be at most one second;
use the conservative end of its uncertainty interval for expiry and the opposite end for not-before.
Loss of that clock bound or detected backward movement blocks admission/dispatch until resolved.
Clock monitoring must not turn a backward wall-clock jump into extended offline authority.

## 4. Checkpoint representation and digest rules

The checkpoint attests reconciled state at one instant. Later normal spending, settlement and
valid release activation may advance from it. Persist its immutable object/anchor separately from
live accounting inside the ledger; recomputing its digest at restart uses that retained checkpoint,
not today's changing balances. External continuity is what makes this safe against supported restore.

The exact combined object is:

```json
{
  "environment": "staging",
  "ledger_id": "22222222-2222-4222-8222-222222222222",
  "storage_epoch": "33333333-3333-4333-8333-333333333333",
  "recovery_generation": 8,
  "release_inventory": {"generation": 12, "jws_sha256": "<64 lowercase hex characters>"},
  "release_heads": [
    {"issuer":"...","caller_id":"...","realm":"...","release_type":"...",
     "subject_id":"...","active_jws_sha256":"<64 lowercase hex characters>","head_state":"active"}
  ],
  "settlement_position": [
    {"partition_id":"...","budget_period_id":"...","settled_microusd":0,
     "reserved_microusd":0,"pending_reconciliation_count":0,
     "forfeited_microusd":0,"contingency_used_microusd":0,
     "external_liability_marker":"none"}
  ]
}
```

These are closed objects with exactly the displayed members. Release-head identity/state values
retain the signed-release contract's allowed values; no ad hoc state strings are introduced.
`release_inventory` is the active RELEASE trust inventory at the checkpoint. The witness's
top-level `inventory_generation`/`inventory_jws_sha256` identify the RECOVERY-WITNESS trust inventory
used to verify the witness and do not imply those two inventories share a generation or digest.

Reject duplicate release-head keys `(issuer, caller_id, realm, release_type, subject_id)` and duplicate
settlement keys `(partition_id, budget_period_id)`. Sort arrays ascending by these tuples, comparing
each decoded string by Unicode scalar value, without locale folding or normalization. Reject invalid
Unicode. Hash the resulting exact structures using RFC 8785 UTF-8 bytes and SHA-256:

- `release_heads_sha256`: the sorted `release_heads` array alone.
- `checkpoint_settlement_position_sha256`: the sorted `settlement_position` array alone.
- `checkpoint_digest`: the entire combined object, including both arrays and release inventory.

Unknown members and missing members reject before hashing. Empty arrays hash as `[]`, not null.
Recompute all three digests independently. Compare the object's environment, ledger, epoch and
generation to the witness and external deployment identity; mismatches reject even if a supplied
digest matches some different object. Renewal revision and witness validity are deliberately absent
from the checkpoint so renewal does not require spending reconciliation.

`external_liability_marker` is exactly `none` or `represented_pending`. `none` means no unresolved
external liability remains after reviewed reconciliation; it does not mean a query found no rows.
`represented_pending` means all unresolved external liabilities have been imported exactly once
into ledger pending obligations with conservative reservations, and requires a positive pending
count. Pending count may also include existing obligations, so a positive count does not alone imply
external origin. Unidentified or unbounded liabilities block reconciliation; there is no marker
which authorizes ignoring them. Evidence comes from content-free provider execution/billing
references, retained operational receipts and financial records outside the restored snapshot.
An incomplete export cannot prove zero liabilities. A reviewer must establish the affected interval
and coverage; uncertainty retains liabilities or blocks recovery. These totals do not replace the
obligation-level deduplication and budget/exposure checks required by Shared Execution RC1.

## 5. Ordering, renewal and expiry

Within the authorized epoch, order witnesses lexicographically by
`(recovery_generation, witness_revision)`. Reject lower tuples; accept an equal tuple only when
the exact compact JWS bytes match the accepted bytes. Persist the new floor before acknowledging
acceptance. A conflicting equal tuple blocks service and requires resolution.

A change of checkpoint or quarantine/reconciled status uses a strictly higher recovery generation
and revision 1. Generations need not be consecutive: a stale backup can lag several external
transitions. Within one generation only routine renewal is permitted. It increases revision and
may change only revision, witness ID, issuance/validity times and signature bytes. All other payload
fields except the witness-inventory reference, which may advance only through a valid root-signed
successor inventory chain. Renewal cannot clear quarantine. Quarantine witnesses cannot be routinely
renewed into authority.

Renewal is an atomic external anchor update and changes no database spending or recovery generation.
It requires an unchanged current reconciled anchor and established attachment continuity. Begin
renewal before expiry. Expiry blocks serving, but a later verified renewal may resume it prospectively
if continuity remained established; it never authorizes activity during the gap. No disaster
reconciliation is needed merely because time elapsed. Missing continuity requires section 7.

At runtime check locally verified witness validity and known quarantine at both admission and the
final dispatch gate. Expiry blocks new dispatch, including admitted work which has not been sent.
Already-sent work remains a liability and may settle under its existing execution/accounting rules;
expiry does not reset reservations or create permission for another provider call. Bound offline
operation by the earliest of witness expiry, applicable signed authority and budget-period coverage.

## 6. Retrieval and quarantine delivery

Fetch the current exact signed anchor transition, witness and inventory from the deployment anchor at startup. While serving,
attempt refresh at least every 30 seconds with a five-second timeout. When reachable, a published
quarantine is observed within 35 seconds plus a scheduling delay bounded to one second by the
deployment; inability to meet that scheduling bound stops dispatch. During disconnection the
previously described expiry/authority bounds apply, not a promise of immediate unseen revocation.

Use TLS and a dedicated Ed25519 workload identity with audience
`stoin:tiamat-recovery-anchor`, exact scope `tiamat.recovery.anchor.read`, environment/ledger
binding, maximum 300-second lifetime and request binding under the existing signed-release
workload-authentication rules. Such credentials authorize retrieval only. Signature and monotonic
anchor verification remain mandatory.

V1 uses polling; there is no push-notification endpoint or implied push authentication contract.
A planned recovery launcher stops/isolates workers independently of polling before replacing storage.
It must not wait for an offline executor to discover quarantine on its own.

On learning quarantine, first close the local admission/dispatch latch, then use the recovery gate
to block the database and invalidate its coordinator. Failure to write the database does not reopen
the local latch. A witness-receipt acknowledgment is not a recovery-safe acknowledgment. Only the
launcher may declare recovery safe after all workers' provider egress and old database access are
stopped or isolated. This also covers a worker paused after its final check but before network send.

## 7. Recovery sequence and implementation changes

1. Read the latest external anchor. Atomically install the next root-signed `quarantined` anchor
   transition and higher-generation quarantined witness before attaching a restore. After an
   unplanned crash, lack of proof of prior invalidation requires this action now; an unreachable
   anchor means no serving credentials.
2. Stop or externally isolate every old worker's provider egress and database access, including
   disconnected workers. Revoke old attachment credentials and terminate existing sessions; changing
   a password alone does not terminate them. Apply the database quarantine gate when reachable.
   Record already-sent and uncertain sends as liabilities. Do not infer cancellation from shutdown.
3. Attach the candidate database to an isolated recovery endpoint with recovery-only credentials.
   Keep dispatch blocked. The replacement is not accessible to old worker identities.
4. Reconcile the entire affected interval against independent evidence. Import/deduplicate all
   possible liabilities and check reservations, spending, forfeitures, contingency and exposure
   limits. Verify current release inventory and complete release-head set against signed authority.
5. Build a candidate checkpoint from the locked, reconciled ledger for a new generation greater than
   the external quarantine generation. Control reviews its content-free evidence and signs a
   reconciled witness. The launcher installs a root-signed next anchor transition as recovery-pending;
   that continuity state still forbids serving. Retain the stopped-workers condition throughout.
6. Extend `authorize_reconciled_state` to accept the verified checkpoint object and all three digests,
   expected release inventory/heads, external target generation, ledger/epoch identity and observed
   database source generation. In one locked transaction verify every value against actual reconciled
   data, bind the immutable checkpoint, restamp authority and advance the database fence. Require the
   target to equal the externally authorized generation and exceed the source; remove the old
   `source + 1` restriction. Bare liability count alone is insufficient. An ambiguous commit requires
   authoritative readback; it never authorizes serving on assumption.
7. Verify committed checkpoint, external current witness and attachment binding together. Read the
   PostgreSQL identity/timeline/flushed-WAL beacon and install the next root-signed transition from
   recovery-pending to continuity-established. Only then may the launcher provision new scoped
   serving credentials and allow one coordinator to acquire authority. A crash between steps leaves
   service blocked; restart resumes by readback, without another accounting reset or blind generation
   increment. Concurrent newer quarantine defeats the compare-and-swap and keeps service blocked.
8. Run stale-owner, duplicate, expired-lease and no-second-dispatch probes before reconnecting callers.

The eight steps combine the earlier nine-step procedure's accounting and startup probes; none is
optional because a signed witness exists. Initial empty-ledger provisioning uses the same blocked
bootstrap and independently establishes absence of prior obligations for that deployment identity.

Worker fences are the full identity
`(environment, ledger_id, storage_epoch, recovery_generation, coordinator_generation)` plus existing
record/lease ownership. Compare for equality on every authoritative admission, dispatch, settlement
and release-activation transaction. Never compare only a coordinator integer which a restore can
rewind. Epochs are compared for equality, not order. Database fencing complements external worker
isolation; it cannot revoke a network request already sent or stop an isolated old copy by itself.

Current code does not yet implement the full contract. Required work includes exact-JWS anchor and
witness verification, an external anchor adapter/launcher, PostgreSQL continuity-beacon reader,
immutable checkpoint persistence, recovery API extension, generation jump handling, composite fences
at all write boundaries, runtime expiry/latch and clock checks, renewal and polling.
The migration must use Tiamat's separate lineage; no migration is created by this draft. The
selected deployment must demonstrate actual storage/credential/egress isolation before activation.

## 8. Required acceptance evidence

1. Invalid signature, wrong key purpose/use/ledger/environment, revoked key, malformed framing,
   unknown version/member, duplicate member, and all digest/identity mismatches reject.
2. Lower tuple, conflicting equal tuple, retired epoch and rolled-back witness inventory reject;
   byte-identical equal replay succeeds. Renewal changing checkpoint/status/inventory rejects.
3. Independent implementations produce identical component/combined digests; duplicate keys,
   Unicode ordering edges, floats, booleans, and integers beyond the safe range are covered.
4. Normal spending, renewal, Control outage and ordinary restart preserve all spending and succeed
   with the external anchor reachable. The signed continuity beacon must reject older WAL, changed
   system ID/timeline, or checkpoint mismatch. Missing anchor or uncertain continuity blocks startup.
5. Expiry/not-before boundaries, clock rollback and excessive clock uncertainty block dispatch;
   renewal after expiry permits only prospective operation, and never an uncovered budget period.
6. Actual database/host snapshot restoration cannot rewind the external floor. Crash followed by
   restore without pre-notification enters quarantine; a same-generation snapshot before later
   spending cannot use the ordinary-restart path. Unknown/data-losing failover behaves the same.
7. Quarantine racing admitted work, a worker paused between dispatch commit and send, an in-flight
   request and an old worker reconnecting after restore proves isolation and retained liabilities.
   No old worker can access the replacement ledger; coordinator-number reuse alone cannot pass.
8. Recovery authorizes a legitimate generation jump, rejects an incorrect checkpoint/settlement
   position, and rejects incomplete or duplicated external liabilities. Inject crashes and ambiguous
   commits between each external/database/credential step; none opens a partial recovery.
9. Poll delivery meets its reachable bound; a disconnected process obeys its existing finite
   authority. Witness receipt alone never satisfies the restore-safe barrier.
10. Two independent processes demonstrate Control lacks direct database writes and Tiamat cannot
    mint authority or lower an external floor. Anchor tests reject unsigned state changes, stale
    predecessor hashes, rollback/branch attempts and unapproved epoch replacement. Deployment tests
    establish anchor durability and signed-transition recovery, restore exclusions, credential/session
    revocation, egress isolation and attachment continuity.

Evidence must name tested revisions and environment. Existing local ledger tests remain evidence
for their tested behavior only. No new implementation, lifecycle test, hosted recovery guarantee,
deployment, provider call or production activation is claimed by this draft.
