# Tiamat recovery companion amendment v1 — Draft 0.1

Status: coordinated amendment candidate. This document does not alter the frozen Shared Model
Execution RC1 bundle, deploy an anchor, or authorize provider work.

## Purpose

This packet reconciles the recovery assumptions in the frozen
[`tiamat-signed-release-format-v1-rc1.md`](tiamat-signed-release-format-v1-rc1.md) and the local
[`tiamat-execution-ledger-recovery-rc1.md`](tiamat-execution-ledger-recovery-rc1.md) with the
reviewed recovery lifecycle in
[`tiamat-control-recovery-witness-v1-draft-0.5.md`](tiamat-control-recovery-witness-v1-draft-0.5.md).
It must be released as coordinated successor documents. Applying only one replacement leaves
contradictory startup rules.

## Signed-release successor: replacement for section 7

Replace Signed Release RC1 section 7 with this text in its versioned successor:

> A valid signature never proves database freshness or restores spending capacity.
>
> Every serving start requires a current, root-authorized external recovery-anchor transition. The
> transition contains the exact verified recovery-witness bytes/digest, environment, ledger identity,
> storage epoch, recovery generation/revision, predecessor transition digest, continuity state and,
> when continuity is established, a PostgreSQL continuity beacon. The anchor and its root trust
> material reside outside PostgreSQL, the database host/VM, and all database snapshot boundaries.
>
> The beacon binds PostgreSQL system identifier, timeline ID, durable flushed-WAL LSN and immutable
> reconciled checkpoint digest. An ordinary restart may load locally staged authority only when the
> external anchor is reconciled/established and the attached database reports the same identifier and
> timeline, the same checkpoint digest, and a flushed LSN at or beyond the beacon. Normal spending may
> advance after that checkpoint. It does not invalidate ordinary restart eligibility by itself.
>
> A restore, clone, rollback, endpoint replacement, or potentially data-losing failover must first
> publish a higher signed quarantined transition before the candidate database receives serving
> credentials. Recovery reconciles obligations and authority, binds a new checkpoint, then creates a
> recovery-pending transition. Only a signed continuity-establishing transition after the database
> beacon is read may provision new serving credentials. A matching database-local restore gate alone
> is insufficient.
>
> When the anchor is unavailable, a new serving process dispatches nothing. A running executor may
> use only its already-verified, unexpired authority window; the earliest witness, grant, budget-period
> or local-clock bound ends it. No synchronous Control call is required for normal inference.
>
> The supported deployment must enforce this launcher for every restore/failover path and prove it.
> A storage rollback that bypasses both the launcher and the independent anchor store is outside the
> v1 detectable threat boundary and is not a permitted deployment recovery path.

The successor's negative vectors must add unsigned transition mutation, predecessor replay/branch,
old-WAL beacon, system/timeline mismatch, continuity-state change without a signed transition,
retired-epoch resume, and crash-then-restore. Positive vectors must cover routine beacon refresh,
witness-inventory rotation under an unchanged checkpoint, and ordinary restart after normal spending.

## Ledger-recovery successor: required changes

The ledger recovery successor keeps its local database role but changes its deployment witness and
recovery procedure as follows:

1. Treat `tiamat.restore_gate` as a local transaction fence only. It is not the recovery authority
   and cannot be the sole proof of fresh state.
2. Bind each coordinator/record authority operation to
   `(environment, ledger_id, storage_epoch, recovery_generation, coordinator_generation)`. A restored
   coordinator integer by itself can never fence an old process.
3. Extend `authorize_reconciled_state` to receive the verified combined checkpoint object/digest,
   component digests, release inventory/heads, deployment identity, source generation and externally
   authorized target generation. It verifies those values under a recovery-only transaction, writes an
   immutable local checkpoint anchor, and advances to the external target. The target must exceed the
   source; it need not equal source plus one.
4. Record a PostgreSQL continuity beacon only after the reconciled checkpoint is committed. The
   external launcher signs and stores that beacon in the next anchor transition. On ordinary startup,
   compare the live database beacon with the external one before loading authority.
5. Quarantine first closes executor admission/dispatch and fences workers. Provider requests already
   sent remain obligations. Recovery isolates old worker database access and provider egress before
   candidate storage is attached.
6. A backup from a retired epoch may supply recovery evidence only. It cannot receive serving
   credentials until a new epoch's quarantined-to-established sequence completes.

The implementation must demonstrate actual PostgreSQL queries for system identifier, timeline and
durable WAL position on the chosen supported service. It must prove those fields across restart and
restore rather than substituting generated test strings in deployment evidence.

## Transition roles

| Role | May do |
| --- | --- |
| Control policy notary | Sign recovery witnesses and witness-inventory changes. |
| Recovery launcher/root signer | Sign predecessor-linked anchor transitions and provision/revoke serving attachment credentials. |
| External anchor service | Verify signed transitions and persist the single compare-and-swap chain. |
| Tiamat serving process | Read/verify the anchor and database beacon; never write an anchor transition. |
| Recovery-only database role | Reconcile and bind the checkpoint; never mint external authority. |

## Freeze condition

This amendment becomes part of a successor release only after the recovery-witness format and
anchor-transition format have independent schema/vector review, and the selected deployment proves
the anchor's separate durability, signed transition chain, attachment continuity, worker isolation
and recovery behavior.
