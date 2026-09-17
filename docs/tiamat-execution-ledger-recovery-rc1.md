# Tiamat execution ledger — local durable-state and recovery checkpoint

**Status:** local implementation; not deployed or production-authorized  
**Migration lineage:** `tiamat_migrations`, head `0001_execution_ledger`  
**Cloud Lucy migration lineage:** unchanged at `0071`; `0072` remains available

## Boundary

Tiamat uses a dedicated PostgreSQL database. Production and nonproduction use different databases
and credentials. The ledger contains authorization identities, keyed digests, execution states,
fences, leases, reservations, settlement state, and content-free provider-cost references. It does
not contain prompts, messages, model candidates, customer facts, transcripts, or durable response
content.

The serving login is a non-owner with `NOBYPASSRLS`. Caller, realm, environment, and spending
partition settings constrain access. The separately held offline recovery role can inspect all
content-free partitions and must never be supplied to a serving process.

## Restore gate

Every environment has three independent fences:

1. `storage_epoch`, provisioned outside ordinary database backups;
2. `recovery_generation`, advanced for a reviewed restore/reconciliation event; and
3. `coordinator_generation`, atomically advanced when a coordinator takes authority.

The executor admits and dispatches only when its deployment witness matches the database epoch and
recovery generation, the restore gate is unblocked, and its coordinator generation remains current.
An old coordinator or a database restored behind a newly provisioned recovery witness therefore
cannot resume dispatch.

This local mechanism does not by itself prove that a hosting provider survives a node loss. A
production release still requires a replicated PostgreSQL service, documented RPO/RTO, failover
evidence, and the recovery drill below.

## Stale-backup recovery procedure

1. Stop and network-quarantine every executor that can reach the affected environment.
2. Advance the deployment-owned expected recovery generation. Do not modify the restored database
   to match it yet.
3. Restore the candidate database into an isolated endpoint using recovery-only credentials.
4. Mark the environment blocked and advance the coordinator fence.
5. Compare every execution at or after the backup boundary with content-free provider billing and
   accounting evidence. Add missing liabilities as pending or settled records; never infer that a
   missing record means no provider dispatch occurred.
6. Verify that each unresolved liability is represented exactly once and that no partition exceeds
   its authoritative allowance/contingency state.
7. Invoke the offline authorization operation with the old database generation, the next exact
   recovery generation, the storage epoch, and the independently counted unresolved liabilities.
8. Provision serving credentials for the recovered endpoint, start one coordinator, and confirm it
   atomically acquires a higher coordinator generation before accepting traffic.
9. Run duplicate, stale-owner, expired-lease, and no-second-dispatch probes before reconnecting a
   caller.

Restoring a backup never constitutes authorization to resume. Failure to reconcile or match the
external witness leaves dispatch blocked.

## Verification remaining before deployment

- Run the dedicated migration into a fresh real PostgreSQL database.
- Run serving-role negative tests proving cross-caller, cross-realm, and cross-environment denial.
- Kill a coordinator after `admitted`, after durable `dispatched`, and during settlement; verify the
  authoritative reaper results and one-dispatch invariant.
- Restore a deliberately stale backup under a newer external recovery generation and prove that no
  admission or dispatch succeeds before reconciliation.
- Demonstrate single-node loss and failover on the selected production-class database service.

Docker/PostgreSQL was unavailable on the development machine when this checkpoint was written, so
none of those database-backed claims is marked passed yet.
