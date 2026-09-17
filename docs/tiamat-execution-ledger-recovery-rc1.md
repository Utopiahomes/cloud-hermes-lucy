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

## Verified locally

- The dedicated migration upgraded a fresh PostgreSQL 16 database.
- A non-owner, `NOBYPASSRLS` serving login completed replay, admission, durable dispatch, and
  settlement while a wrong-realm session could not observe the record.
- Concurrent first admission created exactly one durable execution record.
- A replacement coordinator fenced the old generation and adopted an expired lease before dispatch.
- The authoritative reaper settled expired `admitted` work at zero and retained an expired
  `dispatched` reservation as `outcome_unknown`.
- An unclear dispatch commit aborted at zero only under the same live owner epoch; once the reaper
  established a newer `outcome_unknown` state, resolution preserved that uncertainty and held cost.
- A physical stale database snapshot remained internally valid but could not resume under the newer
  deployment-owned recovery witness.

## Verification remaining before deployment

- Inject actual connection loss during the dispatch-commit and settlement windows; the current
  suite proves authoritative lookup outcomes after acknowledgement loss at stable boundaries.
- Prove cost overrun, route quarantine, reconciliation, and 30-day tombstone expiry against the
  durable store.
- Demonstrate single-node loss and failover on the selected production-class database service.

The local database used a loopback-only Docker service with tmpfs and synthetic credentials; it is
not deployment or production durability evidence.
