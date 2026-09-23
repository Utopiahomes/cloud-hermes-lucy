"""Read-only reporting of a Tiamat ledger's recovery state, for review before any ceremony.

Everything here runs in one ``READ ONLY`` transaction with the recovery login and changes
nothing. The report is content-free: identities, generations, digests, counts and the PostgreSQL
continuity beacon, never ledger rows. It is the readback a reviewer compares with the external
anchor before and after each recovery step, and what an ambiguous commit is resolved from.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

import psycopg

from lucy.shared_execution.recovery_anchor import RecoveryAnchorIdentity
from lucy.shared_execution.recovery_checkpoint import (
    RecoveryCheckpoint,
    construct_recovery_checkpoint,
)

_COUNTED_TABLES = (
    "spending_partitions",
    "grant_releases",
    "execution_records",
    "execution_idempotency_aliases",
    "financial_events",
    "route_rate_quarantines",
    "signed_releases",
    "release_heads",
)


class LedgerProjectionUnsupported(ValueError):
    """The ledger holds state whose checkpoint projection is not yet specified."""


@dataclass(frozen=True)
class LedgerRecoveryReport:
    environment: str
    ledger_id: UUID
    storage_epoch: UUID
    recovery_generation: int
    coordinator_generation: int
    dispatch_blocked: bool
    block_reason: str | None
    anchor_floor_version: int
    anchor_floor_sha256: str | None
    inventories: tuple[tuple[int, str, str], ...]
    retained_checkpoints: tuple[tuple[int, str], ...]
    counts: dict[str, int]
    system_identifier: str
    timeline_id: int
    flushed_wal_lsn: str

    def as_dict(self) -> dict[str, object]:
        return {
            "environment": self.environment,
            "ledger_id": str(self.ledger_id),
            "storage_epoch": str(self.storage_epoch),
            "recovery_generation": self.recovery_generation,
            "coordinator_generation": self.coordinator_generation,
            "dispatch_blocked": self.dispatch_blocked,
            "block_reason": self.block_reason,
            "anchor_floor": {
                "transition_version": self.anchor_floor_version,
                "transition_sha256": self.anchor_floor_sha256,
            },
            "trust_inventories": [
                {"inventory_generation": generation, "state": state, "jws_sha256": digest}
                for generation, state, digest in self.inventories
            ],
            "retained_checkpoints": [
                {"recovery_generation": generation, "checkpoint_sha256": digest}
                for generation, digest in self.retained_checkpoints
            ],
            "counts": dict(sorted(self.counts.items())),
            "beacon": {
                "system_identifier": self.system_identifier,
                "timeline_id": self.timeline_id,
                "flushed_wal_lsn": self.flushed_wal_lsn,
            },
        }


def read_ledger_recovery_state(database_url: str, *, environment: str) -> LedgerRecoveryReport:
    with psycopg.connect(database_url) as connection, connection.transaction():
        connection.execute("SET TRANSACTION READ ONLY")
        return _read(connection, environment)


def _read(connection: psycopg.Connection[Any], environment: str) -> LedgerRecoveryReport:
    identity = connection.execute(
        "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
    ).fetchone()
    gate = connection.execute(
        """
        SELECT storage_epoch, recovery_generation, coordinator_generation, dispatch_blocked,
               block_reason, anchor_floor_version, anchor_floor_sha256
        FROM tiamat.restore_gate WHERE environment = %s
        """,
        (environment,),
    ).fetchone()
    if identity is None or gate is None:
        raise LookupError("ledger identity or restore gate is missing")
    inventories = connection.execute(
        """
        SELECT inventory_generation, state, jws_sha256 FROM tiamat.trust_inventories
        WHERE environment = %s ORDER BY inventory_generation
        """,
        (environment,),
    ).fetchall()
    checkpoints = connection.execute(
        """
        SELECT recovery_generation, checkpoint_sha256 FROM tiamat.recovery_checkpoints
        WHERE environment = %s ORDER BY recovery_generation
        """,
        (environment,),
    ).fetchall()
    counts: dict[str, int] = {}
    for table in _COUNTED_TABLES:
        row = connection.execute(
            f"SELECT count(*) FROM tiamat.{table} WHERE environment = %s",  # noqa: S608
            (environment,),
        ).fetchone()
        counts[table] = 0 if row is None else int(row[0])
    beacon = connection.execute(
        """
        SELECT (pg_catalog.pg_control_system()).system_identifier::text,
               (pg_catalog.pg_control_checkpoint()).timeline_id::bigint,
               pg_catalog.pg_current_wal_flush_lsn()::text
        """
    ).fetchone()
    if beacon is None:
        raise LookupError("continuity beacon is unavailable")
    return LedgerRecoveryReport(
        environment=environment,
        ledger_id=UUID(str(identity[0])),
        storage_epoch=UUID(str(gate[0])),
        recovery_generation=int(gate[1]),
        coordinator_generation=int(gate[2]),
        dispatch_blocked=bool(gate[3]),
        block_reason=None if gate[4] is None else str(gate[4]),
        anchor_floor_version=int(gate[5]),
        anchor_floor_sha256=None if gate[6] is None else str(gate[6]),
        inventories=tuple((int(r[0]), str(r[1]), str(r[2])) for r in inventories),
        retained_checkpoints=tuple((int(r[0]), str(r[1])) for r in checkpoints),
        counts=counts,
        system_identifier=str(beacon[0]),
        timeline_id=int(beacon[1]),
        flushed_wal_lsn=str(beacon[2]),
    )


def empty_ledger_checkpoint(
    report: LedgerRecoveryReport, *, target_recovery_generation: int
) -> RecoveryCheckpoint:
    """The only checkpoint projection currently specified: an empty ledger's.

    It names the ledger's single active RELEASE inventory, with no release heads and no
    settlement positions, and is refused for any ledger with financial or release history.
    """

    if target_recovery_generation <= report.recovery_generation:
        raise LedgerProjectionUnsupported("checkpoint_generation_not_higher")
    if any(report.counts.values()):
        raise LedgerProjectionUnsupported("recovery_ledger_financial_state_unsupported")
    active = [(g, d) for g, state, d in report.inventories if state == "active"]
    if len(active) != 1:
        raise LedgerProjectionUnsupported("checkpoint_requires_one_active_inventory")
    generation, digest = active[0]
    identity = RecoveryAnchorIdentity(report.environment, report.ledger_id, report.storage_epoch)
    return construct_recovery_checkpoint(
        {
            "environment": report.environment,
            "ledger_id": str(report.ledger_id),
            "storage_epoch": str(report.storage_epoch),
            "recovery_generation": target_recovery_generation,
            "release_inventory": {"generation": generation, "jws_sha256": digest},
            "release_heads": [],
            "settlement_position": [],
        },
        identity=identity,
    )
