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


_READBACK_TABLES = (
    "restore_gate",
    "ledger_identity",
    "trust_inventories",
    "signed_releases",
    "release_heads",
    "spending_partitions",
    "grant_releases",
    "execution_records",
    "execution_idempotency_aliases",
    "financial_events",
    "route_rate_quarantines",
    "jti_replay",
    "startup_attestations",
    "recovery_checkpoints",
)
_GATE_COLUMNS = (
    "storage_epoch",
    "recovery_generation",
    "coordinator_generation",
    "dispatch_blocked",
    "block_reason",
    "verified_at",
    "anchor_floor_version",
    "anchor_floor_sha256",
)


def read_ledger_schema_readback(database_url: str, *, environment: str) -> dict[str, object]:
    """A read-only readback that adapts to whatever schema revision the ledger is at.

    ``read_ledger_recovery_state`` assumes the current schema. A ledger provisioned earlier (the
    commissioned staging ledger was last recorded at 0006) may lack tables and columns it reads,
    so this consults the catalog first and reads only what exists and what the login may read:
    the migration revision, each table's presence and this login's privileges on it, the gate's
    existing columns, per-environment counts, the inventories, and the continuity beacon if its
    functions are callable. Nothing is written; the output is content-free.
    """

    with psycopg.connect(database_url) as connection, connection.transaction():
        connection.execute("SET TRANSACTION READ ONLY")
        login = _one(connection, "SELECT current_user::text")
        present = {
            str(row[0])
            for row in connection.execute(
                "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'tiamat'"
            ).fetchall()
        }
        revision = None
        if "alembic_version" in present and _may(connection, "alembic_version", "SELECT"):
            revision = _one(connection, "SELECT version_num FROM tiamat.alembic_version")
        tables: dict[str, object] = {}
        for table in _READBACK_TABLES:
            if table not in present:
                tables[table] = {"present": False}
                continue
            entry: dict[str, object] = {
                "present": True,
                "privileges": {
                    privilege.lower(): _may(connection, table, privilege)
                    for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE")
                },
            }
            if (
                table != "ledger_identity"
                and _may(connection, table, "SELECT")
                and "environment" in _columns(connection, table)
            ):
                entry["environment_rows"] = int(
                    _one(
                        connection,
                        f"SELECT count(*) FROM tiamat.{table} WHERE environment = %s",  # noqa: S608
                        (environment,),
                    )
                )
            tables[table] = entry
        readback: dict[str, object] = {
            "environment": environment,
            "login": login,
            "schema_revision": revision,
            "tables": tables,
        }
        if "ledger_identity" in present and _may(connection, "ledger_identity", "SELECT"):
            readback["ledger_id"] = str(
                _one(connection, "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton")
            )
        if "restore_gate" in present and _may(connection, "restore_gate", "SELECT"):
            available = [c for c in _GATE_COLUMNS if c in _columns(connection, "restore_gate")]
            row = connection.execute(
                f"SELECT {', '.join(available)} FROM tiamat.restore_gate "  # noqa: S608
                "WHERE environment = %s",
                (environment,),
            ).fetchone()
            readback["gate"] = (
                None
                if row is None
                else {
                    column: (
                        value if isinstance(value, bool | int) or value is None else str(value)
                    )
                    for column, value in zip(available, row, strict=True)
                }
            )
            readback["gate_columns_missing"] = [c for c in _GATE_COLUMNS if c not in available]
        if "trust_inventories" in present and _may(connection, "trust_inventories", "SELECT"):
            readback["trust_inventories"] = [
                {"inventory_generation": int(r[0]), "state": str(r[1]), "jws_sha256": str(r[2])}
                for r in connection.execute(
                    """
                    SELECT inventory_generation, state, jws_sha256 FROM tiamat.trust_inventories
                    WHERE environment = %s ORDER BY inventory_generation
                    """,
                    (environment,),
                ).fetchall()
            ]
        callable_beacon = all(
            _one(connection, "SELECT pg_catalog.has_function_privilege(%s, 'EXECUTE')", (name,))
            for name in (
                "pg_catalog.pg_control_system()",
                "pg_catalog.pg_control_checkpoint()",
                "pg_catalog.pg_current_wal_flush_lsn()",
            )
        )
        if callable_beacon:
            beacon = connection.execute(
                """
                SELECT (pg_catalog.pg_control_system()).system_identifier::text,
                       (pg_catalog.pg_control_checkpoint()).timeline_id::bigint,
                       pg_catalog.pg_current_wal_flush_lsn()::text
                """
            ).fetchone()
            if beacon is not None:
                readback["beacon"] = {
                    "system_identifier": str(beacon[0]),
                    "timeline_id": int(beacon[1]),
                    "flushed_wal_lsn": str(beacon[2]),
                }
        readback["beacon_callable"] = callable_beacon
        return readback


def _one(connection: psycopg.Connection[Any], query: str, params: tuple[object, ...] = ()) -> Any:
    row = connection.execute(query, params).fetchone()
    return None if row is None else row[0]


def _may(connection: psycopg.Connection[Any], table: str, privilege: str) -> bool:
    return bool(
        _one(
            connection,
            "SELECT pg_catalog.has_table_privilege(%s, %s)",
            (f"tiamat.{table}", privilege),
        )
    )


def _columns(connection: psycopg.Connection[Any], table: str) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            """
            SELECT attname FROM pg_catalog.pg_attribute
            WHERE attrelid = %s::regclass AND attnum > 0 AND NOT attisdropped
            """,
            (f"tiamat.{table}",),
        ).fetchall()
    }
