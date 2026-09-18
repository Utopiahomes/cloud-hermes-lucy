"""Offline recovery-gate operations for the dedicated Tiamat database.

These functions are not imported by the serving API. They require the migration/recovery login and
are intended for a stopped or network-quarantined environment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from uuid import UUID

import psycopg


class RecoveryRejected(RuntimeError):
    pass


_OPERATIONAL_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
type ReleaseHeadKey = tuple[str, str, str, str, str]
type ReleaseHeadValue = tuple[str, str]


@dataclass(frozen=True)
class DayZeroLedgerIdentity:
    """Canonical identity emitted only after a real isolated ledger is initialized blocked."""

    ledger_id: UUID
    environment: str
    storage_epoch: UUID
    recovery_generation: int


def initialize_environment(
    database_url: str,
    *,
    environment: str,
    storage_epoch: UUID,
    recovery_generation: int,
) -> DayZeroLedgerIdentity:
    """Initialize a new empty ledger in a blocked state."""

    if not environment or recovery_generation < 1:
        raise ValueError("recovery identity is invalid")
    with psycopg.connect(database_url) as connection, connection.transaction():
        identity_row = connection.execute(
            "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
        ).fetchone()
        if identity_row is None:
            raise RecoveryRejected("ledger identity is missing")
        ledger_id = UUID(str(identity_row[0]))
        # A day-zero checkpoint can only describe a ledger with no authority, execution,
        # replay, release, or settlement history. Check every mutable ledger table instead
        # of inferring cleanliness from a small representative subset.
        for table in (
            "jti_replay",
            "spending_partitions",
            "execution_records",
            "grant_releases",
            "route_rate_quarantines",
            "financial_events",
            "trust_inventories",
            "signed_releases",
            "release_heads",
            "execution_idempotency_aliases",
        ):
            row = connection.execute(f"SELECT count(*) FROM tiamat.{table}").fetchone()
            if row is None or int(row[0]) != 0:
                raise RecoveryRejected("initialization requires an empty execution ledger")
        connection.execute(
            """
            INSERT INTO tiamat.restore_gate (
                environment, storage_epoch, recovery_generation,
                coordinator_generation, dispatch_blocked, block_reason
            ) VALUES (%s, %s, %s, 1, true, 'initial_reconciliation_required')
            ON CONFLICT DO NOTHING
            """,
            (environment, storage_epoch, recovery_generation),
        )
        gate = connection.execute(
            """
            SELECT storage_epoch, recovery_generation, dispatch_blocked, block_reason
            FROM tiamat.restore_gate WHERE environment = %s
            """,
            (environment,),
        ).fetchone()
        if (
            gate is None
            or UUID(str(gate[0])) != storage_epoch
            or int(gate[1]) != recovery_generation
            or not bool(gate[2])
            or str(gate[3]) != "initial_reconciliation_required"
        ):
            raise RecoveryRejected("existing restore gate differs from day-zero identity")
        return DayZeroLedgerIdentity(
            ledger_id=ledger_id,
            environment=environment,
            storage_epoch=storage_epoch,
            recovery_generation=recovery_generation,
        )


def quarantine_environment(database_url: str, *, environment: str, reason: str) -> None:
    """Fail closed before inspection, restore, or reconciliation begins."""

    if not environment or _OPERATIONAL_CODE.fullmatch(reason) is None:
        raise ValueError("environment and reason are required")
    with psycopg.connect(database_url) as connection:
        result = connection.execute(
            """
            UPDATE tiamat.restore_gate
            SET dispatch_blocked = true,
                block_reason = %s,
                verified_at = NULL,
                coordinator_generation = coordinator_generation + 1,
                updated_at = clock_timestamp()
            WHERE environment = %s
            """,
            (reason, environment),
        )
        if result.rowcount != 1:
            raise RecoveryRejected("restore gate is not initialized")


def authorize_reconciled_state(
    database_url: str,
    *,
    environment: str,
    expected_storage_epoch: UUID,
    current_recovery_generation: int,
    next_recovery_generation: int,
    unresolved_provider_liabilities: int,
    expected_inventory: tuple[int, str] | None = None,
    expected_release_heads: dict[ReleaseHeadKey, ReleaseHeadValue] | None = None,
) -> None:
    """Unblock only an inspected ledger with an externally advanced generation.

    Unknown provider liabilities must be represented by pending ledger records before this command;
    the count is compared rather than trusted as a release instruction.
    """

    if next_recovery_generation != current_recovery_generation + 1:
        raise RecoveryRejected("recovery generation must advance exactly once")
    if unresolved_provider_liabilities < 0:
        raise ValueError("liability count cannot be negative")
    with psycopg.connect(  # noqa: SIM117 - transaction must begin after connection
        database_url
    ) as connection:
        with connection.transaction():
            gate = connection.execute(
                """
                SELECT storage_epoch, recovery_generation, dispatch_blocked
                FROM tiamat.restore_gate
                WHERE environment = %s
                FOR UPDATE
                """,
                (environment,),
            ).fetchone()
            if (
                gate is None
                or gate[0] != expected_storage_epoch
                or int(gate[1]) != current_recovery_generation
                or not bool(gate[2])
            ):
                raise RecoveryRejected("restore gate does not match the reviewed source state")
            observed = connection.execute(
                """
                SELECT count(*)
                FROM tiamat.execution_records
                WHERE environment = %s
                  AND settlement_status = 'pending_reconciliation'
                """,
                (environment,),
            ).fetchone()
            if observed is None or int(observed[0]) != unresolved_provider_liabilities:
                raise RecoveryRejected("unresolved provider liabilities were not reconciled")
            inventory_rows = connection.execute(
                """
                SELECT inventory_generation, jws_sha256
                FROM tiamat.trust_inventories
                WHERE environment = %s AND state = 'active'
                """,
                (environment,),
            ).fetchall()
            if expected_inventory is None:
                if inventory_rows:
                    raise RecoveryRejected("active trust inventory lacks external confirmation")
            elif (
                len(inventory_rows) != 1
                or (int(inventory_rows[0][0]), str(inventory_rows[0][1])) != expected_inventory
            ):
                raise RecoveryRejected("active trust inventory differs from external confirmation")
            head_rows = connection.execute(
                """
                SELECT issuer, caller_id, realm, release_type, subject_id,
                       active_jws_sha256, head_state
                FROM tiamat.release_heads
                WHERE environment = %s
                """,
                (environment,),
            ).fetchall()
            observed_heads = {
                (str(row[0]), str(row[1]), str(row[2]), str(row[3]), str(row[4])): (
                    str(row[5]),
                    str(row[6]),
                )
                for row in head_rows
            }
            if expected_release_heads is None:
                if observed_heads:
                    raise RecoveryRejected("active release heads lack external confirmation")
            elif observed_heads != expected_release_heads:
                raise RecoveryRejected("release heads differ from external confirmation")
            connection.execute(
                """
                UPDATE tiamat.trust_inventories
                SET activation_recovery_generation = %s
                WHERE environment = %s AND state = 'active'
                """,
                (next_recovery_generation, environment),
            )
            connection.execute(
                """
                UPDATE tiamat.release_heads SET recovery_generation = %s
                WHERE environment = %s
                """,
                (next_recovery_generation, environment),
            )
            connection.execute(
                """
                UPDATE tiamat.restore_gate
                SET recovery_generation = %s,
                    coordinator_generation = coordinator_generation + 1,
                    dispatch_blocked = false,
                    block_reason = NULL,
                    verified_at = clock_timestamp(),
                    updated_at = clock_timestamp()
                WHERE environment = %s
                """,
                (next_recovery_generation, environment),
            )
