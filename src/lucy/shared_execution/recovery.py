"""Offline recovery-gate operations for the dedicated Tiamat database.

These functions are not imported by the serving API. They require the migration/recovery login and
are intended for a stopped or network-quarantined environment.
"""

from __future__ import annotations

import re
from uuid import UUID

import psycopg


class RecoveryRejected(RuntimeError):
    pass


_OPERATIONAL_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def initialize_environment(
    database_url: str,
    *,
    environment: str,
    storage_epoch: UUID,
    recovery_generation: int,
) -> None:
    """Initialize a new empty ledger in a blocked state."""

    if not environment or recovery_generation < 1:
        raise ValueError("recovery identity is invalid")
    with psycopg.connect(database_url) as connection:
        row = connection.execute("SELECT count(*) FROM tiamat.execution_records").fetchone()
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
