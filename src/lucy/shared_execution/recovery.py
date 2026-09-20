"""Offline recovery-gate operations for the dedicated Tiamat database.

These functions are not imported by the serving API. They require the migration/recovery login and
are intended for a stopped or network-quarantined environment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from lucy.shared_execution.recovery_anchor import (
    RecoveryAnchorRejected,
    require_monotonic_anchor_floor,
)
from lucy.shared_execution.recovery_checkpoint import RecoveryCheckpoint


class RecoveryRejected(RuntimeError):
    pass


_OPERATIONAL_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
type ReleaseHeadKey = tuple[str, str, str, str, str]
type ReleaseHeadValue = tuple[str, str]


@dataclass(frozen=True)
class AnchorFloorRecord:
    """The exact external anchor transition a recovery-gate command was performed under."""

    transition_version: int
    transition_sha256: str

    def __post_init__(self) -> None:
        if self.transition_version < 1 or _HEX_DIGEST.fullmatch(self.transition_sha256) is None:
            raise ValueError("anchor floor record is invalid")


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


def _bind_recovery_checkpoint(
    connection: psycopg.Connection[Any],
    *,
    environment: str,
    identity_ledger_id: UUID,
    storage_epoch: UUID,
    recovery_generation: int,
    checkpoint: RecoveryCheckpoint | None,
) -> None:
    """Append the immutable checkpoint this generation is authorized under.

    The row is what a later restart recomputes its digest from, so it is written inside the same
    transaction which unblocks the ledger. A ledger whose schema can retain one must: unblocking
    without a retained checkpoint would leave the launcher with no independent digest source.
    """

    supported = connection.execute(
        """
        SELECT count(*) FROM information_schema.tables
        WHERE table_schema = 'tiamat' AND table_name = 'recovery_checkpoints'
        """
    ).fetchone()
    if supported is None:
        raise RecoveryRejected("recovery checkpoint schema could not be read")
    if int(supported[0]) == 0:
        if checkpoint is not None:
            raise RecoveryRejected("ledger does not retain recovery checkpoints")
        return
    if checkpoint is None:
        raise RecoveryRejected("recovery checkpoint is required on this ledger")
    bound_generation = checkpoint.object.get("recovery_generation")
    if bound_generation != recovery_generation:
        raise RecoveryRejected("recovery checkpoint generation does not match the authorization")
    if (
        str(checkpoint.object.get("ledger_id")) != str(identity_ledger_id)
        or str(checkpoint.object.get("storage_epoch")) != str(storage_epoch)
        or str(checkpoint.object.get("environment")) != environment
    ):
        raise RecoveryRejected("recovery checkpoint identity does not match the ledger")
    existing = connection.execute(
        """
        SELECT checkpoint_sha256 FROM tiamat.recovery_checkpoints
        WHERE environment = %s AND recovery_generation = %s
        """,
        (environment, recovery_generation),
    ).fetchone()
    if existing is not None:
        # The table is append-only, so a repeated authorization may only reassert exact bytes.
        if str(existing[0]) != checkpoint.checkpoint_sha256:
            raise RecoveryRejected("a different recovery checkpoint is already bound")
        return
    connection.execute(
        """
        INSERT INTO tiamat.recovery_checkpoints (
            environment, recovery_generation, ledger_id, storage_epoch,
            checkpoint_sha256, release_heads_sha256, settlement_position_sha256, checkpoint
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            environment,
            recovery_generation,
            identity_ledger_id,
            storage_epoch,
            checkpoint.checkpoint_sha256,
            checkpoint.release_heads_sha256,
            checkpoint.settlement_position_sha256,
            Jsonb(checkpoint.object),
        ),
    )


def _record_anchor_floor(
    connection: psycopg.Connection[Any],
    *,
    environment: str,
    anchor_floor: AnchorFloorRecord | None,
) -> None:
    """Advance the stored anchor floor inside the caller's open transaction.

    The gate row is locked before the comparison so a concurrent issuer cannot interleave. A
    ledger which predates the D1 columns has no floor to record; supplying one there, or omitting
    one where the columns exist, is rejected rather than silently ignored.
    """

    supported = connection.execute(
        """
        SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'tiamat' AND table_name = 'restore_gate'
          AND column_name = 'anchor_floor_version'
        """
    ).fetchone()
    if supported is None:
        raise RecoveryRejected("restore gate schema could not be read")
    if int(supported[0]) == 0:
        if anchor_floor is not None:
            raise RecoveryRejected("ledger does not record an anchor floor")
        return
    if anchor_floor is None:
        raise RecoveryRejected("anchor floor record is required on this ledger")
    stored = connection.execute(
        """
        SELECT anchor_floor_version, anchor_floor_sha256
        FROM tiamat.restore_gate WHERE environment = %s FOR UPDATE
        """,
        (environment,),
    ).fetchone()
    if stored is None:
        raise RecoveryRejected("restore gate is not initialized")
    try:
        advance = require_monotonic_anchor_floor(
            current_version=int(stored[0]),
            current_sha256=None if stored[1] is None else str(stored[1]),
            candidate_version=anchor_floor.transition_version,
            candidate_sha256=anchor_floor.transition_sha256,
        )
    except RecoveryAnchorRejected as exc:
        raise RecoveryRejected("anchor floor cannot move backward") from exc
    if not advance:
        return
    connection.execute(
        """
        UPDATE tiamat.restore_gate
        SET anchor_floor_version = %s,
            anchor_floor_sha256 = %s,
            updated_at = clock_timestamp()
        WHERE environment = %s
        """,
        (anchor_floor.transition_version, anchor_floor.transition_sha256, environment),
    )


def quarantine_environment(
    database_url: str,
    *,
    environment: str,
    reason: str,
    anchor_floor: AnchorFloorRecord | None = None,
) -> None:
    """Fail closed before inspection, restore, or reconciliation begins.

    ``anchor_floor`` is the external anchor transition this quarantine was performed under. On a
    ledger carrying the D1 floor columns it is mandatory: a quarantine which left the floor behind
    would let a later replay of the superseded transition still satisfy startup.
    """

    if not environment or _OPERATIONAL_CODE.fullmatch(reason) is None:
        raise ValueError("environment and reason are required")
    with psycopg.connect(database_url) as connection, connection.transaction():
        _record_anchor_floor(connection, environment=environment, anchor_floor=anchor_floor)
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
    anchor_floor: AnchorFloorRecord | None = None,
    checkpoint: RecoveryCheckpoint | None = None,
) -> None:
    """Unblock only an inspected ledger with an externally advanced generation.

    Unknown provider liabilities must be represented by pending ledger records before this command;
    the count is compared rather than trusted as a release instruction.

    ``anchor_floor`` is the external anchor transition this authorization was performed under, and
    is mandatory on a ledger carrying the D1 floor columns. Unblocking without advancing the floor
    would leave a superseded transition acceptable to the next startup.

    ``checkpoint`` is the reconciled checkpoint this generation is authorized under, retained
    immutably for the launcher to recompute from later. It is mandatory on a ledger which can
    retain one. This binds the reviewed checkpoint; the wider Draft 0.5 section 7.6 change, which
    replaces the exact ``current + 1`` rule with an externally authorized generation jump and
    verifies the checkpoint against reconciled ledger contents, remains separate and reviewed.
    """

    if next_recovery_generation != current_recovery_generation + 1:
        raise RecoveryRejected("recovery generation must advance exactly once")
    if unresolved_provider_liabilities < 0:
        raise ValueError("liability count cannot be negative")
    with psycopg.connect(  # noqa: SIM117 - transaction must begin after connection
        database_url
    ) as connection:
        with connection.transaction():
            _record_anchor_floor(connection, environment=environment, anchor_floor=anchor_floor)
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
            identity_row = connection.execute(
                "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
            ).fetchone()
            if identity_row is None:
                raise RecoveryRejected("ledger identity is missing")
            _bind_recovery_checkpoint(
                connection,
                environment=environment,
                identity_ledger_id=UUID(str(identity_row[0])),
                storage_epoch=expected_storage_epoch,
                recovery_generation=next_recovery_generation,
                checkpoint=checkpoint,
            )
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
