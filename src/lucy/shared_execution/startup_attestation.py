"""Issue one short-lived D1 startup attestation from verified recovery authority.

This is intentionally an offline launcher primitive, not a web endpoint and not a
deployment entrypoint.  It reads the external anchor but never signs or changes it.
The checkpoint digest arrives only through an injected durable source; the ledger
implementation here reads the immutable row bound when a generation was authorized.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol, cast
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

from lucy.shared_execution.recovery_anchor import (
    ExternalRecoveryAnchor,
    PostgresContinuityBeacon,
    RecoveryAnchorIdentity,
    RecoveryAnchorRejected,
    require_monotonic_anchor_floor,
    require_transition_dispatch_authority,
)
from lucy.shared_execution.recovery_checkpoint import (
    RecoveryCheckpointRejected,
    construct_recovery_checkpoint,
)


class StartupAttestationRejected(RuntimeError):
    """The launcher could not safely establish a new startup claimant."""


@dataclass(frozen=True)
class RetainedCheckpoint:
    """The retained checkpoint's digest and whether its release inventory is installed."""

    checkpoint_sha256: str
    release_inventory_installed: bool


class RecoveryCheckpointDigestSource(Protocol):
    """Read a recovery checkpoint from an independently durable source.

    Implementations must derive this from an approved, immutable checkpoint record;
    the launcher deliberately never accepts a caller-provided digest or rebuilds one
    from mutable live spending/release tables.
    """

    def read_checkpoint(self, identity: RecoveryAnchorIdentity) -> RetainedCheckpoint: ...


@dataclass(frozen=True)
class LedgerRecoveryCheckpointSource:
    """Read the immutable checkpoint digest bound to the ledger's current recovery generation.

    The digest comes from the append-only row written when that generation was authorized, never
    from live spending or release tables, and never from the caller. A ledger whose gate has moved
    to a generation with no retained checkpoint yields nothing rather than an older digest.
    """

    recovery_database_url: str

    def read_checkpoint(self, identity: RecoveryAnchorIdentity) -> RetainedCheckpoint:
        try:
            with psycopg.connect(
                _conninfo(self.recovery_database_url), row_factory=dict_row
            ) as connection:
                connection.execute(
                    "SELECT set_config('tiamat.environment', %s, true)",
                    (identity.environment,),
                )
                row = connection.execute(
                    """
                    SELECT bound.checkpoint_sha256, bound.ledger_id, bound.storage_epoch,
                           bound.checkpoint AS checkpoint
                    FROM tiamat.restore_gate AS gate
                    JOIN tiamat.recovery_checkpoints AS bound
                      ON bound.environment = gate.environment
                     AND bound.recovery_generation = gate.recovery_generation
                    WHERE gate.environment = %s
                    """,
                    (identity.environment,),
                ).fetchone()
        except psycopg.Error as exc:
            raise RecoveryCheckpointRejected("checkpoint_binding_unavailable") from exc
        if row is None:
            raise RecoveryCheckpointRejected("checkpoint_binding_absent")
        if row["ledger_id"] != identity.ledger_id or row["storage_epoch"] != identity.storage_epoch:
            raise RecoveryCheckpointRejected("checkpoint_binding_identity_mismatch")
        stored = row["checkpoint"]
        if not isinstance(stored, dict):
            raise RecoveryCheckpointRejected("checkpoint_binding_object_invalid")
        # Validate the retained object's full schema and recompute its digest rather than trusting
        # the stored one. A malformed object must not be read as installed authority, and a digest
        # that disagrees with its own object means the binding cannot be relied on at all.
        checkpoint = construct_recovery_checkpoint(stored, identity=identity)
        if checkpoint.checkpoint_sha256 != str(row["checkpoint_sha256"]):
            raise RecoveryCheckpointRejected("checkpoint_binding_digest_mismatch")
        return RetainedCheckpoint(
            checkpoint_sha256=checkpoint.checkpoint_sha256,
            release_inventory_installed=checkpoint.release_inventory_installed,
        )


@dataclass(frozen=True)
class StartupAttestationReceipt:
    """Content-free local evidence of one issued claimant."""

    attestation_id: UUID
    anchor_transition_sha256: str
    anchor_transition_version: int
    expires_at: datetime


class StartupAttestationIssuer:
    """Issue exactly one recovery-role claimant in one PostgreSQL transaction."""

    def __init__(
        self,
        *,
        anchor: ExternalRecoveryAnchor,
        identity: RecoveryAnchorIdentity,
        recovery_database_url: str,
        checkpoint_source: RecoveryCheckpointDigestSource,
    ) -> None:
        self._anchor = anchor
        self._identity = identity
        self._database_url = recovery_database_url
        self._checkpoint_source = checkpoint_source

    def issue(self, *, now: datetime) -> StartupAttestationReceipt:
        """Strong-read authority, then atomically supersede and issue a claimant.

        The transaction locks the gate first and uses ``NOWAIT`` for the active
        claimant.  D1 consumes in the reverse order; waiting here could deadlock a
        launcher with a consumer, so contention is reported for a fresh retry.
        """

        if now.tzinfo is None:
            raise ValueError("startup-attestation time must be aware")
        try:
            transition = self._anchor.read(self._identity.key)
            retained = self._checkpoint_source.read_checkpoint(self._identity)
        except (RecoveryAnchorRejected, ValueError) as exc:
            raise StartupAttestationRejected("startup_attestation_authority_unavailable") from exc
        checkpoint_digest = retained.checkpoint_sha256
        if not _is_hex_digest(checkpoint_digest):
            raise StartupAttestationRejected("startup_checkpoint_digest_invalid")
        if transition.witness.checkpoint_digest != checkpoint_digest:
            raise StartupAttestationRejected("startup_checkpoint_digest_mismatch")
        # A day-zero ledger has no installed release inventory, and Draft 0.5 section 4 says that
        # sentinel can neither reconcile nor authorize dispatch. The rule belongs to established
        # authority: anything else is refused on continuity, which is the more specific reason.
        if (
            transition.continuity == "continuity_established"
            and not retained.release_inventory_installed
        ):
            raise StartupAttestationRejected("startup_checkpoint_inventory_not_installed")
        try:
            with (
                psycopg.connect(_conninfo(self._database_url), row_factory=dict_row) as connection,
                connection.transaction(),
            ):
                connection.execute(
                    "SELECT set_config('tiamat.environment', %s, true)",
                    (self._identity.environment,),
                )
                self._require_recovery_role(connection)
                gate = self._lock_gate(connection)
                observed = self._observe_continuity(connection, checkpoint_digest)
                try:
                    witness = require_transition_dispatch_authority(
                        transition,
                        self._identity,
                        observed_beacon=observed,
                        now=now,
                    )
                except RecoveryAnchorRejected as exc:
                    raise StartupAttestationRejected(str(exc)) from exc
                self._require_gate_matches_identity(
                    gate,
                    transition.exact_sha256,
                    transition.transition_version,
                    witness.recovery_generation,
                )
                active = self._lock_active_claimant_nowait(connection)
                database_now = self._database_now(connection)
                if not witness.valid_at(database_now):
                    raise StartupAttestationRejected("recovery_dispatch_not_authorized")
                expires_at = min(witness.not_after, database_now + timedelta(minutes=10))
                if expires_at <= database_now:
                    raise StartupAttestationRejected("startup_attestation_expired")
                if active is not None:
                    connection.execute(
                        """
                            UPDATE tiamat.startup_attestations
                            SET superseded_at = clock_timestamp()
                            WHERE attestation_id = %s
                            """,
                        (active["attestation_id"],),
                    )
                self._advance_floor_if_needed(
                    connection, gate, transition.exact_sha256, transition.transition_version
                )
                row = connection.execute(
                    """
                        INSERT INTO tiamat.startup_attestations (
                            environment, anchor_transition_sha256, anchor_transition_version,
                            system_identifier, timeline_id, flushed_lsn, checkpoint_digest,
                            ledger_id, storage_epoch, recovery_generation, expires_at
                        ) VALUES (%s, %s, %s, %s, %s, %s::pg_lsn, %s, %s, %s, %s, %s)
                        RETURNING attestation_id, expires_at
                        """,
                    (
                        self._identity.environment,
                        transition.exact_sha256,
                        transition.transition_version,
                        observed.system_identifier,
                        observed.timeline_id,
                        observed.flushed_wal_lsn,
                        checkpoint_digest,
                        self._identity.ledger_id,
                        self._identity.storage_epoch,
                        witness.recovery_generation,
                        expires_at,
                    ),
                ).fetchone()
                if row is None:
                    raise StartupAttestationRejected("startup_attestation_insert_failed")
                return StartupAttestationReceipt(
                    attestation_id=UUID(str(row["attestation_id"])),
                    anchor_transition_sha256=transition.exact_sha256,
                    anchor_transition_version=transition.transition_version,
                    expires_at=row["expires_at"],
                )
        except StartupAttestationRejected:
            raise
        except psycopg.errors.LockNotAvailable as exc:
            raise StartupAttestationRejected("startup_attestation_busy") from exc
        except psycopg.Error as exc:
            if exc.sqlstate == "ZX105":
                raise StartupAttestationRejected("startup_attestation_expired") from exc
            raise StartupAttestationRejected("startup_attestation_store_unavailable") from exc

    @staticmethod
    def _require_recovery_role(connection: psycopg.Connection[Any]) -> None:
        row = connection.execute("SELECT current_user").fetchone()
        if row is None or str(row["current_user"]) != "tiamat_recovery":
            raise StartupAttestationRejected("startup_attestation_recovery_role_required")

    def _lock_gate(self, connection: psycopg.Connection[Any]) -> dict[str, Any]:
        row = connection.execute(
            """
            SELECT gate.storage_epoch, gate.recovery_generation, gate.dispatch_blocked,
                   gate.anchor_floor_version, gate.anchor_floor_sha256, identity.ledger_id
            FROM tiamat.restore_gate AS gate
            CROSS JOIN tiamat.ledger_identity AS identity
            WHERE gate.environment = %s AND identity.singleton
            FOR UPDATE OF gate
            """,
            (self._identity.environment,),
        ).fetchone()
        if row is None:
            raise StartupAttestationRejected("startup_restore_gate_unavailable")
        return cast(dict[str, Any], row)

    @staticmethod
    def _observe_continuity(
        connection: psycopg.Connection[Any], checkpoint_digest: str
    ) -> PostgresContinuityBeacon:
        row = connection.execute(
            """
            SELECT
              (pg_control_system()).system_identifier::text AS system_identifier,
              (pg_control_checkpoint()).timeline_id::bigint AS timeline_id,
              pg_current_wal_flush_lsn()::text AS flushed_wal_lsn
            """
        ).fetchone()
        if row is None:
            raise StartupAttestationRejected("recovery_continuity_beacon_unavailable")
        try:
            return PostgresContinuityBeacon(
                str(row["system_identifier"]),
                int(row["timeline_id"]),
                str(row["flushed_wal_lsn"]),
                checkpoint_digest,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StartupAttestationRejected("recovery_continuity_beacon_invalid") from exc

    def _require_gate_matches_identity(
        self,
        gate: dict[str, Any],
        anchor_digest: str,
        anchor_version: int,
        recovery_generation: int,
    ) -> None:
        if (
            bool(gate["dispatch_blocked"])
            or gate["ledger_id"] != self._identity.ledger_id
            or gate["storage_epoch"] != self._identity.storage_epoch
            or int(gate["recovery_generation"]) != recovery_generation
        ):
            raise StartupAttestationRejected("startup_restore_gate_not_authorized")
        _floor_must_advance(gate, anchor_digest, anchor_version)

    @staticmethod
    def _lock_active_claimant_nowait(connection: psycopg.Connection[Any]) -> dict[str, Any] | None:
        return connection.execute(
            """
            SELECT attestation_id
            FROM tiamat.startup_attestations
            WHERE environment = current_setting('tiamat.environment', true)
              AND consumed_at IS NULL AND superseded_at IS NULL
            FOR UPDATE NOWAIT
            """
        ).fetchone()

    @staticmethod
    def _database_now(connection: psycopg.Connection[Any]) -> datetime:
        row = connection.execute("SELECT clock_timestamp() AS now").fetchone()
        if row is None or not isinstance(row["now"], datetime) or row["now"].tzinfo is None:
            raise StartupAttestationRejected("startup_attestation_clock_unavailable")
        return row["now"]

    @staticmethod
    def _advance_floor_if_needed(
        connection: psycopg.Connection[Any],
        gate: dict[str, Any],
        anchor_digest: str,
        anchor_version: int,
    ) -> None:
        if not _floor_must_advance(gate, anchor_digest, anchor_version):
            return
        connection.execute(
            """
            UPDATE tiamat.restore_gate
            SET anchor_floor_version = %s, anchor_floor_sha256 = %s, updated_at = clock_timestamp()
            WHERE environment = current_setting('tiamat.environment', true)
            """,
            (anchor_version, anchor_digest),
        )


def _floor_must_advance(gate: dict[str, Any], anchor_digest: str, anchor_version: int) -> bool:
    """Apply the shared floor rule to a locked gate row, in this module's vocabulary."""

    stored_digest = gate["anchor_floor_sha256"]
    try:
        return require_monotonic_anchor_floor(
            current_version=int(gate["anchor_floor_version"]),
            current_sha256=None if stored_digest is None else str(stored_digest),
            candidate_version=anchor_version,
            candidate_sha256=anchor_digest,
        )
    except RecoveryAnchorRejected as exc:
        raise StartupAttestationRejected("startup_anchor_floor_rollback") from exc


def _conninfo(database_url: str) -> str:
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


def _is_hex_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
