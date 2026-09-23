"""Offline recovery-gate operations for the dedicated Tiamat database.

These functions are not imported by the serving API. They require the migration/recovery login and
are intended for a stopped or network-quarantined environment.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from psycopg.types.json import Jsonb

from lucy.shared_execution.recovery_anchor import (
    RecoveryAnchorKey,
    RecoveryAnchorRejected,
    VerifiedAnchorTransition,
    require_monotonic_anchor_floor,
)
from lucy.shared_execution.recovery_checkpoint import (
    RecoveryCheckpoint,
    RecoveryCheckpointRejected,
    construct_recovery_checkpoint,
)
from lucy.shared_execution.signed_releases import SignedReleaseRejected, verify_trust_inventory


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


# The ledger's financial and signed-release history. Recovery Draft 0.5 section 4 defines the
# settlement projection only for an empty history until populated projections are specified and
# tested, so both operations below require every one of these to be empty for the environment.
_FINANCIAL_HISTORY_TABLES = (
    "spending_partitions",
    "grant_releases",
    "execution_records",
    "execution_idempotency_aliases",
    "financial_events",
    "route_rate_quarantines",
    "signed_releases",
    "release_heads",
)


@dataclass(frozen=True)
class FirstReleaseInventory:
    environment: str
    inventory_generation: int
    jws_sha256: str
    activation_recovery_generation: int


def install_first_release_inventory(
    database_url: str,
    *,
    environment: str,
    expected_ledger_id: UUID,
    expected_storage_epoch: UUID,
    expected_recovery_generation: int,
    exact_jws: bytes,
    release_root_key_id: str,
    release_root_public_key: Ed25519PublicKey,
) -> FirstReleaseInventory:
    """Install the first RELEASE trust inventory of a blocked, never-reconciled ledger.

    Draft 0.5 section 4: reconciliation must first replace the day-zero ``not_installed`` sentinel
    with a separately verified installed RELEASE trust inventory, and activation otherwise needs
    an open gate. This is that one-time step, not a general exception to the blocked-gate rule:

    - the exact bytes verify against the pinned release root as generation 1 with no predecessor;
    - in one transaction, the gate is locked and must be blocked, of this epoch and of the
      recovery generation the reviewer read back, on this ledger, and never reconciled: no
      retained checkpoint and no startup claimant was ever issued for the environment;
    - no inventory has ever been active, and the only staged one, if any, is these exact bytes;
    - the ledger's financial and release history is empty;
    - the inventory is activated, stamped with the gate's current generation, and dispatch stays
      blocked. Any failure rolls back the whole operation.
    """

    try:
        inventory = verify_trust_inventory(
            exact_jws,
            root_key_id=release_root_key_id,
            root_public_key=release_root_public_key,
            environment=environment,
        )
    except SignedReleaseRejected as exc:
        raise RecoveryRejected("first_inventory_not_verified") from exc
    if inventory.inventory_generation != 1 or inventory.previous_inventory_digest is not None:
        raise RecoveryRejected("first_inventory_not_generation_one")
    jws_sha256 = hashlib.sha256(exact_jws).hexdigest()
    with psycopg.connect(database_url) as connection, connection.transaction():
        gate = _lock_blocked_gate(
            connection,
            environment=environment,
            expected_ledger_id=expected_ledger_id,
            expected_storage_epoch=expected_storage_epoch,
        )
        if gate.recovery_generation != expected_recovery_generation:
            raise RecoveryRejected("first_inventory_generation_differs")
        for evidence in ("recovery_checkpoints", "startup_attestations"):
            # A retained checkpoint or any claimant proves the gate was once authorized.
            row = connection.execute(
                f"SELECT count(*) FROM tiamat.{evidence} WHERE environment = %s",  # noqa: S608
                (environment,),
            ).fetchone()
            if row is None or int(row[0]) != 0:
                raise RecoveryRejected("first_inventory_ledger_already_reconciled")
        rows = connection.execute(
            """
            SELECT inventory_generation, state, jws_sha256, exact_jws, root_key_id
            FROM tiamat.trust_inventories
            WHERE environment = %s
            FOR UPDATE
            """,
            (environment,),
        ).fetchall()
        for generation, state, digest, stored, root_key_id in rows:
            if state != "staged":
                raise RecoveryRejected("first_inventory_prior_inventory_activated")
            if (
                int(generation) != 1
                or str(digest) != jws_sha256
                or bytes(stored) != exact_jws
                or str(root_key_id) != inventory.root_key_id
            ):
                raise RecoveryRejected("first_inventory_staged_candidate_differs")
        _require_empty_financial_history(connection, environment)
        if not rows:
            connection.execute(
                """
                INSERT INTO tiamat.trust_inventories (
                    environment, inventory_generation, exact_jws, jws_sha256,
                    previous_inventory_digest, root_key_id, state
                ) VALUES (%s, 1, %s, %s, NULL, %s, 'staged')
                """,
                (environment, exact_jws, jws_sha256, inventory.root_key_id),
            )
        connection.execute(
            """
            UPDATE tiamat.trust_inventories
            SET state = 'active', activated_at = clock_timestamp(),
                activation_recovery_generation = %s
            WHERE environment = %s AND inventory_generation = 1 AND state = 'staged'
            """,
            (gate.recovery_generation, environment),
        )
        return FirstReleaseInventory(
            environment=environment,
            inventory_generation=1,
            jws_sha256=jws_sha256,
            activation_recovery_generation=gate.recovery_generation,
        )


@dataclass(frozen=True)
class AuthorizedRecovery:
    environment: str
    source_recovery_generation: int
    target_recovery_generation: int
    checkpoint_sha256: str
    anchor_floor: AnchorFloorRecord


class InstalledAnchorReader(Protocol):
    def read(self, key: RecoveryAnchorKey) -> VerifiedAnchorTransition: ...


def authorize_recovery_generation(
    database_url: str,
    *,
    anchor: InstalledAnchorReader,
    authorized: VerifiedAnchorTransition,
    checkpoint: RecoveryCheckpoint,
    source_recovery_generation: int,
) -> AuthorizedRecovery:
    """Draft 0.5 section 7 step 6: authorize an externally authorized generation jump.

    ``authorized`` is the exact-byte verified ``recovery_pending`` step, and ``anchor`` must
    strong-read it back as the external anchor's current head immediately before the
    transaction: a verified step never installed must not open a gate or pin a floor. A newer
    concurrent quarantine after that read still defeats the next compare-and-swap and keeps
    serving blocked (section 7 step 7). Its reconciled witness names the target generation and
    all three checkpoint digests; ``source_recovery_generation`` is the database generation the
    reviewer observed.
    The target must equal the witness's generation and exceed the source; there is no ``+ 1``
    rule. In one transaction the gate is locked and checked, the checkpoint is verified against the
    actual ledger and bound immutably, authority is restamped, the anchor floor advances to the
    pending transition and the gate opens at the target generation.

    Content verification covers only the empty-ledger projection: an installed inventory equal to
    the ledger's single active one, no release heads and no settlement positions, over a ledger
    with no financial or release history. A populated ledger is refused until its projection is
    specified and tested. Opening the gate grants no serving authority by itself: the launcher
    also needs ``continuity_established`` with a beacon, installed after this commits.
    """

    witness = authorized.witness
    identity = witness.identity
    if authorized.continuity != "recovery_pending" or authorized.beacon is not None:
        raise RecoveryRejected("recovery_authorization_requires_pending_anchor")
    if witness.status != "reconciled" or witness.witness_revision != 1:
        raise RecoveryRejected("recovery_authorization_requires_reconciled_witness")
    target = witness.recovery_generation
    if source_recovery_generation < 1 or target <= source_recovery_generation:
        raise RecoveryRejected("recovery_generation_must_advance")
    try:
        recomputed = construct_recovery_checkpoint(dict(checkpoint.object), identity=identity)
    except RecoveryCheckpointRejected as exc:
        raise RecoveryRejected("recovery_checkpoint_invalid") from exc
    if (
        recomputed != checkpoint
        or recomputed.object["recovery_generation"] != target
        or recomputed.checkpoint_sha256 != witness.checkpoint_digest
        or recomputed.release_heads_sha256 != witness.release_heads_sha256
        or recomputed.settlement_position_sha256 != witness.checkpoint_settlement_position_sha256
    ):
        raise RecoveryRejected("recovery_checkpoint_differs_from_witness")
    if not recomputed.release_inventory_installed:
        raise RecoveryRejected("recovery_checkpoint_inventory_not_installed")
    if recomputed.object["release_heads"] != []:
        raise RecoveryRejected("recovery_checkpoint_release_heads_unsupported")
    if recomputed.object["settlement_position"] != []:
        raise RecoveryRejected("recovery_checkpoint_settlement_projection_unsupported")
    inventory = recomputed.object["release_inventory"]
    assert isinstance(inventory, dict)
    floor = AnchorFloorRecord(authorized.transition_version, authorized.exact_sha256)
    try:
        head = anchor.read(identity.key)
    except (RecoveryAnchorRejected, ValueError) as exc:
        raise RecoveryRejected("recovery_anchor_head_unavailable") from exc
    if head.exact_sha256 != authorized.exact_sha256:
        raise RecoveryRejected("recovery_anchor_head_is_not_the_pending_step")
    with psycopg.connect(database_url) as connection, connection.transaction():
        gate = _lock_blocked_gate(
            connection,
            environment=identity.environment,
            expected_ledger_id=identity.ledger_id,
            expected_storage_epoch=identity.storage_epoch,
        )
        if gate.recovery_generation != source_recovery_generation:
            raise RecoveryRejected("recovery_source_generation_differs")
        _record_anchor_floor(connection, environment=identity.environment, anchor_floor=floor)
        active = connection.execute(
            """
            SELECT inventory_generation, jws_sha256
            FROM tiamat.trust_inventories
            WHERE environment = %s AND state = 'active'
            FOR UPDATE
            """,
            (identity.environment,),
        ).fetchall()
        if len(active) != 1 or (int(active[0][0]), str(active[0][1])) != (
            inventory["generation"],
            inventory["jws_sha256"],
        ):
            raise RecoveryRejected("recovery_checkpoint_inventory_differs_from_ledger")
        _require_empty_financial_history(connection, identity.environment)
        _bind_recovery_checkpoint(
            connection,
            environment=identity.environment,
            identity_ledger_id=identity.ledger_id,
            storage_epoch=identity.storage_epoch,
            recovery_generation=target,
            checkpoint=recomputed,
        )
        connection.execute(
            """
            UPDATE tiamat.trust_inventories
            SET activation_recovery_generation = %s
            WHERE environment = %s AND state = 'active'
            """,
            (target, identity.environment),
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
            (target, identity.environment),
        )
    return AuthorizedRecovery(
        environment=identity.environment,
        source_recovery_generation=source_recovery_generation,
        target_recovery_generation=target,
        checkpoint_sha256=recomputed.checkpoint_sha256,
        anchor_floor=floor,
    )


@dataclass(frozen=True)
class _LockedGate:
    recovery_generation: int


def _lock_blocked_gate(
    connection: psycopg.Connection[Any],
    *,
    environment: str,
    expected_ledger_id: UUID,
    expected_storage_epoch: UUID,
) -> _LockedGate:
    """Lock the gate first, as every gate writer does, then check the ledger's identity."""

    gate = connection.execute(
        """
        SELECT storage_epoch, recovery_generation, dispatch_blocked
        FROM tiamat.restore_gate
        WHERE environment = %s
        FOR UPDATE
        """,
        (environment,),
    ).fetchone()
    if gate is None:
        raise RecoveryRejected("restore_gate_not_initialized")
    if UUID(str(gate[0])) != expected_storage_epoch:
        raise RecoveryRejected("restore_gate_epoch_differs")
    if not bool(gate[2]):
        raise RecoveryRejected("restore_gate_not_blocked")
    identity = connection.execute(
        "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
    ).fetchone()
    if identity is None or UUID(str(identity[0])) != expected_ledger_id:
        raise RecoveryRejected("ledger_identity_differs")
    # The checks that follow read the ledger's authority and history and act on what they saw.
    # Every writer of these tables takes the gate's lock first (staging its shared lock), so the
    # gate lock above already orders them. A count cannot lock rows that do not exist yet, so as a
    # backstop against any writer that does not, SHARE ROW EXCLUSIVE conflicts with every row
    # write and with itself: it waits for an uncommitted writer to finish, then keeps every other
    # writer out until this transaction ends. Tables whose writers all hold the gate row
    # exclusively (checkpoints, claimants) need no table lock.
    connection.execute(
        "LOCK TABLE "
        + ", ".join(f"tiamat.{table}" for table in _SNAPSHOT_TABLES)
        + " IN SHARE ROW EXCLUSIVE MODE"
    )
    return _LockedGate(recovery_generation=int(gate[1]))


_SNAPSHOT_TABLES = tuple(sorted({"trust_inventories", *_FINANCIAL_HISTORY_TABLES}))


def _inventory_authorizes_grant(
    exact_jws: bytes, *, caller_id: str, realm: str, partition_id: str
) -> bool:
    try:
        segment = exact_jws.split(b".")[1]
        payload = json.loads(base64.urlsafe_b64decode(segment + b"=" * (-len(segment) % 4)))
        wanted = {
            "caller_id": caller_id,
            "realm": realm,
            "release_type": "spending_grant",
            "subject_id": partition_id,
        }
        return any(
            key.get("status") == "active" and wanted in key.get("authorized_scopes", [])
            for key in payload["keys"]
        )
    except (IndexError, KeyError, TypeError, ValueError, AttributeError):
        return False


def _require_empty_financial_history(connection: psycopg.Connection[Any], environment: str) -> None:
    for table in _FINANCIAL_HISTORY_TABLES:
        row = connection.execute(
            f"SELECT count(*) FROM tiamat.{table} WHERE environment = %s",  # noqa: S608
            (environment,),
        ).fetchone()
        if row is None or int(row[0]) != 0:
            raise RecoveryRejected("recovery_ledger_financial_state_unsupported")


def create_spending_partition(
    database_url: str,
    *,
    environment: str,
    expected_ledger_id: UUID,
    expected_storage_epoch: UUID,
    expected_recovery_generation: int,
    caller_id: str,
    realm: str,
    partition_id: str,
) -> None:
    """Create one empty, blocked spending partition for a signed grant to be activated onto.

    Grant activation (the release manager's path) projects a verified signed grant onto an
    existing partition row and cannot create one. This is the reviewed step that creates it, after
    reconciliation: the gate must be open at the generation the reviewer read back, of this epoch
    and ledger, with a checkpoint retained for it. The row carries no allowance, no spend and no
    concurrency, and is blocked with ``no_active_grant``, the one block a grant activation clears.
    Until a signed grant for exactly this caller, realm and partition is activated, nothing can
    be admitted against it. An existing partition is never changed.
    """

    with psycopg.connect(database_url) as connection, connection.transaction():
        gate = connection.execute(
            """
            SELECT storage_epoch, recovery_generation, dispatch_blocked
            FROM tiamat.restore_gate
            WHERE environment = %s
            FOR UPDATE
            """,
            (environment,),
        ).fetchone()
        if gate is None:
            raise RecoveryRejected("restore_gate_not_initialized")
        if UUID(str(gate[0])) != expected_storage_epoch:
            raise RecoveryRejected("restore_gate_epoch_differs")
        if bool(gate[2]) or int(gate[1]) != expected_recovery_generation:
            raise RecoveryRejected("spending_partition_requires_the_reconciled_generation")
        identity = connection.execute(
            "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
        ).fetchone()
        if identity is None or UUID(str(identity[0])) != expected_ledger_id:
            raise RecoveryRejected("ledger_identity_differs")
        bound = connection.execute(
            """
            SELECT 1 FROM tiamat.recovery_checkpoints
            WHERE environment = %s AND recovery_generation = %s
            """,
            (environment, expected_recovery_generation),
        ).fetchone()
        if bound is None:
            raise RecoveryRejected("spending_partition_requires_the_reconciled_generation")
        active = connection.execute(
            """
            SELECT exact_jws FROM tiamat.trust_inventories
            WHERE environment = %s AND state = 'active'
            """,
            (environment,),
        ).fetchone()
        # The active inventory's exact bytes were verified against the pinned root when they were
        # installed; a partition is created only for a grant subject that inventory authorizes.
        if active is None or not _inventory_authorizes_grant(
            bytes(active[0]), caller_id=caller_id, realm=realm, partition_id=partition_id
        ):
            raise RecoveryRejected("spending_partition_not_authorized_by_inventory")
        created = connection.execute(
            """
            INSERT INTO tiamat.spending_partitions (
                environment, caller_id, realm, partition_id, blocked, block_reason
            ) VALUES (%s, %s, %s, %s, true, 'no_active_grant')
            ON CONFLICT DO NOTHING
            RETURNING partition_id
            """,
            (environment, caller_id, realm, partition_id),
        ).fetchone()
        if created is None:
            raise RecoveryRejected("spending_partition_exists")
