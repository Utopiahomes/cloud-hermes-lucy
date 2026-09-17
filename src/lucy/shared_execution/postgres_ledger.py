"""PostgreSQL-backed, content-free execution ledger for Tiamat RC1.

This adapter owns no prompts, model output, customer facts, or transcript content. The database is
separate from the legacy Cloud Lucy migration lineage. A deployment-provisioned recovery witness
must match before the coordinator can admit or dispatch work; an old restored database therefore
cannot silently resume spending under a newer recovery generation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row

from lucy.shared_execution.auth import AuthenticationStateUnavailable


class LedgerUnavailable(RuntimeError):
    """The authoritative database could not establish current state."""


class DispatchBlocked(RuntimeError):
    """The environment or spending partition is fail-closed."""


class DurableIdempotencyConflict(RuntimeError):
    """A scoped digest already names a different canonical request."""


class DurableFenceRejected(RuntimeError):
    """A mutation used stale state, owner, or fencing generations."""


@dataclass(frozen=True)
class RecoveryWitness:
    environment: str
    storage_epoch: UUID
    recovery_generation: int

    def __post_init__(self) -> None:
        if not self.environment or self.recovery_generation < 1:
            raise ValueError("recovery witness is invalid")


@dataclass(frozen=True)
class LedgerScope:
    issuer: str
    caller_id: str
    realm: str
    environment: str
    partition_id: str

    def __post_init__(self) -> None:
        if not all((self.issuer, self.caller_id, self.realm, self.environment, self.partition_id)):
            raise ValueError("ledger scope is incomplete")


@dataclass(frozen=True)
class LedgerAdmission:
    idempotency_key_digest: str
    identity_digest: str
    digest_key_version: str
    operation: str
    contract_major: int
    execution_profile_id: str
    profile_release_id: str
    owner_id: UUID
    execution_deadline: datetime
    eligibility_generation: int
    reserved_microusd: int

    def __post_init__(self) -> None:
        if (
            len(self.idempotency_key_digest) != 64
            or len(self.identity_digest) != 64
            or not self.digest_key_version
            or not self.operation
            or self.contract_major < 1
            or not self.execution_profile_id
            or not self.profile_release_id
            or self.execution_deadline.tzinfo is None
            or self.eligibility_generation < 1
            or self.reserved_microusd < 1
        ):
            raise ValueError("ledger admission is invalid")


@dataclass(frozen=True)
class LedgerRecord:
    execution_id: UUID
    identity_digest: str
    state: str
    coordinator_generation: int
    record_generation: int
    lease_owner_id: UUID
    lease_expires_at: datetime
    execution_deadline: datetime
    reserved_microusd: int
    settlement_status: str
    settled_microusd: int | None
    failure_code: str | None

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> LedgerRecord:
        return cls(
            execution_id=row["execution_id"],
            identity_digest=row["identity_digest"],
            state=row["state"],
            coordinator_generation=row["coordinator_generation"],
            record_generation=row["record_generation"],
            lease_owner_id=row["lease_owner_id"],
            lease_expires_at=row["lease_expires_at"],
            execution_deadline=row["execution_deadline"],
            reserved_microusd=row["reserved_microusd"],
            settlement_status=row["settlement_status"],
            settled_microusd=row["settled_microusd"],
            failure_code=row["failure_code"],
        )


_RECORD_COLUMNS = """
execution_id, identity_digest, state, coordinator_generation, record_generation,
lease_owner_id, lease_expires_at, execution_deadline, reserved_microusd,
settlement_status, settled_microusd, failure_code
"""


class PostgresJtiReplayStore:
    """Atomic, scoped JWT replay state in the dedicated Tiamat database."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def consume(self, namespace: tuple[str, str, str, str], jti: UUID, expires_at: int) -> bool:
        issuer, subject, realm, environment = namespace
        try:
            with psycopg.connect(  # noqa: SIM117 - transaction must begin after connection
                _psycopg_conninfo(self._database_url), row_factory=dict_row
            ) as connection:
                with connection.transaction():
                    _set_scope(
                        connection,
                        LedgerScope(issuer, subject, realm, environment, "authentication"),
                    )
                    row = connection.execute(
                        """
                        INSERT INTO tiamat.jti_replay (
                            issuer, subject, realm, environment, jti, expires_at
                        ) VALUES (%s, %s, %s, %s, %s, to_timestamp(%s))
                        ON CONFLICT DO NOTHING
                        RETURNING jti
                        """,
                        (issuer, subject, realm, environment, jti, expires_at),
                    ).fetchone()
                    return row is not None
        except psycopg.Error as exc:
            raise AuthenticationStateUnavailable from exc


class PostgresExecutionLedger:
    """Atomic admission, fencing, settlement, and recovery over PostgreSQL."""

    def __init__(self, database_url: str, witness: RecoveryWitness) -> None:
        self._database_url = database_url
        self._witness = witness

    def acquire_coordinator_generation(self) -> int:
        """Fence an older coordinator before this process may acquire execution leases."""

        try:
            with psycopg.connect(  # noqa: SIM117 - transaction must begin after connection
                _psycopg_conninfo(self._database_url), row_factory=dict_row
            ) as connection:
                with connection.transaction():
                    connection.execute(
                        "SELECT set_config('tiamat.environment', %s, true)",
                        (self._witness.environment,),
                    )
                    row = connection.execute(
                        """
                        SELECT storage_epoch, recovery_generation, coordinator_generation,
                               dispatch_blocked
                        FROM tiamat.restore_gate
                        WHERE environment = %s
                        FOR UPDATE
                        """,
                        (self._witness.environment,),
                    ).fetchone()
                    self._validate_gate(row)
                    updated = connection.execute(
                        """
                        UPDATE tiamat.restore_gate
                        SET coordinator_generation = coordinator_generation + 1,
                            updated_at = clock_timestamp()
                        WHERE environment = %s
                        RETURNING coordinator_generation
                        """,
                        (self._witness.environment,),
                    ).fetchone()
                    assert updated is not None
                    return int(updated["coordinator_generation"])
        except DispatchBlocked:
            raise
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    def create_or_get(
        self,
        scope: LedgerScope,
        admission: LedgerAdmission,
        *,
        coordinator_generation: int,
        now: datetime,
    ) -> tuple[LedgerRecord, bool]:
        if now.tzinfo is None or admission.execution_deadline <= now:
            raise ValueError("execution times must be aware and ordered")
        try:
            with psycopg.connect(  # noqa: SIM117 - transaction must begin after connection
                _psycopg_conninfo(self._database_url), row_factory=dict_row
            ) as connection:
                with connection.transaction():
                    _set_scope(connection, scope)
                    gate = connection.execute(
                        """
                        SELECT storage_epoch, recovery_generation, coordinator_generation,
                               dispatch_blocked
                        FROM tiamat.restore_gate
                        WHERE environment = %s
                        FOR SHARE
                        """,
                        (scope.environment,),
                    ).fetchone()
                    self._validate_gate(gate, coordinator_generation)
                    # The partition row serializes both duplicate admission and financial exposure.
                    # A waiter takes a fresh READ COMMITTED snapshot for the lookup below after the
                    # first transaction commits, avoiding a unique-key race masquerading as outage.
                    partition = connection.execute(
                        """
                        SELECT p.*, g.not_before, g.not_after, g.period_start, g.period_end,
                               g.revoked_at
                        FROM tiamat.spending_partitions p
                        LEFT JOIN tiamat.grant_releases g
                          ON g.release_id = p.active_grant_release_id
                         AND g.environment = p.environment
                         AND g.caller_id = p.caller_id
                         AND g.realm = p.realm
                         AND g.partition_id = p.partition_id
                        WHERE p.environment = %s AND p.caller_id = %s AND p.realm = %s
                          AND p.partition_id = %s
                        FOR UPDATE OF p
                        """,
                        (
                            scope.environment,
                            scope.caller_id,
                            scope.realm,
                            scope.partition_id,
                        ),
                    ).fetchone()
                    existing = connection.execute(
                        f"""
                        SELECT {_RECORD_COLUMNS}
                        FROM tiamat.execution_records
                        WHERE issuer = %s AND caller_id = %s AND realm = %s
                          AND environment = %s AND operation = %s AND contract_major = %s
                          AND idempotency_key_digest = %s
                        FOR UPDATE
                        """,
                        (
                            scope.issuer,
                            scope.caller_id,
                            scope.realm,
                            scope.environment,
                            admission.operation,
                            admission.contract_major,
                            admission.idempotency_key_digest,
                        ),
                    ).fetchone()
                    if existing is not None:
                        record = LedgerRecord.from_row(existing)
                        if record.identity_digest != admission.identity_digest:
                            raise DurableIdempotencyConflict
                        return record, False
                    _validate_partition(partition, admission.reserved_microusd, now)
                    exposure = connection.execute(
                        """
                        SELECT
                          count(*) FILTER (WHERE state IN ('admitted', 'dispatched')) AS active,
                          count(*) FILTER (
                            WHERE state NOT IN ('admitted', 'dispatched')
                              AND settlement_status = 'pending_reconciliation'
                          ) AS pending,
                          coalesce(sum(reserved_microusd) FILTER (
                            WHERE state IN ('admitted', 'dispatched')
                               OR settlement_status = 'pending_reconciliation'
                          ), 0) AS held
                        FROM tiamat.execution_records
                        WHERE environment = %s AND caller_id = %s AND realm = %s
                          AND partition_id = %s
                        """,
                        (
                            scope.environment,
                            scope.caller_id,
                            scope.realm,
                            scope.partition_id,
                        ),
                    ).fetchone()
                    assert exposure is not None and partition is not None
                    active, pending, held = (
                        int(exposure["active"]),
                        int(exposure["pending"]),
                        int(exposure["held"]),
                    )
                    maximum = int(partition["maximum_concurrency"])
                    if active >= maximum:
                        raise DispatchBlocked("request-time concurrency is saturated")
                    if active + pending >= 2 * maximum:
                        raise DispatchBlocked("financial exposure is saturated")
                    available = int(partition["allowance_microusd"]) - int(
                        partition["period_spend_microusd"]
                    )
                    if held + admission.reserved_microusd > available:
                        raise DispatchBlocked("spending authority is exhausted")

                    execution_id = uuid4()
                    inserted = connection.execute(
                        f"""
                        INSERT INTO tiamat.execution_records (
                            execution_id, issuer, caller_id, realm, environment, operation,
                            contract_major, partition_id, idempotency_key_digest, identity_digest,
                            digest_key_version, execution_profile_id, profile_release_id, state,
                            coordinator_generation, record_generation, lease_owner_id,
                            lease_expires_at, execution_deadline, eligibility_generation,
                            reserved_microusd, settlement_status, reconciliation_deadline,
                            tombstone_until
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            'admitted', %s, 1, %s, %s, %s, %s, %s,
                            'pending_reconciliation', %s, %s
                        )
                        RETURNING {_RECORD_COLUMNS}
                        """,
                        (
                            execution_id,
                            scope.issuer,
                            scope.caller_id,
                            scope.realm,
                            scope.environment,
                            admission.operation,
                            admission.contract_major,
                            scope.partition_id,
                            admission.idempotency_key_digest,
                            admission.identity_digest,
                            admission.digest_key_version,
                            admission.execution_profile_id,
                            admission.profile_release_id,
                            coordinator_generation,
                            admission.owner_id,
                            min(now + timedelta(seconds=5), admission.execution_deadline),
                            admission.execution_deadline,
                            admission.eligibility_generation,
                            admission.reserved_microusd,
                            admission.execution_deadline + timedelta(hours=24),
                            now + timedelta(minutes=10),
                        ),
                    ).fetchone()
                    assert inserted is not None
                    return LedgerRecord.from_row(inserted), True
        except (DispatchBlocked, DurableIdempotencyConflict):
            raise
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    def dispatch(
        self,
        scope: LedgerScope,
        execution_id: UUID,
        *,
        coordinator_generation: int,
        record_generation: int,
        owner_id: UUID,
    ) -> LedgerRecord:
        """Commit dispatched durably; only this returned record is send-eligible."""

        return self._cas_transition(
            scope,
            execution_id,
            expected_state="admitted",
            target_state="dispatched",
            coordinator_generation=coordinator_generation,
            record_generation=record_generation,
            owner_id=owner_id,
            extra_sql=(
                "dispatched_at = clock_timestamp(), "
                "lease_expires_at = execution_deadline + interval '30 seconds',"
            ),
        )

    def settle_terminal(
        self,
        scope: LedgerScope,
        execution_id: UUID,
        *,
        coordinator_generation: int,
        record_generation: int,
        owner_id: UUID,
        state: str,
        settled_microusd: int,
        failure_code: str | None = None,
    ) -> LedgerRecord:
        """Atomically settle a dispatched result and release its financial exposure."""

        if state not in {"completed", "failed"} or settled_microusd < 0:
            raise ValueError("terminal settlement is invalid")
        try:
            with psycopg.connect(  # noqa: SIM117 - transaction must begin after connection
                _psycopg_conninfo(self._database_url), row_factory=dict_row
            ) as connection:
                with connection.transaction():
                    _set_scope(connection, scope)
                    gate = connection.execute(
                        """
                        SELECT storage_epoch, recovery_generation, coordinator_generation,
                               dispatch_blocked
                        FROM tiamat.restore_gate
                        WHERE environment = %s
                        FOR SHARE
                        """,
                        (scope.environment,),
                    ).fetchone()
                    self._validate_gate(gate, coordinator_generation)
                    partition = connection.execute(
                        """
                        SELECT period_spend_microusd
                        FROM tiamat.spending_partitions
                        WHERE environment = %s AND caller_id = %s AND realm = %s
                          AND partition_id = %s
                        FOR UPDATE
                        """,
                        (
                            scope.environment,
                            scope.caller_id,
                            scope.realm,
                            scope.partition_id,
                        ),
                    ).fetchone()
                    if partition is None:
                        raise DispatchBlocked("spending partition is unavailable")
                    row = connection.execute(
                        f"""
                        UPDATE tiamat.execution_records
                        SET state = %s,
                            record_generation = record_generation + 1,
                            settlement_status = 'settled',
                            settled_microusd = %s,
                            failure_code = %s,
                            terminal_at = clock_timestamp(),
                            updated_at = clock_timestamp()
                        WHERE execution_id = %s AND issuer = %s AND caller_id = %s
                          AND realm = %s AND environment = %s AND state = 'dispatched'
                          AND coordinator_generation = %s AND record_generation = %s
                          AND lease_owner_id = %s AND %s <= reserved_microusd
                        RETURNING {_RECORD_COLUMNS}
                        """,
                        (
                            state,
                            settled_microusd,
                            failure_code,
                            execution_id,
                            scope.issuer,
                            scope.caller_id,
                            scope.realm,
                            scope.environment,
                            coordinator_generation,
                            record_generation,
                            owner_id,
                            settled_microusd,
                        ),
                    ).fetchone()
                    if row is None:
                        raise DurableFenceRejected
                    connection.execute(
                        """
                        UPDATE tiamat.spending_partitions
                        SET period_spend_microusd = period_spend_microusd + %s,
                            generation = generation + 1,
                            updated_at = clock_timestamp()
                        WHERE environment = %s AND caller_id = %s AND realm = %s
                          AND partition_id = %s
                        """,
                        (
                            settled_microusd,
                            scope.environment,
                            scope.caller_id,
                            scope.realm,
                            scope.partition_id,
                        ),
                    )
                    return LedgerRecord.from_row(row)
        except (DispatchBlocked, DurableFenceRejected):
            raise
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    def mark_outcome_unknown(
        self,
        scope: LedgerScope,
        execution_id: UUID,
        *,
        coordinator_generation: int,
        record_generation: int,
        owner_id: UUID,
    ) -> LedgerRecord:
        """Durably retain the reservation before returning an ambiguous outcome."""

        return self._cas_transition(
            scope,
            execution_id,
            expected_state="dispatched",
            target_state="outcome_unknown",
            coordinator_generation=coordinator_generation,
            record_generation=record_generation,
            owner_id=owner_id,
            extra_sql=(
                "settlement_status = 'pending_reconciliation', "
                "settled_microusd = NULL, "
                "failure_code = 'execution_outcome_unknown',"
            ),
        )

    def takeover_expired(
        self,
        scope: LedgerScope,
        execution_id: UUID,
        *,
        coordinator_generation: int,
        owner_id: UUID,
        now: datetime,
    ) -> LedgerRecord:
        """Adopt an expired live record under a strictly newer coordinator fence."""

        try:
            with psycopg.connect(  # noqa: SIM117 - transaction must begin after connection
                _psycopg_conninfo(self._database_url), row_factory=dict_row
            ) as connection:
                with connection.transaction():
                    _set_scope(connection, scope)
                    gate = connection.execute(
                        """
                        SELECT storage_epoch, recovery_generation, coordinator_generation,
                               dispatch_blocked
                        FROM tiamat.restore_gate
                        WHERE environment = %s
                        FOR SHARE
                        """,
                        (scope.environment,),
                    ).fetchone()
                    self._validate_gate(gate, coordinator_generation)
                    row = connection.execute(
                        f"""
                        UPDATE tiamat.execution_records
                        SET coordinator_generation = %s,
                            record_generation = record_generation + 1,
                            lease_owner_id = %s,
                            lease_expires_at = CASE state
                                WHEN 'admitted' THEN least(
                                    %s + interval '5 seconds', execution_deadline
                                )
                                ELSE execution_deadline + interval '30 seconds'
                            END,
                            updated_at = clock_timestamp()
                        WHERE execution_id = %s AND issuer = %s AND caller_id = %s
                          AND realm = %s AND environment = %s
                          AND state IN ('admitted', 'dispatched')
                          AND lease_expires_at <= %s
                          AND coordinator_generation < %s
                        RETURNING {_RECORD_COLUMNS}
                        """,
                        (
                            coordinator_generation,
                            owner_id,
                            now,
                            execution_id,
                            scope.issuer,
                            scope.caller_id,
                            scope.realm,
                            scope.environment,
                            now,
                            coordinator_generation,
                        ),
                    ).fetchone()
                    if row is None:
                        raise DurableFenceRejected
                    return LedgerRecord.from_row(row)
        except (DispatchBlocked, DurableFenceRejected):
            raise
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    def forfeit_due_reconciliations(
        self,
        scope: LedgerScope,
        *,
        now: datetime,
        coordinator_generation: int,
    ) -> tuple[LedgerRecord, ...]:
        """Charge full reservations after the 24-hour reconciliation deadline."""

        try:
            with psycopg.connect(  # noqa: SIM117 - transaction must begin after connection
                _psycopg_conninfo(self._database_url), row_factory=dict_row
            ) as connection:
                with connection.transaction():
                    _set_scope(connection, scope)
                    gate = connection.execute(
                        """
                        SELECT storage_epoch, recovery_generation, coordinator_generation,
                               dispatch_blocked
                        FROM tiamat.restore_gate
                        WHERE environment = %s
                        FOR SHARE
                        """,
                        (scope.environment,),
                    ).fetchone()
                    self._validate_gate(gate, coordinator_generation)
                    connection.execute(
                        """
                        SELECT period_spend_microusd
                        FROM tiamat.spending_partitions
                        WHERE environment = %s AND caller_id = %s AND realm = %s
                          AND partition_id = %s
                        FOR UPDATE
                        """,
                        (
                            scope.environment,
                            scope.caller_id,
                            scope.realm,
                            scope.partition_id,
                        ),
                    ).fetchone()
                    rows = connection.execute(
                        f"""
                        UPDATE tiamat.execution_records
                        SET settlement_status = 'reservation_forfeited',
                            settled_microusd = reserved_microusd,
                            coordinator_generation = %s,
                            record_generation = record_generation + 1,
                            tombstone_until = greatest(
                                tombstone_until, clock_timestamp() + interval '30 days'
                            ),
                            updated_at = clock_timestamp()
                        WHERE issuer = %s AND caller_id = %s AND realm = %s
                          AND environment = %s AND partition_id = %s
                          AND settlement_status = 'pending_reconciliation'
                          AND coordinator_generation <= %s
                          AND reconciliation_deadline <= %s
                        RETURNING {_RECORD_COLUMNS}
                        """,
                        (
                            coordinator_generation,
                            scope.issuer,
                            scope.caller_id,
                            scope.realm,
                            scope.environment,
                            scope.partition_id,
                            coordinator_generation,
                            now,
                        ),
                    ).fetchall()
                    charge = sum(int(row["settled_microusd"]) for row in rows)
                    if charge:
                        connection.execute(
                            """
                            UPDATE tiamat.spending_partitions
                            SET period_spend_microusd = period_spend_microusd + %s,
                                generation = generation + 1,
                                updated_at = clock_timestamp()
                            WHERE environment = %s AND caller_id = %s AND realm = %s
                              AND partition_id = %s
                            """,
                            (
                                charge,
                                scope.environment,
                                scope.caller_id,
                                scope.realm,
                                scope.partition_id,
                            ),
                        )
                    return tuple(LedgerRecord.from_row(row) for row in rows)
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    def reap_scope(
        self,
        scope: LedgerScope,
        *,
        now: datetime,
        coordinator_generation: int,
    ) -> tuple[LedgerRecord, ...]:
        """Apply authoritative expiry for one caller scope without bypassing RLS."""

        try:
            with psycopg.connect(  # noqa: SIM117 - transaction must begin after connection
                _psycopg_conninfo(self._database_url), row_factory=dict_row
            ) as connection:
                with connection.transaction():
                    _set_scope(connection, scope)
                    gate = connection.execute(
                        """
                        SELECT storage_epoch, recovery_generation, coordinator_generation,
                               dispatch_blocked
                        FROM tiamat.restore_gate
                        WHERE environment = %s
                        FOR SHARE
                        """,
                        (scope.environment,),
                    ).fetchone()
                    self._validate_gate(gate, coordinator_generation)
                    rows = connection.execute(
                        f"""
                        UPDATE tiamat.execution_records
                        SET state = CASE state
                                WHEN 'admitted' THEN 'failed'
                                ELSE 'outcome_unknown'
                            END,
                            coordinator_generation = %s,
                            record_generation = record_generation + 1,
                            settlement_status = CASE state
                                WHEN 'admitted' THEN 'settled'
                                ELSE 'pending_reconciliation'
                            END,
                            settled_microusd = CASE state
                                WHEN 'admitted' THEN 0
                                ELSE NULL
                            END,
                            failure_code = CASE state
                                WHEN 'admitted' THEN 'execution_aborted'
                                ELSE 'execution_outcome_unknown'
                            END,
                            terminal_at = CASE state
                                WHEN 'admitted' THEN clock_timestamp()
                                ELSE terminal_at
                            END,
                            updated_at = clock_timestamp()
                        WHERE issuer = %s AND caller_id = %s AND realm = %s
                          AND environment = %s AND state IN ('admitted', 'dispatched')
                          AND coordinator_generation <= %s
                          AND lease_expires_at <= %s
                        RETURNING {_RECORD_COLUMNS}
                        """,
                        (
                            coordinator_generation,
                            scope.issuer,
                            scope.caller_id,
                            scope.realm,
                            scope.environment,
                            coordinator_generation,
                            now,
                        ),
                    ).fetchall()
                    return tuple(LedgerRecord.from_row(row) for row in rows)
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    def _cas_transition(
        self,
        scope: LedgerScope,
        execution_id: UUID,
        *,
        expected_state: str,
        target_state: str,
        coordinator_generation: int,
        record_generation: int,
        owner_id: UUID,
        extra_sql: str,
    ) -> LedgerRecord:
        try:
            with psycopg.connect(  # noqa: SIM117 - transaction must begin after connection
                _psycopg_conninfo(self._database_url), row_factory=dict_row
            ) as connection:
                with connection.transaction():
                    _set_scope(connection, scope)
                    gate = connection.execute(
                        """
                        SELECT storage_epoch, recovery_generation, coordinator_generation,
                               dispatch_blocked
                        FROM tiamat.restore_gate
                        WHERE environment = %s
                        FOR SHARE
                        """,
                        (scope.environment,),
                    ).fetchone()
                    self._validate_gate(gate, coordinator_generation)
                    row = connection.execute(
                        f"""
                        UPDATE tiamat.execution_records
                        SET state = %s,
                            record_generation = record_generation + 1,
                            {extra_sql}
                            updated_at = clock_timestamp()
                        WHERE execution_id = %s AND issuer = %s AND caller_id = %s
                          AND realm = %s AND environment = %s
                          AND state = %s AND coordinator_generation = %s
                          AND record_generation = %s AND lease_owner_id = %s
                        RETURNING {_RECORD_COLUMNS}
                        """,
                        (
                            target_state,
                            execution_id,
                            scope.issuer,
                            scope.caller_id,
                            scope.realm,
                            scope.environment,
                            expected_state,
                            coordinator_generation,
                            record_generation,
                            owner_id,
                        ),
                    ).fetchone()
                    if row is None:
                        raise DurableFenceRejected
                    return LedgerRecord.from_row(row)
        except (DispatchBlocked, DurableFenceRejected):
            raise
        except psycopg.Error as exc:
            raise LedgerUnavailable from exc

    def _validate_gate(
        self, row: dict[str, Any] | None, coordinator_generation: int | None = None
    ) -> None:
        if row is None:
            raise DispatchBlocked("restore gate is not initialized")
        if (
            row["storage_epoch"] != self._witness.storage_epoch
            or int(row["recovery_generation"]) != self._witness.recovery_generation
            or bool(row["dispatch_blocked"])
        ):
            raise DispatchBlocked("restore authority is not current")
        if (
            coordinator_generation is not None
            and int(row["coordinator_generation"]) != coordinator_generation
        ):
            raise DurableFenceRejected


def _set_scope(connection: psycopg.Connection[Any], scope: LedgerScope) -> None:
    for setting, value in (
        ("tiamat.caller_id", scope.caller_id),
        ("tiamat.realm", scope.realm),
        ("tiamat.environment", scope.environment),
        ("tiamat.partition_id", scope.partition_id),
    ):
        connection.execute("SELECT set_config(%s, %s, true)", (setting, value))


def _psycopg_conninfo(database_url: str) -> str:
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


def _validate_partition(row: dict[str, Any] | None, reservation: int, now: datetime) -> None:
    if row is None or bool(row["blocked"]) or row["active_grant_release_id"] is None:
        raise DispatchBlocked("spending partition is blocked")
    if (
        row["revoked_at"] is not None
        or not row["not_before"] <= now < row["not_after"]
        or not row["period_start"] <= now < row["period_end"]
        or reservation > int(row["largest_per_call_microusd"])
    ):
        raise DispatchBlocked("spending grant is not applicable")
