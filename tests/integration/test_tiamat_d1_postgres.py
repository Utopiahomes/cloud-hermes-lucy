"""D1 verification against an explicitly disposable PostgreSQL 16 database.

This module never targets a commissioned ledger. Set TIAMAT_D1_TEST_DATABASE_URL
to a fresh database named ``tiamat_test_d1``; the database is destroyed after
the evidence run, not by this test module.
"""

from __future__ import annotations

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import token_urlsafe
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from psycopg import sql
from sqlalchemy.engine import make_url

from deploy.postgres.finalize_tiamat_d1_v1 import finalize_d1
from lucy.shared_execution.recovery import (
    AnchorFloorRecord,
    RecoveryRejected,
    authorize_reconciled_state,
    quarantine_environment,
)
from lucy.shared_execution.recovery_anchor import (
    InMemoryExternalRecoveryAnchor,
    PostgresContinuityBeacon,
    RecoveryAnchorIdentity,
    VerifiedAnchorTransition,
    VerifiedRecoveryWitness,
)
from lucy.shared_execution.recovery_checkpoint import construct_recovery_checkpoint
from lucy.shared_execution.startup_attestation import (
    RetainedCheckpoint,
    StartupAttestationIssuer,
)

TEST_DATABASE_NAME = "tiamat_test_d1"
TEST_DATABASE_PREFIX = f"{TEST_DATABASE_NAME}_"
ANCHOR_SHA256 = "a" * 64
CHECKPOINT_SHA256 = "b" * 64


@dataclass(frozen=True, repr=False)
class _DatabaseUrls:
    owner: str
    recovery: str
    runtime: str
    ledger_id: UUID

    def __repr__(self) -> str:
        return "_DatabaseUrls(credentials=redacted)"


def _url_for_role(owner_url: str, role: str, password: str) -> str:
    return (
        make_url(owner_url)
        .set(username=role, password=password)
        .render_as_string(hide_password=False)
    )


class _CheckpointSource:
    def read_checkpoint(self, identity: RecoveryAnchorIdentity) -> RetainedCheckpoint:
        return RetainedCheckpoint(
            checkpoint_sha256=CHECKPOINT_SHA256, release_inventory_installed=True
        )


def _is_explicit_disposable_database(owner_url: str) -> bool:
    database_name = make_url(owner_url).database
    if database_name == TEST_DATABASE_NAME:
        return True
    if database_name is None or not database_name.startswith(TEST_DATABASE_PREFIX):
        return False
    confirmation = os.environ.get("TIAMAT_M2_TEST_CONFIRMATION")
    return confirmation == f"m2-disposable:{database_name}"


def _migration_heads() -> tuple[str, ...]:
    configuration = Config(str(Path("tiamat_alembic.ini").resolve()))
    return tuple(sorted(ScriptDirectory.from_config(configuration).get_heads()))


def _migrate_to_head(owner_url: str) -> None:
    environment = os.environ.copy()
    environment["TIAMAT_MIGRATION_DATABASE_URL"] = owner_url
    completed = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "tiamat_alembic.ini", "upgrade", "head"],
        cwd=os.getcwd(),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        pytest.fail("M2 integration migration failed", pytrace=False)


@pytest.fixture(scope="module")
def database_urls() -> _DatabaseUrls:
    owner_url = os.environ.get("TIAMAT_D1_TEST_DATABASE_URL")
    if not owner_url:
        pytest.skip("TIAMAT_D1_TEST_DATABASE_URL is not configured")
    if not _is_explicit_disposable_database(owner_url):
        pytest.fail(
            "M2 integration requires tiamat_test_d1 or an explicitly confirmed disposable suffix",
            pytrace=False,
        )
    _migrate_to_head(owner_url)
    role_password = token_urlsafe(32)
    with psycopg.connect(owner_url, autocommit=True) as owner:
        version = int(owner.execute("SHOW server_version_num").fetchone()[0])
        assert 160000 <= version < 170000
        revision = owner.execute("SELECT version_num FROM tiamat.alembic_version").fetchone()
        assert revision == _migration_heads()
        for role in ("tiamat_runtime", "tiamat_recovery"):
            existing = owner.execute(
                "SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)
            ).fetchone()
            if existing is None:
                owner.execute(
                    sql.SQL(
                        "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
                        "NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}"
                    ).format(sql.Identifier(role), sql.Literal(role_password))
                )
            else:
                owner.execute(
                    sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(role_password)
                    )
                )
        database_name = make_url(owner_url).database
        assert database_name is not None
        owner.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO tiamat_runtime, tiamat_recovery").format(
                sql.Identifier(database_name)
            )
        )
        owner.execute("GRANT USAGE ON SCHEMA tiamat TO tiamat_runtime, tiamat_recovery")
        owner.execute("GRANT SELECT, INSERT, UPDATE ON tiamat.restore_gate TO tiamat_recovery")
        owner.execute("GRANT SELECT ON tiamat.ledger_identity TO tiamat_recovery")
        owner.execute(
            "GRANT SELECT (environment, settlement_status) "
            "ON tiamat.execution_records TO tiamat_recovery"
        )
        owner.execute(
            "GRANT SELECT ON tiamat.trust_inventories, tiamat.release_heads TO tiamat_recovery"
        )
        owner.execute(
            "GRANT UPDATE (activation_recovery_generation) "
            "ON tiamat.trust_inventories TO tiamat_recovery"
        )
        owner.execute(
            "GRANT UPDATE (recovery_generation) ON tiamat.release_heads TO tiamat_recovery"
        )
        ledger_id = owner.execute(
            "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
        ).fetchone()[0]
        owner.execute("SELECT set_config('tiamat.environment', 'd1-finalizer', false)")
        owner.execute(
            "INSERT INTO tiamat.restore_gate "
            "(environment, storage_epoch, recovery_generation, coordinator_generation, "
            "dispatch_blocked, block_reason) "
            "VALUES ('d1-finalizer', %s, 1, 1, true, 'test_only') ON CONFLICT DO NOTHING",
            (uuid4(),),
        )
    try:
        finalize_d1(owner_url, environment="d1-finalizer", expected_ledger_id=ledger_id)
    except Exception as exc:
        pytest.fail(f"D1 finalization failed: {type(exc).__name__}: {exc}", pytrace=False)
    return _DatabaseUrls(
        owner=owner_url,
        recovery=_url_for_role(owner_url, "tiamat_recovery", role_password),
        runtime=_url_for_role(owner_url, "tiamat_runtime", role_password),
        ledger_id=ledger_id,
    )


def _seed(
    urls: _DatabaseUrls,
    *,
    floor: bool = True,
    blocked: bool = False,
    attested: bool = True,
    expired: bool = False,
    system_identifier: str | None = None,
    timeline_id: int | None = None,
    flushed_lsn: str | None = None,
) -> str:
    environment = f"d1-{uuid4().hex}"
    storage_epoch = uuid4()
    with psycopg.connect(urls.recovery) as recovery:
        recovery.execute(
            "INSERT INTO tiamat.restore_gate "
            "(environment, storage_epoch, recovery_generation, coordinator_generation, "
            "dispatch_blocked, block_reason, verified_at, anchor_floor_version, "
            "anchor_floor_sha256) "
            "VALUES (%s, %s, 1, 1, %s, %s, %s, %s, %s)",
            (
                environment,
                storage_epoch,
                blocked,
                "test_only" if blocked else None,
                None if blocked else datetime.now(UTC),
                1 if floor else 0,
                ANCHOR_SHA256 if floor else None,
            ),
        )
        if attested:
            observed = recovery.execute(
                "SELECT (pg_catalog.pg_control_system()).system_identifier::text, "
                "(pg_catalog.pg_control_checkpoint()).timeline_id::bigint, "
                "pg_catalog.pg_current_wal_flush_lsn()::text"
            ).fetchone()
            assert observed is not None
            recovery.execute(
                "INSERT INTO tiamat.startup_attestations "
                "(environment, anchor_transition_sha256, anchor_transition_version, "
                "system_identifier, timeline_id, flushed_lsn, checkpoint_digest, "
                "ledger_id, storage_epoch, recovery_generation, expires_at) "
                "VALUES (%s, %s, 1, %s, %s, %s, %s, %s, %s, 1, %s)",
                (
                    environment,
                    ANCHOR_SHA256,
                    system_identifier or str(observed[0]),
                    timeline_id or int(observed[1]),
                    flushed_lsn or str(observed[2]),
                    CHECKPOINT_SHA256,
                    urls.ledger_id,
                    storage_epoch,
                    datetime.now(UTC) + timedelta(minutes=-1 if expired else 5),
                ),
            )
    return environment


def _consume(urls: _DatabaseUrls, environment: str) -> int:
    with psycopg.connect(urls.runtime) as runtime:
        runtime.execute("SELECT set_config('tiamat.environment', %s, true)", (environment,))
        row = runtime.execute(
            "SELECT tiamat.consume_startup_attestation_v2(%s)", (ANCHOR_SHA256,)
        ).fetchone()
        assert row is not None
        return int(row[0])


@pytest.mark.parametrize(
    ("options", "sqlstate"),
    [
        ({"attested": False}, "ZX101"),
        ({"floor": False}, "ZX102"),
        ({"blocked": True}, "ZX102"),
        ({"system_identifier": "0"}, "ZX103"),
        ({"timeline_id": 999999}, "ZX103"),
        ({"flushed_lsn": "FFFFFFFF/FFFFFFFF"}, "ZX104"),
    ],
)
def test_attestation_rejection_cases(
    database_urls: _DatabaseUrls, options: dict[str, Any], sqlstate: str
) -> None:
    environment = _seed(database_urls, **options)
    with pytest.raises(psycopg.Error) as rejected:
        _consume(database_urls, environment)
    assert rejected.value.sqlstate == sqlstate


def test_database_rejects_an_expired_claimant_at_write_time(
    database_urls: _DatabaseUrls,
) -> None:
    """M2's issuer-bound expiry trigger prevents malformed historical claimants."""

    environment = f"expired-{uuid4().hex}"
    storage_epoch = uuid4()
    with psycopg.connect(database_urls.recovery) as recovery:
        recovery.execute(
            """
            INSERT INTO tiamat.restore_gate
              (environment, storage_epoch, recovery_generation, coordinator_generation,
               dispatch_blocked, block_reason, anchor_floor_version, anchor_floor_sha256)
            VALUES (%s, %s, 1, 1, true, 'test_only', 1, %s)
            """,
            (environment, storage_epoch, ANCHOR_SHA256),
        )
        observed = recovery.execute(
            "SELECT (pg_catalog.pg_control_system()).system_identifier::text, "
            "(pg_catalog.pg_control_checkpoint()).timeline_id::bigint, "
            "pg_catalog.pg_current_wal_flush_lsn()::text"
        ).fetchone()
        assert observed is not None
        with pytest.raises(psycopg.DatabaseError, match="startup_attestation_expired") as rejected:
            recovery.execute(
                """
                INSERT INTO tiamat.startup_attestations
                  (environment, anchor_transition_sha256, anchor_transition_version,
                   system_identifier, timeline_id, flushed_lsn, checkpoint_digest,
                   ledger_id, storage_epoch, recovery_generation, expires_at)
                VALUES (%s, %s, 1, %s, %s, %s, %s, %s, %s, 1,
                        clock_timestamp() - interval '1 second')
                """,
                (
                    environment,
                    ANCHOR_SHA256,
                    str(observed[0]),
                    int(observed[1]),
                    str(observed[2]),
                    CHECKPOINT_SHA256,
                    database_urls.ledger_id,
                    storage_epoch,
                ),
            )
        assert rejected.value.sqlstate == "ZX105"


def test_database_overrides_a_future_caller_issuance_time(
    database_urls: _DatabaseUrls,
) -> None:
    """A recovery caller cannot turn a supplied future timestamp into extra authority."""

    environment = f"clock-{uuid4().hex}"
    storage_epoch = uuid4()
    with psycopg.connect(database_urls.recovery) as recovery:
        recovery.execute(
            """
            INSERT INTO tiamat.restore_gate
              (environment, storage_epoch, recovery_generation, coordinator_generation,
               dispatch_blocked, block_reason, anchor_floor_version, anchor_floor_sha256)
            VALUES (%s, %s, 1, 1, true, 'test_only', 1, %s)
            """,
            (environment, storage_epoch, ANCHOR_SHA256),
        )
        observed = recovery.execute(
            "SELECT (pg_catalog.pg_control_system()).system_identifier::text, "
            "(pg_catalog.pg_control_checkpoint()).timeline_id::bigint, "
            "pg_catalog.pg_current_wal_flush_lsn()::text"
        ).fetchone()
        assert observed is not None
        inserted = recovery.execute(
            """
            INSERT INTO tiamat.startup_attestations
              (environment, anchor_transition_sha256, anchor_transition_version,
               system_identifier, timeline_id, flushed_lsn, checkpoint_digest,
               ledger_id, storage_epoch, recovery_generation, created_at, expires_at)
            VALUES (%s, %s, 1, %s, %s, %s, %s, %s, %s, 1,
                    clock_timestamp() + interval '1 day', clock_timestamp() + interval '5 minutes')
            RETURNING created_at, expires_at
            """,
            (
                environment,
                ANCHOR_SHA256,
                str(observed[0]),
                int(observed[1]),
                str(observed[2]),
                CHECKPOINT_SHA256,
                database_urls.ledger_id,
                storage_epoch,
            ),
        ).fetchone()
    assert inserted is not None
    assert inserted[1] <= inserted[0] + timedelta(minutes=10)
    assert inserted[0] < datetime.now(UTC) + timedelta(minutes=1)
    with (
        psycopg.connect(database_urls.recovery) as recovery,
        pytest.raises(psycopg.DatabaseError) as rejected,
    ):
        recovery.execute(
            """
            UPDATE tiamat.startup_attestations
            SET expires_at = clock_timestamp() + interval '1 day'
            WHERE environment = %s
            """,
            (environment,),
        )
    assert rejected.value.sqlstate == "ZX106"


def test_runtime_anchor_digest_mismatch_does_not_consume_claimant(
    database_urls: _DatabaseUrls,
) -> None:
    environment = _seed(database_urls)
    other_digest = "f" * 64
    with psycopg.connect(database_urls.runtime) as runtime:
        runtime.execute("SELECT set_config('tiamat.environment', %s, true)", (environment,))
        with pytest.raises(psycopg.Error) as rejected:
            runtime.execute("SELECT tiamat.consume_startup_attestation_v2(%s)", (other_digest,))
        assert rejected.value.sqlstate == "ZX101"
    assert _consume(database_urls, environment) == 2


def test_one_successful_consumer_and_no_replay(database_urls: _DatabaseUrls) -> None:
    environment = _seed(database_urls)
    generation = _consume(database_urls, environment)
    assert generation == 2
    with psycopg.connect(database_urls.runtime) as runtime:
        runtime.execute("SELECT set_config('tiamat.environment', %s, true)", (environment,))
        current = runtime.execute(
            "SELECT tiamat.verify_attestation_current(%s)", (generation,)
        ).fetchone()
        assert current == (True,)
        with pytest.raises(psycopg.Error) as replay:
            runtime.execute("SELECT tiamat.consume_startup_attestation_v2(%s)", (ANCHOR_SHA256,))
        assert replay.value.sqlstate == "ZX101"


def test_runtime_cannot_update_restore_gate(database_urls: _DatabaseUrls) -> None:
    environment = _seed(database_urls)
    with psycopg.connect(database_urls.runtime) as runtime:
        runtime.execute("SELECT set_config('tiamat.environment', %s, true)", (environment,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime.execute(
                "UPDATE tiamat.restore_gate SET dispatch_blocked = false WHERE environment = %s",
                (environment,),
            )


def test_finalizer_postconditions_hold_on_postgresql_16(database_urls: _DatabaseUrls) -> None:
    with psycopg.connect(database_urls.owner) as owner:
        topology = owner.execute(
            "SELECT pg_has_role(current_user, 'tiamat_recovery', 'SET'), "
            "pg_has_role(current_user, 'tiamat_recovery', 'USAGE'), "
            "has_schema_privilege('tiamat_recovery', 'tiamat', 'CREATE'), "
            "has_table_privilege('tiamat_runtime', 'tiamat.restore_gate', 'UPDATE')"
        ).fetchone()
        assert topology == (False, False, False, False)
        for signature, must_execute in (
            ("tiamat.consume_startup_attestation(text)", False),
            ("tiamat.consume_startup_attestation_v2(text)", True),
            ("tiamat.verify_attestation_current(bigint)", True),
            ("tiamat.block_dispatch(text)", True),
        ):
            function_state = owner.execute(
                "SELECT pg_get_userbyid(proowner), "
                "has_function_privilege('tiamat_runtime', oid, 'EXECUTE') "
                "FROM pg_proc WHERE oid = to_regprocedure(%s)",
                (signature,),
            ).fetchone()
            assert function_state == ("tiamat_recovery", must_execute)


def test_two_concurrent_consumers_have_one_winner(database_urls: _DatabaseUrls) -> None:
    environment = _seed(database_urls)

    def attempt() -> tuple[str, int | str]:
        try:
            return ("won", _consume(database_urls, environment))
        except psycopg.Error as exc:
            return ("rejected", exc.sqlstate or "")

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(2)))
    assert sorted(outcomes) == [("rejected", "ZX101"), ("won", 2)]


def test_superseded_claimant_cannot_be_consumed(database_urls: _DatabaseUrls) -> None:
    environment = _seed(database_urls)
    with psycopg.connect(database_urls.recovery) as recovery:
        recovery.execute(
            "UPDATE tiamat.startup_attestations SET superseded_at = clock_timestamp() "
            "WHERE environment = %s AND consumed_at IS NULL",
            (environment,),
        )
    with pytest.raises(psycopg.Error) as rejected:
        _consume(database_urls, environment)
    assert rejected.value.sqlstate == "ZX101"


def test_advanced_anchor_floor_rejects_stale_attestation(database_urls: _DatabaseUrls) -> None:
    environment = _seed(database_urls)
    with psycopg.connect(database_urls.recovery) as recovery:
        recovery.execute(
            "UPDATE tiamat.restore_gate SET anchor_floor_version = 2, "
            "anchor_floor_sha256 = %s WHERE environment = %s",
            ("c" * 64, environment),
        )
    with pytest.raises(psycopg.Error) as rejected:
        _consume(database_urls, environment)
    assert rejected.value.sqlstate == "ZX102"


def test_changed_base_fence_rejects_attestation(database_urls: _DatabaseUrls) -> None:
    environment = _seed(database_urls)
    with psycopg.connect(database_urls.recovery) as recovery:
        recovery.execute(
            "UPDATE tiamat.restore_gate SET recovery_generation = 2 WHERE environment = %s",
            (environment,),
        )
    with pytest.raises(psycopg.Error) as rejected:
        _consume(database_urls, environment)
    assert rejected.value.sqlstate == "ZX102"


def test_one_way_block_invalidates_consumed_attestation(database_urls: _DatabaseUrls) -> None:
    environment = _seed(database_urls)
    generation = _consume(database_urls, environment)
    with psycopg.connect(database_urls.runtime) as runtime:
        runtime.execute("SELECT set_config('tiamat.environment', %s, true)", (environment,))
        runtime.execute("SELECT tiamat.block_dispatch('test_only')")
        current = runtime.execute(
            "SELECT tiamat.verify_attestation_current(%s)", (generation,)
        ).fetchone()
        assert current == (False,)


def test_m2_issuer_writes_real_floor_and_v2_claimant(database_urls: _DatabaseUrls) -> None:
    environment = f"m2-{uuid4().hex}"
    storage_epoch = uuid4()
    identity = RecoveryAnchorIdentity(environment, database_urls.ledger_id, storage_epoch)
    with psycopg.connect(database_urls.recovery) as recovery:
        recovery.execute(
            """
            INSERT INTO tiamat.restore_gate
              (environment, storage_epoch, recovery_generation, coordinator_generation,
               dispatch_blocked, verified_at, anchor_floor_version, anchor_floor_sha256)
            VALUES (%s, %s, 1, 1, false, clock_timestamp(), 0, NULL)
            """,
            (environment, storage_epoch),
        )
        observed = recovery.execute(
            """
            SELECT (pg_catalog.pg_control_system()).system_identifier::text,
                   (pg_catalog.pg_control_checkpoint()).timeline_id::bigint,
                   pg_catalog.pg_current_wal_flush_lsn()::text
            """
        ).fetchone()
    assert observed is not None
    now = datetime.now(UTC)
    witness = VerifiedRecoveryWitness(
        identity=identity,
        recovery_generation=1,
        witness_revision=1,
        status="reconciled",
        checkpoint_digest=CHECKPOINT_SHA256,
        release_heads_sha256="c" * 64,
        checkpoint_settlement_position_sha256="d" * 64,
        witness_inventory_digest="e" * 64,
        exact_jws=b"m2-integration-witness",
        not_before=now - timedelta(minutes=1),
        not_after=now + timedelta(minutes=30),
    )
    transition = VerifiedAnchorTransition(
        witness=witness,
        transition_version=1,
        previous_transition_sha256=None,
        continuity="continuity_established",
        beacon=PostgresContinuityBeacon(
            str(observed[0]), int(observed[1]), str(observed[2]), CHECKPOINT_SHA256
        ),
        exact_jws=b"m2-integration-transition",
    )
    anchor = InMemoryExternalRecoveryAnchor()
    anchor.install(transition, expected_transition_sha256=None, now=now)
    receipt = StartupAttestationIssuer(
        anchor=anchor,
        identity=identity,
        recovery_database_url=database_urls.recovery,
        checkpoint_source=_CheckpointSource(),
    ).issue(now=now)
    with psycopg.connect(database_urls.recovery) as recovery:
        gate = recovery.execute(
            """
            SELECT anchor_floor_version, anchor_floor_sha256
            FROM tiamat.restore_gate WHERE environment = %s
            """,
            (environment,),
        ).fetchone()
        attestation = recovery.execute(
            """
            SELECT created_at, expires_at FROM tiamat.startup_attestations
            WHERE attestation_id = %s
            """,
            (receipt.attestation_id,),
        ).fetchone()
    assert gate == (1, transition.exact_sha256)
    assert attestation is not None
    assert attestation[1] <= attestation[0] + timedelta(minutes=10)
    with psycopg.connect(database_urls.runtime) as runtime:
        runtime.execute("SELECT set_config('tiamat.environment', %s, true)", (environment,))
        generation = runtime.execute(
            "SELECT tiamat.consume_startup_attestation_v2(%s)", (transition.exact_sha256,)
        ).fetchone()
    assert generation == (2,)


def _gate_floor(urls: _DatabaseUrls, environment: str) -> tuple[Any, ...] | None:
    with psycopg.connect(urls.recovery) as recovery:
        return recovery.execute(
            """
            SELECT anchor_floor_version, anchor_floor_sha256, dispatch_blocked
            FROM tiamat.restore_gate WHERE environment = %s
            """,
            (environment,),
        ).fetchone()


def test_quarantine_advances_the_anchor_floor_it_was_performed_under(
    database_urls: _DatabaseUrls,
) -> None:
    environment = _seed(database_urls)
    quarantine_environment(
        database_urls.recovery,
        environment=environment,
        reason="restore_review",
        anchor_floor=AnchorFloorRecord(transition_version=2, transition_sha256="c" * 64),
    )

    assert _gate_floor(database_urls, environment) == (2, "c" * 64, True)
    # The superseded transition is exactly what a rollback would replay.
    with psycopg.connect(database_urls.runtime) as runtime:
        runtime.execute("SELECT set_config('tiamat.environment', %s, true)", (environment,))
        with pytest.raises(psycopg.Error) as rejected:
            runtime.execute(
                "SELECT tiamat.consume_startup_attestation_v2(%s)", (ANCHOR_SHA256,)
            )
    assert rejected.value.sqlstate == "ZX102"


def test_quarantine_refuses_to_lower_the_anchor_floor(database_urls: _DatabaseUrls) -> None:
    environment = _seed(database_urls)
    quarantine_environment(
        database_urls.recovery,
        environment=environment,
        reason="restore_review",
        anchor_floor=AnchorFloorRecord(transition_version=3, transition_sha256="c" * 64),
    )

    with pytest.raises(RecoveryRejected, match="anchor floor cannot move backward"):
        quarantine_environment(
            database_urls.recovery,
            environment=environment,
            reason="restore_review",
            anchor_floor=AnchorFloorRecord(transition_version=2, transition_sha256="d" * 64),
        )

    assert _gate_floor(database_urls, environment) == (3, "c" * 64, True)


def test_quarantine_on_a_d1_ledger_requires_an_anchor_floor(
    database_urls: _DatabaseUrls,
) -> None:
    environment = _seed(database_urls)
    with pytest.raises(RecoveryRejected, match="anchor floor record is required"):
        quarantine_environment(
            database_urls.recovery, environment=environment, reason="restore_review"
        )

    assert _gate_floor(database_urls, environment) == (1, ANCHOR_SHA256, False)


def test_authorize_advances_the_anchor_floor_and_unblocks(
    database_urls: _DatabaseUrls,
) -> None:
    environment = _seed(database_urls, blocked=True)
    with psycopg.connect(database_urls.recovery) as recovery:
        storage_epoch = recovery.execute(
            "SELECT storage_epoch FROM tiamat.restore_gate WHERE environment = %s",
            (environment,),
        ).fetchone()
    assert storage_epoch is not None
    identity = RecoveryAnchorIdentity(
        environment,
        database_urls.ledger_id,
        UUID(str(storage_epoch[0])),
    )
    checkpoint = construct_recovery_checkpoint(
        {
            "environment": environment,
            "ledger_id": str(database_urls.ledger_id),
            "storage_epoch": str(storage_epoch[0]),
            "recovery_generation": 2,
            "release_inventory": {"generation": 1, "jws_sha256": "f" * 64},
            "release_heads": [],
            "settlement_position": [],
        },
        identity=identity,
    )

    authorize_reconciled_state(
        database_urls.recovery,
        environment=environment,
        expected_storage_epoch=storage_epoch[0],
        current_recovery_generation=1,
        next_recovery_generation=2,
        unresolved_provider_liabilities=0,
        anchor_floor=AnchorFloorRecord(transition_version=4, transition_sha256="e" * 64),
        checkpoint=checkpoint,
    )

    assert _gate_floor(database_urls, environment) == (4, "e" * 64, False)
