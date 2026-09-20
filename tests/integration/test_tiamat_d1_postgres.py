"""D1 verification against an explicitly disposable PostgreSQL 16 database.

This module never targets a commissioned ledger. Set TIAMAT_D1_TEST_DATABASE_URL
to a fresh database named ``tiamat_test_d1``; the database is destroyed after
the evidence run, not by this test module.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg import sql
from sqlalchemy.engine import make_url

from deploy.postgres.finalize_tiamat_d1_v1 import finalize_d1

TEST_DATABASE_NAME = "tiamat_test_d1"
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
    return make_url(owner_url).set(username=role, password=password).render_as_string(
        hide_password=False
    )


@pytest.fixture(scope="module")
def database_urls() -> _DatabaseUrls:
    owner_url = os.environ.get("TIAMAT_D1_TEST_DATABASE_URL")
    if not owner_url:
        pytest.skip("TIAMAT_D1_TEST_DATABASE_URL is not configured")
    if make_url(owner_url).database != TEST_DATABASE_NAME:
        pytest.fail("D1 integration test requires exact disposable tiamat_test_d1 database")
    role_password = token_urlsafe(32)
    with psycopg.connect(owner_url, autocommit=True) as owner:
        version = int(owner.execute("SHOW server_version_num").fetchone()[0])
        assert 160000 <= version < 170000
        revision = owner.execute("SELECT version_num FROM tiamat.alembic_version").fetchone()
        assert revision == ("0007_startup_attestation",)
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
        owner.execute("GRANT CONNECT ON DATABASE tiamat_test_d1 TO tiamat_runtime, tiamat_recovery")
        owner.execute("GRANT USAGE ON SCHEMA tiamat TO tiamat_runtime, tiamat_recovery")
        owner.execute("GRANT SELECT, INSERT, UPDATE ON tiamat.restore_gate TO tiamat_recovery")
        owner.execute("GRANT SELECT ON tiamat.ledger_identity TO tiamat_recovery")
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
        function_owner = owner.execute(
            "SELECT pg_get_userbyid(proowner) FROM pg_proc "
            "WHERE oid = to_regprocedure('tiamat.consume_startup_attestation(text)')"
        ).fetchone()[0]
    if function_owner != "tiamat_recovery":
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
            "SELECT tiamat.consume_startup_attestation(%s)", (ANCHOR_SHA256,)
        ).fetchone()
        assert row is not None
        return int(row[0])


@pytest.mark.parametrize(
    ("options", "sqlstate"),
    [
        ({"attested": False}, "ZX101"),
        ({"expired": True}, "ZX101"),
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
            runtime.execute("SELECT tiamat.consume_startup_attestation(%s)", (ANCHOR_SHA256,))
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
        for signature in (
            "tiamat.consume_startup_attestation(text)",
            "tiamat.verify_attestation_current(bigint)",
            "tiamat.block_dispatch(text)",
        ):
            function_state = owner.execute(
                "SELECT pg_get_userbyid(proowner), "
                "has_function_privilege('tiamat_runtime', oid, 'EXECUTE') "
                "FROM pg_proc WHERE oid = to_regprocedure(%s)",
                (signature,),
            ).fetchone()
            assert function_state == ("tiamat_recovery", True)


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
