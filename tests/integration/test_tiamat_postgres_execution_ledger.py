from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url

from lucy.shared_execution.auth import AuthenticationStateUnavailable
from lucy.shared_execution.postgres_ledger import (
    LedgerAdmission,
    LedgerScope,
    PostgresExecutionLedger,
    PostgresJtiReplayStore,
    RecoveryWitness,
)

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DATABASE_URL = os.environ.get("TIAMAT_TEST_DATABASE_URL")


@pytest.fixture(scope="module")
def database_url() -> str:
    if DATABASE_URL is None:
        pytest.skip("TIAMAT_TEST_DATABASE_URL is not configured")
    parsed = make_url(DATABASE_URL)
    if parsed.database is None or not parsed.database.startswith("tiamat_test"):
        pytest.fail("TIAMAT_TEST_DATABASE_URL must name a disposable tiamat_test* database")
    config = Config(os.path.join(ROOT, "tiamat_alembic.ini"))
    config.set_main_option("script_location", os.path.join(ROOT, "tiamat_migrations"))
    config.set_main_option("sqlalchemy.url", DATABASE_URL)
    command.upgrade(config, "head")
    return DATABASE_URL


def _seed(database_url: str) -> tuple[LedgerScope, RecoveryWitness, datetime]:
    suffix = uuid4().hex
    environment = f"test-{suffix}"
    partition = f"partition-{suffix}"
    caller = f"stoin:synth:test-{suffix}"
    epoch = uuid4()
    now = datetime.now(UTC)
    with psycopg.connect(database_url) as connection:
        connection.execute("SELECT set_config('tiamat.environment', %s, false)", (environment,))
        connection.execute("SELECT set_config('tiamat.partition_id', %s, false)", (partition,))
        connection.execute("SELECT set_config('tiamat.caller_id', %s, false)", (caller,))
        connection.execute("SELECT set_config('tiamat.realm', 'test-realm', false)")
        connection.execute(
            """
            INSERT INTO tiamat.restore_gate (
              environment, storage_epoch, recovery_generation, coordinator_generation,
              dispatch_blocked, block_reason, verified_at
            ) VALUES (%s, %s, 1, 1, false, NULL, clock_timestamp())
            """,
            (environment, epoch),
        )
        connection.execute(
            """
            INSERT INTO tiamat.spending_partitions (
              environment, caller_id, realm, partition_id, allowance_microusd,
              contingency_reserve_microusd, maximum_concurrency,
              largest_per_call_microusd, blocked
            ) VALUES (%s, %s, 'test-realm', %s, 20000, 8000, 2, 2000, false)
            """,
            (environment, caller, partition),
        )
        connection.execute(
            """
            INSERT INTO tiamat.grant_releases (
              release_id, environment, caller_id, realm, partition_id, budget_period_id,
              not_before, not_after, period_start, period_end,
              allowance_microusd, maximum_concurrency, largest_per_call_microusd,
              contingency_reserve_microusd, signed_artifact_digest, activated_at
            ) VALUES (
              %s, %s, %s, 'test-realm', %s, %s, %s, %s, %s, %s,
              20000, 2, 2000, 8000, %s,
              clock_timestamp()
            )
            """,
            (
                f"grant-{suffix}",
                environment,
                caller,
                partition,
                f"period-{suffix}",
                now - timedelta(hours=1),
                now + timedelta(hours=36),
                now - timedelta(hours=12),
                now + timedelta(hours=12),
                "a" * 64,
            ),
        )
        connection.execute(
            """
            UPDATE tiamat.spending_partitions
            SET active_grant_release_id = %s, budget_period_id = %s
            WHERE environment = %s AND caller_id = %s AND realm = 'test-realm'
              AND partition_id = %s
            """,
            (f"grant-{suffix}", f"period-{suffix}", environment, caller, partition),
        )
    return (
        LedgerScope("https://test.internal", caller, "test-realm", environment, partition),
        RecoveryWitness(environment, epoch, 1),
        now,
    )


def test_durable_replay_fencing_and_cross_scope_isolation(database_url: str) -> None:
    scope, witness, now = _seed(database_url)
    replay = PostgresJtiReplayStore(database_url)
    namespace = (scope.issuer, scope.caller_id, scope.realm, scope.environment)
    jti = uuid4()
    assert replay.consume(namespace, jti, int((now + timedelta(minutes=10)).timestamp()))
    assert not replay.consume(namespace, jti, int((now + timedelta(minutes=10)).timestamp()))

    ledger = PostgresExecutionLedger(database_url, witness)
    coordinator = ledger.acquire_coordinator_generation()
    owner = uuid4()
    record, created = ledger.create_or_get(
        scope,
        LedgerAdmission(
            idempotency_key_digest="b" * 64,
            identity_digest="c" * 64,
            digest_key_version="digest-v1",
            operation="inference.execute",
            contract_major=1,
            execution_profile_id="profile.v1",
            profile_release_id="profiles.1",
            owner_id=owner,
            execution_deadline=now + timedelta(seconds=15),
            eligibility_generation=1,
            reserved_microusd=2_000,
        ),
        coordinator_generation=coordinator,
        now=now,
    )
    assert created and record.state == "admitted"
    dispatched = ledger.dispatch(
        scope,
        record.execution_id,
        coordinator_generation=coordinator,
        record_generation=record.record_generation,
        owner_id=owner,
    )
    settled = ledger.settle_terminal(
        scope,
        dispatched.execution_id,
        coordinator_generation=coordinator,
        record_generation=dispatched.record_generation,
        owner_id=owner,
        state="completed",
        settled_microusd=20,
    )
    assert settled.state == "completed"
    assert settled.settled_microusd == 20

    with psycopg.connect(database_url) as connection:
        connection.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (scope.environment,)
        )
        connection.execute("SELECT set_config('tiamat.realm', 'wrong-realm', false)")
        connection.execute("SELECT set_config('tiamat.caller_id', %s, false)", (scope.caller_id,))
        hidden = connection.execute(
            "SELECT count(*) FROM tiamat.execution_records WHERE execution_id = %s",
            (record.execution_id,),
        ).fetchone()
        assert hidden is not None and int(hidden[0]) == 0


def test_unreachable_database_fails_replay_state_closed() -> None:
    replay = PostgresJtiReplayStore("postgresql://none:none@127.0.0.1:1/nope?connect_timeout=1")
    with pytest.raises(AuthenticationStateUnavailable):
        replay.consume(("issuer", "caller", "realm", "test"), uuid4(), 1)
