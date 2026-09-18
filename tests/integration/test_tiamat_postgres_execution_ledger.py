from __future__ import annotations

import base64
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from psycopg import sql
from psycopg.rows import dict_row
from sqlalchemy.engine import make_url

from lucy.shared_execution.auth import AuthenticationStateUnavailable
from lucy.shared_execution.postgres_authority import (
    AuthorityScope,
    AuthorityTransitionRejected,
    PostgresSignedAuthorityStore,
)
from lucy.shared_execution.postgres_ledger import (
    DispatchBlocked,
    DurableFenceRejected,
    LedgerAdmission,
    LedgerScope,
    LedgerUnavailable,
    PostgresExecutionLedger,
    PostgresJtiReplayStore,
    RecoveryWitness,
)
from lucy.shared_execution.recovery import (
    RecoveryRejected,
    authorize_reconciled_state,
    quarantine_environment,
)
from lucy.shared_execution.signed_releases import (
    load_authorized_profile,
    verify_release,
    verify_trust_inventory,
)

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DATABASE_URL = os.environ.get("TIAMAT_TEST_DATABASE_URL")
BUNDLE = os.path.join(ROOT, "contracts", "tiamat-signed-release-v1-rc1-bundle")


@pytest.fixture(scope="module")
def database_urls() -> tuple[str, str]:
    if DATABASE_URL is None:
        pytest.skip("TIAMAT_TEST_DATABASE_URL is not configured")
    parsed = make_url(DATABASE_URL)
    if parsed.database is None or not parsed.database.startswith("tiamat_test"):
        pytest.fail("TIAMAT_TEST_DATABASE_URL must name a disposable tiamat_test* database")
    config = Config(os.path.join(ROOT, "tiamat_alembic.ini"))
    config.set_main_option("script_location", os.path.join(ROOT, "tiamat_migrations"))
    config.set_main_option(
        "sqlalchemy.url", DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
    )
    command.upgrade(config, "head")
    runtime_url = DATABASE_URL.replace(
        "tiamat_migration:synthetic-tiamat-only",
        "tiamat_runtime_test:synthetic-runtime-only",
    )
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute(
            """
            DO $bootstrap$
            BEGIN
              IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tiamat_runtime_test') THEN
                CREATE ROLE tiamat_runtime_test LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
                  NOCREATEROLE NOREPLICATION NOBYPASSRLS
                  PASSWORD 'synthetic-runtime-only';
              END IF;
            END
            $bootstrap$
            """
        )
        connection.execute("GRANT CONNECT ON DATABASE tiamat_test TO tiamat_runtime_test")
        connection.execute("GRANT USAGE ON SCHEMA tiamat TO tiamat_runtime_test")
        connection.execute(
            """
            GRANT SELECT, INSERT, UPDATE, DELETE ON
              tiamat.jti_replay, tiamat.spending_partitions,
              tiamat.execution_records, tiamat.grant_releases,
              tiamat.route_rate_quarantines, tiamat.financial_events
            TO tiamat_runtime_test
            """
        )
        connection.execute("GRANT SELECT, UPDATE ON tiamat.restore_gate TO tiamat_runtime_test")
    return DATABASE_URL, runtime_url


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


def _admission(
    now: datetime,
    *,
    key_digest: str,
    identity_digest: str = "c" * 64,
    owner_id: UUID | None = None,
) -> LedgerAdmission:
    return LedgerAdmission(
        idempotency_key_digest=key_digest,
        identity_digest=identity_digest,
        digest_key_version="digest-v1",
        operation="inference.execute",
        contract_major=1,
        execution_profile_id="profile.v1",
        profile_release_id="profiles.1",
        provider_route_id="vertex-gemini-primary",
        rate_release_id="rates.2026-09-17",
        owner_id=owner_id or uuid4(),
        execution_deadline=now + timedelta(seconds=15),
        eligibility_generation=1,
        reserved_microusd=2_000,
    )


def _bundle_json(*parts: str) -> dict[str, Any]:
    with open(os.path.join(BUNDLE, *parts), encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict)
    return value


def _sign_synthetic_release(payload: dict[str, Any]) -> bytes:
    header = json.dumps(
        {
            "alg": "EdDSA",
            "kid": "release-key-staging-1",
            "typ": "stoin-signed-release+jws",
        },
        separators=(",", ":"),
    ).encode()
    body = json.dumps(payload, separators=(",", ":")).encode()

    def encoded(value: bytes) -> bytes:
        return base64.urlsafe_b64encode(value).rstrip(b"=")

    signing = encoded(header) + b"." + encoded(body)
    signature = Ed25519PrivateKey.from_private_bytes(bytes(range(32))).sign(signing)
    return signing + b"." + encoded(signature)


def test_signed_authority_stages_activates_and_loads_exact_bytes(
    database_urls: tuple[str, str],
) -> None:
    migration_url, _ = database_urls
    keys = _bundle_json("test-keys.json")
    root_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(keys["root_public_key_b64"]))
    inventory_vector = _bundle_json("vectors", "positive", "inventory.pos.bootstrap.json")
    inventory_jws = inventory_vector["compact_jws"].encode()
    inventory = verify_trust_inventory(
        inventory_jws,
        root_key_id="tiamat-trust-root-staging-1",
        root_public_key=root_key,
        environment="staging",
    )
    store = PostgresSignedAuthorityStore(migration_url)
    inventory_digest = hashlib.sha256(inventory_jws).hexdigest()
    store.stage_inventory(inventory_jws, inventory, inventory_digest)
    store.stage_inventory(inventory_jws, inventory, inventory_digest)
    with pytest.raises(AuthorityTransitionRejected, match="recovery_gate_blocked"):
        store.activate_inventory("staging", 1)
    staging_epoch = uuid4()
    with psycopg.connect(migration_url) as connection:
        connection.execute("SELECT set_config('tiamat.environment', 'staging', true)")
        connection.execute(
            """
            INSERT INTO tiamat.restore_gate (
              environment, storage_epoch, recovery_generation, coordinator_generation,
              dispatch_blocked, block_reason, verified_at
            ) VALUES ('staging', %s, 1, 1, false, NULL, clock_timestamp())
            """,
            (staging_epoch,),
        )
        connection.execute(
            "SELECT set_config('tiamat.caller_id', %s, true)", ("stoin:synth:utopia-homes",)
        )
        connection.execute("SELECT set_config('tiamat.realm', 'utopia-homes', true)")
        connection.execute("SELECT set_config('tiamat.partition_id', 'utopia-public', true)")
        connection.execute(
            """
            INSERT INTO tiamat.spending_partitions (
              environment, caller_id, realm, partition_id, blocked, block_reason
            ) VALUES (
              'staging', 'stoin:synth:utopia-homes', 'utopia-homes',
              'utopia-public', true, 'no_active_grant'
            )
            """
        )
    store.activate_inventory("staging", 1)

    profile_vector = _bundle_json("vectors", "positive", "release.pos.execution-profile.json")
    profile_jws = profile_vector["compact_jws"].encode()
    profile = verify_release(
        profile_jws,
        inventory=inventory,
        expected_issuer="stoin-control",
        expected_environment="staging",
        expected_caller_id="stoin:synth:utopia-homes",
        expected_realm="utopia-homes",
        now=datetime(2026, 9, 18, 12, tzinfo=UTC),
    )
    store.stage_release(profile, "release-key-staging-1")
    store.stage_release(profile, "release-key-staging-1")
    scope = AuthorityScope("staging", "stoin-control", "stoin:synth:utopia-homes", "utopia-homes")
    store.activate_release(
        scope,
        "execution_profile",
        "utopia-homes.public-answer.generate.v1",
        "profiles-2026-09-17.1",
    )
    assert (
        store.load_active_jws(scope, "execution_profile", "utopia-homes.public-answer.generate.v1")
        == profile_jws
    )
    privacy_vector = _bundle_json("vectors", "positive", "release.pos.privacy-policy.json")
    privacy = verify_release(
        privacy_vector["compact_jws"].encode(),
        inventory=inventory,
        expected_issuer="stoin-control",
        expected_environment="staging",
        expected_caller_id="stoin:synth:utopia-homes",
        expected_realm="utopia-homes",
        now=datetime(2026, 9, 18, 12, tzinfo=UTC),
    )
    store.stage_release(privacy, "release-key-staging-1")
    store.activate_release(scope, "privacy_policy", "utopia-public-zdr", privacy.payload.release_id)
    revocation_vector = _bundle_json("vectors", "positive", "release.pos.release-revocation.json")
    revocation = verify_release(
        revocation_vector["compact_jws"].encode(),
        inventory=inventory,
        expected_issuer="stoin-control",
        expected_environment="staging",
        expected_caller_id="stoin:synth:utopia-homes",
        expected_realm="utopia-homes",
        now=datetime(2026, 9, 18, 12, tzinfo=UTC),
    )
    store.stage_release(revocation, "release-key-staging-1")
    store.activate_release(
        scope,
        "revocation",
        "utopia-public-revocations",
        revocation.payload.release_id,
    )
    store.apply_revocation(scope, revocation)
    store.apply_revocation(scope, revocation)
    with pytest.raises(AuthorityTransitionRejected, match="active_release_unavailable"):
        store.load_active_jws(scope, "privacy_policy", "utopia-public-zdr")

    grant_vector = _bundle_json("vectors", "positive", "release.pos.spending-grant.json")
    grant = verify_release(
        grant_vector["compact_jws"].encode(),
        inventory=inventory,
        expected_issuer="stoin-control",
        expected_environment="staging",
        expected_caller_id="stoin:synth:utopia-homes",
        expected_realm="utopia-homes",
        now=datetime(2026, 9, 18, 12, tzinfo=UTC),
    )
    store.stage_release(grant, "release-key-staging-1")
    with pytest.raises(AuthorityTransitionRejected, match="release_not_successor"):
        store.activate_release(scope, "spending_grant", "utopia-public", grant.payload.release_id)

    bootstrap_payload = _bundle_json("examples", "spending-grant.json")
    bootstrap_payload["release_id"] = "grant-utopia-public-2026-09-17.1"
    bootstrap_payload["sequence"] = 1
    bootstrap_payload["predecessor_release_id"] = None
    bootstrap_jws = _sign_synthetic_release(bootstrap_payload)
    bootstrap = verify_release(
        bootstrap_jws,
        inventory=inventory,
        expected_issuer="stoin-control",
        expected_environment="staging",
        expected_caller_id="stoin:synth:utopia-homes",
        expected_realm="utopia-homes",
        now=datetime(2026, 9, 18, 12, tzinfo=UTC),
    )
    store.stage_release(bootstrap, "release-key-staging-1")
    store.activate_release(scope, "spending_grant", "utopia-public", bootstrap.payload.release_id)
    store.activate_release(scope, "spending_grant", "utopia-public", grant.payload.release_id)
    with psycopg.connect(migration_url, row_factory=dict_row) as connection:
        connection.execute("SELECT set_config('tiamat.environment', 'staging', true)")
        connection.execute("SELECT set_config('tiamat.caller_id', %s, true)", (scope.caller_id,))
        connection.execute("SELECT set_config('tiamat.realm', %s, true)", (scope.realm,))
        connection.execute("SELECT set_config('tiamat.partition_id', 'utopia-public', true)")
        projected = connection.execute(
            """
            SELECT active_grant_release_id, budget_period_id, allowance_microusd,
                   maximum_concurrency, largest_per_call_microusd, blocked
            FROM tiamat.spending_partitions
            WHERE environment = 'staging' AND caller_id = %s AND realm = %s
              AND partition_id = 'utopia-public'
            """,
            (scope.caller_id, scope.realm),
        ).fetchone()
    assert projected is not None
    assert projected["active_grant_release_id"] == grant.payload.release_id
    assert projected["allowance_microusd"] == 3_000_000
    assert projected["maximum_concurrency"] == 2
    assert projected["largest_per_call_microusd"] == 2_000
    assert projected["blocked"] is False
    quarantine_environment(migration_url, environment="staging", reason="restore_test")
    with pytest.raises(RecoveryRejected, match="external confirmation"):
        authorize_reconciled_state(
            migration_url,
            environment="staging",
            expected_storage_epoch=staging_epoch,
            current_recovery_generation=1,
            next_recovery_generation=2,
            unresolved_provider_liabilities=0,
        )
    expected_heads = {
        (
            "stoin-control",
            "stoin:synth:utopia-homes",
            "utopia-homes",
            "execution_profile",
            "utopia-homes.public-answer.generate.v1",
        ): (profile.jws_sha256, "active"),
        (
            "stoin-control",
            "stoin:synth:utopia-homes",
            "utopia-homes",
            "privacy_policy",
            "utopia-public-zdr",
        ): (privacy.jws_sha256, "revoked"),
        (
            "stoin-control",
            "stoin:synth:utopia-homes",
            "utopia-homes",
            "revocation",
            "utopia-public-revocations",
        ): (revocation.jws_sha256, "active"),
        (
            "stoin-control",
            "stoin:synth:utopia-homes",
            "utopia-homes",
            "spending_grant",
            "utopia-public",
        ): (grant.jws_sha256, "active"),
    }
    authorize_reconciled_state(
        migration_url,
        environment="staging",
        expected_storage_epoch=staging_epoch,
        current_recovery_generation=1,
        next_recovery_generation=2,
        unresolved_provider_liabilities=0,
        expected_inventory=(1, inventory_digest),
        expected_release_heads=expected_heads,
    )
    assert (
        store.load_active_jws(scope, "execution_profile", "utopia-homes.public-answer.generate.v1")
        == profile_jws
    )
    with pytest.raises(AuthorityTransitionRejected, match="active_release_unavailable"):
        load_authorized_profile(
            store,
            scope=scope,
            root_key_id="tiamat-trust-root-staging-1",
            root_public_key=root_key,
            issuer="stoin-control",
            environment="staging",
            caller_id="stoin:synth:utopia-homes",
            realm="utopia-homes",
            profile_id="utopia-homes.public-answer.generate.v1",
            partition_id="utopia-public",
            now=datetime(2026, 9, 18, 12, tzinfo=UTC),
        )


def test_durable_replay_fencing_and_cross_scope_isolation(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, now = _seed(owner_url)
    replay = PostgresJtiReplayStore(runtime_url)
    namespace = (scope.issuer, scope.caller_id, scope.realm, scope.environment)
    jti = uuid4()
    assert replay.consume(namespace, jti, int((now + timedelta(minutes=10)).timestamp()))
    assert not replay.consume(namespace, jti, int((now + timedelta(minutes=10)).timestamp()))

    ledger = PostgresExecutionLedger(runtime_url, witness)
    coordinator = ledger.acquire_coordinator_generation()
    owner = uuid4()
    admission = _admission(now, key_digest="b" * 64, owner_id=owner)
    record, created = ledger.create_or_get(
        scope,
        admission,
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

    with psycopg.connect(runtime_url) as connection:
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


def test_concurrent_first_admission_creates_exactly_one_record(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, now = _seed(owner_url)
    ledger = PostgresExecutionLedger(runtime_url, witness)
    coordinator = ledger.acquire_coordinator_generation()
    admission = _admission(now, key_digest="d" * 64)

    def admit() -> tuple[str, bool]:
        record, created = ledger.create_or_get(
            scope, admission, coordinator_generation=coordinator, now=now
        )
        return str(record.execution_id), created

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _index: admit(), range(2)))
    assert {execution_id for execution_id, _created in results} == {results[0][0]}
    assert sorted(created for _execution_id, created in results) == [False, True]


def test_connection_loss_inside_dispatch_transaction_rolls_back_state(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, now = _seed(owner_url)
    base_ledger = PostgresExecutionLedger(runtime_url, witness)
    coordinator = base_ledger.acquire_coordinator_generation()
    owner = uuid4()
    admitted, _ = base_ledger.create_or_get(
        scope,
        _admission(now, key_digest="0" * 64, owner_id=owner),
        coordinator_generation=coordinator,
        now=now,
    )
    reached, release = Event(), Event()
    backend_pid: list[int] = []

    def probe(name: str, connection: psycopg.Connection[Any]) -> None:
        if name != "dispatch_before_commit":
            return
        row = connection.execute("SELECT pg_backend_pid()").fetchone()
        assert row is not None
        backend_pid.append(int(row["pg_backend_pid"]))
        reached.set()
        assert release.wait(timeout=10)

    faulted_ledger = PostgresExecutionLedger(runtime_url, witness, transaction_probe=probe)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            faulted_ledger.dispatch,
            scope,
            admitted.execution_id,
            coordinator_generation=coordinator,
            record_generation=admitted.record_generation,
            owner_id=owner,
        )
        assert reached.wait(timeout=10)
        with psycopg.connect(owner_url, autocommit=True) as connection:
            assert connection.execute(
                "SELECT pg_terminate_backend(%s)", (backend_pid[0],)
            ).fetchone() == (True,)
        release.set()
        with pytest.raises(LedgerUnavailable):
            future.result(timeout=10)
    record, created = base_ledger.create_or_get(
        scope,
        _admission(now, key_digest="0" * 64, owner_id=owner),
        coordinator_generation=coordinator,
        now=now,
    )
    assert not created
    assert record.state == "admitted"


def test_connection_loss_inside_settlement_rolls_back_all_accounting(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, now = _seed(owner_url)
    base_ledger = PostgresExecutionLedger(runtime_url, witness)
    coordinator = base_ledger.acquire_coordinator_generation()
    owner = uuid4()
    admitted, _ = base_ledger.create_or_get(
        scope,
        _admission(now, key_digest="f" * 64, owner_id=owner),
        coordinator_generation=coordinator,
        now=now,
    )
    dispatched = base_ledger.dispatch(
        scope,
        admitted.execution_id,
        coordinator_generation=coordinator,
        record_generation=admitted.record_generation,
        owner_id=owner,
    )
    reached, release = Event(), Event()
    backend_pid: list[int] = []

    def probe(name: str, connection: psycopg.Connection[Any]) -> None:
        if name != "settlement_before_commit":
            return
        row = connection.execute("SELECT pg_backend_pid() ").fetchone()
        assert row is not None
        backend_pid.append(int(row["pg_backend_pid"]))
        reached.set()
        assert release.wait(timeout=10)

    faulted_ledger = PostgresExecutionLedger(runtime_url, witness, transaction_probe=probe)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            faulted_ledger.settle_terminal,
            scope,
            dispatched.execution_id,
            coordinator_generation=coordinator,
            record_generation=dispatched.record_generation,
            owner_id=owner,
            state="completed",
            settled_microusd=2_500,
            provider_cost_reference_digest="4" * 64,
        )
        assert reached.wait(timeout=10)
        with psycopg.connect(owner_url, autocommit=True) as connection:
            assert connection.execute(
                "SELECT pg_terminate_backend(%s)", (backend_pid[0],)
            ).fetchone() == (True,)
        release.set()
        with pytest.raises(LedgerUnavailable):
            future.result(timeout=10)

    with psycopg.connect(owner_url) as connection:
        execution = connection.execute(
            "SELECT state, settlement_status, settled_microusd "
            "FROM tiamat.execution_records WHERE execution_id = %s",
            (dispatched.execution_id,),
        ).fetchone()
        assert execution == ("dispatched", "pending_reconciliation", None)
        partition = connection.execute(
            """
            SELECT period_spend_microusd, contingency_spend_microusd,
                   external_liability_microusd
            FROM tiamat.spending_partitions
            WHERE environment = %s AND caller_id = %s AND realm = %s
              AND partition_id = %s
            """,
            (scope.environment, scope.caller_id, scope.realm, scope.partition_id),
        ).fetchone()
        assert partition == (0, 0, 0)
        assert connection.execute(
            "SELECT count(*) FROM tiamat.route_rate_quarantines WHERE source_execution_id = %s",
            (dispatched.execution_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM tiamat.financial_events WHERE execution_id = %s",
            (dispatched.execution_id,),
        ).fetchone() == (0,)


def test_failover_fences_old_coordinator_and_adopts_only_after_lease_expiry(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, now = _seed(owner_url)
    ledger = PostgresExecutionLedger(runtime_url, witness)
    first_coordinator = ledger.acquire_coordinator_generation()
    first_owner = uuid4()
    record, _ = ledger.create_or_get(
        scope,
        _admission(now, key_digest="e" * 64, owner_id=first_owner),
        coordinator_generation=first_coordinator,
        now=now,
    )
    second_coordinator = ledger.acquire_coordinator_generation()
    with pytest.raises(DurableFenceRejected):
        ledger.dispatch(
            scope,
            record.execution_id,
            coordinator_generation=first_coordinator,
            record_generation=record.record_generation,
            owner_id=first_owner,
        )
    second_owner = uuid4()
    adopted = ledger.takeover_expired(
        scope,
        record.execution_id,
        coordinator_generation=second_coordinator,
        owner_id=second_owner,
        now=now + timedelta(seconds=6),
    )
    dispatched = ledger.dispatch(
        scope,
        adopted.execution_id,
        coordinator_generation=second_coordinator,
        record_generation=adopted.record_generation,
        owner_id=second_owner,
    )
    assert dispatched.state == "dispatched"


def test_authoritative_reaper_distinguishes_never_sent_from_ambiguous_dispatch(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, now = _seed(owner_url)
    ledger = PostgresExecutionLedger(runtime_url, witness)
    coordinator = ledger.acquire_coordinator_generation()

    admitted, _ = ledger.create_or_get(
        scope,
        _admission(now, key_digest="f" * 64),
        coordinator_generation=coordinator,
        now=now,
    )
    admitted_result = ledger.reap_scope(
        scope, now=now + timedelta(seconds=6), coordinator_generation=coordinator
    )
    admitted_reaped = next(
        row for row in admitted_result if row.execution_id == admitted.execution_id
    )
    assert admitted_reaped.state == "failed"
    assert admitted_reaped.failure_code == "execution_aborted"
    assert admitted_reaped.settled_microusd == 0

    owner = uuid4()
    second, _ = ledger.create_or_get(
        scope,
        _admission(now, key_digest="1" * 64, owner_id=owner),
        coordinator_generation=coordinator,
        now=now,
    )
    dispatched = ledger.dispatch(
        scope,
        second.execution_id,
        coordinator_generation=coordinator,
        record_generation=second.record_generation,
        owner_id=owner,
    )
    dispatched_result = ledger.reap_scope(
        scope,
        now=dispatched.execution_deadline + timedelta(seconds=31),
        coordinator_generation=coordinator,
    )
    ambiguous = next(row for row in dispatched_result if row.execution_id == second.execution_id)
    assert ambiguous.state == "outcome_unknown"
    assert ambiguous.settlement_status == "pending_reconciliation"
    assert ambiguous.settled_microusd is None


def test_unclear_dispatch_commit_aborts_only_same_live_owner(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, now = _seed(owner_url)
    ledger = PostgresExecutionLedger(runtime_url, witness)
    coordinator = ledger.acquire_coordinator_generation()
    owner = uuid4()
    admitted, _ = ledger.create_or_get(
        scope,
        _admission(now, key_digest="2" * 64, owner_id=owner),
        coordinator_generation=coordinator,
        now=now,
    )
    dispatched = ledger.dispatch(
        scope,
        admitted.execution_id,
        coordinator_generation=coordinator,
        record_generation=admitted.record_generation,
        owner_id=owner,
    )
    aborted = ledger.resolve_unclear_dispatch_commit(
        scope,
        dispatched.execution_id,
        coordinator_generation=coordinator,
        record_generation=dispatched.record_generation,
        owner_id=owner,
    )
    assert aborted.state == "failed"
    assert aborted.failure_code == "execution_aborted"
    assert aborted.settlement_status == "settled"
    assert aborted.settled_microusd == 0


def test_unclear_dispatch_resolution_preserves_newer_reaper_uncertainty(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, now = _seed(owner_url)
    ledger = PostgresExecutionLedger(runtime_url, witness)
    coordinator = ledger.acquire_coordinator_generation()
    owner = uuid4()
    admitted, _ = ledger.create_or_get(
        scope,
        _admission(now, key_digest="3" * 64, owner_id=owner),
        coordinator_generation=coordinator,
        now=now,
    )
    dispatched = ledger.dispatch(
        scope,
        admitted.execution_id,
        coordinator_generation=coordinator,
        record_generation=admitted.record_generation,
        owner_id=owner,
    )
    ledger.reap_scope(
        scope,
        now=dispatched.execution_deadline + timedelta(seconds=31),
        coordinator_generation=coordinator,
    )
    resolved = ledger.resolve_unclear_dispatch_commit(
        scope,
        dispatched.execution_id,
        coordinator_generation=coordinator,
        record_generation=dispatched.record_generation,
        owner_id=owner,
    )
    assert resolved.state == "outcome_unknown"
    assert resolved.failure_code == "execution_outcome_unknown"
    assert resolved.settlement_status == "pending_reconciliation"
    assert resolved.settled_microusd is None


def test_settlement_overrun_charges_actual_and_quarantines_exact_route(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, now = _seed(owner_url)
    ledger = PostgresExecutionLedger(runtime_url, witness)
    coordinator = ledger.acquire_coordinator_generation()
    owner = uuid4()
    admitted, _ = ledger.create_or_get(
        scope,
        _admission(now, key_digest="4" * 64, owner_id=owner),
        coordinator_generation=coordinator,
        now=now,
    )
    dispatched = ledger.dispatch(
        scope,
        admitted.execution_id,
        coordinator_generation=coordinator,
        record_generation=admitted.record_generation,
        owner_id=owner,
    )
    overrun = ledger.settle_terminal(
        scope,
        dispatched.execution_id,
        coordinator_generation=coordinator,
        record_generation=dispatched.record_generation,
        owner_id=owner,
        state="completed",
        settled_microusd=2_500,
        provider_cost_reference_digest="9" * 64,
    )
    assert overrun.state == "failed"
    assert overrun.settlement_status == "settlement_overrun"
    assert overrun.failure_code == "cost_settlement_violation"

    with psycopg.connect(runtime_url) as connection:
        for setting, value in (
            ("tiamat.environment", scope.environment),
            ("tiamat.realm", scope.realm),
            ("tiamat.caller_id", scope.caller_id),
            ("tiamat.partition_id", scope.partition_id),
        ):
            connection.execute("SELECT set_config(%s, %s, false)", (setting, value))
        partition = connection.execute(
            """
            SELECT period_spend_microusd, contingency_spend_microusd,
                   external_liability_microusd, blocked
            FROM tiamat.spending_partitions
            WHERE environment = %s AND caller_id = %s AND realm = %s
              AND partition_id = %s
            """,
            (scope.environment, scope.caller_id, scope.realm, scope.partition_id),
        ).fetchone()
        assert partition == (2_500, 500, 0, False)
        assert connection.execute(
            "SELECT count(*) FROM tiamat.financial_events WHERE execution_id = %s",
            (overrun.execution_id,),
        ).fetchone() == (1,)

    with pytest.raises(DispatchBlocked, match="quarantined"):
        ledger.create_or_get(
            scope,
            _admission(now, key_digest="5" * 64),
            coordinator_generation=coordinator,
            now=now,
        )


def test_late_overrun_blocks_partition_when_contingency_cannot_cover_liability(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, now = _seed(owner_url)
    ledger = PostgresExecutionLedger(runtime_url, witness)
    coordinator = ledger.acquire_coordinator_generation()
    owner = uuid4()
    admitted, _ = ledger.create_or_get(
        scope,
        _admission(now, key_digest="6" * 64, owner_id=owner),
        coordinator_generation=coordinator,
        now=now,
    )
    dispatched = ledger.dispatch(
        scope,
        admitted.execution_id,
        coordinator_generation=coordinator,
        record_generation=admitted.record_generation,
        owner_id=owner,
    )
    unknown = ledger.mark_outcome_unknown(
        scope,
        dispatched.execution_id,
        coordinator_generation=coordinator,
        record_generation=dispatched.record_generation,
        owner_id=owner,
    )
    reconciled = ledger.reconcile_cost(
        scope,
        unknown.execution_id,
        coordinator_generation=coordinator,
        actual_microusd=12_000,
        provider_cost_reference_digest="8" * 64,
    )
    assert reconciled.state == "failed"
    assert reconciled.settlement_status == "settlement_overrun"

    with psycopg.connect(runtime_url) as connection:
        for setting, value in (
            ("tiamat.environment", scope.environment),
            ("tiamat.realm", scope.realm),
            ("tiamat.caller_id", scope.caller_id),
            ("tiamat.partition_id", scope.partition_id),
        ):
            connection.execute("SELECT set_config(%s, %s, false)", (setting, value))
        partition = connection.execute(
            """
            SELECT period_spend_microusd, contingency_spend_microusd,
                   external_liability_microusd, blocked, block_reason
            FROM tiamat.spending_partitions
            WHERE environment = %s AND caller_id = %s AND realm = %s
              AND partition_id = %s
            """,
            (scope.environment, scope.caller_id, scope.realm, scope.partition_id),
        ).fetchone()
        assert partition == (
            12_000,
            8_000,
            2_000,
            True,
            "settlement_liability_unfunded",
        )
    with pytest.raises(DispatchBlocked):
        ledger.create_or_get(
            scope,
            _admission(
                now,
                key_digest="7" * 64,
            ),
            coordinator_generation=coordinator,
            now=now,
        )


def test_billing_evidence_can_invalidate_an_already_returned_candidate(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, now = _seed(owner_url)
    ledger = PostgresExecutionLedger(runtime_url, witness)
    coordinator = ledger.acquire_coordinator_generation()
    owner = uuid4()
    admitted, _ = ledger.create_or_get(
        scope,
        _admission(now, key_digest="a" * 64, owner_id=owner),
        coordinator_generation=coordinator,
        now=now,
    )
    dispatched = ledger.dispatch(
        scope,
        admitted.execution_id,
        coordinator_generation=coordinator,
        record_generation=admitted.record_generation,
        owner_id=owner,
    )
    completed = ledger.settle_terminal(
        scope,
        dispatched.execution_id,
        coordinator_generation=coordinator,
        record_generation=dispatched.record_generation,
        owner_id=owner,
        state="completed",
        settled_microusd=100,
        provider_cost_reference_digest="6" * 64,
    )
    assert completed.state == "completed"
    invalidated = ledger.reconcile_cost(
        scope,
        completed.execution_id,
        coordinator_generation=coordinator,
        actual_microusd=2_500,
        provider_cost_reference_digest="5" * 64,
    )
    assert invalidated.state == "failed"
    assert invalidated.settlement_status == "settlement_overrun"
    assert invalidated.failure_code == "cost_settlement_violation"
    with psycopg.connect(owner_url) as connection:
        assert connection.execute(
            "SELECT count(*) FROM tiamat.financial_events WHERE execution_id = %s",
            (completed.execution_id,),
        ).fetchone() == (2,)
        assert connection.execute(
            """
            SELECT period_spend_microusd FROM tiamat.spending_partitions
            WHERE environment = %s AND caller_id = %s AND realm = %s
              AND partition_id = %s
            """,
            (scope.environment, scope.caller_id, scope.realm, scope.partition_id),
        ).fetchone() == (2_500,)


def test_expired_idempotency_tombstone_leaves_financial_evidence(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, now = _seed(owner_url)
    ledger = PostgresExecutionLedger(runtime_url, witness)
    coordinator = ledger.acquire_coordinator_generation()
    owner = uuid4()
    admitted, _ = ledger.create_or_get(
        scope,
        _admission(now, key_digest="8" * 64, owner_id=owner),
        coordinator_generation=coordinator,
        now=now,
    )
    dispatched = ledger.dispatch(
        scope,
        admitted.execution_id,
        coordinator_generation=coordinator,
        record_generation=admitted.record_generation,
        owner_id=owner,
    )
    ledger.settle_terminal(
        scope,
        dispatched.execution_id,
        coordinator_generation=coordinator,
        record_generation=dispatched.record_generation,
        owner_id=owner,
        state="completed",
        settled_microusd=100,
        provider_cost_reference_digest="7" * 64,
    )
    with psycopg.connect(owner_url) as connection:
        connection.execute(
            "UPDATE tiamat.execution_records SET tombstone_until = %s WHERE execution_id = %s",
            (now + timedelta(seconds=1), admitted.execution_id),
        )
    expired = ledger.expire_tombstones(
        scope,
        coordinator_generation=coordinator,
        now=now + timedelta(minutes=11),
    )
    assert expired == (admitted.execution_id,)
    with psycopg.connect(owner_url) as connection:
        assert connection.execute(
            "SELECT count(*) FROM tiamat.execution_records WHERE execution_id = %s",
            (admitted.execution_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM tiamat.financial_events WHERE execution_id = %s",
            (admitted.execution_id,),
        ).fetchone() == (1,)


def test_forfeited_reservation_keeps_thirty_day_tombstone_and_financial_event(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, now = _seed(owner_url)
    ledger = PostgresExecutionLedger(runtime_url, witness)
    coordinator = ledger.acquire_coordinator_generation()
    owner = uuid4()
    admitted, _ = ledger.create_or_get(
        scope,
        _admission(now, key_digest="9" * 64, owner_id=owner),
        coordinator_generation=coordinator,
        now=now,
    )
    dispatched = ledger.dispatch(
        scope,
        admitted.execution_id,
        coordinator_generation=coordinator,
        record_generation=admitted.record_generation,
        owner_id=owner,
    )
    ledger.mark_outcome_unknown(
        scope,
        dispatched.execution_id,
        coordinator_generation=coordinator,
        record_generation=dispatched.record_generation,
        owner_id=owner,
    )
    with psycopg.connect(owner_url) as connection:
        connection.execute(
            "UPDATE tiamat.execution_records SET reconciliation_deadline = %s "
            "WHERE execution_id = %s",
            (admitted.execution_deadline, admitted.execution_id),
        )
    forfeited = ledger.forfeit_due_reconciliations(
        scope,
        now=now + timedelta(seconds=16),
        coordinator_generation=coordinator,
    )
    row = next(item for item in forfeited if item.execution_id == admitted.execution_id)
    assert row.settlement_status == "reservation_forfeited"
    assert row.settled_microusd == row.reserved_microusd
    assert (
        ledger.expire_tombstones(
            scope,
            coordinator_generation=coordinator,
            now=now + timedelta(days=29),
        )
        == ()
    )
    assert ledger.expire_tombstones(
        scope,
        coordinator_generation=coordinator,
        now=now + timedelta(days=31),
    ) == (admitted.execution_id,)
    with psycopg.connect(owner_url) as connection:
        assert connection.execute(
            "SELECT count(*) FROM tiamat.financial_events WHERE execution_id = %s",
            (admitted.execution_id,),
        ).fetchone() == (1,)


def test_restore_generation_mismatch_blocks_until_offline_reconciliation(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, _now = _seed(owner_url)
    quarantine_environment(owner_url, environment=scope.environment, reason="stale_restore_review")
    with pytest.raises(DispatchBlocked):
        PostgresExecutionLedger(runtime_url, witness).acquire_coordinator_generation()

    authorize_reconciled_state(
        owner_url,
        environment=scope.environment,
        expected_storage_epoch=witness.storage_epoch,
        current_recovery_generation=1,
        next_recovery_generation=2,
        unresolved_provider_liabilities=0,
    )
    with pytest.raises(DispatchBlocked):
        PostgresExecutionLedger(runtime_url, witness).acquire_coordinator_generation()
    next_witness = RecoveryWitness(scope.environment, witness.storage_epoch, 2)
    assert PostgresExecutionLedger(runtime_url, next_witness).acquire_coordinator_generation() >= 2


def test_stale_database_snapshot_cannot_resume_under_new_recovery_witness(
    database_urls: tuple[str, str],
) -> None:
    owner_url, runtime_url = database_urls
    scope, witness, _now = _seed(owner_url)
    source_database = make_url(owner_url).database
    assert source_database is not None and source_database.startswith("tiamat_test")
    restore_database = f"tiamat_test_restore_{uuid4().hex[:8]}"
    admin_url = make_url(owner_url).set(database="postgres").render_as_string(hide_password=False)
    stale_runtime_url = (
        make_url(runtime_url).set(database=restore_database).render_as_string(hide_password=False)
    )

    with psycopg.connect(admin_url, autocommit=True) as connection:
        connection.execute(
            sql.SQL("CREATE DATABASE {} TEMPLATE {}").format(
                sql.Identifier(restore_database), sql.Identifier(source_database)
            )
        )
    try:
        quarantine_environment(
            owner_url, environment=scope.environment, reason="snapshot_restore_review"
        )
        authorize_reconciled_state(
            owner_url,
            environment=scope.environment,
            expected_storage_epoch=witness.storage_epoch,
            current_recovery_generation=1,
            next_recovery_generation=2,
            unresolved_provider_liabilities=0,
        )
        current_witness = RecoveryWitness(scope.environment, witness.storage_epoch, 2)
        with pytest.raises(DispatchBlocked):
            PostgresExecutionLedger(
                stale_runtime_url, current_witness
            ).acquire_coordinator_generation()
    finally:
        with psycopg.connect(admin_url, autocommit=True) as connection:
            connection.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s",
                (restore_database,),
            )
            connection.execute(
                sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(restore_database))
            )


def test_unreachable_database_fails_replay_state_closed() -> None:
    replay = PostgresJtiReplayStore("postgresql://none:none@127.0.0.1:1/nope?connect_timeout=1")
    with pytest.raises(AuthenticationStateUnavailable):
        replay.consume(("issuer", "caller", "realm", "test"), uuid4(), 1)
