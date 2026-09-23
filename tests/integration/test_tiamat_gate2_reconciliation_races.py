"""Gate 2 reconciliation: the ledger snapshot is exclusive, whatever else writes concurrently.

Staging an inventory or a release, and writing ledger history, take no gate lock. These cases use
two connections, deterministically ordered, to prove that the first-inventory install and the
recovery authorization cannot act on a snapshot a concurrent writer changes before they commit:
a writer that got in first makes them wait and then refuse, and a writer that comes second waits
until they have committed.

Also here: a pre-reconciliation quarantine reason other than the day-zero one, and the reviewed
spending-partition setup a signed grant is activated onto.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import psycopg
import pytest

from lucy.shared_execution.postgres_authority import PostgresSignedAuthorityStore
from lucy.shared_execution.recovery import (
    AnchorFloorRecord,
    RecoveryRejected,
    authorize_recovery_generation,
    create_spending_partition,
    install_first_release_inventory,
    quarantine_environment,
)
from lucy.shared_execution.signed_releases import verify_release, verify_trust_inventory
from tests.integration.conftest import DisposableRoles
from tests.integration.test_tiamat_gate2_reconciliation import (
    _Ledger,
    _report_checkpoint,
    make_ledger,
)
from tests.integration.tiamat_signed_trust import AUTHORITY_ISSUER, RELEASE_KEY_ID
from tests.integration.tiamat_signed_trust import ROOT_KEY_ID as RELEASE_ROOT_KEY_ID


@pytest.fixture
def ledger(disposable_roles: DisposableRoles) -> _Ledger:
    return make_ledger(disposable_roles)


def _named(url: str, name: str) -> str:
    return f"{url}{'&' if '?' in url else '?'}application_name={name}"


def _wait_for_lock_wait(
    ledger: _Ledger, name: str, events: tuple[str, ...], timeout: float = 20.0
) -> None:
    """Until the named recovery session waits on one of the given lock events. The observer is
    the same role, so PostgreSQL shows it the session's wait state."""

    deadline = time.monotonic() + timeout
    with psycopg.connect(ledger.roles.recovery, autocommit=True) as observer:
        while time.monotonic() < deadline:
            row = observer.execute(
                """
                SELECT count(*) FROM pg_catalog.pg_stat_activity
                WHERE application_name = %s AND wait_event_type = 'Lock'
                  AND wait_event = ANY(%s)
                """,
                (name, list(events)),
            ).fetchone()
            if row is not None and int(row[0]) > 0:
                return
            time.sleep(0.05)
    raise AssertionError(f"{name} never waited on a lock")


class _Background:
    def __init__(self, work: Callable[[], Any]) -> None:
        self.result: Any = None
        self.error: BaseException | None = None

        def run() -> None:
            try:
                self.result = work()
            except BaseException as exc:  # noqa: BLE001 - reported to the test thread
                self.error = exc

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def join(self) -> Any:
        self.thread.join(timeout=60)
        assert not self.thread.is_alive(), "the recovery operation did not finish"
        if self.error is not None:
            raise self.error
        return self.result


@contextmanager
def _paused_on(
    ledger: _Ledger, table: str, condition: str, event: str = "UPDATE"
) -> Iterator[Callable[[], None]]:
    """A trigger that parks the matching write on an advisory lock this test holds. The
    operation is then mid-transaction with every lock it took; ``release()`` lets it finish."""

    name = f"g2r_pause_{uuid4().hex[:8]}"
    key = int(uuid4().int % (2**62))
    holder = psycopg.connect(ledger.roles.owner, autocommit=True)
    holder.execute("SELECT pg_advisory_lock(%s)", (key,))
    with psycopg.connect(ledger.roles.owner, autocommit=True) as owner:
        owner.execute(
            f"""
            CREATE FUNCTION tiamat.{name}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.environment = '{ledger.environment}' AND ({condition}) THEN
                    PERFORM pg_advisory_xact_lock({key});
                END IF;
                RETURN NEW;
            END $$
            """
        )
        owner.execute(
            f"CREATE TRIGGER {name} BEFORE {event} ON tiamat.{table} "
            f"FOR EACH ROW EXECUTE FUNCTION tiamat.{name}()"
        )
    released = False

    def release() -> None:
        nonlocal released
        if not released:
            holder.execute("SELECT pg_advisory_unlock(%s)", (key,))
            released = True

    release.key = key  # type: ignore[attr-defined]
    try:
        yield release
    finally:
        release()
        holder.close()
        with psycopg.connect(ledger.roles.owner, autocommit=True) as owner:
            owner.execute(f"DROP TRIGGER {name} ON tiamat.{table}")
            owner.execute(f"DROP FUNCTION tiamat.{name}()")


def _stage_generation_two(connection: psycopg.Connection[Any], ledger: _Ledger) -> None:
    """What ``stage_inventory`` writes, as the release manager, left uncommitted by the caller."""

    connection.execute("SELECT set_config('tiamat.environment', %s, true)", (ledger.environment,))
    connection.execute(
        """
        INSERT INTO tiamat.trust_inventories (
            environment, inventory_generation, exact_jws, jws_sha256,
            previous_inventory_digest, root_key_id, state
        ) VALUES (%s, 2, %s, %s, %s, %s, 'staged')
        """,
        (ledger.environment, b"concurrent", "c" * 64, "d" * 64, RELEASE_ROOT_KEY_ID),
    )


def _insert_partition(connection: psycopg.Connection[Any], ledger: _Ledger) -> None:
    connection.execute(
        """
        INSERT INTO tiamat.spending_partitions (
            environment, caller_id, realm, partition_id, blocked, block_reason
        ) VALUES (%s, %s, 'g2r-realm', 'partition-concurrent', true, 'no_active_grant')
        """,
        (ledger.environment, ledger.release.caller_id),
    )


def _first_inventory(ledger: _Ledger, url: str, exact: bytes | None = None) -> str:
    return install_first_release_inventory(
        url,
        environment=ledger.environment,
        expected_ledger_id=ledger.identity.ledger_id,
        expected_storage_epoch=ledger.identity.storage_epoch,
        expected_recovery_generation=1,
        exact_jws=exact or ledger.first_inventory_jws(),
        release_root_key_id=RELEASE_ROOT_KEY_ID,
        release_root_public_key=ledger.release.root_public_key,
    ).jws_sha256


def test_first_inventory_waits_for_an_earlier_stage_and_then_refuses(ledger: _Ledger) -> None:
    name = f"g2r-op-{uuid4().hex[:8]}"
    gate_before = ledger.gate()
    with psycopg.connect(ledger.roles.release_manager) as stager:
        _stage_generation_two(stager, ledger)  # uncommitted
        operation = _Background(
            lambda: _first_inventory(ledger, _named(ledger.roles.recovery, name))
        )
        _wait_for_lock_wait(ledger, name, ("relation",))
        assert operation.thread.is_alive()
        stager.commit()
    with pytest.raises(RecoveryRejected, match="first_inventory_staged_candidate_differs"):
        operation.join()
    assert ledger.gate() == gate_before
    assert [row[:2] for row in ledger.inventories()] == [(2, "staged")]


def test_a_stage_during_the_first_inventory_waits_until_it_commits(ledger: _Ledger) -> None:
    name = f"g2r-op-{uuid4().hex[:8]}"
    with _paused_on(ledger, "trust_inventories", "NEW.state = 'active'") as release:
        operation = _Background(
            lambda: _first_inventory(ledger, _named(ledger.roles.recovery, name))
        )
        _wait_for_lock_wait(ledger, name, ("advisory",))  # parked after its checks
        with psycopg.connect(ledger.roles.release_manager) as stager:
            stager.execute("SET lock_timeout = '1s'")
            with pytest.raises(psycopg.errors.LockNotAvailable):
                _stage_generation_two(stager, ledger)
        release()
        operation.join()
    assert ledger.inventories() == [(1, "active", 1)]
    # Once the install has committed, staging proceeds as usual.
    with psycopg.connect(ledger.roles.release_manager) as stager:
        _stage_generation_two(stager, ledger)
    assert [row[:2] for row in ledger.inventories()] == [(1, "active"), (2, "staged")]


def test_authorization_waits_for_earlier_history_and_then_refuses(ledger: _Ledger) -> None:
    ledger.install_first_inventory()
    pending = ledger.pending(_report_checkpoint(ledger, target=2))
    ledger.install(pending)
    name = f"g2r-op-{uuid4().hex[:8]}"
    gate_before = ledger.gate()
    with psycopg.connect(ledger.roles.recovery) as writer:
        _insert_partition(writer, ledger)  # uncommitted
        operation = _Background(
            lambda: authorize_recovery_generation(
                _named(ledger.roles.recovery, name),
                anchor=ledger.store(pending),
                authorized=pending.candidate,
                checkpoint=pending.step.checkpoint,
                source_recovery_generation=1,
            )
        )
        _wait_for_lock_wait(ledger, name, ("relation",))
        assert operation.thread.is_alive()
        writer.commit()
    with pytest.raises(RecoveryRejected, match="recovery_ledger_financial_state_unsupported"):
        operation.join()
    assert ledger.gate() == gate_before
    assert ledger.retained() == []


def test_history_written_during_authorization_waits_until_it_commits(ledger: _Ledger) -> None:
    ledger.install_first_inventory()
    pending = ledger.pending(_report_checkpoint(ledger, target=2))
    ledger.install(pending)
    name = f"g2r-op-{uuid4().hex[:8]}"
    opening = "OLD.dispatch_blocked AND NOT NEW.dispatch_blocked"
    with _paused_on(ledger, "restore_gate", opening) as release:
        operation = _Background(
            lambda: authorize_recovery_generation(
                _named(ledger.roles.recovery, name),
                anchor=ledger.store(pending),
                authorized=pending.candidate,
                checkpoint=pending.step.checkpoint,
                source_recovery_generation=1,
            )
        )
        _wait_for_lock_wait(ledger, name, ("advisory",))  # parked on the gate opening
        with psycopg.connect(ledger.roles.recovery) as writer:
            writer.execute("SET lock_timeout = '1s'")
            with pytest.raises(psycopg.errors.LockNotAvailable):
                _insert_partition(writer, ledger)
        release()
        assert operation.join().target_recovery_generation == 2
    assert ledger.gate()[:2] == (2, False)
    # Once the authorization has committed, the write proceeds as usual.
    with psycopg.connect(ledger.roles.recovery) as writer:
        _insert_partition(writer, ledger)


def test_a_different_pre_reconciliation_block_reason_is_permitted(ledger: _Ledger) -> None:
    """Never reconciled is proven by the absence of a retained checkpoint and of any claimant,
    not by the block reason's text: a ledger quarantined again before its first reconciliation,
    under the anchor floor it was quarantined at, still takes its first inventory and reconciles."""

    bootstrap_sha = hashlib.sha256(ledger.head.transition_jws).hexdigest()
    quarantine_environment(
        ledger.roles.recovery,
        environment=ledger.environment,
        reason="operator_quarantine",
        anchor_floor=AnchorFloorRecord(1, bootstrap_sha),
    )
    assert ledger.gate()[1:] == (True, 2, 1, bootstrap_sha, "operator_quarantine")
    ledger.install_first_inventory()
    pending = ledger.pending(_report_checkpoint(ledger, target=2))
    ledger.install(pending)
    ledger.authorize(pending)
    assert ledger.gate()[:2] == (2, False)


def _partition(ledger: _Ledger, generation: int, partition_id: str = "partition-a") -> None:
    create_spending_partition(
        ledger.roles.recovery,
        environment=ledger.environment,
        expected_ledger_id=ledger.identity.ledger_id,
        expected_storage_epoch=ledger.identity.storage_epoch,
        expected_recovery_generation=generation,
        caller_id=ledger.release.caller_id,
        realm="g2r-realm",
        partition_id=partition_id,
    )


def _partition_row(ledger: _Ledger) -> tuple[Any, ...] | None:
    with psycopg.connect(ledger.roles.recovery) as recovery:
        row = recovery.execute(
            """
            SELECT blocked, block_reason, allowance_microusd, period_spend_microusd,
                   maximum_concurrency, active_grant_release_id
            FROM tiamat.spending_partitions
            WHERE environment = %s AND partition_id = 'partition-a'
            """,
            (ledger.environment,),
        ).fetchone()
    return None if row is None else tuple(row)


GRANT_SUBJECTS = [
    ("execution_profile", "profile-reconciliation"),
    ("privacy_policy", "policy-a"),
    ("spending_grant", "partition-a"),
]


def test_the_partition_is_created_only_after_reconciliation_and_only_once(
    ledger: _Ledger,
) -> None:
    with pytest.raises(RecoveryRejected, match="requires_the_reconciled_generation"):
        _partition(ledger, 1)  # the gate is still blocked
    ledger.install_first_inventory(ledger.release.inventory_jws(GRANT_SUBJECTS))
    pending = ledger.pending(_report_checkpoint(ledger, target=2))
    ledger.install(pending)
    ledger.authorize(pending)
    with pytest.raises(RecoveryRejected, match="requires_the_reconciled_generation"):
        _partition(ledger, 1)  # not the generation the reviewer read back
    with pytest.raises(RecoveryRejected, match="not_authorized_by_inventory"):
        _partition(ledger, 2, "partition-unlisted")
    _partition(ledger, 2)
    assert _partition_row(ledger) == (True, "no_active_grant", 0, 0, 0, None)
    with pytest.raises(RecoveryRejected, match="spending_partition_exists"):
        _partition(ledger, 2)


def test_a_signed_grant_activates_onto_the_created_partition(ledger: _Ledger) -> None:
    exact = ledger.release.inventory_jws(GRANT_SUBJECTS)
    ledger.install_first_inventory(exact)
    pending = ledger.pending(_report_checkpoint(ledger, target=2))
    ledger.install(pending)
    ledger.authorize(pending)
    _partition(ledger, 2)

    release_id = f"grant-{uuid4().hex[:8]}"
    store = PostgresSignedAuthorityStore(ledger.roles.release_manager)
    store.stage_release(_signed_grant(ledger, exact, release_id), RELEASE_KEY_ID)
    store.activate_release(ledger.release.scope, "spending_grant", "partition-a", release_id)
    assert _partition_row(ledger) == (False, None, 20_000, 0, 2, release_id)


def _signed_grant(ledger: _Ledger, inventory_jws: bytes, release_id: str) -> Any:
    now = datetime.now(UTC)
    inventory = verify_trust_inventory(
        inventory_jws,
        root_key_id=RELEASE_ROOT_KEY_ID,
        root_public_key=ledger.release.root_public_key,
        environment=ledger.environment,
    )
    return verify_release(
        ledger.release.release_jws(
            "spending_grant",
            "partition-a",
            release_id,
            {
                "partition_id": "partition-a",
                "budget_period_id": "period-a",
                "period_start": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "period_end": (now + timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "allowance_microusd": 20_000,
                "maximum_concurrency": 2,
                "largest_per_call_microusd": 2_000,
                "contingency_reserve_microusd": 8_000,
            },
        ),
        inventory=inventory,
        expected_issuer=AUTHORITY_ISSUER,
        expected_environment=ledger.environment,
        expected_caller_id=ledger.release.caller_id,
        expected_realm="g2r-realm",
        now=now,
    )


def _wait_for_advisory_waiter(ledger: _Ledger, key: int, timeout: float = 20.0) -> None:
    """Until some session waits on the advisory lock. pg_locks shows every role's locks."""

    deadline = time.monotonic() + timeout
    with psycopg.connect(ledger.roles.owner, autocommit=True) as observer:
        while time.monotonic() < deadline:
            row = observer.execute(
                """
                SELECT count(*) FROM pg_catalog.pg_locks
                WHERE locktype = 'advisory' AND NOT granted
                  AND classid = %s AND objid = %s AND objsubid = 1
                """,
                (key >> 32, key & 0xFFFFFFFF),
            ).fetchone()
            if row is not None and int(row[0]) > 0:
                return
            time.sleep(0.05)
    raise AssertionError("the stage never reached its pause")


def _signed_policy(ledger: _Ledger, inventory_jws: bytes) -> Any:
    inventory = verify_trust_inventory(
        inventory_jws,
        root_key_id=RELEASE_ROOT_KEY_ID,
        root_public_key=ledger.release.root_public_key,
        environment=ledger.environment,
    )
    return verify_release(
        ledger.release.release_jws(
            "privacy_policy",
            "policy-a",
            f"policy-{uuid4().hex[:8]}",
            {
                "policy_id": "policy-a",
                "approved_provider_route_ids": ["route-a"],
                "required_provider_privacy": ["zero_data_retention", "no_training"],
                "data_collection": "denied",
                "training": "denied",
                "fallback_allowed": False,
                "allowed_regions": ["us"],
                "retention_ceiling_seconds": 0,
                "eligibility_generation": 1,
            },
        ),
        inventory=inventory,
        expected_issuer=AUTHORITY_ISSUER,
        expected_environment=ledger.environment,
        expected_caller_id=ledger.release.caller_id,
        expected_realm="g2r-realm",
        now=datetime.now(UTC),
    )


@pytest.mark.parametrize("operation_name", ["first_inventory", "authorization"])
def test_a_real_release_stage_in_progress_orders_the_recovery_step_behind_it(
    ledger: _Ledger, operation_name: str
) -> None:
    """The release manager's own stage_release of a signed privacy policy is paused at its
    insert while the recovery step starts. (A grant cannot be staged here at all: its row needs an
    existing spending partition, which an empty ledger lacks.) Staging takes the gate's shared
    lock first, so the step waits on the gate, never on a table the stage still has to reach, and
    after the stage commits the step sees it and refuses."""

    exact = ledger.release.inventory_jws(GRANT_SUBJECTS)
    pending = None
    if operation_name == "authorization":
        ledger.install_first_inventory(exact)
        pending = ledger.pending(_report_checkpoint(ledger, target=2))
        ledger.install(pending)
    policy = _signed_policy(ledger, exact)
    store = PostgresSignedAuthorityStore(ledger.roles.release_manager)
    gate_before = ledger.gate()
    name = f"g2r-op-{uuid4().hex[:8]}"
    with _paused_on(ledger, "signed_releases", "true", "INSERT") as release:
        stage = _Background(lambda: store.stage_release(policy, RELEASE_KEY_ID))
        _wait_for_advisory_waiter(ledger, release.key)  # type: ignore[attr-defined]
        if pending is None:
            operation = _Background(
                lambda: _first_inventory(ledger, _named(ledger.roles.recovery, name), exact)
            )
        else:
            verified = pending
            operation = _Background(
                lambda: authorize_recovery_generation(
                    _named(ledger.roles.recovery, name),
                    anchor=ledger.store(verified),
                    authorized=verified.candidate,
                    checkpoint=verified.step.checkpoint,
                    source_recovery_generation=1,
                )
            )
        _wait_for_lock_wait(ledger, name, ("transactionid", "tuple"))
        release()
        stage.join()
    with pytest.raises(RecoveryRejected, match="recovery_ledger_financial_state_unsupported"):
        operation.join()
    assert ledger.gate() == gate_before
