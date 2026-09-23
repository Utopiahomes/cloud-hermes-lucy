"""Gate 2 reconciliation on the disposable ledger: first inventory, generation jump, launch.

Each case gets its own environment on the disposable database, initialized blocked at recovery
generation one, and its own signing roots. Anchor transitions are genuinely signed and installed
through the real M4 writer over an in-memory conditional table; database steps run as the
recovery login, as deployed. Nothing here touches AWS or the commissioned ledger.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.anchor_writer import AnchorWriter, AnchorWriteRequest
from lucy.shared_execution.recovery import (
    RecoveryRejected,
    authorize_recovery_generation,
    install_first_release_inventory,
)
from lucy.shared_execution.recovery_anchor import (
    PostgresContinuityBeaconReader,
    RecoveryAnchorIdentity,
)
from lucy.shared_execution.recovery_anchor_commissioning import (
    build_continued_quarantine_successor,
    build_quarantined_bootstrap,
)
from lucy.shared_execution.recovery_anchor_dynamodb import DynamoDbExternalRecoveryAnchor
from lucy.shared_execution.recovery_anchor_reconciliation import (
    AnchorHead,
    ReconciliationStep,
    VerifiedReconciliationStep,
    build_continuity_established,
    build_recovery_pending,
    install_through_writer,
    verify_reconciliation_package,
)
from lucy.shared_execution.recovery_anchor_trust import load_anchor_trust, verified_anchor_reader
from lucy.shared_execution.recovery_checkpoint import (
    RecoveryCheckpoint,
    construct_recovery_checkpoint,
)
from lucy.shared_execution.recovery_ledger_report import (
    LedgerProjectionUnsupported,
    empty_ledger_checkpoint,
    read_ledger_recovery_state,
)
from lucy.shared_execution.signed_releases import INVENTORY_TYP
from lucy.shared_execution.startup_attestation import (
    LedgerRecoveryCheckpointSource,
    StartupAttestationIssuer,
)
from tests.integration.conftest import DisposableRoles
from tests.integration.tiamat_signed_trust import ROOT_KEY_ID as RELEASE_ROOT_KEY_ID
from tests.integration.tiamat_signed_trust import SyntheticReleaseTrust, _compact
from tests.unit.test_tiamat_anchor_writer import ConditionalTable, _root

ANCHOR_ROOT_KEY_ID = "tiamat-recovery-root.reconciliation-test.1"
ROOT = Path(__file__).resolve().parents[2]
TABLE = "tiamat-recovery-anchor"


class _Clock:
    def __init__(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)

    def __call__(self) -> datetime:
        return self.now


@dataclass
class _Ledger:
    roles: DisposableRoles
    identity: RecoveryAnchorIdentity
    release: SyntheticReleaseTrust
    anchor_root: Ed25519PrivateKey
    table: ConditionalTable
    writer: AnchorWriter
    clock: _Clock
    head: AnchorHead

    @property
    def environment(self) -> str:
        return self.identity.environment

    def first_inventory_jws(self) -> bytes:
        return self.release.inventory_jws([("execution_profile", "profile-reconciliation")])

    def install_first_inventory(self, exact_jws: bytes | None = None) -> str:
        installed = install_first_release_inventory(
            self.roles.recovery,
            environment=self.environment,
            expected_ledger_id=self.identity.ledger_id,
            expected_storage_epoch=self.identity.storage_epoch,
            expected_recovery_generation=1,
            exact_jws=exact_jws or self.first_inventory_jws(),
            release_root_key_id=RELEASE_ROOT_KEY_ID,
            release_root_public_key=self.release.root_public_key,
        )
        return installed.jws_sha256

    def pending(self, checkpoint: RecoveryCheckpoint) -> VerifiedReconciliationStep:
        step, _ = build_recovery_pending(
            head=self.head,
            identity=self.identity,
            root_key_id=ANCHOR_ROOT_KEY_ID,
            root_private_key=self.anchor_root,
            witness_key_id="tiamat-recovery-witness.reconciled.1",
            witness_private_key=Ed25519PrivateKey.generate(),
            checkpoint=checkpoint,
            now=self.clock.now,
        )
        return self.verify(step)

    def verify(self, step: ReconciliationStep) -> VerifiedReconciliationStep:
        return verify_reconciliation_package(
            json.loads(json.dumps(step.public_package())),
            now=self.clock.now,
            expected_root_public_sha256=hashlib.sha256(
                base64.b64decode(step.root_public_key_b64)
            ).hexdigest(),
            expected_ceremony=step.ceremony,
        )

    def store(self, verified: VerifiedReconciliationStep) -> DynamoDbExternalRecoveryAnchor:
        return DynamoDbExternalRecoveryAnchor(
            client=self.table, table_name=TABLE, decode_transition=verified.decoder()
        )

    def install(self, verified: VerifiedReconciliationStep) -> str:
        return install_through_writer(self.store(verified), self.writer.write, verified)

    def authorize(
        self, verified: VerifiedReconciliationStep, *, source: int = 1, checkpoint: Any = None
    ) -> Any:
        return authorize_recovery_generation(
            self.roles.recovery,
            anchor=self.store(verified),
            authorized=verified.candidate,
            checkpoint=checkpoint or verified.step.checkpoint,
            source_recovery_generation=source,
        )

    def gate(self) -> tuple[Any, ...]:
        with psycopg.connect(self.roles.recovery) as recovery:
            row = recovery.execute(
                """
                SELECT recovery_generation, dispatch_blocked, coordinator_generation,
                       anchor_floor_version, anchor_floor_sha256, block_reason
                FROM tiamat.restore_gate WHERE environment = %s
                """,
                (self.environment,),
            ).fetchone()
        assert row is not None
        return tuple(row)

    def inventories(self) -> list[tuple[Any, ...]]:
        with psycopg.connect(self.roles.recovery) as recovery:
            return [
                tuple(row)
                for row in recovery.execute(
                    """
                    SELECT inventory_generation, state, activation_recovery_generation
                    FROM tiamat.trust_inventories WHERE environment = %s
                    ORDER BY inventory_generation
                    """,
                    (self.environment,),
                ).fetchall()
            ]

    def retained(self) -> list[tuple[Any, ...]]:
        with psycopg.connect(self.roles.recovery) as recovery:
            return [
                tuple(row)
                for row in recovery.execute(
                    """
                    SELECT recovery_generation, checkpoint_sha256
                    FROM tiamat.recovery_checkpoints WHERE environment = %s
                    """,
                    (self.environment,),
                ).fetchall()
            ]


@pytest.fixture
def ledger(disposable_roles: DisposableRoles) -> _Ledger:
    environment = f"g2r-{uuid4().hex[:10]}"
    storage_epoch = uuid4()
    with psycopg.connect(disposable_roles.owner) as owner:
        row = owner.execute(
            "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
        ).fetchone()
    assert row is not None
    identity = RecoveryAnchorIdentity(environment, UUID(str(row[0])), storage_epoch)
    with psycopg.connect(disposable_roles.recovery) as recovery:
        # What initialize_environment writes: a blocked gate awaiting its first reconciliation.
        recovery.execute(
            """
            INSERT INTO tiamat.restore_gate (
                environment, storage_epoch, recovery_generation,
                coordinator_generation, dispatch_blocked, block_reason
            ) VALUES (%s, %s, 1, 1, true, 'initial_reconciliation_required')
            """,
            (environment, storage_epoch),
        )
    anchor_root = Ed25519PrivateKey.generate()
    clock = _Clock()
    artifacts, _ = build_quarantined_bootstrap(
        identity=identity,
        root_key_id=ANCHOR_ROOT_KEY_ID,
        root_private_key=anchor_root,
        witness_key_id="tiamat-recovery-witness.bootstrap.1",
        witness_private_key=Ed25519PrivateKey.generate(),
        checkpoint={
            "environment": environment,
            "ledger_id": str(identity.ledger_id),
            "storage_epoch": str(storage_epoch),
            "recovery_generation": 1,
            "release_inventory": {"state": "not_installed"},
            "release_heads": [],
            "settlement_position": [],
        },
        now=clock.now - timedelta(minutes=5),
    )
    table = ConditionalTable()
    writer = AnchorWriter(
        roots={f"ENV#{environment}#LEDGER#{identity.ledger_id}": _root_for(anchor_root)},
        client=table,
        table_name=TABLE,
        clock=clock,
    )
    writer.write(
        AnchorWriteRequest(
            anchor_key=f"ENV#{environment}#LEDGER#{identity.ledger_id}",
            transition_jws=artifacts.transition_jws,
            witness_jws=artifacts.witness_jws,
            inventory_jws=artifacts.inventory_jws,
        )
    )
    return _Ledger(
        roles=disposable_roles,
        identity=identity,
        release=SyntheticReleaseTrust(environment, f"caller-{uuid4().hex[:8]}", "g2r-realm"),
        anchor_root=anchor_root,
        table=table,
        writer=writer,
        clock=clock,
        head=AnchorHead(
            transition_jws=artifacts.transition_jws,
            witness_jws=artifacts.witness_jws,
            inventory_jws=artifacts.inventory_jws,
            witness_key_id=artifacts.witness_key_id,
        ),
    )


def _root_for(private: Ed25519PrivateKey) -> Any:
    root = _root(private)
    return type(root)(ANCHOR_ROOT_KEY_ID, root.root_public_key_b64, root.root_public_key_sha256)


def _report_checkpoint(ledger: _Ledger, target: int) -> RecoveryCheckpoint:
    report = read_ledger_recovery_state(ledger.roles.recovery, environment=ledger.environment)
    return empty_ledger_checkpoint(report, target_recovery_generation=target)


def _checkpoint(
    ledger: _Ledger,
    *,
    target: int,
    inventory: dict[str, object],
    positions: list[dict[str, object]] | None = None,
) -> RecoveryCheckpoint:
    return construct_recovery_checkpoint(
        {
            "environment": ledger.environment,
            "ledger_id": str(ledger.identity.ledger_id),
            "storage_epoch": str(ledger.identity.storage_epoch),
            "recovery_generation": target,
            "release_inventory": inventory,
            "release_heads": [],
            "settlement_position": positions or [],
        },
        identity=ledger.identity,
    )


def _position() -> dict[str, object]:
    return {
        "partition_id": "partition-a",
        "budget_period_id": "2026-09",
        "settled_microusd": 0,
        "reserved_microusd": 0,
        "pending_reconciliation_count": 0,
        "forfeited_microusd": 0,
        "contingency_used_microusd": 0,
        "external_liability_marker": "none",
    }


def _seed_partition(ledger: _Ledger) -> None:
    with psycopg.connect(ledger.roles.recovery) as recovery:
        recovery.execute(
            """
            INSERT INTO tiamat.spending_partitions (
                environment, caller_id, realm, partition_id, blocked, block_reason
            ) VALUES (%s, %s, 'g2r-realm', 'partition-a', true, 'no_active_grant')
            """,
            (ledger.environment, ledger.release.caller_id),
        )


# First-inventory install


def test_the_first_inventory_installs_once_and_dispatch_stays_blocked(ledger: _Ledger) -> None:
    before = ledger.gate()
    digest = ledger.install_first_inventory()
    assert ledger.inventories() == [(1, "active", 1)]
    # Dispatch, generation, coordinator and floor are untouched.
    assert ledger.gate() == before and before[1] is True
    report = read_ledger_recovery_state(ledger.roles.recovery, environment=ledger.environment)
    assert report.inventories == ((1, "active", digest),)
    # One-time: a second install, even of the same bytes, is refused.
    with pytest.raises(RecoveryRejected, match="first_inventory_prior_inventory_activated"):
        ledger.install_first_inventory()


def test_a_staged_candidate_of_the_same_bytes_is_accepted(ledger: _Ledger) -> None:
    from lucy.shared_execution.postgres_authority import PostgresSignedAuthorityStore
    from lucy.shared_execution.signed_releases import verify_trust_inventory

    exact = ledger.first_inventory_jws()
    inventory = verify_trust_inventory(
        exact,
        root_key_id=RELEASE_ROOT_KEY_ID,
        root_public_key=ledger.release.root_public_key,
        environment=ledger.environment,
    )
    # Control stages through the release manager while blocked; only activation is refused there.
    PostgresSignedAuthorityStore(ledger.roles.release_manager).stage_inventory(
        exact, inventory, hashlib.sha256(exact).hexdigest()
    )
    ledger.install_first_inventory(exact)
    assert ledger.inventories() == [(1, "active", 1)]


def _generation_two(ledger: _Ledger) -> bytes:
    exact = ledger.first_inventory_jws()
    segment = exact.split(b".")[1]
    payload = json.loads(base64.urlsafe_b64decode(segment + b"=" * (-len(segment) % 4)))
    payload["inventory_generation"] = 2
    payload["previous_inventory_digest"] = hashlib.sha256(exact).hexdigest()
    return _compact(payload, kid=RELEASE_ROOT_KEY_ID, typ=INVENTORY_TYP, key=ledger.release.root)


@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("foreign_root", "first_inventory_not_verified"),
        ("generation_two", "first_inventory_not_generation_one"),
        ("other_epoch", "restore_gate_epoch_differs"),
        ("other_ledger", "ledger_identity_differs"),
        ("gate_open", "restore_gate_not_blocked"),
        ("staged_other_bytes", "first_inventory_staged_candidate_differs"),
        ("financial_history", "recovery_ledger_financial_state_unsupported"),
        ("already_reconciled", "first_inventory_ledger_already_reconciled"),
        ("other_generation", "first_inventory_generation_differs"),
    ],
)
def test_the_first_inventory_refuses_invalid_preconditions(
    ledger: _Ledger, case: str, reason: str
) -> None:
    exact = ledger.first_inventory_jws()
    epoch, ledger_id = ledger.identity.storage_epoch, ledger.identity.ledger_id
    public_key = ledger.release.root_public_key
    generation = 1
    if case == "other_generation":
        generation = 2
    elif case == "foreign_root":
        public_key = Ed25519PrivateKey.generate().public_key()
    elif case == "generation_two":
        exact = _generation_two(ledger)
    elif case == "other_epoch":
        epoch = uuid4()
    elif case == "other_ledger":
        ledger_id = uuid4()
    elif case == "gate_open":
        with psycopg.connect(ledger.roles.recovery) as recovery:
            recovery.execute(
                "UPDATE tiamat.restore_gate SET dispatch_blocked = false, block_reason = NULL, "
                "verified_at = clock_timestamp() "
                "WHERE environment = %s",
                (ledger.environment,),
            )
    elif case == "staged_other_bytes":
        other = ledger.release.inventory_jws([("execution_profile", "a-different-subject")])
        from lucy.shared_execution.postgres_authority import PostgresSignedAuthorityStore
        from lucy.shared_execution.signed_releases import verify_trust_inventory

        PostgresSignedAuthorityStore(ledger.roles.release_manager).stage_inventory(
            other,
            verify_trust_inventory(
                other,
                root_key_id=RELEASE_ROOT_KEY_ID,
                root_public_key=public_key,
                environment=ledger.environment,
            ),
            hashlib.sha256(other).hexdigest(),
        )
    elif case == "financial_history":
        _seed_partition(ledger)
    else:
        with psycopg.connect(ledger.roles.recovery) as recovery:
            recovery.execute(
                """
                INSERT INTO tiamat.recovery_checkpoints (
                    environment, recovery_generation, ledger_id, storage_epoch,
                    checkpoint_sha256, release_heads_sha256, settlement_position_sha256,
                    checkpoint
                ) VALUES (%s, 1, %s, %s, %s, %s, %s, '{}'::jsonb)
                """,
                (ledger.environment, ledger_id, epoch, "a" * 64, "b" * 64, "c" * 64),
            )
    gate_before, inventories_before = ledger.gate(), ledger.inventories()
    with pytest.raises(RecoveryRejected, match=reason):
        install_first_release_inventory(
            ledger.roles.recovery,
            environment=ledger.environment,
            expected_ledger_id=ledger_id,
            expected_storage_epoch=epoch,
            expected_recovery_generation=generation,
            exact_jws=exact,
            release_root_key_id=RELEASE_ROOT_KEY_ID,
            release_root_public_key=public_key,
        )
    assert ledger.gate() == gate_before
    assert ledger.inventories() == inventories_before


def _fail_on(
    ledger: _Ledger, table: str, event: str, condition: str = "true"
) -> Any:  # a context manager that installs a failing trigger scoped to this environment
    import contextlib

    name = f"g2r_fail_{uuid4().hex[:8]}"

    @contextlib.contextmanager
    def installed() -> Any:
        with psycopg.connect(ledger.roles.owner, autocommit=True) as owner:
            owner.execute(
                f"""
                CREATE FUNCTION tiamat.{name}() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    IF NEW.environment = '{ledger.environment}' AND ({condition}) THEN
                        RAISE EXCEPTION 'injected failure';
                    END IF;
                    RETURN NEW;
                END $$
                """
            )
            owner.execute(
                f"CREATE TRIGGER {name} BEFORE {event} ON tiamat.{table} "
                f"FOR EACH ROW EXECUTE FUNCTION tiamat.{name}()"
            )
        try:
            yield
        finally:
            with psycopg.connect(ledger.roles.owner, autocommit=True) as owner:
                owner.execute(f"DROP TRIGGER {name} ON tiamat.{table}")
                owner.execute(f"DROP FUNCTION tiamat.{name}()")

    return installed()


def test_a_failed_first_inventory_install_leaves_nothing_behind(ledger: _Ledger) -> None:
    """The staged insert precedes the activation; the injected activation failure undoes both."""

    gate_before = ledger.gate()
    with _fail_on(ledger, "trust_inventories", "UPDATE"), pytest.raises(psycopg.Error):
        ledger.install_first_inventory()
    assert ledger.inventories() == []
    assert ledger.gate() == gate_before
    # And the ledger can still take its one first inventory afterwards.
    ledger.install_first_inventory()
    assert ledger.inventories() == [(1, "active", 1)]


# Generation-jump authorization


def test_a_legitimate_generation_jump_opens_the_gate_and_the_launcher_issues(
    ledger: _Ledger,
) -> None:
    ledger.install_first_inventory()
    checkpoint = _report_checkpoint(ledger, target=3)
    pending = ledger.pending(checkpoint)
    assert ledger.install(pending) == "installed_and_verified"
    coordinator_before = ledger.gate()[2]

    authorized = ledger.authorize(pending, source=1)

    assert authorized.target_recovery_generation == 3
    generation, blocked, coordinator, floor_version, floor_sha, reason = ledger.gate()
    assert (generation, blocked, coordinator, reason) == (3, False, coordinator_before + 1, None)
    assert (floor_version, floor_sha) == (2, pending.candidate.exact_sha256)
    assert ledger.retained() == [(3, checkpoint.checkpoint_sha256)]
    assert ledger.inventories() == [(1, "active", 3)]

    # Step 7: the beacon is read after the checkpoint is bound, then continuity is established.
    beacon = PostgresContinuityBeaconReader(ledger.roles.recovery).read(
        checkpoint_digest=checkpoint.checkpoint_sha256
    )
    # The operator tool reads the same beacon, bound to the checkpoint retained for generation 3.
    tool_beacon = _ledger_tool().bound_checkpoint_beacon(
        ledger.roles.recovery, environment=ledger.environment
    )
    assert tool_beacon["checkpoint_digest"] == checkpoint.checkpoint_sha256
    assert tool_beacon["system_identifier"] == beacon.system_identifier
    ledger.clock.now += timedelta(minutes=1)
    established_step, _ = build_continuity_established(
        pending=pending.step,
        root_private_key=ledger.anchor_root,
        beacon=beacon,
        now=ledger.clock.now,
    )
    established = ledger.verify(established_step)
    assert ledger.install(established) == "installed_and_verified"

    # The launcher, reading through the new trust file, issues exactly one claimant.
    reader = verified_anchor_reader(
        load_anchor_trust(established_step.trust_document()),
        now=ledger.clock.now,
        environment={"TIAMAT_RECOVERY_ANCHOR_TABLE": TABLE, "AWS_REGION": "us-east-1"},
        client_factory=lambda *_args, **_kwargs: ledger.table,
    )
    receipt = StartupAttestationIssuer(
        anchor=reader,
        identity=ledger.identity,
        recovery_database_url=ledger.roles.recovery,
        checkpoint_source=LedgerRecoveryCheckpointSource(ledger.roles.recovery),
    ).issue(now=datetime.now(UTC))
    assert receipt.anchor_transition_sha256 == established.candidate.exact_sha256
    assert receipt.anchor_transition_version == 3
    assert ledger.gate()[3:5] == (3, established.candidate.exact_sha256)


@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("wrong_checkpoint", "recovery_checkpoint_differs_from_witness"),
        ("wrong_settlement", "recovery_checkpoint_differs_from_witness"),
        ("inventory_not_on_ledger", "recovery_checkpoint_inventory_differs_from_ledger"),
        ("populated_ledger", "recovery_ledger_financial_state_unsupported"),
        ("source_differs", "recovery_source_generation_differs"),
        ("target_not_higher", "recovery_generation_must_advance"),
        ("gate_open", "restore_gate_not_blocked"),
        ("quarantined_anchor", "recovery_authorization_requires_pending_anchor"),
    ],
)
def test_authorization_refuses_what_the_ledger_or_witness_does_not_support(
    ledger: _Ledger, case: str, reason: str
) -> None:
    digest = ledger.install_first_inventory()
    installed = {"generation": 1, "jws_sha256": digest}
    checkpoint = _checkpoint(ledger, target=2, inventory=installed)
    presented: RecoveryCheckpoint | None = None
    source = 1
    if case == "source_differs":
        # A signed, installed target above the stated source: only the ledger can refuse it.
        source = 2
        checkpoint = _checkpoint(ledger, target=3, inventory=installed)
    elif case == "inventory_not_on_ledger":
        checkpoint = _checkpoint(
            ledger, target=2, inventory={"generation": 1, "jws_sha256": "e" * 64}
        )
    pending = ledger.pending(checkpoint)
    ledger.install(pending)
    authorized = pending.candidate
    if case == "wrong_checkpoint":
        presented = _checkpoint(
            ledger, target=2, inventory={"generation": 1, "jws_sha256": "e" * 64}
        )
    elif case == "wrong_settlement":
        presented = _checkpoint(ledger, target=2, inventory=installed, positions=[_position()])
    elif case == "populated_ledger":
        _seed_partition(ledger)
    elif case == "target_not_higher":
        source = 2
    elif case == "gate_open":
        with psycopg.connect(ledger.roles.recovery) as recovery:
            recovery.execute(
                "UPDATE tiamat.restore_gate SET dispatch_blocked = false, block_reason = NULL, "
                "verified_at = clock_timestamp() "
                "WHERE environment = %s",
                (ledger.environment,),
            )
    elif case == "quarantined_anchor":
        authorized = pending.head
    gate_before, retained_before = ledger.gate(), ledger.retained()
    with pytest.raises(RecoveryRejected, match=reason):
        authorize_recovery_generation(
            ledger.roles.recovery,
            anchor=ledger.store(pending),
            authorized=authorized,
            checkpoint=presented or checkpoint,
            source_recovery_generation=source,
        )
    assert ledger.gate() == gate_before
    assert ledger.retained() == retained_before


def test_a_verified_pending_step_never_installed_opens_nothing(ledger: _Ledger) -> None:
    ledger.install_first_inventory()
    pending = ledger.pending(_report_checkpoint(ledger, target=2))
    gate_before = ledger.gate()
    with pytest.raises(RecoveryRejected, match="recovery_anchor_head_is_not_the_pending_step"):
        ledger.authorize(pending)
    assert ledger.gate() == gate_before
    assert ledger.retained() == []


def test_a_failed_authorization_opens_nothing_and_binds_nothing(ledger: _Ledger) -> None:
    ledger.install_first_inventory()
    pending = ledger.pending(_report_checkpoint(ledger, target=2))
    ledger.install(pending)
    gate_before = ledger.gate()
    # Only the final update, which opens the gate, fails: the floor advance, the checkpoint
    # insert and the inventory restamp have already been written in the same transaction.
    opening = "OLD.dispatch_blocked AND NOT NEW.dispatch_blocked"
    with _fail_on(ledger, "restore_gate", "UPDATE", opening), pytest.raises(psycopg.Error):
        ledger.authorize(pending)
    assert ledger.gate() == gate_before  # floor version and digest included
    assert ledger.retained() == []
    assert ledger.inventories() == [(1, "active", 1)]
    # Readback resolves it; nothing opened, so the same authorization can be retried whole.
    ledger.authorize(pending)
    assert ledger.gate()[:2] == (2, False)


def test_the_empty_ledger_projection_refuses_financial_history(ledger: _Ledger) -> None:
    ledger.install_first_inventory()
    _seed_partition(ledger)
    report = read_ledger_recovery_state(ledger.roles.recovery, environment=ledger.environment)
    assert report.counts["spending_partitions"] == 1
    with pytest.raises(LedgerProjectionUnsupported, match="financial_state_unsupported"):
        empty_ledger_checkpoint(report, target_recovery_generation=2)


def test_the_empty_ledger_projection_requires_an_installed_inventory(ledger: _Ledger) -> None:
    report = read_ledger_recovery_state(ledger.roles.recovery, environment=ledger.environment)
    assert report.dispatch_blocked and report.recovery_generation == 1
    with pytest.raises(LedgerProjectionUnsupported, match="one_active_inventory"):
        empty_ledger_checkpoint(report, target_recovery_generation=2)


def _ledger_tool() -> ModuleType:
    path = ROOT / "deploy/postgres/tiamat_reconciliation_ledger_v1.py"
    spec = importlib.util.spec_from_file_location("tiamat_reconciliation_ledger", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_beacon_tool_refuses_a_blocked_or_unbound_gate(ledger: _Ledger) -> None:
    tool = _ledger_tool()
    with pytest.raises(ValueError, match="no checkpoint is bound"):
        tool.bound_checkpoint_beacon(ledger.roles.recovery, environment=ledger.environment)
    ledger.install_first_inventory()
    pending = ledger.pending(_report_checkpoint(ledger, target=2))
    ledger.install(pending)
    ledger.authorize(pending)
    with psycopg.connect(ledger.roles.recovery) as recovery:
        recovery.execute(
            "UPDATE tiamat.restore_gate SET dispatch_blocked = true, block_reason = 'probe' "
            "WHERE environment = %s",
            (ledger.environment,),
        )
    with pytest.raises(ValueError, match="gate is blocked"):
        tool.bound_checkpoint_beacon(ledger.roles.recovery, environment=ledger.environment)


def _prepare_tool() -> ModuleType:
    path = ROOT / "deploy/aws/prepare_tiamat_reconciliation_step_v1.py"
    spec = importlib.util.spec_from_file_location("prepare_reconciliation_step", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _private(kind: str, key_id: str, key: Ed25519PrivateKey) -> dict[str, object]:
    return {
        "format_version": "1",
        f"{kind}_key_id": key_id,
        f"{kind}_private_key_b64": base64.b64encode(key.private_bytes_raw()).decode(),
    }


def test_the_commissioned_shape_reconciles_from_an_expired_successor_head(
    disposable_roles: DisposableRoles,
) -> None:
    """The commissioned ledger's shape: a v2 continued-quarantine head at witness generation 2,
    its witness long expired, over a gate at generation 1. Pending is signed through the
    operator tool from the successor's published package, at generation 3; the gate jumps 1->3."""

    environment = f"g2r-{uuid4().hex[:10]}"
    storage_epoch = uuid4()
    with psycopg.connect(disposable_roles.owner) as owner:
        row = owner.execute(
            "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
        ).fetchone()
    assert row is not None
    identity = RecoveryAnchorIdentity(environment, UUID(str(row[0])), storage_epoch)
    with psycopg.connect(disposable_roles.recovery) as recovery:
        recovery.execute(
            """
            INSERT INTO tiamat.restore_gate (
                environment, storage_epoch, recovery_generation,
                coordinator_generation, dispatch_blocked, block_reason
            ) VALUES (%s, %s, 1, 1, true, 'initial_reconciliation_required')
            """,
            (environment, storage_epoch),
        )
    root = Ed25519PrivateKey.generate()
    clock = _Clock()
    now = clock.now
    bootstrap_at, successor_at = now - timedelta(hours=40), now - timedelta(hours=30)
    bootstrap, _ = build_quarantined_bootstrap(
        identity=identity,
        root_key_id=ANCHOR_ROOT_KEY_ID,
        root_private_key=root,
        witness_key_id="tiamat-recovery-witness.bootstrap.1",
        witness_private_key=Ed25519PrivateKey.generate(),
        checkpoint={
            "environment": environment,
            "ledger_id": str(identity.ledger_id),
            "storage_epoch": str(storage_epoch),
            "recovery_generation": 1,
            "release_inventory": {"state": "not_installed"},
            "release_heads": [],
            "settlement_position": [],
        },
        now=bootstrap_at,
    )
    successor, _ = build_continued_quarantine_successor(
        predecessor=bootstrap,
        identity=identity,
        root_private_key=root,
        witness_key_id="tiamat-recovery-witness.successor.2",
        witness_private_key=Ed25519PrivateKey.generate(),
        predecessor_verified_at=bootstrap_at,
        now=successor_at,
        validity=timedelta(hours=24),
    )
    table = ConditionalTable()
    anchor_key = f"ENV#{environment}#LEDGER#{identity.ledger_id}"
    writer = AnchorWriter(
        roots={anchor_key: _root_for(root)}, client=table, table_name=TABLE, clock=clock
    )
    clock.now = bootstrap_at
    writer.write(
        AnchorWriteRequest(
            anchor_key=anchor_key,
            transition_jws=bootstrap.transition_jws,
            witness_jws=bootstrap.witness_jws,
            inventory_jws=bootstrap.inventory_jws,
        )
    )
    clock.now = successor_at
    writer.write(
        AnchorWriteRequest(
            anchor_key=anchor_key,
            transition_jws=successor.transition_jws,
            witness_jws=successor.witness_jws,
            inventory_jws=successor.inventory_jws,
            head_inventory_jws=bootstrap.inventory_jws,
        )
    )
    clock.now = now
    release = SyntheticReleaseTrust(environment, f"caller-{uuid4().hex[:8]}", "g2r-realm")
    install_first_release_inventory(
        disposable_roles.recovery,
        environment=environment,
        expected_ledger_id=identity.ledger_id,
        expected_storage_epoch=storage_epoch,
        expected_recovery_generation=1,
        exact_jws=release.inventory_jws([("execution_profile", "profile-reconciliation")]),
        release_root_key_id=RELEASE_ROOT_KEY_ID,
        release_root_public_key=release.root_public_key,
    )
    report = read_ledger_recovery_state(disposable_roles.recovery, environment=environment)
    checkpoint = empty_ledger_checkpoint(report, target_recovery_generation=3)
    pin = hashlib.sha256(root.public_key().public_bytes_raw()).hexdigest()

    pending_package = _prepare_tool().build_pending_package(
        head_package=successor.public_package(identity),
        checkpoint=checkpoint.object,
        root_private_identity=_private("root", ANCHOR_ROOT_KEY_ID, root),
        witness_private_identity=_private(
            "witness", "tiamat-recovery-witness.reconciled.3", Ed25519PrivateKey.generate()
        ),
        expected_root_public_sha256=pin,
        now=now,
    )
    pending = verify_reconciliation_package(
        pending_package,
        now=now,
        expected_root_public_sha256=pin,
        expected_ceremony="recovery_pending",
    )
    assert pending.head.transition_version == 2
    assert pending.head.witness.recovery_generation == 2
    assert not pending.head.witness.valid_at(now)
    assert pending.candidate.witness.recovery_generation == 3
    store = DynamoDbExternalRecoveryAnchor(
        client=table, table_name=TABLE, decode_transition=pending.decoder()
    )
    assert install_through_writer(store, writer.write, pending) == "installed_and_verified"

    authorized = authorize_recovery_generation(
        disposable_roles.recovery,
        anchor=store,
        authorized=pending.candidate,
        checkpoint=pending.step.checkpoint,
        source_recovery_generation=1,
    )
    assert (authorized.source_recovery_generation, authorized.target_recovery_generation) == (
        1,
        3,
    )
    assert authorized.anchor_floor.transition_version == 3

    beacon = _ledger_tool().bound_checkpoint_beacon(
        disposable_roles.recovery, environment=environment
    )
    clock.now = now + timedelta(minutes=1)
    established_package, trust = _prepare_tool().build_established_package(
        pending_package=pending_package,
        beacon=beacon,
        root_private_identity=_private("root", ANCHOR_ROOT_KEY_ID, root),
        expected_root_public_sha256=pin,
        now=clock.now,
    )
    established = verify_reconciliation_package(
        established_package,
        now=clock.now,
        expected_root_public_sha256=pin,
        expected_ceremony="continuity_established",
    )
    store = DynamoDbExternalRecoveryAnchor(
        client=table, table_name=TABLE, decode_transition=established.decoder()
    )
    assert install_through_writer(store, writer.write, established) == "installed_and_verified"
    reader = verified_anchor_reader(
        load_anchor_trust(trust),
        now=clock.now,
        environment={"TIAMAT_RECOVERY_ANCHOR_TABLE": TABLE, "AWS_REGION": "us-east-1"},
        client_factory=lambda *_args, **_kwargs: table,
    )
    receipt = StartupAttestationIssuer(
        anchor=reader,
        identity=identity,
        recovery_database_url=disposable_roles.recovery,
        checkpoint_source=LedgerRecoveryCheckpointSource(disposable_roles.recovery),
    ).issue(now=datetime.now(UTC))
    assert receipt.anchor_transition_version == 4
    assert receipt.anchor_transition_sha256 == established.candidate.exact_sha256
