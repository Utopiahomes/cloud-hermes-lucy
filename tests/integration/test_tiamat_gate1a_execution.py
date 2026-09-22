"""Gate 1A: one complete synthetic execution through the integrated Tiamat path.

Verified anchor read, launcher continuity check, startup attestation, executor consuming the
claimant, synthetic provider dispatch, durable receipt and accounting, then clean shutdown.

Everything here is disposable: a throwaway ledger identity on a disposable PostgreSQL 16
database, an in-memory anchor, and an in-process provider that spends nothing. The commissioned
staging ledger, the live DynamoDB anchor and real provider credentials are untouched.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

from lucy.shared_execution.postgres_ledger import (
    LedgerAdmission,
    LedgerScope,
    PostgresExecutionLedger,
    RecoveryWitness,
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
    LedgerRecoveryCheckpointSource,
    StartupAttestationIssuer,
)
from tests.integration.conftest import DisposableRoles

ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE_PREFIX = "tiamat_test_d1"
RESERVED_MICROUSD = 2_000


@dataclass
class _Trace:
    """A content-free record of what the integrated path actually did."""

    steps: list[str] = field(default_factory=list)

    def record(self, step: str, **detail: object) -> None:
        rendered = " ".join(f"{name}={value}" for name, value in sorted(detail.items()))
        self.steps.append(f"{step} {rendered}".strip())


@dataclass(frozen=True)
class _SyntheticResult:
    content: str
    input_tokens: int
    output_tokens: int
    cost_microusd: int

    @property
    def cost_reference_digest(self) -> str:
        reference = f"synthetic:{self.input_tokens}:{self.output_tokens}:{self.cost_microusd}"
        return hashlib.sha256(reference.encode("ascii")).hexdigest()


class _SyntheticProvider:
    """Deterministic in-process provider. It reaches no network and spends nothing."""

    def __init__(self) -> None:
        self.calls = 0

    def execute(self, prompt: str) -> _SyntheticResult:
        self.calls += 1
        content = f"synthetic answer to {len(prompt)} characters"
        return _SyntheticResult(
            content=content,
            input_tokens=len(prompt),
            output_tokens=len(content),
            cost_microusd=137,
        )


@dataclass(frozen=True, repr=False)
class _Environment:
    owner: str
    recovery: str
    runtime: str
    ledger_id: UUID
    environment: str
    storage_epoch: UUID
    scope: LedgerScope

    def __repr__(self) -> str:
        return "_Environment(credentials=redacted)"


@pytest.fixture(scope="module")
def integrated(disposable_roles: DisposableRoles) -> _Environment:
    """One throwaway ledger identity and spending authority on the shared disposable database."""

    environment = f"g1a-{uuid4().hex[:8]}"
    storage_epoch = uuid4()
    caller, partition = f"caller-{uuid4().hex[:8]}", f"partition-{uuid4().hex[:8]}"
    with psycopg.connect(disposable_roles.owner) as owner:
        finalized = owner.execute(
            """
            SELECT pg_catalog.pg_get_userbyid(p.proowner) = 'tiamat_recovery'
              AND pg_catalog.has_function_privilege('tiamat_runtime', p.oid, 'EXECUTE')
            FROM pg_catalog.pg_proc AS p
            WHERE p.oid =
              pg_catalog.to_regprocedure('tiamat.consume_startup_attestation_v2(text)')
            """
        ).fetchone()
        if finalized is None or not finalized[0]:
            pytest.fail("gate 1A needs a D1-finalized disposable database", pytrace=False)
        ledger_row = owner.execute(
            "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
        ).fetchone()
    assert ledger_row is not None
    scope = LedgerScope(
        issuer="stoin:control",
        caller_id=caller,
        realm="g1a-realm",
        environment=environment,
        partition_id=partition,
    )
    _seed_environment(disposable_roles.recovery, environment, storage_epoch, scope)
    return _Environment(
        owner=disposable_roles.owner,
        recovery=disposable_roles.recovery,
        runtime=disposable_roles.runtime,
        ledger_id=UUID(str(ledger_row[0])),
        environment=environment,
        storage_epoch=storage_epoch,
        scope=scope,
    )


def _seed_environment(
    recovery_url: str, environment: str, storage_epoch: UUID, scope: LedgerScope
) -> None:
    """Create the unblocked gate, the spending authority and the budget period."""

    now = datetime.now(UTC)
    with psycopg.connect(recovery_url, autocommit=True) as recovery:
        recovery.execute("SELECT set_config('tiamat.environment', %s, false)", (environment,))
        recovery.execute("SELECT set_config('tiamat.caller_id', %s, false)", (scope.caller_id,))
        recovery.execute("SELECT set_config('tiamat.realm', %s, false)", (scope.realm,))
        recovery.execute(
            "SELECT set_config('tiamat.partition_id', %s, false)", (scope.partition_id,)
        )
        recovery.execute(
            """
            INSERT INTO tiamat.restore_gate
              (environment, storage_epoch, recovery_generation, coordinator_generation,
               dispatch_blocked, verified_at, anchor_floor_version, anchor_floor_sha256)
            VALUES (%s, %s, 1, 1, false, clock_timestamp(), 0, NULL)
            """,
            (environment, storage_epoch),
        )
        release_id = f"grant-{uuid4().hex[:8]}"
        period_id = f"period-{uuid4().hex[:8]}"
        recovery.execute(
            """
            INSERT INTO tiamat.spending_partitions (
              environment, caller_id, realm, partition_id, allowance_microusd,
              contingency_reserve_microusd, maximum_concurrency,
              largest_per_call_microusd, blocked
            ) VALUES (%s, %s, %s, %s, 20000, 8000, 2, 2000, false)
            """,
            (environment, scope.caller_id, scope.realm, scope.partition_id),
        )
        recovery.execute(
            """
            INSERT INTO tiamat.grant_releases (
              release_id, environment, caller_id, realm, partition_id, budget_period_id,
              not_before, not_after, period_start, period_end,
              allowance_microusd, contingency_reserve_microusd, maximum_concurrency,
              largest_per_call_microusd, signed_artifact_digest, activated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 20000, 8000, 2, 2000,
                      %s, clock_timestamp())
            """,
            (
                release_id,
                environment,
                scope.caller_id,
                scope.realm,
                scope.partition_id,
                period_id,
                now - timedelta(hours=1),
                now + timedelta(hours=6),
                now - timedelta(hours=1),
                now + timedelta(hours=6),
                hashlib.sha256(release_id.encode("ascii")).hexdigest(),
            ),
        )
        recovery.execute(
            """
            UPDATE tiamat.spending_partitions
            SET active_grant_release_id = %s, budget_period_id = %s
            WHERE environment = %s AND caller_id = %s AND realm = %s AND partition_id = %s
            """,
            (
                release_id,
                period_id,
                environment,
                scope.caller_id,
                scope.realm,
                scope.partition_id,
            ),
        )


def _identity(integrated: _Environment) -> RecoveryAnchorIdentity:
    return RecoveryAnchorIdentity(
        integrated.environment, integrated.ledger_id, integrated.storage_epoch
    )


def _bind_checkpoint(integrated: _Environment) -> str:
    """Retain the immutable checkpoint this generation is authorized under."""

    identity = _identity(integrated)
    checkpoint = construct_recovery_checkpoint(
        {
            "environment": identity.environment,
            "ledger_id": str(identity.ledger_id),
            "storage_epoch": str(identity.storage_epoch),
            "recovery_generation": 1,
            "release_inventory": {"state": "not_installed"},
            "release_heads": [],
            "settlement_position": [],
        },
        identity=identity,
    )
    with psycopg.connect(integrated.recovery, autocommit=True) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (identity.environment,)
        )
        recovery.execute(
            """
            INSERT INTO tiamat.recovery_checkpoints
              (environment, recovery_generation, ledger_id, storage_epoch,
               checkpoint_sha256, release_heads_sha256, settlement_position_sha256, checkpoint)
            VALUES (%s, 1, %s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
            """,
            (
                identity.environment,
                identity.ledger_id,
                identity.storage_epoch,
                checkpoint.checkpoint_sha256,
                checkpoint.release_heads_sha256,
                checkpoint.settlement_position_sha256,
                Jsonb(checkpoint.object),
            ),
        )
    return checkpoint.checkpoint_sha256


def _established_anchor(
    integrated: _Environment, checkpoint_digest: str, now: datetime
) -> tuple[InMemoryExternalRecoveryAnchor, VerifiedAnchorTransition]:
    """A disposable established anchor whose beacon describes this exact database."""

    identity = _identity(integrated)
    with psycopg.connect(integrated.recovery) as recovery:
        observed = recovery.execute(
            """
            SELECT (pg_catalog.pg_control_system()).system_identifier::text,
                   (pg_catalog.pg_control_checkpoint()).timeline_id::bigint,
                   pg_catalog.pg_current_wal_flush_lsn()::text
            """
        ).fetchone()
    assert observed is not None
    witness = VerifiedRecoveryWitness(
        identity=identity,
        recovery_generation=1,
        witness_revision=1,
        status="reconciled",
        checkpoint_digest=checkpoint_digest,
        release_heads_sha256="c" * 64,
        checkpoint_settlement_position_sha256="d" * 64,
        witness_inventory_digest="e" * 64,
        exact_jws=b"gate-1a-disposable-witness",
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(hours=1),
    )
    transition = VerifiedAnchorTransition(
        witness=witness,
        transition_version=1,
        previous_transition_sha256=None,
        continuity="continuity_established",
        beacon=PostgresContinuityBeacon(
            str(observed[0]), int(observed[1]), str(observed[2]), checkpoint_digest
        ),
        exact_jws=b"gate-1a-disposable-transition",
    )
    anchor = InMemoryExternalRecoveryAnchor()
    anchor.install(transition, expected_transition_sha256=None, now=now)
    return anchor, transition


def test_gate_1a_one_synthetic_execution_end_to_end(integrated: _Environment) -> None:
    trace = _Trace()
    now = datetime.now(UTC)
    identity = _identity(integrated)

    checkpoint_digest = _bind_checkpoint(integrated)
    trace.record("checkpoint_retained", generation=1)

    anchor, transition = _established_anchor(integrated, checkpoint_digest, now)
    trace.record(
        "anchor_read",
        continuity=transition.continuity,
        version=transition.transition_version,
    )

    # 1. The launcher verifies continuity against the live database and issues one claimant.
    receipt = StartupAttestationIssuer(
        anchor=anchor,
        identity=identity,
        recovery_database_url=integrated.recovery,
        checkpoint_source=LedgerRecoveryCheckpointSource(integrated.recovery),
    ).issue(now=now)
    trace.record("claimant_issued", expires_in_seconds=int((receipt.expires_at - now).seconds))

    # 2. The executor reads the anchor itself and consumes that claimant to acquire its fence.
    ledger = PostgresExecutionLedger(
        integrated.runtime,
        RecoveryWitness(
            environment=integrated.environment,
            storage_epoch=integrated.storage_epoch,
            recovery_generation=1,
        ),
    )
    # The executor performs its own read; it never trusts a digest handed to it in process.
    observed_head = anchor.read(identity.key)
    assert observed_head.exact_sha256 == transition.exact_sha256
    coordinator_generation = ledger.consume_startup_attestation(observed_head.exact_sha256)
    trace.record("claimant_consumed", coordinator_generation=coordinator_generation)

    # 3. Admit one request against the durable ledger.
    owner_id = uuid4()
    key_digest = hashlib.sha256(b"gate-1a-idempotency").hexdigest()
    identity_digest = hashlib.sha256(b"gate-1a-canonical-request").hexdigest()
    admission = LedgerAdmission(
        idempotency_key_digest=key_digest,
        identity_digest=identity_digest,
        digest_key_version="digest-v1",
        operation="inference.execute",
        contract_major=1,
        execution_profile_id="profile.v1",
        profile_release_id="profiles.1",
        provider_route_id="synthetic-local",
        rate_release_id="rates.gate-1a",
        owner_id=owner_id,
        execution_deadline=now + timedelta(seconds=30),
        eligibility_generation=1,
        reserved_microusd=RESERVED_MICROUSD,
    )
    record, created = ledger.create_or_get(
        integrated.scope, admission, coordinator_generation=coordinator_generation, now=now
    )
    assert created and record.state == "admitted"
    trace.record("admitted", reserved_microusd=record.reserved_microusd)

    # 4. Commit dispatch. The ledger rechecks the claimant inside this transaction.
    dispatched = ledger.dispatch(
        integrated.scope,
        record.execution_id,
        coordinator_generation=coordinator_generation,
        record_generation=record.record_generation,
        owner_id=owner_id,
    )
    assert dispatched.state == "dispatched"
    trace.record("dispatch_committed", record_generation=dispatched.record_generation)

    # 5. Only a committed dispatch may reach a provider.
    provider = _SyntheticProvider()
    result = provider.execute("what time is check-in?")
    trace.record("provider_returned", output_tokens=result.output_tokens)

    # 6. Settle durably, releasing the reservation and recording the cost.
    settled = ledger.settle_terminal(
        integrated.scope,
        record.execution_id,
        coordinator_generation=coordinator_generation,
        record_generation=dispatched.record_generation,
        owner_id=owner_id,
        state="completed",
        settled_microusd=result.cost_microusd,
        provider_cost_reference_digest=result.cost_reference_digest,
    )
    trace.record(
        "settled",
        state=settled.state,
        settlement_status=settled.settlement_status,
        settled_microusd=settled.settled_microusd,
    )

    assert settled.state == "completed"
    assert settled.settlement_status == "settled"
    assert settled.settled_microusd == result.cost_microusd

    # 7. Replay of the same idempotency key returns the same execution, dispatching nothing more.
    replayed, created_again = ledger.create_or_get(
        integrated.scope, admission, coordinator_generation=coordinator_generation, now=now
    )
    assert not created_again
    assert replayed.execution_id == record.execution_id
    # The provider call count is this test's own control flow, not a system guarantee:
    # nothing yet gates a provider call on committed dispatch. That belongs to the service
    # layer running on the durable ledger, which Gate 1A does not deliver.
    trace.record("replay_idempotent", execution_id_matches=True)

    # 8. Clean shutdown retires this fence without quarantining, so a launcher can issue the
    # next claimant. Blocking dispatch is quarantine, and an ordinary stop is not that.
    retired = ledger.retire_coordinator(coordinator_generation)
    assert retired == coordinator_generation + 1
    assert not ledger.verify_attestation_current(coordinator_generation)
    trace.record("shutdown", attestation_current=False, gate_blocked=False)

    # 9. The ledger is immediately relaunchable: a fresh claimant is issued and consumed.
    relaunch = StartupAttestationIssuer(
        anchor=anchor,
        identity=identity,
        recovery_database_url=integrated.recovery,
        checkpoint_source=LedgerRecoveryCheckpointSource(integrated.recovery),
    ).issue(now=datetime.now(UTC))
    assert relaunch.attestation_id != receipt.attestation_id
    relaunched = ledger.consume_startup_attestation(transition.exact_sha256)
    assert relaunched == retired + 1
    trace.record("relaunched", coordinator_generation=relaunched)

    _assert_durable_state(integrated, record.execution_id, result, coordinator_generation)
    print("\n".join(f"  {index + 1}. {step}" for index, step in enumerate(trace.steps)))


def _assert_durable_state(
    integrated: _Environment,
    execution_id: UUID,
    result: _SyntheticResult,
    coordinator_generation: int,
) -> None:
    """Everything the run claims must survive in the database, not only in memory."""

    with psycopg.connect(integrated.recovery) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (integrated.environment,)
        )
        execution = recovery.execute(
            """
            SELECT state, settlement_status, settled_microusd, provider_route_id,
                   coordinator_generation
            FROM tiamat.execution_records WHERE execution_id = %s
            """,
            (execution_id,),
        ).fetchone()
        claimant = recovery.execute(
            """
            SELECT consumed_coordinator_generation IS NOT NULL, anchor_transition_version
            FROM tiamat.startup_attestations
            WHERE environment = %s AND consumed_coordinator_generation = %s
            """,
            (integrated.environment, coordinator_generation),
        ).fetchone()
        gate = recovery.execute(
            """
            SELECT anchor_floor_version, dispatch_blocked, block_reason
            FROM tiamat.restore_gate WHERE environment = %s
            """,
            (integrated.environment,),
        ).fetchone()
        spending = recovery.execute(
            """
            SELECT period_spend_microusd, contingency_spend_microusd
            FROM tiamat.spending_partitions
            WHERE environment = %s AND caller_id = %s AND realm = %s AND partition_id = %s
            """,
            (
                integrated.environment,
                integrated.scope.caller_id,
                integrated.scope.realm,
                integrated.scope.partition_id,
            ),
        ).fetchone()
        events = recovery.execute(
            "SELECT count(*) FROM tiamat.financial_events WHERE environment = %s",
            (integrated.environment,),
        ).fetchone()

    # The reservation must have been released and the settled cost recorded, not merely
    # echoed back on the execution row.
    assert spending == (result.cost_microusd, 0)
    assert events is not None and int(events[0]) >= 1
    assert execution == (
        "completed",
        "settled",
        result.cost_microusd,
        "synthetic-local",
        coordinator_generation,
    )
    assert claimant == (True, 1)
    assert gate == (1, False, None)


def test_the_gate_reader_cannot_widen_its_own_scope(integrated: _Environment) -> None:
    """The definer gate reader follows the caller's own scope, never an argument.

    Inside the function ``current_user`` is its recovery owner, whose policy sees every row.
    An environment argument would therefore let the serving role read a gate that its own
    row-level security policy hides, so the scope comes from the session setting instead.
    """

    with psycopg.connect(integrated.runtime) as runtime:
        runtime.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (integrated.environment,)
        )
        scoped = runtime.execute(
            "SELECT storage_epoch FROM tiamat.share_locked_restore_gate()"
        ).fetchone()
        assert scoped is not None and scoped[0] == integrated.storage_epoch

        # The row follows the session scope, and there is no argument with which a caller
        # could ask for a different one.
        runtime.execute("SELECT set_config('tiamat.environment', %s, false)", ("staging",))
        other = runtime.execute(
            "SELECT storage_epoch FROM tiamat.share_locked_restore_gate()"
        ).fetchone()
        assert other is None or other[0] != integrated.storage_epoch

        # With no scope at all the function refuses rather than serving an arbitrary row.
        runtime.execute("SELECT set_config('tiamat.environment', '', false)")
        with pytest.raises(psycopg.Error) as refused:
            runtime.execute("SELECT storage_epoch FROM tiamat.share_locked_restore_gate()")
    assert refused.value.sqlstate == "ZX108"


def test_a_direct_gate_read_still_hides_other_environments(integrated: _Environment) -> None:
    """The serving role's own row-level security is unchanged by migration 0012."""

    with psycopg.connect(integrated.runtime) as runtime:
        runtime.execute("SELECT set_config('tiamat.environment', %s, false)", ("staging",))
        foreign = runtime.execute(
            "SELECT count(*) FROM tiamat.restore_gate WHERE environment = %s",
            (integrated.environment,),
        ).fetchone()
    assert foreign == (0,)
