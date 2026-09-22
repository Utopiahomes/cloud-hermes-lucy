"""Gate 1A: one complete synthetic execution through the integrated Tiamat path.

Verified anchor read, launcher continuity check, startup attestation, executor consuming the
claimant, synthetic provider dispatch, durable receipt and accounting, then clean shutdown.

Everything here is disposable: a throwaway ledger identity on a disposable PostgreSQL 16
database, an in-memory anchor, and an in-process provider that spends nothing. The commissioned
staging ledger, the live DynamoDB anchor and real provider credentials are untouched.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

from lucy.shared_execution.durable_executor import (
    DurableExecutor,
    ExecutionRefused,
    IdempotencyRecoveryUnavailable,
    ProviderOutcome,
)
from lucy.shared_execution.postgres_authority import (
    AuthorityScope,
    PostgresSignedAuthorityStore,
)
from lucy.shared_execution.postgres_ledger import (
    DispatchBlocked,
    DurableFenceRejected,
    LedgerAdmission,
    LedgerRecord,
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
from lucy.shared_execution.recovery_checkpoint import (
    RecoveryCheckpointRejected,
    construct_recovery_checkpoint,
)
from lucy.shared_execution.signed_releases import RELEASE_ADAPTER, VerifiedRelease
from lucy.shared_execution.startup_attestation import (
    LedgerRecoveryCheckpointSource,
    StartupAttestationIssuer,
    StartupAttestationRejected,
)
from tests.integration.conftest import DisposableRoles

ROOT = Path(__file__).resolve().parents[2]
# A synthetic installed inventory: the day-zero sentinel cannot authorize dispatch, so the
# happy path is seeded with an installed one. It is seeded, not activated through a signed
# release, which the evidence records as a limit of this proof.
INSTALLED_INVENTORY = {"generation": 1, "jws_sha256": "b" * 64}
TEST_DATABASE_PREFIX = "tiamat_test_d1"
RESERVED_MICROUSD = 2_000
AUTHORITY_ISSUER = "stoin-control"
# The signed authority every Gate 1A and 1B admission is pinned to.
PROFILE_ID, PROFILE_RELEASE = "profile.v1", "profiles.1"
POLICY_ID, POLICY_RELEASE = "policy.v1", "policy.1"
REVOCATIONS = "gate1-revocations"


@dataclass
class _Trace:
    """A content-free record of what the integrated path actually did."""

    steps: list[str] = field(default_factory=list)

    def record(self, step: str, **detail: object) -> None:
        rendered = " ".join(f"{name}={value}" for name, value in sorted(detail.items()))
        self.steps.append(f"{step} {rendered}".strip())


class _SyntheticProvider:
    """Deterministic in-process provider. It reaches no network and spends nothing.

    It records the ledger state it was handed, so the test can show the executor reached it only
    from a committed dispatch rather than asserting its own call ordering.
    """

    def __init__(self) -> None:
        self.dispatched_states: list[str] = []
        self.last_cost_microusd = 137

    def __call__(self, dispatched: LedgerRecord, work: object = None) -> ProviderOutcome:
        self.dispatched_states.append(dispatched.state)
        reference = f"synthetic:{dispatched.execution_id}:{self.last_cost_microusd}"
        return ProviderOutcome(
            settled_microusd=self.last_cost_microusd,
            cost_reference_digest=hashlib.sha256(reference.encode("ascii")).hexdigest(),
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
    release_manager: str = ""

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
    env = _Environment(
        owner=disposable_roles.owner,
        recovery=disposable_roles.recovery,
        runtime=disposable_roles.runtime,
        ledger_id=UUID(str(ledger_row[0])),
        environment=environment,
        storage_epoch=storage_epoch,
        scope=scope,
        release_manager=disposable_roles.release_manager,
    )
    _seed_signed_authority(env)
    return env


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


def _authority(env: _Environment) -> AuthorityScope:
    return AuthorityScope(env.environment, AUTHORITY_ISSUER, env.scope.caller_id, env.scope.realm)


def _stage(
    env: _Environment,
    release_type: str,
    subject_id: str,
    release_id: str,
    *,
    sequence: int,
    predecessor: str | None = None,
) -> str:
    """Stage one release row as ``stage_release`` would, without the signature it verifies.

    Signature verification is covered by the signed-release tests; these cases test what the
    ledger does with authority once it is in the tables.
    """

    exact = f"{env.environment}:{release_type}:{subject_id}:{release_id}".encode()
    digest = hashlib.sha256(exact).hexdigest()
    now = datetime.now(UTC)
    with psycopg.connect(env.release_manager, autocommit=True) as manager:
        manager.execute("SELECT set_config('tiamat.environment', %s, false)", (env.environment,))
        manager.execute(
            "SELECT set_config('tiamat.caller_id', %s, false)", (env.scope.caller_id,)
        )
        manager.execute("SELECT set_config('tiamat.realm', %s, false)", (env.scope.realm,))
        manager.execute(
            """
            INSERT INTO tiamat.signed_releases (
                environment, issuer, caller_id, realm, release_type, subject_id,
                release_id, sequence, predecessor_release_id, signing_key_id,
                not_before, not_after, content_digest, exact_jws, jws_sha256, state
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'release-key-gate1',
                      %s, %s, %s, %s, %s, 'staged')
            """,
            (
                env.environment,
                AUTHORITY_ISSUER,
                env.scope.caller_id,
                env.scope.realm,
                release_type,
                subject_id,
                release_id,
                sequence,
                predecessor,
                now - timedelta(hours=1),
                now + timedelta(days=1),
                digest,
                exact,
                digest,
            ),
        )
    return digest


def _seed_signed_authority(
    env: _Environment,
    *,
    profile: tuple[str, str] = (PROFILE_ID, PROFILE_RELEASE),
    policy: tuple[str, str] = (POLICY_ID, POLICY_RELEASE),
) -> None:
    """Stage and activate the profile and privacy policy admissions are pinned to."""

    store = PostgresSignedAuthorityStore(env.release_manager)
    for release_type, (subject_id, release_id) in (
        ("execution_profile", profile),
        ("privacy_policy", policy),
    ):
        _stage(env, release_type, subject_id, release_id, sequence=1)
        store.activate_release(_authority(env), release_type, subject_id, release_id)


def _activate_successor(
    env: _Environment,
    release_type: str,
    subject_id: str,
    release_id: str,
    *,
    predecessor: str,
    sequence: int,
) -> None:
    """Stage and activate a routine successor, as the release manager does."""

    _stage(env, release_type, subject_id, release_id, sequence=sequence, predecessor=predecessor)
    PostgresSignedAuthorityStore(env.release_manager).activate_release(
        _authority(env), release_type, subject_id, release_id
    )


def _prepare_revocation(
    env: _Environment,
    target_type: str,
    target_release_id: str,
    *,
    revocations: str = REVOCATIONS,
) -> Callable[[], None]:
    """Stage a revocation release now; return the step that activates and applies it.

    Staging first lets a race put only the revocation's own commit inside the window it
    measures, so a slow connection to the database cannot pass for a blocked lock.
    """

    release_id = f"revocation-{uuid4().hex[:8]}"
    digest = _stage(env, "revocation", revocations, release_id, sequence=1)
    now = datetime.now(UTC)
    payload = RELEASE_ADAPTER.validate_python(
        {
            "format_version": "1",
            "release_id": release_id,
            "subject_id": revocations,
            "issuer": AUTHORITY_ISSUER,
            "environment": env.environment,
            "caller_id": env.scope.caller_id,
            "realm": env.scope.realm,
            "issued_at": now.isoformat(),
            "not_before": (now - timedelta(hours=1)).isoformat(),
            "not_after": (now + timedelta(days=1)).isoformat(),
            "sequence": 1,
            "predecessor_release_id": None,
            "content_digest": digest,
            "release_type": "revocation",
            "content": {
                "target_type": "release",
                "target_release_type": target_type,
                "target_release_id": target_release_id,
                "reason_code": "gate1_security_revocation",
                "effective_at": now.isoformat(),
                "eligibility_generation": 2,
            },
        }
    )
    store = PostgresSignedAuthorityStore(env.release_manager)
    revocation = VerifiedRelease(payload=payload, exact_jws=b"gate1", jws_sha256=digest)
    return lambda: store.activate_revocation(_authority(env), revocation)


def _revoke(
    env: _Environment, target_type: str, target_release_id: str, **options: str
) -> None:
    """Activate and apply one revocation, in one commit, as the release manager does."""

    _prepare_revocation(env, target_type, target_release_id, **options)()


def _admission(now: datetime, *, owner_id: UUID, key: bytes) -> LedgerAdmission:
    return LedgerAdmission(
        idempotency_key_digest=hashlib.sha256(key).hexdigest(),
        identity_digest=hashlib.sha256(b"gate-1a-canonical-request").hexdigest(),
        digest_key_version="digest-v1",
        operation="inference.execute",
        contract_major=1,
        execution_profile_id=PROFILE_ID,
        profile_release_id=PROFILE_RELEASE,
        privacy_policy_id=POLICY_ID,
        privacy_policy_release_id=POLICY_RELEASE,
        provider_route_id="synthetic-local",
        rate_release_id="rates.gate-1a",
        owner_id=owner_id,
        execution_deadline=now + timedelta(seconds=30),
        eligibility_generation=1,
        reserved_microusd=RESERVED_MICROUSD,
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
            "release_inventory": INSTALLED_INVENTORY,
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

    return _established_anchor_for(integrated, _identity(integrated), checkpoint_digest, now)


def _established_anchor_with_validity(
    integrated: _Environment,
    identity: RecoveryAnchorIdentity,
    checkpoint_digest: str,
    now: datetime,
    *,
    not_after: datetime,
) -> tuple[InMemoryExternalRecoveryAnchor, VerifiedAnchorTransition]:
    """An established anchor whose witness stops being valid at ``not_after``."""

    _, transition = _established_anchor_for(integrated, identity, checkpoint_digest, now)
    bounded = replace(transition, witness=replace(transition.witness, not_after=not_after))
    anchor = InMemoryExternalRecoveryAnchor()
    anchor.install(bounded, expected_transition_sha256=None, now=now)
    return anchor, bounded


def _ledger(integrated: _Environment) -> PostgresExecutionLedger:
    return PostgresExecutionLedger(
        integrated.runtime,
        RecoveryWitness(
            environment=integrated.environment,
            storage_epoch=integrated.storage_epoch,
            recovery_generation=1,
        ),
    )


def _current_coordinator_generation(integrated: _Environment) -> int:
    with psycopg.connect(integrated.recovery) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (integrated.environment,)
        )
        row = recovery.execute(
            "SELECT coordinator_generation FROM tiamat.restore_gate WHERE environment = %s",
            (integrated.environment,),
        ).fetchone()
    assert row is not None
    return int(row[0])


def _gate_state(integrated: _Environment) -> tuple[bool, str | None]:
    with psycopg.connect(integrated.recovery) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (integrated.environment,)
        )
        row = recovery.execute(
            "SELECT dispatch_blocked, block_reason FROM tiamat.restore_gate WHERE environment = %s",
            (integrated.environment,),
        ).fetchone()
    assert row is not None
    return bool(row[0]), None if row[1] is None else str(row[1])


def _unblock(integrated: _Environment) -> None:
    """Only the recovery role may reopen a gate; the serving role has no such path."""

    with psycopg.connect(integrated.recovery, autocommit=True) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (integrated.environment,)
        )
        recovery.execute(
            """
            UPDATE tiamat.restore_gate
            SET dispatch_blocked = false, block_reason = NULL, verified_at = clock_timestamp()
            WHERE environment = %s
            """,
            (integrated.environment,),
        )


def _fresh_fence(integrated: _Environment) -> int:
    """Issue and consume a claimant, returning the coordinator generation it established."""

    now = datetime.now(UTC)
    digest = _bind_checkpoint(integrated)
    anchor, transition = _established_anchor(integrated, digest, now)
    StartupAttestationIssuer(
        anchor=anchor,
        identity=_identity(integrated),
        recovery_database_url=integrated.recovery,
        checkpoint_source=LedgerRecoveryCheckpointSource(integrated.recovery),
    ).issue(now=now)
    return _ledger(integrated).consume_startup_attestation(transition.exact_sha256)


def _bind_sentinel_checkpoint(
    integrated: _Environment, identity: RecoveryAnchorIdentity
) -> str:
    """Bind a day-zero checkpoint for a separate environment, gate unblocked at generation one."""

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
            INSERT INTO tiamat.restore_gate
              (environment, storage_epoch, recovery_generation, coordinator_generation,
               dispatch_blocked, verified_at, anchor_floor_version, anchor_floor_sha256)
            VALUES (%s, %s, 1, 1, false, clock_timestamp(), 0, NULL)
            ON CONFLICT (environment) DO NOTHING
            """,
            (identity.environment, identity.storage_epoch),
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


def _established_anchor_for(
    integrated: _Environment,
    identity: RecoveryAnchorIdentity,
    checkpoint_digest: str,
    now: datetime,
) -> tuple[InMemoryExternalRecoveryAnchor, VerifiedAnchorTransition]:
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

    # 3. Serve the request through the durable executor. The provider is reachable only from
    # inside it, after the ledger has committed the dispatch under this fence.
    provider = _SyntheticProvider()
    executor = DurableExecutor(
        ledger=ledger,
        scope=integrated.scope,
        coordinator_generation=coordinator_generation,
        provider=provider,
    )
    owner_id = uuid4()
    admission = _admission(now, owner_id=owner_id, key=b"gate-1a-idempotency")
    outcome = executor.execute(admission, now=now)
    trace.record("served", state=outcome.state, settlement_status=outcome.settlement_status)

    assert outcome.state == "completed"
    assert outcome.settlement_status == "settled"
    assert outcome.settled_microusd == provider.last_cost_microusd
    assert provider.dispatched_states == ["dispatched"]
    trace.record("provider_called_after_commit", dispatched_state=provider.dispatched_states[0])

    # 4. A duplicate of the same idempotency key reaches no provider. This executor holds no
    # volatile body, so RC1 answers the durable completion with idempotency_recovery_unavailable
    # rather than an empty success; the served API's body replay is proven in its own tests.
    with pytest.raises(IdempotencyRecoveryUnavailable) as unavailable:
        executor.execute(admission, now=now)
    assert unavailable.value.execution_id == outcome.execution_id
    assert len(provider.dispatched_states) == 1
    trace.record("replay_idempotent", execution_id_matches=True, body="recovery_unavailable")

    # 8. Clean shutdown retires this fence without quarantining, so a launcher can issue the
    # next claimant. Blocking dispatch is quarantine, and an ordinary stop is not that.
    retired = executor.shutdown()
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

    _assert_durable_state(integrated, outcome.execution_id, provider, coordinator_generation)
    print("\n".join(f"  {index + 1}. {step}" for index, step in enumerate(trace.steps)))


def _assert_durable_state(
    integrated: _Environment,
    execution_id: UUID,
    provider: _SyntheticProvider,
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
    assert spending == (provider.last_cost_microusd, 0)
    assert events is not None and int(events[0]) >= 1
    assert execution == (
        "completed",
        "settled",
        provider.last_cost_microusd,
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


def test_a_stale_fence_reaches_no_provider(integrated: _Environment) -> None:
    """The service, not the caller, refuses a provider call without a committed dispatch."""

    ledger = _ledger(integrated)
    provider = _SyntheticProvider()
    stale = DurableExecutor(
        ledger=ledger,
        scope=integrated.scope,
        coordinator_generation=1,
        provider=provider,
    )

    with pytest.raises(ExecutionRefused):
        stale.execute(
            _admission(datetime.now(UTC), owner_id=uuid4(), key=b"gate-1a-stale"),
            now=datetime.now(UTC),
        )

    assert provider.dispatched_states == []


def test_retirement_is_generation_checked(integrated: _Environment) -> None:
    """A stale generation cannot retire a fence it no longer holds."""

    ledger = _ledger(integrated)
    current = _current_coordinator_generation(integrated)

    with pytest.raises(DispatchBlocked):
        ledger.retire_coordinator(current - 1)

    assert _current_coordinator_generation(integrated) == current


def test_retirement_never_clears_a_dispatch_block(integrated: _Environment) -> None:
    """Retiring a fence is not an unblock: a quarantined gate stays quarantined."""

    ledger = _ledger(integrated)
    ledger.block_dispatch("quarantine_under_test")
    blocked_generation = _current_coordinator_generation(integrated)

    retired = ledger.retire_coordinator(blocked_generation)

    assert retired == blocked_generation + 1
    assert _gate_state(integrated) == (True, "quarantine_under_test")
    # Restore the environment for any later case: only the recovery role may unblock.
    _unblock(integrated)


def test_a_clean_stop_drains_before_retiring(integrated: _Environment) -> None:
    """In-flight work must reach a terminal state before its fence is retired.

    Retiring first would strand it: the fence it was admitted under no longer settles, and a
    provider call may already have been sent.
    """

    ledger = _ledger(integrated)
    generation = _fresh_fence(integrated)
    admitted, created = ledger.create_or_get(
        integrated.scope,
        _admission(datetime.now(UTC), owner_id=uuid4(), key=b"gate-1a-drain"),
        coordinator_generation=generation,
        now=datetime.now(UTC),
    )
    assert created and admitted.state == "admitted"

    executor = DurableExecutor(
        ledger=ledger,
        scope=integrated.scope,
        coordinator_generation=generation,
        provider=_SyntheticProvider(),
    )
    with pytest.raises(ExecutionRefused, match="drain"):
        executor.shutdown()
    assert _current_coordinator_generation(integrated) == generation


def test_the_day_zero_sentinel_cannot_authorize_dispatch(integrated: _Environment) -> None:
    """Draft 0.5 section 4: the not_installed sentinel may not authorize serving.

    The launcher must refuse to mint a claimant over it, however valid the signed authority.
    """

    environment = f"g1a-sentinel-{uuid4().hex[:8]}"
    storage_epoch = uuid4()
    identity = RecoveryAnchorIdentity(environment, integrated.ledger_id, storage_epoch)
    digest = _bind_sentinel_checkpoint(integrated, identity)
    anchor, _ = _established_anchor_for(integrated, identity, digest, datetime.now(UTC))

    with pytest.raises(StartupAttestationRejected, match="inventory_not_installed"):
        StartupAttestationIssuer(
            anchor=anchor,
            identity=identity,
            recovery_database_url=integrated.recovery,
            checkpoint_source=LedgerRecoveryCheckpointSource(integrated.recovery),
        ).issue(now=datetime.now(UTC))


def test_shutdown_and_a_concurrent_admission_cannot_both_win(
    integrated: _Environment,
) -> None:
    """A request admitted beside a shutdown must not be stranded by the retirement.

    The drain check and the generation move share one transaction, so either the admission
    commits first and the retirement refuses, or the retirement wins and the admission fails its
    own fence. Both succeeding would leave work that can never settle.
    """

    ledger = _ledger(integrated)
    generation = _fresh_fence(integrated)
    executor = DurableExecutor(
        ledger=ledger,
        scope=integrated.scope,
        coordinator_generation=generation,
        provider=_SyntheticProvider(),
    )
    admission = _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes)

    outcomes: dict[str, object] = {}

    def _admit() -> None:
        try:
            outcomes["admitted"] = ledger.create_or_get(
                integrated.scope,
                admission,
                coordinator_generation=generation,
                now=datetime.now(UTC),
            )[1]
        except (DispatchBlocked, DurableFenceRejected) as exc:
            outcomes["admitted"] = f"refused:{type(exc).__name__}"

    def _retire() -> None:
        try:
            outcomes["retired"] = executor.shutdown()
        except ExecutionRefused as exc:
            outcomes["retired"] = f"refused:{exc}"

    with ThreadPoolExecutor(max_workers=2) as pool:
        tasks = [pool.submit(_admit), pool.submit(_retire)]
        for task in tasks:
            task.result()

    admitted_won = outcomes["admitted"] is True
    retired_won = isinstance(outcomes["retired"], int)
    assert admitted_won != retired_won, outcomes

    if admitted_won:
        # The fence still owns the work, so it can still be settled under it.
        assert _current_coordinator_generation(integrated) == generation
    else:
        assert _current_coordinator_generation(integrated) == generation + 1
        assert ledger.in_flight_under_fence(integrated.scope, generation) == 0


def test_a_malformed_retained_checkpoint_is_not_installed_authority(
    integrated: _Environment,
) -> None:
    """A checkpoint whose object does not validate must never read as installed authority."""

    environment = f"g1a-malformed-{uuid4().hex[:8]}"
    identity = RecoveryAnchorIdentity(environment, integrated.ledger_id, uuid4())
    with psycopg.connect(integrated.recovery, autocommit=True) as recovery:
        recovery.execute("SELECT set_config('tiamat.environment', %s, false)", (environment,))
        recovery.execute(
            """
            INSERT INTO tiamat.restore_gate
              (environment, storage_epoch, recovery_generation, coordinator_generation,
               dispatch_blocked, verified_at, anchor_floor_version, anchor_floor_sha256)
            VALUES (%s, %s, 1, 1, false, clock_timestamp(), 0, NULL)
            """,
            (environment, identity.storage_epoch),
        )
        # An object that would pass the old key-shape test but is not a valid checkpoint.
        recovery.execute(
            """
            INSERT INTO tiamat.recovery_checkpoints
              (environment, recovery_generation, ledger_id, storage_epoch,
               checkpoint_sha256, release_heads_sha256, settlement_position_sha256, checkpoint)
            VALUES (%s, 1, %s, %s, %s, %s, %s, %s)
            """,
            (
                environment,
                identity.ledger_id,
                identity.storage_epoch,
                "a" * 64,
                "b" * 64,
                "c" * 64,
                Jsonb({"release_inventory": {"generation": 1, "jws_sha256": "f" * 64}}),
            ),
        )

    with pytest.raises(RecoveryCheckpointRejected):
        LedgerRecoveryCheckpointSource(integrated.recovery).read_checkpoint(identity)
