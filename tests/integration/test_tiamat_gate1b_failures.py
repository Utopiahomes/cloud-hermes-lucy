"""Gate 1B: the failure cases that could invalidate Gate 2.

Expiry while running, quarantine during dispatch, and old-worker fencing. Each asks whether the
system refuses, and whether the synthetic provider was reached at all: a refusal that still sent a
provider call would be no refusal.

The setup helpers come from the Gate 1A module so the two gates exercise the same environment
rather than a second, subtly different one. Everything is disposable, and no real provider,
commissioned ledger or live anchor write is involved.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest

from lucy.shared_execution.durable_executor import DurableExecutor, ExecutionRefused
from lucy.shared_execution.postgres_ledger import DispatchBlocked, DurableFenceRejected, LedgerScope
from lucy.shared_execution.recovery_anchor import (
    InMemoryExternalRecoveryAnchor,
    VerifiedAnchorTransition,
)
from lucy.shared_execution.startup_attestation import (
    LedgerRecoveryCheckpointSource,
    StartupAttestationIssuer,
)
from tests.integration.conftest import DisposableRoles
from tests.integration.test_tiamat_gate1a_execution import (
    _admission,
    _bind_checkpoint,
    _current_coordinator_generation,
    _Environment,
    _established_anchor_with_validity,
    _fresh_fence,
    _identity,
    _ledger,
    _seed_environment,
    _SyntheticProvider,
    _unblock,
)

# Long enough that issuing and consuming a claimant over the network cannot itself consume the
# window, short enough that waiting for real expiry stays cheap.
LIFETIME_SECONDS = 8


@pytest.fixture
def gate1b(disposable_roles: DisposableRoles) -> _Environment:
    """A throwaway ledger identity per case.

    Each failure case leaves the gate somewhere different - blocked, retired, expired - so they
    get their own environment rather than inheriting whatever the previous one left behind.
    """

    environment = f"g1b-{uuid4().hex[:8]}"
    storage_epoch = uuid4()
    with psycopg.connect(disposable_roles.owner) as owner:
        ledger_row = owner.execute(
            "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton"
        ).fetchone()
    assert ledger_row is not None
    scope = LedgerScope(
        issuer="stoin:control",
        caller_id=f"caller-{uuid4().hex[:8]}",
        realm="g1b-realm",
        environment=environment,
        partition_id=f"partition-{uuid4().hex[:8]}",
    )
    _seed_environment(disposable_roles.recovery, environment, storage_epoch, scope)
    return _Environment(
        owner=disposable_roles.owner,
        recovery=disposable_roles.recovery,
        runtime=disposable_roles.runtime,
        ledger_id=ledger_row[0],
        environment=environment,
        storage_epoch=storage_epoch,
        scope=scope,
    )


def _short_lived_fence(
    gate1b: _Environment,
    *,
    claimant_lifetime: timedelta | None = None,
    witness_lifetime: timedelta = timedelta(hours=1),
) -> tuple[int, InMemoryExternalRecoveryAnchor, VerifiedAnchorTransition]:
    """Consume a claimant under authority that stays valid longer than the claimant does.

    A short witness proves authority lapsing. A short claimant under a long witness proves the
    ordinary case: the claimant is the thing that needs renewing, and the signed authority behind
    it has not changed. The issuer bounds a claimant by its own lifetime or the witness's
    ``not_after``, whichever comes first.
    """

    now = datetime.now(UTC)
    digest = _bind_checkpoint(gate1b)
    identity = _identity(gate1b)
    anchor, transition = _established_anchor_with_validity(
        gate1b, identity, digest, now, not_after=now + witness_lifetime
    )
    StartupAttestationIssuer(
        anchor=anchor,
        identity=identity,
        recovery_database_url=gate1b.recovery,
        checkpoint_source=LedgerRecoveryCheckpointSource(gate1b.recovery),
        **({} if claimant_lifetime is None else {"claimant_lifetime": claimant_lifetime}),
    ).issue(now=now)
    return _ledger(gate1b).consume_startup_attestation(transition.exact_sha256), anchor, transition


def test_expiry_while_running_stops_dispatch(gate1b: _Environment) -> None:
    """A claimant that has expired must not keep authorizing dispatch.

    The claimant's own expiry is at most the signed witness's ``not_after``, so an expired
    claimant is the conservative signal that authority has lapsed while the process kept running.
    """

    ledger = _ledger(gate1b)
    generation, _, _ = _short_lived_fence(
        gate1b, witness_lifetime=timedelta(seconds=LIFETIME_SECONDS)
    )
    provider = _SyntheticProvider()
    executor = DurableExecutor(
        ledger=ledger,
        scope=gate1b.scope,
        coordinator_generation=generation,
        provider=provider,
    )
    assert ledger.verify_attestation_current(generation)

    time.sleep(LIFETIME_SECONDS + 2)

    assert not ledger.verify_attestation_current(generation)
    with pytest.raises(ExecutionRefused):
        executor.execute(
            _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes),
            now=datetime.now(UTC),
        )
    assert provider.dispatched_states == []


def test_quarantine_during_dispatch_refuses_and_sends_nothing(gate1b: _Environment) -> None:
    """A quarantine landing after admission must stop the dispatch it would have authorized."""

    ledger = _ledger(gate1b)
    generation = _fresh_fence(gate1b)
    provider = _SyntheticProvider()
    now = datetime.now(UTC)
    admission = _admission(now, owner_id=uuid4(), key=uuid4().bytes)

    admitted, created = ledger.create_or_get(
        gate1b.scope, admission, coordinator_generation=generation, now=now
    )
    assert created and admitted.state == "admitted"

    ledger.block_dispatch("quarantine_during_dispatch")

    with pytest.raises((DispatchBlocked, DurableFenceRejected)):
        ledger.dispatch(
            gate1b.scope,
            admitted.execution_id,
            coordinator_generation=generation,
            record_generation=admitted.record_generation,
            owner_id=admission.owner_id,
        )
    assert provider.dispatched_states == []

    with psycopg.connect(gate1b.recovery) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (gate1b.environment,)
        )
        state = recovery.execute(
            "SELECT state FROM tiamat.execution_records WHERE execution_id = %s",
            (admitted.execution_id,),
        ).fetchone()
    # The work stays admitted and unsent: quarantine refuses it rather than completing it.
    assert state == ("admitted",)
    _unblock(gate1b)


def test_an_old_worker_cannot_dispatch_after_a_newer_coordinator_starts(
    gate1b: _Environment,
) -> None:
    """The composite fence, not a coordinator integer alone, is what stops a stale worker."""

    ledger = _ledger(gate1b)
    old_generation = _fresh_fence(gate1b)
    old_provider = _SyntheticProvider()
    old_worker = DurableExecutor(
        ledger=ledger,
        scope=gate1b.scope,
        coordinator_generation=old_generation,
        provider=old_provider,
    )

    # A newer coordinator takes over: a fresh claimant is issued and consumed.
    new_generation = _fresh_fence(gate1b)
    assert new_generation > old_generation

    with pytest.raises(ExecutionRefused):
        old_worker.execute(
            _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes),
            now=datetime.now(UTC),
        )

    assert old_provider.dispatched_states == []
    assert not ledger.verify_attestation_current(old_generation)
    assert ledger.verify_attestation_current(new_generation)


def test_an_old_worker_cannot_settle_work_it_had_already_dispatched(
    gate1b: _Environment,
) -> None:
    """Takeover must not let a stale worker close out its own in-flight record.

    Its provider call may genuinely have been sent, so the record has to remain a liability for
    reconciliation rather than being settled under a fence that no longer holds.
    """

    ledger = _ledger(gate1b)
    old_generation = _fresh_fence(gate1b)
    now = datetime.now(UTC)
    admission = _admission(now, owner_id=uuid4(), key=uuid4().bytes)
    record, created = ledger.create_or_get(
        gate1b.scope, admission, coordinator_generation=old_generation, now=now
    )
    assert created
    dispatched = ledger.dispatch(
        gate1b.scope,
        record.execution_id,
        coordinator_generation=old_generation,
        record_generation=record.record_generation,
        owner_id=admission.owner_id,
    )

    # The newer coordinator cannot start while that work is in flight, so quarantine is what
    # actually displaces a stuck worker; the fence moves either way.
    ledger.block_dispatch("takeover_under_test")

    with pytest.raises((DispatchBlocked, DurableFenceRejected)):
        ledger.settle_terminal(
            gate1b.scope,
            record.execution_id,
            coordinator_generation=old_generation,
            record_generation=dispatched.record_generation,
            owner_id=admission.owner_id,
            state="completed",
            settled_microusd=10,
        )

    with psycopg.connect(gate1b.recovery) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (gate1b.environment,)
        )
        row = recovery.execute(
            """
            SELECT state, settlement_status FROM tiamat.execution_records
            WHERE execution_id = %s
            """,
            (record.execution_id,),
        ).fetchone()
    assert row is not None and row[0] == "dispatched"
    _unblock(gate1b)


def test_a_claimant_cannot_outlive_its_issuance_bound(gate1b: _Environment) -> None:
    """The database refuses to extend a claimant beyond the issuer's ten-minute ceiling."""

    generation = _fresh_fence(gate1b)
    with psycopg.connect(gate1b.recovery, autocommit=True) as recovery:  # noqa: SIM117
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (gate1b.environment,)
        )
        with pytest.raises(psycopg.Error) as refused:
            recovery.execute(
                """
                UPDATE tiamat.startup_attestations
                SET expires_at = created_at + interval '2 hours'
                WHERE environment = %s AND consumed_coordinator_generation = %s
                """,
                (gate1b.environment, generation),
            )
    assert refused.value.sqlstate in {"ZX105", "ZX106"}


def test_a_claimant_renews_under_the_same_still_valid_witness(gate1b: _Environment) -> None:
    """Ordinary renewal: the claimant expires, the signed authority behind it does not.

    This is the case a long-running executor meets routinely. No new anchor, no new witness and
    no recovery step: the same established authority issues the next claimant.
    """

    ledger = _ledger(gate1b)
    generation, anchor, transition = _short_lived_fence(
        gate1b,
        claimant_lifetime=timedelta(seconds=LIFETIME_SECONDS),
        witness_lifetime=timedelta(hours=1),
    )
    assert ledger.verify_attestation_current(generation)

    time.sleep(LIFETIME_SECONDS + 2)
    assert not ledger.verify_attestation_current(generation)

    # The witness is the same object the first claimant was issued under, and it is still valid.
    assert transition.witness.valid_at(datetime.now(UTC))
    renewed_receipt = StartupAttestationIssuer(
        anchor=anchor,
        identity=_identity(gate1b),
        recovery_database_url=gate1b.recovery,
        checkpoint_source=LedgerRecoveryCheckpointSource(gate1b.recovery),
    ).issue(now=datetime.now(UTC))
    assert renewed_receipt.anchor_transition_sha256 == transition.exact_sha256
    renewed = ledger.consume_startup_attestation(transition.exact_sha256)

    assert renewed > generation
    assert ledger.verify_attestation_current(renewed)
    provider = _SyntheticProvider()
    executor = DurableExecutor(
        ledger=ledger,
        scope=gate1b.scope,
        coordinator_generation=renewed,
        provider=provider,
    )
    now = datetime.now(UTC)
    outcome = executor.execute(
        _admission(now, owner_id=uuid4(), key=uuid4().bytes), now=now
    )
    assert outcome.state == "completed"
    assert provider.dispatched_states == ["dispatched"]
    assert _current_coordinator_generation(gate1b) == renewed
