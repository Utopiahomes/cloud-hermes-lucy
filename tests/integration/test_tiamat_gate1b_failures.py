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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

from lucy.shared_execution.durable_executor import (
    DurableExecutor,
    ExecutionRefused,
    ProviderOutcome,
)
from lucy.shared_execution.postgres_ledger import (
    DispatchBlocked,
    DurableFenceRejected,
    LedgerRecord,
    LedgerScope,
)
from lucy.shared_execution.recovery_anchor import (
    InMemoryExternalRecoveryAnchor,
    RecoveryAnchorRejected,
    VerifiedAnchorTransition,
)
from lucy.shared_execution.replay_cache import (
    PostgresReplayCache,
    ReplayOutputMismatch,
    output_digest,
)
from lucy.shared_execution.runtime_anchor_watch import RuntimeAnchorWatch
from lucy.shared_execution.served_startup import ServedStartupRefused, start_serving
from lucy.shared_execution.startup_attestation import (
    LedgerRecoveryCheckpointSource,
    StartupAttestationIssuer,
    StartupAttestationRejected,
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


class _UnreachableAnchor:
    """An anchor store that cannot be read, as an AWS outage presents itself."""

    def read(self, key: object) -> VerifiedAnchorTransition:
        raise RecoveryAnchorRejected("recovery_anchor_unavailable")

    def install(self, *args: object, **kwargs: object) -> VerifiedAnchorTransition:
        raise AssertionError("an outage must not write the anchor")


def test_a_restart_cannot_reuse_the_claimant_it_already_consumed(gate1b: _Environment) -> None:
    """A process restarting finds its claimant spent, so it cannot serve without the launcher."""

    ledger = _ledger(gate1b)
    generation, _, transition = _short_lived_fence(gate1b)
    assert ledger.verify_attestation_current(generation)

    # The restarted process reads the same anchor and tries to consume again.
    with pytest.raises(DispatchBlocked, match="startup attestation unavailable"):
        ledger.consume_startup_attestation(transition.exact_sha256)

    # The fence the old process held is untouched, so nothing was silently taken over.
    assert _current_coordinator_generation(gate1b) == generation


def test_a_restart_after_a_clean_stop_needs_a_new_claimant(gate1b: _Environment) -> None:
    """After retirement there is no claimant at all: the launcher must run again."""

    ledger = _ledger(gate1b)
    generation, _, transition = _short_lived_fence(gate1b)
    executor = DurableExecutor(
        ledger=ledger,
        scope=gate1b.scope,
        coordinator_generation=generation,
        provider=_SyntheticProvider(),
    )
    retired = executor.shutdown()

    with pytest.raises(DispatchBlocked):
        ledger.consume_startup_attestation(transition.exact_sha256)
    assert _current_coordinator_generation(gate1b) == retired


def test_an_outage_at_startup_issues_no_claimant(gate1b: _Environment) -> None:
    """With the anchor unreadable the launcher refuses, so no process can start."""

    _bind_checkpoint(gate1b)
    with pytest.raises(StartupAttestationRejected, match="authority_unavailable"):
        StartupAttestationIssuer(
            anchor=_UnreachableAnchor(),
            identity=_identity(gate1b),
            recovery_database_url=gate1b.recovery,
            checkpoint_source=LedgerRecoveryCheckpointSource(gate1b.recovery),
        ).issue(now=datetime.now(UTC))

    with psycopg.connect(gate1b.recovery) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (gate1b.environment,)
        )
        claimants = recovery.execute(
            """
            SELECT count(*) FROM tiamat.startup_attestations
            WHERE environment = %s AND consumed_at IS NULL AND superseded_at IS NULL
            """,
            (gate1b.environment,),
        ).fetchone()
    assert claimants == (0,)


def test_an_outage_while_running_serves_only_to_the_claimant_s_bound(
    gate1b: _Environment,
) -> None:
    """Bounded authority: an outage does not stop work already authorized, expiry does.

    Draft 0.5 section 2 permits a running process to rely on verified authority for its bounded
    interval. The claimant is that bound, so an unreachable anchor changes nothing until it
    lapses, and no replacement can be issued while the outage lasts.
    """

    ledger = _ledger(gate1b)
    generation, _, _ = _short_lived_fence(
        gate1b, claimant_lifetime=timedelta(seconds=LIFETIME_SECONDS)
    )
    provider = _SyntheticProvider()
    executor = DurableExecutor(
        ledger=ledger,
        scope=gate1b.scope,
        coordinator_generation=generation,
        provider=provider,
    )

    # The anchor is unreachable from here on; work already authorized still completes.
    now = datetime.now(UTC)
    outcome = executor.execute(_admission(now, owner_id=uuid4(), key=uuid4().bytes), now=now)
    assert outcome.state == "completed"
    assert provider.dispatched_states == ["dispatched"]

    time.sleep(LIFETIME_SECONDS + 2)

    with pytest.raises(ExecutionRefused):
        executor.execute(
            _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes),
            now=datetime.now(UTC),
        )
    assert provider.dispatched_states == ["dispatched"]

    # Nothing can replace the claimant while the outage lasts.
    with pytest.raises(StartupAttestationRejected, match="authority_unavailable"):
        StartupAttestationIssuer(
            anchor=_UnreachableAnchor(),
            identity=_identity(gate1b),
            recovery_database_url=gate1b.recovery,
            checkpoint_source=LedgerRecoveryCheckpointSource(gate1b.recovery),
        ).issue(now=datetime.now(UTC))


def test_two_launchers_racing_produce_one_claimant(gate1b: _Environment) -> None:
    """Concurrent issuance never leaves two active claimants for one environment."""

    now = datetime.now(UTC)
    digest = _bind_checkpoint(gate1b)
    identity = _identity(gate1b)
    anchor, transition = _established_anchor_with_validity(
        gate1b, identity, digest, now, not_after=now + timedelta(hours=1)
    )

    def _issue() -> str:
        try:
            StartupAttestationIssuer(
                anchor=anchor,
                identity=identity,
                recovery_database_url=gate1b.recovery,
                checkpoint_source=LedgerRecoveryCheckpointSource(gate1b.recovery),
            ).issue(now=datetime.now(UTC))
            return "issued"
        except StartupAttestationRejected as exc:
            return f"refused:{exc}"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [task.result() for task in [pool.submit(_issue), pool.submit(_issue)]]

    assert "issued" in results
    with psycopg.connect(gate1b.recovery) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (gate1b.environment,)
        )
        active = recovery.execute(
            """
            SELECT count(*) FROM tiamat.startup_attestations
            WHERE environment = %s AND consumed_at IS NULL AND superseded_at IS NULL
            """,
            (gate1b.environment,),
        ).fetchone()
    assert active == (1,)

    # Whichever claimant survived, exactly one consumer can take it.
    consumed = _ledger(gate1b).consume_startup_attestation(transition.exact_sha256)
    assert consumed > 1


def test_a_quarantine_observed_at_the_dispatch_gate_stops_the_send(
    gate1b: _Environment,
) -> None:
    """A quarantine seen after the ledger committed the dispatch must still stop the provider.

    Nothing is sent and nothing is released. Closing the latch also blocks the gate, which
    invalidates the very fence the executor would need to mark its own record, so the record
    stays dispatched and unsettled: the liability reconciliation must resolve.
    """

    ledger = _ledger(gate1b)
    generation, anchor, transition = _short_lived_fence(gate1b)
    provider = _SyntheticProvider()

    class _WatchClosingAtTheGate(RuntimeAnchorWatch):
        """Open when the request is admitted, closed by the time it would be sent."""

        def __init__(self) -> None:
            super().__init__(
                anchor=anchor,
                identity=_identity(gate1b),
                consumed_transition_sha256=transition.exact_sha256,
                ledger=ledger,
                clock=lambda: datetime.now(UTC),
            )
            self.checks = 0

        def require_open(self) -> None:
            self.checks += 1
            if self.checks > 1:
                self.close("recovery_anchor_superseded")
            super().require_open()

    watch = _WatchClosingAtTheGate()
    executor = DurableExecutor(
        ledger=ledger,
        scope=gate1b.scope,
        coordinator_generation=generation,
        provider=provider,
        watch=watch,
    )

    with pytest.raises(ExecutionRefused, match="superseded"):
        executor.execute(
            _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes),
            now=datetime.now(UTC),
        )

    assert provider.dispatched_states == []
    with psycopg.connect(gate1b.recovery) as recovery:
        recovery.execute(
            "SELECT set_config('tiamat.environment', %s, false)", (gate1b.environment,)
        )
        row = recovery.execute(
            """
            SELECT state, settlement_status FROM tiamat.execution_records
            WHERE environment = %s AND coordinator_generation = %s
            """,
            (gate1b.environment, generation),
        ).fetchone()
    assert row is not None
    # Either the executor retained the exposure explicitly, or the fence was already gone and the
    # record remains in flight. Both are liabilities; neither is a settlement or a release.
    assert row[0] in {"dispatched", "outcome_unknown"}
    assert row[1] != "settled"
    _unblock(gate1b)


def test_a_closed_latch_refuses_before_anything_is_admitted(gate1b: _Environment) -> None:
    """Once the latch is closed nothing is admitted, so no reservation is taken at all."""

    ledger = _ledger(gate1b)
    generation, anchor, transition = _short_lived_fence(gate1b)
    watch = RuntimeAnchorWatch(
        anchor=anchor,
        identity=_identity(gate1b),
        consumed_transition_sha256=transition.exact_sha256,
        ledger=ledger,
        clock=lambda: datetime.now(UTC),
    )
    watch.close("recovery_continuity_withdrawn")
    provider = _SyntheticProvider()
    executor = DurableExecutor(
        ledger=ledger,
        scope=gate1b.scope,
        coordinator_generation=generation,
        provider=provider,
        watch=watch,
    )

    with pytest.raises(ExecutionRefused, match="continuity_withdrawn"):
        executor.execute(
            _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes),
            now=datetime.now(UTC),
        )

    assert provider.dispatched_states == []
    assert ledger.in_flight_under_fence(gate1b.scope, generation) == 0
    _unblock(gate1b)


def test_a_refresh_outage_leaves_a_running_executor_serving(gate1b: _Environment) -> None:
    """A failed runtime refresh is not a withdrawal: the claimant's bound still governs.

    This is the case the earlier outage test could not reach, because nothing refreshed at all.
    """

    ledger = _ledger(gate1b)
    generation, _, transition = _short_lived_fence(gate1b)
    watch = RuntimeAnchorWatch(
        anchor=_UnreachableAnchor(),
        identity=_identity(gate1b),
        consumed_transition_sha256=transition.exact_sha256,
        ledger=ledger,
        clock=lambda: datetime.now(UTC),
    )

    assert watch.refresh() == "anchor_unavailable"
    assert watch.closed_reason is None

    provider = _SyntheticProvider()
    executor = DurableExecutor(
        ledger=ledger,
        scope=gate1b.scope,
        coordinator_generation=generation,
        provider=provider,
        watch=watch,
    )
    now = datetime.now(UTC)
    outcome = executor.execute(_admission(now, owner_id=uuid4(), key=uuid4().bytes), now=now)

    assert outcome.state == "completed"
    assert provider.dispatched_states == ["dispatched"]


def _issuer_for(gate1b: _Environment, anchor: object) -> StartupAttestationIssuer:
    return StartupAttestationIssuer(
        anchor=anchor,  # type: ignore[arg-type]
        identity=_identity(gate1b),
        recovery_database_url=gate1b.recovery,
        checkpoint_source=LedgerRecoveryCheckpointSource(gate1b.recovery),
    )


def test_an_unattended_restart_obtains_and_consumes_a_claimant(gate1b: _Environment) -> None:
    """An ordinary restart needs no operator: the launcher runs and serving resumes."""

    ledger = _ledger(gate1b)
    now = datetime.now(UTC)
    digest = _bind_checkpoint(gate1b)
    identity = _identity(gate1b)
    anchor, transition = _established_anchor_with_validity(
        gate1b, identity, digest, now, not_after=now + timedelta(hours=1)
    )

    started = start_serving(
        anchor=anchor,
        identity=identity,
        issuer=_issuer_for(gate1b, anchor),
        ledger=ledger,
        clock=lambda: datetime.now(UTC),
    )

    assert started.launcher_invoked
    assert started.anchor_transition_sha256 == transition.exact_sha256
    assert ledger.verify_attestation_current(started.coordinator_generation)

    provider = _SyntheticProvider()
    executor = DurableExecutor(
        ledger=ledger,
        scope=gate1b.scope,
        coordinator_generation=started.coordinator_generation,
        provider=provider,
        watch=started.watch,
    )
    outcome = executor.execute(
        _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes),
        now=datetime.now(UTC),
    )
    assert outcome.state == "completed"
    assert provider.dispatched_states == ["dispatched"]


def test_a_waiting_claimant_is_consumed_without_invoking_the_launcher(
    gate1b: _Environment,
) -> None:
    """A claimant already issued is taken as it stands, not replaced."""

    ledger = _ledger(gate1b)
    now = datetime.now(UTC)
    digest = _bind_checkpoint(gate1b)
    identity = _identity(gate1b)
    anchor, transition = _established_anchor_with_validity(
        gate1b, identity, digest, now, not_after=now + timedelta(hours=1)
    )
    _issuer_for(gate1b, anchor).issue(now=now)

    started = start_serving(
        anchor=anchor,
        identity=identity,
        issuer=_issuer_for(gate1b, anchor),
        ledger=ledger,
        clock=lambda: datetime.now(UTC),
    )

    assert not started.launcher_invoked
    assert ledger.verify_attestation_current(started.coordinator_generation)


def test_startup_fails_closed_when_the_anchor_cannot_be_read(gate1b: _Environment) -> None:
    """Startup is the one moment with no verified interval to fall back on."""

    _bind_checkpoint(gate1b)
    with pytest.raises(ServedStartupRefused, match="unavailable"):
        start_serving(
            anchor=_UnreachableAnchor(),
            identity=_identity(gate1b),
            issuer=_issuer_for(gate1b, _UnreachableAnchor()),
            ledger=_ledger(gate1b),
            clock=lambda: datetime.now(UTC),
        )


def test_startup_fails_closed_on_a_quarantined_anchor(gate1b: _Environment) -> None:
    """A restart cannot serve over authority that does not authorize dispatch."""

    ledger = _ledger(gate1b)
    now = datetime.now(UTC)
    digest = _bind_checkpoint(gate1b)
    identity = _identity(gate1b)
    established, transition = _established_anchor_with_validity(
        gate1b, identity, digest, now, not_after=now + timedelta(hours=1)
    )
    quarantined = InMemoryExternalRecoveryAnchor()
    quarantined.install(
        replace(
            transition,
            continuity="quarantined",
            beacon=None,
            witness=replace(transition.witness, status="quarantined"),
            exact_jws=b"gate-1b-quarantined-transition",
        ),
        expected_transition_sha256=None,
        now=now,
    )

    with pytest.raises(ServedStartupRefused):
        start_serving(
            anchor=quarantined,
            identity=identity,
            issuer=_issuer_for(gate1b, quarantined),
            ledger=ledger,
            clock=lambda: datetime.now(UTC),
        )
    assert established is not None


def test_concurrent_restarts_leave_one_current_fence(gate1b: _Environment) -> None:
    """Two processes restarting at once must not both end up serving."""

    ledger = _ledger(gate1b)
    now = datetime.now(UTC)
    digest = _bind_checkpoint(gate1b)
    identity = _identity(gate1b)
    anchor, _ = _established_anchor_with_validity(
        gate1b, identity, digest, now, not_after=now + timedelta(hours=1)
    )

    def _start() -> object:
        try:
            return start_serving(
                anchor=anchor,
                identity=identity,
                issuer=_issuer_for(gate1b, anchor),
                ledger=ledger,
                clock=lambda: datetime.now(UTC),
            ).coordinator_generation
        except ServedStartupRefused as exc:
            return f"refused:{exc}"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [task.result() for task in [pool.submit(_start), pool.submit(_start)]]

    generations = [result for result in results if isinstance(result, int)]
    assert generations, results
    # Whatever the interleaving, exactly one fence is current at the end and it is the newest.
    current = [
        generation for generation in generations if ledger.verify_attestation_current(generation)
    ]
    assert len(current) == 1
    assert current[0] == max(generations)


def _cache(gate1b: _Environment) -> PostgresReplayCache:
    return PostgresReplayCache(database_url=gate1b.runtime, environment=gate1b.environment)


class _AnsweringProvider(_SyntheticProvider):
    """A synthetic provider that returns a replayable body as well as a cost."""

    def __call__(self, dispatched: LedgerRecord) -> ProviderOutcome:
        outcome = super().__call__(dispatched)
        return replace(
            outcome, output={"mode": "text", "content": f"answer for {dispatched.execution_id}"}
        )


def _scoped(gate1b: _Environment, connection: Any) -> None:
    connection.execute(
        "SELECT set_config('tiamat.environment', %s, false)", (gate1b.environment,)
    )
    connection.execute(
        "SELECT set_config('tiamat.caller_id', %s, false)", (gate1b.scope.caller_id,)
    )


def _serve(gate1b: _Environment, generation: int, admission: Any, cache: Any) -> Any:
    return DurableExecutor(
        ledger=_ledger(gate1b),
        scope=gate1b.scope,
        coordinator_generation=generation,
        provider=_AnsweringProvider(),
        replay_cache=cache,
    ).execute(admission, now=datetime.now(UTC))


def test_a_replay_after_restart_returns_the_same_body(gate1b: _Environment) -> None:
    """The ledger keeps no content, so a replay is served from the cache it agrees with."""

    generation, _, _ = _short_lived_fence(gate1b)
    cache = _cache(gate1b)
    admission = _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes)

    first = _serve(gate1b, generation, admission, cache)
    assert first.state == "completed" and not first.replayed

    # A second executor, as a restarted process would be: no memory of the first.
    replayed_provider = _AnsweringProvider()
    replayed = DurableExecutor(
        ledger=_ledger(gate1b),
        scope=gate1b.scope,
        coordinator_generation=generation,
        provider=replayed_provider,
        replay_cache=cache,
    ).execute(admission, now=datetime.now(UTC))

    assert replayed.replayed
    assert replayed.execution_id == first.execution_id
    assert replayed.output == first.output
    assert replayed_provider.dispatched_states == []


def test_the_ledger_keeps_the_digest_and_never_the_body(gate1b: _Environment) -> None:
    """Content lives only in the cache; the ledger records what it was, not what it said."""

    generation, _, _ = _short_lived_fence(gate1b)
    admission = _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes)
    outcome = _serve(gate1b, generation, admission, _cache(gate1b))

    with psycopg.connect(gate1b.recovery) as recovery:
        _scoped(gate1b, recovery)
        row = recovery.execute(
            "SELECT response_output_sha256 FROM tiamat.execution_records WHERE execution_id = %s",
            (outcome.execution_id,),
        ).fetchone()
        columns = recovery.execute(
            """
            SELECT count(*) FROM information_schema.columns
            WHERE table_schema = 'tiamat' AND table_name = 'execution_records'
              AND column_name IN ('output', 'response', 'content')
            """
        ).fetchone()
    assert row is not None and row[0] == output_digest(outcome.output)
    assert columns == (0,)


def test_a_lost_cache_costs_the_body_and_nothing_else(gate1b: _Environment) -> None:
    """Losing the cache degrades replay; the execution and its accounting are unaffected."""

    generation, _, _ = _short_lived_fence(gate1b)
    cache = _cache(gate1b)
    admission = _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes)
    outcome = _serve(gate1b, generation, admission, cache)

    with psycopg.connect(gate1b.runtime, autocommit=True) as runtime:
        _scoped(gate1b, runtime)
        runtime.execute(
            "DELETE FROM tiamat.replay_cache WHERE environment = %s", (gate1b.environment,)
        )

    with pytest.raises(ExecutionRefused, match="no longer retained"):
        _serve(gate1b, generation, admission, cache)

    with psycopg.connect(gate1b.recovery) as recovery:
        _scoped(gate1b, recovery)
        row = recovery.execute(
            "SELECT state, settlement_status, settled_microusd FROM tiamat.execution_records "
            "WHERE execution_id = %s",
            (outcome.execution_id,),
        ).fetchone()
    # What Tiamat did, and what it spent, remain exactly as recorded.
    assert row == ("completed", "settled", 137)


def test_cached_output_that_disagrees_with_the_ledger_is_not_served(
    gate1b: _Environment,
) -> None:
    """A cache entry is honoured only while it hashes to the digest the ledger recorded."""

    generation, _, _ = _short_lived_fence(gate1b)
    cache = _cache(gate1b)
    admission = _admission(datetime.now(UTC), owner_id=uuid4(), key=uuid4().bytes)
    _serve(gate1b, generation, admission, cache)

    with psycopg.connect(gate1b.runtime, autocommit=True) as runtime:
        _scoped(gate1b, runtime)
        runtime.execute(
            """
            UPDATE tiamat.replay_cache SET output = %s
            WHERE environment = %s AND idempotency_key_digest = %s
            """,
            (
                Jsonb({"mode": "text", "content": "tampered"}),
                gate1b.environment,
                admission.idempotency_key_digest,
            ),
        )

    with pytest.raises(ReplayOutputMismatch):
        _serve(gate1b, generation, admission, cache)
