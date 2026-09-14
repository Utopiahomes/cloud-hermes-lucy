from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from lucy.cost_recovery import CostRecoveryFinalizationV1
from lucy.recovery_coordinator import RecoveryCoordinator, RecoveryStreamTarget, StreamKey
from lucy.recovery_journal import (
    AuthorityJournalEffectV1,
    CostJournalEffectV1,
    InMemoryRecoveryJournal,
    RecoveryActivationHandoffV1,
    RecoveryJournalError,
    RecoveryJournalEventV1,
    RecoveryJournalHeadV1,
    RecoveryStreamBindingV1,
    RecoveryStreamKind,
    RecoveryWriterPauseV1,
    advance_recovery_head,
    recovery_event_digest,
)


def binding(kind: RecoveryStreamKind) -> RecoveryStreamBindingV1:
    return RecoveryStreamBindingV1(
        stream_kind=kind,
        stream_id=uuid4(),
        authority_epoch=1,
        independent_store_id=f"synthetic:{kind.value}",
        writer_identity=f"synthetic:{kind.value}:writer",
        recovery_identity=f"synthetic:{kind.value}:recovery",
        binding_manifest_digest="a" * 64,
    )


def effect(
    kind: RecoveryStreamKind,
) -> AuthorityJournalEffectV1 | CostJournalEffectV1:
    if kind is RecoveryStreamKind.AUTHORITY:
        return AuthorityJournalEffectV1(
            transition="membership_revoked",
            security_realm_id=uuid4(),
            workspace_id=uuid4(),
            subject_id=uuid4(),
            previous_generation=1,
            new_generation=2,
            previous_state="active",
            new_state="revoked",
        )
    return CostJournalEffectV1(
        transition="reservation",
        node_id=uuid4(),
        channel_binding_id=uuid4(),
        attempt_id=uuid4(),
        policy_id=uuid4(),
        policy_version=1,
        rate_version="synthetic-v1",
        accounting_period=datetime.now(UTC),
        maximum_microusd=5_000,
        incurred_microusd=0,
        unresolved_microusd=5_000,
        request_commitment="b" * 64,
    )


def event(previous: RecoveryJournalHeadV1) -> RecoveryJournalEventV1:
    unsigned = RecoveryJournalEventV1.model_construct(
        contract_version="1",
        event_id=uuid4(),
        stream_kind=previous.stream_kind,
        stream_id=previous.stream_id,
        authority_epoch=previous.authority_epoch,
        independent_store_id=previous.independent_store_id,
        binding_manifest_digest=previous.binding_manifest_digest,
        sequence=previous.sequence + 1,
        previous_digest=previous.event_digest,
        operation_id=uuid4(),
        idempotency_key=f"recovery:{uuid4()}",
        source_authority_ref="synthetic:authority",
        source_authority_digest="c" * 64,
        source_generation=1,
        occurred_at=datetime.now(UTC),
        effect=effect(previous.stream_kind),
        event_digest="0" * 64,
    )
    return RecoveryJournalEventV1(
        **unsigned.model_dump(exclude={"event_digest"}),
        event_digest=recovery_event_digest(unsigned),
    )


class Restored:
    def __init__(self, initial: RecoveryJournalHeadV1) -> None:
        self._head = initial
        self.applied: list[int] = []

    def head(self) -> RecoveryJournalHeadV1:
        return self._head

    def apply(
        self, change: RecoveryJournalEventV1, expected: RecoveryJournalHeadV1
    ) -> RecoveryJournalHeadV1:
        if expected != self._head:
            raise RecoveryJournalError("restored head advanced")
        self._head = advance_recovery_head(expected, change)
        self.applied.append(change.sequence)
        return self._head


class Activator:
    def __init__(self) -> None:
        self.handoff: RecoveryActivationHandoffV1 | None = None

    def activate(
        self,
        handoff: RecoveryActivationHandoffV1,
        replayed_heads: Mapping[StreamKey, RecoveryJournalHeadV1],
    ) -> None:
        assert len(replayed_heads) == 2
        self.handoff = handoff


class Finalizer:
    def __init__(self, result: CostRecoveryFinalizationV1 | None = None) -> None:
        self.result = result or CostRecoveryFinalizationV1(
            state="finalized",
            operator_review_required=False,
            paid_admission_not_before=datetime.now(UTC) + timedelta(seconds=90),
        )
        self.expected: RecoveryJournalHeadV1 | None = None

    def finalize(self, expected: RecoveryJournalHeadV1) -> CostRecoveryFinalizationV1:
        self.expected = expected
        return self.result


class RacingJournal:
    def __init__(self, inner: InMemoryRecoveryJournal) -> None:
        self.inner = inner
        self.raced = False

    def head(self) -> RecoveryJournalHeadV1:
        return self.inner.head()

    def event(self, sequence: int) -> RecoveryJournalEventV1:
        return self.inner.event(sequence)

    def acquire_pause(
        self,
        *,
        pause_id: UUID,
        recovery_id: UUID,
        expected: RecoveryJournalHeadV1,
        duration: timedelta,
        now: datetime,
    ) -> RecoveryWriterPauseV1:
        if not self.raced:
            self.raced = True
            self.inner.append(event(expected), expected)
        return self.inner.acquire_pause(
            pause_id=pause_id,
            recovery_id=recovery_id,
            expected=expected,
            duration=duration,
            now=now,
        )


def target(kind: RecoveryStreamKind, *, race: bool = False) -> RecoveryStreamTarget:
    bound = binding(kind)
    journal = InMemoryRecoveryJournal(bound)
    genesis = journal.head()
    journal.append(event(genesis), genesis)
    source = RacingJournal(journal) if race else journal
    return RecoveryStreamTarget(source, Restored(genesis), genesis)


def test_replays_both_streams_and_activates_only_under_exact_pauses() -> None:
    targets = (
        target(RecoveryStreamKind.AUTHORITY),
        target(RecoveryStreamKind.COST),
    )
    activator = Activator()
    finalizer = Finalizer()
    handoff = RecoveryCoordinator(
        targets,
        activator,
        cost_finalizer=finalizer,
        binding_manifest_digest="a" * 64,
    ).recover_and_activate(target_runtime_epoch=uuid4())

    assert activator.handoff == handoff
    assert len(handoff.pauses) == 2
    assert all(item.restored.head() == item.journal.head() for item in targets)
    assert finalizer.expected == targets[1].restored.head()


def test_replays_a_racing_suffix_before_establishing_the_pause() -> None:
    authority = target(RecoveryStreamKind.AUTHORITY, race=True)
    cost = target(RecoveryStreamKind.COST)
    activator = Activator()
    RecoveryCoordinator(
        (authority, cost),
        activator,
        cost_finalizer=Finalizer(),
        binding_manifest_digest="a" * 64,
    ).recover_and_activate(target_runtime_epoch=uuid4())

    assert authority.restored.head().sequence == 2
    assert activator.handoff is not None


def test_rollback_below_witness_never_reaches_activation() -> None:
    authority = target(RecoveryStreamKind.AUTHORITY)
    cost = target(RecoveryStreamKind.COST)
    live = authority.journal.head()
    impossible_witness = live.model_copy(update={"sequence": 2, "event_digest": "f" * 64})
    activator = Activator()
    coordinator = RecoveryCoordinator(
        (RecoveryStreamTarget(authority.journal, authority.restored, impossible_witness), cost),
        activator,
        cost_finalizer=Finalizer(),
        binding_manifest_digest="a" * 64,
    )

    with pytest.raises(RecoveryJournalError, match="below its witness"):
        coordinator.recover_and_activate(target_runtime_epoch=uuid4())
    assert activator.handoff is None


def test_activation_requires_both_distinct_r1_streams() -> None:
    authority = target(RecoveryStreamKind.AUTHORITY)
    with pytest.raises(ValueError, match="authority and cost"):
        RecoveryCoordinator(
            (authority,),
            Activator(),
            cost_finalizer=Finalizer(),
            binding_manifest_digest="a" * 64,
        )


def test_cost_review_prevents_runtime_activation() -> None:
    targets = (
        target(RecoveryStreamKind.AUTHORITY),
        target(RecoveryStreamKind.COST),
    )
    activator = Activator()
    coordinator = RecoveryCoordinator(
        targets,
        activator,
        cost_finalizer=Finalizer(
            CostRecoveryFinalizationV1(
                state="replay_in_progress",
                operator_review_required=True,
                paid_admission_not_before=None,
            )
        ),
        binding_manifest_digest="a" * 64,
    )

    with pytest.raises(RecoveryJournalError, match="cost recovery requires operator review"):
        coordinator.recover_and_activate(target_runtime_epoch=uuid4())
    assert activator.handoff is None


def test_pause_is_rechecked_after_cost_finalization() -> None:
    targets = (
        target(RecoveryStreamKind.AUTHORITY),
        target(RecoveryStreamKind.COST),
    )
    activator = Activator()
    now = [datetime(2026, 9, 10, tzinfo=UTC)]

    class SlowFinalizer:
        def finalize(self, expected: RecoveryJournalHeadV1) -> CostRecoveryFinalizationV1:
            assert expected.stream_kind is RecoveryStreamKind.COST
            now[0] += timedelta(seconds=31)
            return CostRecoveryFinalizationV1(
                state="finalized",
                operator_review_required=False,
                paid_admission_not_before=now[0] + timedelta(seconds=90),
            )

    coordinator = RecoveryCoordinator(
        targets,
        activator,
        cost_finalizer=SlowFinalizer(),
        binding_manifest_digest="a" * 64,
        clock=lambda: now[0],
    )

    with pytest.raises(RecoveryJournalError, match="pause expired"):
        coordinator.recover_and_activate(target_runtime_epoch=uuid4())
    assert activator.handoff is None
