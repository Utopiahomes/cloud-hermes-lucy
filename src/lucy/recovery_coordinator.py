"""Replay independent R1 journals and perform a protected activation handoff."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from lucy.cost_recovery import CostRecoveryFinalizationV1
from lucy.recovery_journal import (
    RecoveryActivationHandoffV1,
    RecoveryJournalError,
    RecoveryJournalEventV1,
    RecoveryJournalHeadV1,
    RecoveryStreamKind,
    RecoveryWriterPauseV1,
    advance_recovery_head,
    required_replay_sequences,
    verify_activation_handoff,
)

StreamKey = tuple[RecoveryStreamKind, UUID]


class ReplayJournal(Protocol):
    def head(self) -> RecoveryJournalHeadV1: ...

    def event(self, sequence: int) -> RecoveryJournalEventV1: ...

    def acquire_pause(
        self,
        *,
        pause_id: UUID,
        recovery_id: UUID,
        expected: RecoveryJournalHeadV1,
        duration: timedelta,
        now: datetime,
    ) -> RecoveryWriterPauseV1: ...


class RestoredStream(Protocol):
    def head(self) -> RecoveryJournalHeadV1: ...

    def apply(
        self, event: RecoveryJournalEventV1, expected: RecoveryJournalHeadV1
    ) -> RecoveryJournalHeadV1: ...


class RecoveryActivator(Protocol):
    def activate(
        self,
        handoff: RecoveryActivationHandoffV1,
        replayed_heads: Mapping[StreamKey, RecoveryJournalHeadV1],
    ) -> None: ...


class CostRecoveryFinalizer(Protocol):
    def finalize(self, expected: RecoveryJournalHeadV1) -> CostRecoveryFinalizationV1: ...


@dataclass(frozen=True)
class RecoveryStreamTarget:
    journal: ReplayJournal
    restored: RestoredStream
    witness: RecoveryJournalHeadV1


class RecoveryCoordinator:
    """Fail closed unless replay and the final two-stream fence are exact."""

    def __init__(
        self,
        targets: Sequence[RecoveryStreamTarget],
        activator: RecoveryActivator,
        *,
        cost_finalizer: CostRecoveryFinalizer,
        binding_manifest_digest: str,
        pause_duration: timedelta = timedelta(seconds=30),
        pause_attempts: int = 3,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not targets:
            raise ValueError("recovery requires at least one stream")
        if pause_attempts < 1:
            raise ValueError("recovery pause attempts must be positive")
        keys = [self._key(target.journal.head()) for target in targets]
        if len(keys) != len(set(keys)):
            raise ValueError("recovery contains duplicate streams")
        if {key[0] for key in keys} != {
            RecoveryStreamKind.AUTHORITY,
            RecoveryStreamKind.COST,
        }:
            raise ValueError("R1 activation requires authority and cost streams")
        if any(
            target.journal.head().binding_manifest_digest != binding_manifest_digest
            for target in targets
        ):
            raise ValueError("recovery binding manifest differs")
        self._targets = tuple(targets)
        self._activator = activator
        self._cost_finalizer = cost_finalizer
        self._manifest = binding_manifest_digest
        self._pause_duration = pause_duration
        self._pause_attempts = pause_attempts
        self._clock = clock or (lambda: datetime.now(UTC))

    def recover_and_activate(self, *, target_runtime_epoch: UUID) -> RecoveryActivationHandoffV1:
        recovery_id = uuid4()
        pause_ids = {self._key(target.journal.head()): uuid4() for target in self._targets}
        for target in self._targets:
            self._replay_to_live(target)

        pauses: list[RecoveryWriterPauseV1] = []
        for target in self._targets:
            key = self._key(target.journal.head())
            pauses.append(self._pause_after_catchup(target, pause_ids[key], recovery_id))

        handoff = RecoveryActivationHandoffV1(
            recovery_id=recovery_id,
            target_runtime_epoch=target_runtime_epoch,
            binding_manifest_digest=self._manifest,
            pauses=tuple(pauses),
            created_at=self._clock(),
        )
        replayed: dict[StreamKey, RecoveryJournalHeadV1] = {}
        live: dict[StreamKey, RecoveryJournalHeadV1] = {}
        for target in self._targets:
            replayed_head = target.restored.head()
            live_head = target.journal.head()
            replayed[self._key(replayed_head)] = replayed_head
            live[self._key(live_head)] = live_head
        verify_activation_handoff(
            handoff,
            replayed_heads=replayed,
            live_heads=live,
            now=self._clock(),
        )
        cost_keys = [key for key in replayed if key[0] is RecoveryStreamKind.COST]
        if len(cost_keys) != 1:
            raise RecoveryJournalError("recovery handoff has no unique cost stream")
        cost_finalization = self._cost_finalizer.finalize(replayed[cost_keys[0]])
        if (
            cost_finalization.state != "finalized"
            or cost_finalization.operator_review_required
        ):
            raise RecoveryJournalError("cost recovery requires operator review")
        replayed = {
            self._key(target.restored.head()): target.restored.head()
            for target in self._targets
        }
        live = {
            self._key(target.journal.head()): target.journal.head()
            for target in self._targets
        }
        verify_activation_handoff(
            handoff,
            replayed_heads=replayed,
            live_heads=live,
            now=self._clock(),
        )
        self._activator.activate(handoff, replayed)
        return handoff

    def _pause_after_catchup(
        self, target: RecoveryStreamTarget, pause_id: UUID, recovery_id: UUID
    ) -> RecoveryWriterPauseV1:
        last_error: RecoveryJournalError | None = None
        for _ in range(self._pause_attempts):
            expected = self._replay_to_live(target)
            try:
                return target.journal.acquire_pause(
                    pause_id=pause_id,
                    recovery_id=recovery_id,
                    expected=expected,
                    duration=self._pause_duration,
                    now=self._clock(),
                )
            except RecoveryJournalError as error:
                last_error = error
        raise RecoveryJournalError("recovery writer pause could not be established") from last_error

    @staticmethod
    def _replay_to_live(target: RecoveryStreamTarget) -> RecoveryJournalHeadV1:
        restored = target.restored.head()
        live = target.journal.head()
        for sequence in required_replay_sequences(restored, live, target.witness):
            event = target.journal.event(sequence)
            expected = target.restored.head()
            predicted = advance_recovery_head(expected, event)
            applied = target.restored.apply(event, expected)
            if applied != predicted:
                raise RecoveryJournalError("restored stream applied an inexact event")
        final = target.restored.head()
        if final != live:
            raise RecoveryJournalError("restored stream did not reach the observed head")
        return final

    @staticmethod
    def _key(head: RecoveryJournalHeadV1) -> StreamKey:
        return head.stream_kind, head.stream_id
