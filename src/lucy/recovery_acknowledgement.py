"""DB-only reconciliation of exact independent-journal acknowledgements."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from lucy.authority_recovery import AuthorityTransitionResultV1, PendingAuthorityEventV1
from lucy.cost_admission import ProviderAttemptAdmissionV1
from lucy.cost_recovery import PendingCostEventV1
from lucy.recovery_journal import (
    RecoveryAppendAcknowledgementV1,
    RecoveryJournalError,
    RecoveryStreamKind,
)


class ExactAcknowledgementSource(Protocol):
    def exact_acknowledgement(
        self, event_id: UUID
    ) -> RecoveryAppendAcknowledgementV1 | None: ...


class AuthorityAcknowledgementStore(Protocol):
    def pending(self, event_id: UUID) -> PendingAuthorityEventV1: ...

    def acknowledge(
        self,
        *,
        event_id: UUID,
        journal_sequence: int,
        journal_event_digest: str,
        journal_head_digest: str,
    ) -> AuthorityTransitionResultV1: ...


class CostAcknowledgementStore(Protocol):
    def pending(self, event_id: UUID) -> PendingCostEventV1: ...

    def acknowledge(
        self, *, attempt_id: UUID, event_id: UUID, head_digest: str
    ) -> ProviderAttemptAdmissionV1: ...

    def acknowledge_outcome(
        self, *, attempt_id: UUID, event_id: UUID, head_digest: str
    ) -> ProviderAttemptAdmissionV1: ...


class AuthorityAcknowledgementReceiver:
    """Acknowledge authority only after an exact durable journal read."""

    def __init__(
        self,
        store: AuthorityAcknowledgementStore,
        journal: ExactAcknowledgementSource,
    ) -> None:
        self._store = store
        self._journal = journal

    def receive(self, event_id: UUID) -> AuthorityTransitionResultV1:
        pending = self._store.pending(event_id)
        acknowledgement = self._journal.exact_acknowledgement(event_id)
        _require_exact(pending, acknowledgement, RecoveryStreamKind.AUTHORITY)
        assert acknowledgement is not None
        return self._store.acknowledge(
            event_id=event_id,
            journal_sequence=acknowledgement.resulting_head.sequence,
            journal_event_digest=acknowledgement.event_digest,
            journal_head_digest=acknowledgement.resulting_head.event_digest,
        )


class CostAcknowledgementReceiver:
    """Acknowledge cost only after an exact durable journal read."""

    def __init__(
        self,
        store: CostAcknowledgementStore,
        journal: ExactAcknowledgementSource,
    ) -> None:
        self._store = store
        self._journal = journal

    def receive(self, event_id: UUID) -> ProviderAttemptAdmissionV1:
        pending = self._store.pending(event_id)
        acknowledgement = self._journal.exact_acknowledgement(event_id)
        _require_exact(pending, acknowledgement, RecoveryStreamKind.COST)
        assert acknowledgement is not None
        head_digest = acknowledgement.resulting_head.event_digest
        if pending.event_type == "reservation":
            return self._store.acknowledge(
                attempt_id=pending.attempt_id,
                event_id=event_id,
                head_digest=head_digest,
            )
        return self._store.acknowledge_outcome(
            attempt_id=pending.attempt_id,
            event_id=event_id,
            head_digest=head_digest,
        )


def _require_exact(
    pending: PendingAuthorityEventV1 | PendingCostEventV1,
    acknowledgement: RecoveryAppendAcknowledgementV1 | None,
    expected_kind: RecoveryStreamKind,
) -> None:
    if (
        acknowledgement is None
        or pending.journal_sequence is None
        or pending.journal_event_digest is None
        or acknowledgement.event_id != pending.event_id
        or acknowledgement.event_digest != pending.journal_event_digest
        or acknowledgement.resulting_head.stream_kind is not expected_kind
        or acknowledgement.resulting_head.sequence != pending.journal_sequence
        or acknowledgement.resulting_head.event_digest != pending.journal_event_digest
        or (
            isinstance(pending, PendingAuthorityEventV1)
            and (
                acknowledgement.resulting_head.stream_id != pending.stream_id
                or acknowledgement.resulting_head.authority_epoch != pending.authority_epoch
            )
        )
    ):
        raise RecoveryJournalError("durable journal acknowledgement is unavailable")
