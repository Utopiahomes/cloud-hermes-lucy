from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from lucy.authority_recovery import (
    AuthorityJournalWriter,
    AuthorityTransitionRequestV1,
    AuthorityTransitionResultV1,
    PendingAuthorityEventV1,
)
from lucy.publication import PublicationRejected, PublicProjectionPublisher
from lucy.recovery_journal import (
    InMemoryRecoveryJournal,
    RecoveryAppendAcknowledgementV1,
    RecoveryJournalError,
    RecoveryJournalEventV1,
    RecoveryJournalHeadV1,
    RecoveryStreamBindingV1,
    RecoveryStreamKind,
)


def request_values() -> dict[str, object]:
    return {
        "subject_id": uuid4(),
        "actor_id": uuid4(),
        "stream_id": uuid4(),
        "authority_epoch": 1,
        "idempotency_key": "authority:membership:test-1",
        "source_authority_ref": "owner-interaction:test-1",
        "source_authority_digest": "a" * 64,
    }


def result_values() -> dict[str, object]:
    return {
        "event_id": uuid4(),
        "state": "PERSISTENCE_PENDING",
        "stream_id": uuid4(),
        "authority_epoch": 1,
        "event_type": "membership_revoked",
        "security_realm_id": uuid4(),
        "workspace_id": uuid4(),
        "subject_id": uuid4(),
        "previous_generation": 1,
        "new_generation": 2,
        "transition_digest": "b" * 64,
        "journal_sequence": None,
        "journal_previous_digest": None,
        "journal_event_digest": None,
        "journal_head_digest": None,
        "replayed": False,
    }


def test_transition_request_rejects_content_bearing_or_noncanonical_metadata() -> None:
    AuthorityTransitionRequestV1.model_validate(request_values())
    for update in (
        {"idempotency_key": "contains a space"},
        {"source_authority_ref": "owner proof with content"},
        {"source_authority_digest": "A" * 64},
    ):
        with pytest.raises(ValidationError, match="identifiers"):
            AuthorityTransitionRequestV1.model_validate(request_values() | update)


def test_transition_result_requires_exact_complete_acknowledgement() -> None:
    AuthorityTransitionResultV1.model_validate(result_values())
    durable = result_values() | {
        "state": "DURABLY_RECORDED",
        "journal_sequence": 1,
        "journal_previous_digest": "0" * 64,
        "journal_event_digest": "c" * 64,
        "journal_head_digest": "c" * 64,
    }
    AuthorityTransitionResultV1.model_validate(durable)
    with pytest.raises(ValidationError, match="incomplete"):
        AuthorityTransitionResultV1.model_validate(durable | {"journal_head_digest": "d" * 64})
    with pytest.raises(ValidationError, match="exactly once"):
        AuthorityTransitionResultV1.model_validate(result_values() | {"new_generation": 3})


def test_pending_event_requires_aware_time_and_canonical_source() -> None:
    values = result_values() | {
        "idempotency_key": "authority:membership:test-1",
        "source_authority_ref": "owner-interaction:test-1",
        "source_authority_digest": "a" * 64,
        "occurred_at": datetime.now(UTC),
    }
    for field in (
        "state",
        "journal_sequence",
        "journal_previous_digest",
        "journal_event_digest",
        "journal_head_digest",
        "replayed",
    ):
        values.pop(field)
    PendingAuthorityEventV1.model_validate(values)
    with pytest.raises(ValidationError, match="metadata"):
        PendingAuthorityEventV1.model_validate(
            values | {"occurred_at": datetime.now().replace(tzinfo=None)}
        )


def test_obsolete_direct_publication_withdrawal_is_closed() -> None:
    publisher = PublicProjectionPublisher(None)  # type: ignore[arg-type]
    with pytest.raises(PublicationRejected, match="authority transition service"):
        publisher.withdraw(channel_binding_id=uuid4(), actor_id=uuid4())


class _FakeTransitions:
    def __init__(self, pending: PendingAuthorityEventV1) -> None:
        self.value = pending

    def pending(self, event_id: UUID) -> PendingAuthorityEventV1:
        assert event_id == self.value.event_id
        return self.value

    def prepare(
        self,
        *,
        event_id: UUID,
        journal_sequence: int,
        journal_previous_digest: str,
        journal_event_digest: str,
    ) -> PendingAuthorityEventV1:
        assert event_id == self.value.event_id
        self.value = self.value.model_copy(
            update={
                "journal_sequence": journal_sequence,
                "journal_previous_digest": journal_previous_digest,
                "journal_event_digest": journal_event_digest,
            }
        )
        return self.value


class _ResponseLossJournal:
    def __init__(self, inner: InMemoryRecoveryJournal) -> None:
        self.inner = inner
        self.lose_next_response = True

    def head(self) -> RecoveryJournalHeadV1:
        return self.inner.head()

    def append(
        self, event: RecoveryJournalEventV1, expected: RecoveryJournalHeadV1
    ) -> RecoveryAppendAcknowledgementV1:
        acknowledgement = self.inner.append(event, expected)
        if self.lose_next_response:
            self.lose_next_response = False
            raise RecoveryJournalError("synthetic response loss")
        return acknowledgement

def test_writer_freezes_exact_event_before_append_and_replays_it() -> None:
    stream_id = uuid4()
    pending = PendingAuthorityEventV1(
        event_id=uuid4(),
        idempotency_key="authority:membership:writer-1",
        stream_id=stream_id,
        authority_epoch=1,
        event_type="membership_revoked",
        security_realm_id=uuid4(),
        workspace_id=uuid4(),
        subject_id=uuid4(),
        previous_generation=1,
        new_generation=2,
        source_authority_ref="owner-interaction:writer-1",
        source_authority_digest="a" * 64,
        transition_digest="b" * 64,
        occurred_at=datetime.now(UTC),
    )
    transitions = _FakeTransitions(pending)
    binding = RecoveryStreamBindingV1(
        stream_kind=RecoveryStreamKind.AUTHORITY,
        stream_id=stream_id,
        authority_epoch=1,
        independent_store_id="arn:aws:dynamodb:us-east-1:429870640638:table/synthetic",
        writer_identity="arn:aws:iam::429870640638:role/synthetic-writer",
        recovery_identity="arn:aws:iam::429870640638:role/synthetic-recovery",
        binding_manifest_digest="c" * 64,
    )
    writer = AuthorityJournalWriter(transitions, InMemoryRecoveryJournal(binding))

    first = writer.append_pending(pending.event_id)
    replay = writer.append_pending(pending.event_id)
    assert first.event_id == replay.event_id == pending.event_id
    assert first.event_digest == replay.event_digest == transitions.value.journal_event_digest
    assert transitions.value.journal_sequence == 1
    assert transitions.value.journal_previous_digest == "0" * 64


def test_writer_recovers_exact_acknowledgement_after_response_loss() -> None:
    stream_id = uuid4()
    pending = PendingAuthorityEventV1(
        event_id=uuid4(),
        idempotency_key="authority:publication:writer-loss",
        stream_id=stream_id,
        authority_epoch=2,
        event_type="publication_withdrawn",
        security_realm_id=uuid4(),
        workspace_id=uuid4(),
        subject_id=uuid4(),
        previous_generation=4,
        new_generation=5,
        source_authority_ref="owner-interaction:writer-loss",
        source_authority_digest="d" * 64,
        transition_digest="e" * 64,
        occurred_at=datetime.now(UTC),
    )
    transitions = _FakeTransitions(pending)
    binding = RecoveryStreamBindingV1(
        stream_kind=RecoveryStreamKind.AUTHORITY,
        stream_id=stream_id,
        authority_epoch=2,
        independent_store_id="arn:aws:dynamodb:us-east-1:429870640638:table/synthetic",
        writer_identity="arn:aws:iam::429870640638:role/synthetic-writer",
        recovery_identity="arn:aws:iam::429870640638:role/synthetic-recovery",
        binding_manifest_digest="f" * 64,
    )
    journal = _ResponseLossJournal(InMemoryRecoveryJournal(binding))
    writer = AuthorityJournalWriter(transitions, journal)

    with pytest.raises(RecoveryJournalError, match="response loss"):
        writer.append_pending(pending.event_id)
    recovered = writer.append_pending(pending.event_id)
    assert recovered.event_id == pending.event_id
    assert recovered.resulting_head.sequence == 1
    assert recovered.event_digest == transitions.value.journal_event_digest
