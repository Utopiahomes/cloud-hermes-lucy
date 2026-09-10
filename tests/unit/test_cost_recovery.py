from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from lucy.cost_admission import ProviderAttemptAdmissionV1, ProviderAttemptRequestV1
from lucy.cost_recovery import CostJournalWriter, PendingCostEventV1
from lucy.recovery_journal import (
    InMemoryRecoveryJournal,
    RecoveryAppendAcknowledgementV1,
    RecoveryJournalError,
    RecoveryJournalEventV1,
    RecoveryJournalHeadV1,
    RecoveryStreamBindingV1,
    RecoveryStreamKind,
)


def pending_values(event_type: str = "reservation") -> dict[str, object]:
    maximum = 5_000
    outcome = event_type != "reservation"
    return {
        "event_id": uuid4(),
        "attempt_id": uuid4(),
        "idempotency_key": f"cost:{uuid4()}",
        "event_type": event_type,
        "node_id": uuid4(),
        "channel_binding_id": uuid4(),
        "policy_id": uuid4(),
        "policy_version": 1,
        "rate_version": "synthetic-v1",
        "accounting_period": datetime.now(UTC),
        "maximum_microusd": maximum,
        "incurred_microusd": 2_000 if outcome else 0,
        "unresolved_microusd": 0 if outcome else maximum,
        "request_commitment": "a" * 64,
        "provider_reference_commitment": "b" * 64 if outcome else None,
        "source_authority_ref": f"cost-policy:{uuid4()}:1",
        "source_authority_digest": "c" * 64,
        "occurred_at": datetime.now(UTC),
        "journal_sequence": None,
        "journal_previous_digest": None,
        "journal_event_digest": None,
    }


class FakePreparations:
    def __init__(self, pending: PendingCostEventV1) -> None:
        self.value = pending

    def pending(self, event_id: UUID) -> PendingCostEventV1:
        assert event_id == self.value.event_id
        return self.value

    def prepare(
        self,
        *,
        event_id: UUID,
        journal_sequence: int,
        journal_previous_digest: str,
        journal_event_digest: str,
    ) -> PendingCostEventV1:
        assert event_id == self.value.event_id
        self.value = self.value.model_copy(
            update={
                "journal_sequence": journal_sequence,
                "journal_previous_digest": journal_previous_digest,
                "journal_event_digest": journal_event_digest,
            }
        )
        return self.value


class ResponseLossJournal:
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


def journal(stream_kind: RecoveryStreamKind = RecoveryStreamKind.COST):
    return InMemoryRecoveryJournal(
        RecoveryStreamBindingV1(
            stream_kind=stream_kind,
            stream_id=uuid4(),
            authority_epoch=1,
            independent_store_id="arn:aws:dynamodb:us-east-1:429870640638:table/synthetic",
            writer_identity="arn:aws:iam::429870640638:role/synthetic-writer",
            recovery_identity="arn:aws:iam::429870640638:role/synthetic-recovery",
            binding_manifest_digest="d" * 64,
        )
    )


def admission(pending: PendingCostEventV1, state: str) -> ProviderAttemptAdmissionV1:
    return ProviderAttemptAdmissionV1.model_validate(
        {
            "attempt_id": pending.attempt_id,
            "policy_id": pending.policy_id,
            "policy_version": pending.policy_version,
            "state": state,
            "reserved_microusd": pending.maximum_microusd,
            "unresolved_microusd": pending.unresolved_microusd,
            "event_id": pending.event_id,
            "replayed": False,
        }
    )


def request(pending: PendingCostEventV1) -> ProviderAttemptRequestV1:
    return ProviderAttemptRequestV1(
        attempt_id=pending.attempt_id,
        idempotency_key=f"public:{pending.attempt_id}",
        node_id=pending.node_id,
        channel_binding_id=pending.channel_binding_id,
        provider="openrouter",
        model="openai/gpt-oss-20b",
        rate_version=pending.rate_version,
        request_commitment=pending.request_commitment,
        session_commitment="e" * 64,
        ip_commitment="f" * 64,
        maximum_microusd=pending.maximum_microusd,
        input_tokens=100,
        output_tokens=100,
        request_bytes=1_000,
        timeout_seconds=20,
        requested_at=datetime.now(UTC),
    )


def test_pending_cost_event_is_content_free_and_accounting_coherent() -> None:
    PendingCostEventV1.model_validate(pending_values())
    with pytest.raises(ValidationError):
        PendingCostEventV1.model_validate(pending_values() | {"prompt": "forbidden"})
    with pytest.raises(ValidationError, match="reservation accounting"):
        PendingCostEventV1.model_validate(pending_values() | {"unresolved_microusd": 0})


def test_reservation_is_frozen_before_append_and_exactly_replayed() -> None:
    pending = PendingCostEventV1.model_validate(pending_values())
    preparations = FakePreparations(pending)
    writer = CostJournalWriter(preparations, journal())

    first = writer.append_reservation(admission(pending, "PERSISTENCE_PENDING"))
    replay = writer.append_reservation(admission(pending, "PERSISTENCE_PENDING"))
    assert first == replay == preparations.value.journal_event_digest
    assert preparations.value.journal_sequence == 1
    assert preparations.value.journal_previous_digest == "0" * 64


def test_private_cost_writer_appends_by_exact_event_identifier() -> None:
    pending = PendingCostEventV1.model_validate(pending_values())
    preparations = FakePreparations(pending)
    acknowledgement = CostJournalWriter(preparations, journal()).append_pending(
        pending.event_id
    )
    assert acknowledgement.event_id == pending.event_id
    assert acknowledgement.resulting_head.sequence == 1
    assert acknowledgement.event_digest == preparations.value.journal_event_digest


def test_outcome_replay_survives_lost_append_response() -> None:
    pending = PendingCostEventV1.model_validate(pending_values("settlement"))
    preparations = FakePreparations(pending)
    writer = CostJournalWriter(preparations, ResponseLossJournal(journal()))
    outcome = admission(pending, "SETTLEMENT_PENDING")

    with pytest.raises(RecoveryJournalError, match="response loss"):
        writer.append_outcome(
            attempt=request(pending),
            admission=outcome,
            incurred_microusd=pending.incurred_microusd,
            provider_reference_commitment=pending.provider_reference_commitment or "",
        )
    recovered = writer.append_outcome(
        attempt=request(pending),
        admission=outcome,
        incurred_microusd=pending.incurred_microusd,
        provider_reference_commitment=pending.provider_reference_commitment or "",
    )
    assert recovered == preparations.value.journal_event_digest


def test_cost_writer_rejects_wrong_stream_or_caller_binding() -> None:
    pending = PendingCostEventV1.model_validate(pending_values())
    with pytest.raises(RecoveryJournalError, match="stream binding"):
        wrong_writer = CostJournalWriter(
            FakePreparations(pending), journal(RecoveryStreamKind.AUTHORITY)
        )
        wrong_writer.append_reservation(admission(pending, "PERSISTENCE_PENDING"))
    wrong = admission(pending, "PERSISTENCE_PENDING").model_copy(update={"attempt_id": uuid4()})
    with pytest.raises(RecoveryJournalError, match="binding differs"):
        CostJournalWriter(FakePreparations(pending), journal()).append_reservation(wrong)
