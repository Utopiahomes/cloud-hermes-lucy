"""Content-free cost journal preparation and append orchestration."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from lucy.cost_admission import ProviderAttemptAdmissionV1, ProviderAttemptRequestV1
from lucy.recovery_journal import (
    CostJournalEffectV1,
    RecoveryAppendAcknowledgementV1,
    RecoveryJournalError,
    RecoveryJournalEventV1,
    RecoveryJournalHeadV1,
    RecoveryStreamBindingV1,
    RecoveryStreamKind,
    advance_recovery_head,
    recovery_event_digest,
)

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+=-]*\Z")


class PendingCostEventV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID
    attempt_id: UUID
    idempotency_key: str
    event_type: Literal["reservation", "settlement", "over_cap"]
    node_id: UUID
    channel_binding_id: UUID
    policy_id: UUID
    policy_version: int = Field(ge=1)
    rate_version: str
    accounting_period: datetime
    maximum_microusd: int = Field(ge=0)
    incurred_microusd: int = Field(ge=0)
    unresolved_microusd: int = Field(ge=0)
    request_commitment: str
    provider_reference_commitment: str | None = None
    source_authority_ref: str
    source_authority_digest: str
    occurred_at: datetime
    journal_sequence: int | None = Field(default=None, ge=1)
    journal_previous_digest: str | None = None
    journal_event_digest: str | None = None

    @model_validator(mode="after")
    def metadata_is_canonical(self) -> PendingCostEventV1:
        digests = [self.request_commitment, self.source_authority_digest]
        if self.provider_reference_commitment is not None:
            digests.append(self.provider_reference_commitment)
        if (
            _SAFE_IDENTIFIER.fullmatch(self.idempotency_key) is None
            or _SAFE_IDENTIFIER.fullmatch(self.rate_version) is None
            or _SAFE_IDENTIFIER.fullmatch(self.source_authority_ref) is None
            or any(_DIGEST.fullmatch(value) is None for value in digests)
            or self.accounting_period.tzinfo is None
            or self.accounting_period.utcoffset() is None
            or self.occurred_at.tzinfo is None
            or self.occurred_at.utcoffset() is None
        ):
            raise ValueError("pending cost event metadata is invalid")
        prepared = (
            self.journal_sequence,
            self.journal_previous_digest,
            self.journal_event_digest,
        )
        if not (
            all(value is None for value in prepared)
            or (
                self.journal_sequence is not None
                and self.journal_previous_digest is not None
                and self.journal_event_digest is not None
                and _DIGEST.fullmatch(self.journal_previous_digest) is not None
                and _DIGEST.fullmatch(self.journal_event_digest) is not None
            )
        ):
            raise ValueError("pending cost journal preparation is incomplete")
        self.effect()
        return self

    def effect(self) -> CostJournalEffectV1:
        return CostJournalEffectV1(
            transition=self.event_type,
            node_id=self.node_id,
            channel_binding_id=self.channel_binding_id,
            attempt_id=self.attempt_id,
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            rate_version=self.rate_version,
            accounting_period=self.accounting_period,
            maximum_microusd=self.maximum_microusd,
            incurred_microusd=self.incurred_microusd,
            unresolved_microusd=self.unresolved_microusd,
            request_commitment=self.request_commitment,
            provider_reference_commitment=self.provider_reference_commitment,
        )


class CostJournalPreparationService:
    """Cost-admission identity operations for one frozen journal event."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def pending(self, event_id: UUID) -> PendingCostEventV1:
        with self._sessions() as session:
            result = session.execute(
                text("SELECT lucy.get_pending_cost_event_v1(:event_id)"),
                {"event_id": event_id},
            ).scalar_one()
        if result is None:
            raise LookupError("pending cost event is unavailable")
        return PendingCostEventV1.model_validate(result)

    def prepare(
        self,
        *,
        event_id: UUID,
        journal_sequence: int,
        journal_previous_digest: str,
        journal_event_digest: str,
    ) -> PendingCostEventV1:
        if (
            journal_sequence < 1
            or _DIGEST.fullmatch(journal_previous_digest) is None
            or _DIGEST.fullmatch(journal_event_digest) is None
        ):
            raise ValueError("cost event preparation is invalid")
        with self._sessions.begin() as session:
            result = session.execute(
                text(
                    "SELECT lucy.prepare_cost_journal_event_v1("
                    ":event_id,:journal_sequence,:journal_previous_digest,"
                    ":journal_event_digest)"
                ),
                {
                    "event_id": event_id,
                    "journal_sequence": journal_sequence,
                    "journal_previous_digest": journal_previous_digest,
                    "journal_event_digest": journal_event_digest,
                },
            ).scalar_one()
        return PendingCostEventV1.model_validate(result)


class CostJournal(Protocol):
    def head(self) -> RecoveryJournalHeadV1: ...

    def append(
        self, event: RecoveryJournalEventV1, expected: RecoveryJournalHeadV1
    ) -> RecoveryAppendAcknowledgementV1: ...


class CostPreparationStore(Protocol):
    def pending(self, event_id: UUID) -> PendingCostEventV1: ...

    def prepare(
        self,
        *,
        event_id: UUID,
        journal_sequence: int,
        journal_previous_digest: str,
        journal_event_digest: str,
    ) -> PendingCostEventV1: ...


class CostJournalWriter:
    """Freeze and append cost metadata without carrying prompt or response bodies."""

    def __init__(self, preparations: CostPreparationStore, journal: CostJournal) -> None:
        self._preparations = preparations
        self._journal = journal

    def append_reservation(self, admission: ProviderAttemptAdmissionV1) -> str:
        if admission.state != "PERSISTENCE_PENDING":
            raise RecoveryJournalError("cost reservation is not pending persistence")
        pending = self._preparations.pending(admission.event_id)
        if pending.attempt_id != admission.attempt_id or pending.event_type != "reservation":
            raise RecoveryJournalError("cost reservation binding differs")
        acknowledgement = self._append(pending)
        return acknowledgement.event_digest

    def append_outcome(
        self,
        *,
        attempt: ProviderAttemptRequestV1,
        admission: ProviderAttemptAdmissionV1,
        incurred_microusd: int,
        provider_reference_commitment: str,
    ) -> str:
        if admission.state not in {"SETTLEMENT_PENDING", "OVER_CAP_PENDING"}:
            raise RecoveryJournalError("cost outcome is not pending persistence")
        pending = self._preparations.pending(admission.event_id)
        if (
            pending.attempt_id != attempt.attempt_id
            or pending.attempt_id != admission.attempt_id
            or pending.event_type not in {"settlement", "over_cap"}
            or pending.incurred_microusd != incurred_microusd
            or pending.provider_reference_commitment != provider_reference_commitment
        ):
            raise RecoveryJournalError("cost outcome binding differs")
        acknowledgement = self._append(pending)
        return acknowledgement.event_digest

    def _append(self, pending: PendingCostEventV1) -> RecoveryAppendAcknowledgementV1:
        live = self._journal.head()
        if live.stream_kind is not RecoveryStreamKind.COST:
            raise RecoveryJournalError("cost journal stream binding differs")
        if pending.journal_sequence is None:
            event = self._event(pending, live.sequence + 1, live.event_digest, live)
            pending = self._preparations.prepare(
                event_id=pending.event_id,
                journal_sequence=event.sequence,
                journal_previous_digest=event.previous_digest,
                journal_event_digest=event.event_digest,
            )
        event = self._event(
            pending,
            pending.journal_sequence,
            pending.journal_previous_digest,
            live,
        )
        if event.event_digest != pending.journal_event_digest:
            raise RecoveryJournalError("prepared cost event digest differs")
        expected = live.model_copy(
            update={
                "sequence": event.sequence - 1,
                "event_digest": event.previous_digest,
            }
        )
        return self._journal.append(event, expected)

    @staticmethod
    def _event(
        pending: PendingCostEventV1,
        sequence: int | None,
        previous_digest: str | None,
        bound_head: RecoveryJournalHeadV1,
    ) -> RecoveryJournalEventV1:
        if sequence is None or previous_digest is None:
            raise RecoveryJournalError("cost event has not been prepared")
        unsigned = RecoveryJournalEventV1.model_construct(
            contract_version="1",
            event_id=pending.event_id,
            stream_kind=RecoveryStreamKind.COST,
            stream_id=bound_head.stream_id,
            authority_epoch=bound_head.authority_epoch,
            independent_store_id=bound_head.independent_store_id,
            binding_manifest_digest=bound_head.binding_manifest_digest,
            sequence=sequence,
            previous_digest=previous_digest,
            operation_id=pending.attempt_id,
            idempotency_key=pending.idempotency_key,
            source_authority_ref=pending.source_authority_ref,
            source_authority_digest=pending.source_authority_digest,
            source_generation=pending.policy_version,
            occurred_at=pending.occurred_at,
            effect=pending.effect(),
            event_digest="0" * 64,
        )
        return RecoveryJournalEventV1(
            **unsigned.model_dump(exclude={"event_digest"}),
            event_digest=recovery_event_digest(unsigned),
        )


class PostgresCostReplayStore:
    """Apply exact cost journal events without recreating executable attempts."""

    def __init__(
        self,
        sessions: sessionmaker[Session],
        binding: RecoveryStreamBindingV1,
    ) -> None:
        if binding.stream_kind is not RecoveryStreamKind.COST:
            raise ValueError("cost replay store requires a cost binding")
        self._sessions = sessions
        self._binding = binding

    def head(self) -> RecoveryJournalHeadV1:
        with self._sessions() as session:
            result = session.execute(
                text("SELECT lucy.restored_cost_recovery_head_v1()")
            ).scalar_one()
        if result is None:
            return self._genesis()
        head = RecoveryJournalHeadV1.model_validate(result)
        self._require_binding(head)
        return head

    def apply(
        self,
        event: RecoveryJournalEventV1,
        expected: RecoveryJournalHeadV1,
    ) -> RecoveryJournalHeadV1:
        self._require_binding(expected)
        self._require_binding(event)
        predicted = advance_recovery_head(expected, event)
        with self._sessions.begin() as session:
            result = session.execute(
                text(
                    "SELECT lucy.apply_cost_recovery_event_v1("
                    "CAST(:expected AS jsonb),CAST(:event AS jsonb))"
                ),
                {
                    "expected": json.dumps(expected.model_dump(mode="json")),
                    "event": json.dumps(event.model_dump(mode="json")),
                },
            ).scalar_one()
        applied = RecoveryJournalHeadV1.model_validate(result)
        if applied != predicted:
            raise RecoveryJournalError("cost recovery applied an inexact event")
        return applied

    def _genesis(self) -> RecoveryJournalHeadV1:
        return RecoveryJournalHeadV1(
            stream_kind=self._binding.stream_kind,
            stream_id=self._binding.stream_id,
            authority_epoch=self._binding.authority_epoch,
            independent_store_id=self._binding.independent_store_id,
            binding_manifest_digest=self._binding.binding_manifest_digest,
            sequence=0,
            event_digest="0" * 64,
        )

    def _require_binding(self, value: RecoveryJournalHeadV1 | RecoveryJournalEventV1) -> None:
        if (
            value.stream_kind is not RecoveryStreamKind.COST
            or value.stream_id != self._binding.stream_id
            or value.authority_epoch != self._binding.authority_epoch
            or value.independent_store_id != self._binding.independent_store_id
            or value.binding_manifest_digest != self._binding.binding_manifest_digest
        ):
            raise RecoveryJournalError("cost recovery stream binding differs")
