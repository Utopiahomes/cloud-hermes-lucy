"""Execute-only PostgreSQL boundary for durable R1 authority changes.

Membership revocation and publication withdrawal take effect in the same
transaction that stages their content-free recovery event.  Only the separate
recovery identity may acknowledge that event as durably journaled.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from lucy.recovery_journal import (
    AuthorityJournalEffectV1,
    AuthorityState,
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


class AuthorityTransitionRequestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_id: UUID
    actor_id: UUID
    stream_id: UUID
    authority_epoch: int = Field(ge=1)
    idempotency_key: str = Field(min_length=1, max_length=300)
    source_authority_ref: str = Field(min_length=1, max_length=512)
    source_authority_digest: str

    @model_validator(mode="after")
    def content_free_identifiers_are_canonical(self) -> AuthorityTransitionRequestV1:
        if (
            _SAFE_IDENTIFIER.fullmatch(self.idempotency_key) is None
            or _SAFE_IDENTIFIER.fullmatch(self.source_authority_ref) is None
            or _DIGEST.fullmatch(self.source_authority_digest) is None
        ):
            raise ValueError("authority transition identifiers are invalid")
        return self


class AuthorityTransitionResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID
    state: Literal["PERSISTENCE_PENDING", "DURABLY_RECORDED"]
    stream_id: UUID
    authority_epoch: int = Field(ge=1)
    event_type: Literal[
        "membership_revoked",
        "publication_withdrawn",
        "channel_activated",
        "channel_withdrawn",
    ]
    security_realm_id: UUID
    workspace_id: UUID
    subject_id: UUID
    previous_generation: int = Field(ge=0)
    new_generation: int = Field(ge=1)
    transition_digest: str
    journal_sequence: int | None = Field(default=None, ge=1)
    journal_previous_digest: str | None = None
    journal_event_digest: str | None = None
    journal_head_digest: str | None = None
    replayed: bool

    @model_validator(mode="after")
    def acknowledgement_is_complete(self) -> AuthorityTransitionResultV1:
        if self.new_generation != self.previous_generation + 1:
            raise ValueError("authority generation did not advance exactly once")
        if _DIGEST.fullmatch(self.transition_digest) is None:
            raise ValueError("authority transition digest is invalid")
        journal_values = (
            self.journal_sequence,
            self.journal_previous_digest,
            self.journal_event_digest,
            self.journal_head_digest,
        )
        if self.state == "PERSISTENCE_PENDING":
            unprepared = all(value is None for value in journal_values)
            prepared = (
                self.journal_sequence is not None
                and self.journal_previous_digest is not None
                and self.journal_event_digest is not None
                and self.journal_head_digest is None
                and _DIGEST.fullmatch(self.journal_previous_digest) is not None
                and _DIGEST.fullmatch(self.journal_event_digest) is not None
            )
            if not (unprepared or prepared):
                raise ValueError("pending authority transition journal state is incomplete")
        if self.state == "DURABLY_RECORDED" and (
            self.journal_sequence is None
            or self.journal_previous_digest is None
            or self.journal_event_digest is None
            or self.journal_head_digest is None
            or self.journal_event_digest != self.journal_head_digest
            or _DIGEST.fullmatch(self.journal_event_digest) is None
        ):
            raise ValueError("durable authority acknowledgement is incomplete")
        return self


class PendingAuthorityEventV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID
    idempotency_key: str
    stream_id: UUID
    authority_epoch: int = Field(ge=1)
    event_type: Literal[
        "membership_revoked",
        "publication_withdrawn",
        "channel_activated",
        "channel_withdrawn",
    ]
    security_realm_id: UUID
    workspace_id: UUID
    subject_id: UUID
    previous_generation: int = Field(ge=0)
    new_generation: int = Field(ge=1)
    source_authority_ref: str
    source_authority_digest: str
    transition_digest: str
    occurred_at: datetime
    journal_sequence: int | None = Field(default=None, ge=1)
    journal_previous_digest: str | None = None
    journal_event_digest: str | None = None

    @model_validator(mode="after")
    def metadata_is_canonical(self) -> PendingAuthorityEventV1:
        if self.new_generation != self.previous_generation + 1:
            raise ValueError("authority generation did not advance exactly once")
        if (
            _SAFE_IDENTIFIER.fullmatch(self.idempotency_key) is None
            or _SAFE_IDENTIFIER.fullmatch(self.source_authority_ref) is None
            or _DIGEST.fullmatch(self.source_authority_digest) is None
            or _DIGEST.fullmatch(self.transition_digest) is None
            or self.occurred_at.tzinfo is None
            or self.occurred_at.utcoffset() is None
        ):
            raise ValueError("pending authority event metadata is invalid")
        journal_values = (
            self.journal_sequence,
            self.journal_previous_digest,
            self.journal_event_digest,
        )
        if not (
            all(value is None for value in journal_values)
            or (
                self.journal_sequence is not None
                and self.journal_previous_digest is not None
                and self.journal_event_digest is not None
                and _DIGEST.fullmatch(self.journal_previous_digest) is not None
                and _DIGEST.fullmatch(self.journal_event_digest) is not None
            )
        ):
            raise ValueError("pending authority journal preparation is incomplete")
        return self


class AuthorityTransitionService:
    """Database-enforced transition and recovery-writer operations."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def revoke_membership(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1:
        return self._stage("stage_membership_revocation_v1", "membership_id", request)

    def withdraw_publication(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1:
        return self._stage("stage_publication_withdrawal_v1", "channel_binding_id", request)

    def activate_channel(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1:
        return self._stage("stage_channel_activation_v1", "channel_binding_id", request)

    def withdraw_channel(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1:
        return self._stage("stage_channel_withdrawal_v1", "channel_binding_id", request)

    def pending(self, event_id: UUID) -> PendingAuthorityEventV1:
        with self._sessions() as session:
            result = session.execute(
                text("SELECT lucy.get_pending_authority_event_v1(:event_id)"),
                {"event_id": event_id},
            ).scalar_one()
        if result is None:
            raise LookupError("pending authority event is unavailable")
        return PendingAuthorityEventV1.model_validate(result)

    def prepare(
        self,
        *,
        event_id: UUID,
        journal_sequence: int,
        journal_previous_digest: str,
        journal_event_digest: str,
    ) -> PendingAuthorityEventV1:
        if (
            journal_sequence < 1
            or _DIGEST.fullmatch(journal_previous_digest) is None
            or _DIGEST.fullmatch(journal_event_digest) is None
        ):
            raise ValueError("authority event preparation is invalid")
        with self._sessions.begin() as session:
            result = session.execute(
                text(
                    "SELECT lucy.prepare_authority_event_v1("
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
        return PendingAuthorityEventV1.model_validate(result)

    def acknowledge(
        self,
        *,
        event_id: UUID,
        journal_sequence: int,
        journal_event_digest: str,
        journal_head_digest: str,
    ) -> AuthorityTransitionResultV1:
        if (
            journal_sequence < 1
            or _DIGEST.fullmatch(journal_event_digest) is None
            or journal_event_digest != journal_head_digest
        ):
            raise ValueError("authority acknowledgement is invalid")
        with self._sessions.begin() as session:
            result = session.execute(
                text(
                    "SELECT lucy.acknowledge_authority_event_v1("
                    ":event_id,:journal_sequence,:journal_event_digest,:journal_head_digest)"
                ),
                {
                    "event_id": event_id,
                    "journal_sequence": journal_sequence,
                    "journal_event_digest": journal_event_digest,
                    "journal_head_digest": journal_head_digest,
                },
            ).scalar_one()
        return AuthorityTransitionResultV1.model_validate(result)

    def _stage(
        self, function: str, subject_parameter: str, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1:
        values = request.model_dump(mode="python")
        values[subject_parameter] = values.pop("subject_id")
        with self._sessions.begin() as session:
            result = session.execute(
                text(
                    f"SELECT lucy.{function}("
                    f":{subject_parameter},:actor_id,:stream_id,:authority_epoch,"
                    ":idempotency_key,:source_authority_ref,:source_authority_digest)"
                ),
                values,
            ).scalar_one()
        return AuthorityTransitionResultV1.model_validate(result)


class AuthorityJournal(Protocol):
    def head(self) -> RecoveryJournalHeadV1: ...

    def append(
        self, event: RecoveryJournalEventV1, expected: RecoveryJournalHeadV1
    ) -> RecoveryAppendAcknowledgementV1: ...


class AuthorityTransitionStore(Protocol):
    def pending(self, event_id: UUID) -> PendingAuthorityEventV1: ...

    def prepare(
        self,
        *,
        event_id: UUID,
        journal_sequence: int,
        journal_previous_digest: str,
        journal_event_digest: str,
    ) -> PendingAuthorityEventV1: ...


class AuthorityTransitionGateway(Protocol):
    def revoke_membership(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1: ...

    def withdraw_publication(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1: ...

    def activate_channel(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1: ...

    def withdraw_channel(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1: ...


class AuthorityWriterResult(Protocol):
    event_id: UUID
    event_digest: str


class AuthorityJournalWriterGateway(Protocol):
    def append_pending(self, event_id: UUID) -> AuthorityWriterResult: ...


class AuthorityAcknowledgementResult(Protocol):
    event_id: UUID
    state: str


class AuthorityAcknowledgementGateway(Protocol):
    def acknowledge_authority(
        self, event_id: UUID, *, head_digest: str
    ) -> AuthorityAcknowledgementResult: ...


class AuthorityTransitionCoordinator:
    """Stage a restriction locally, then require both independent durability barriers."""

    def __init__(
        self,
        transitions: AuthorityTransitionGateway,
        writer: AuthorityJournalWriterGateway,
        acknowledgements: AuthorityAcknowledgementGateway,
    ) -> None:
        self._transitions = transitions
        self._writer = writer
        self._acknowledgements = acknowledgements

    def revoke_membership(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1:
        return self._execute("revoke_membership", request)

    def withdraw_publication(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1:
        return self._execute("withdraw_publication", request)

    def activate_channel(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1:
        return self._execute("activate_channel", request)

    def withdraw_channel(
        self, request: AuthorityTransitionRequestV1
    ) -> AuthorityTransitionResultV1:
        return self._execute("withdraw_channel", request)

    def _execute(
        self,
        operation: Literal[
            "revoke_membership",
            "withdraw_publication",
            "activate_channel",
            "withdraw_channel",
        ],
        request: AuthorityTransitionRequestV1,
    ) -> AuthorityTransitionResultV1:
        if operation == "revoke_membership":
            transition = self._transitions.revoke_membership
        elif operation == "withdraw_publication":
            transition = self._transitions.withdraw_publication
        elif operation == "activate_channel":
            transition = self._transitions.activate_channel
        else:
            transition = self._transitions.withdraw_channel
        staged = transition(request)
        if staged.state == "DURABLY_RECORDED":
            return staged
        if staged.state != "PERSISTENCE_PENDING":
            raise RecoveryJournalError("authority transition returned an invalid state")
        writer_result = self._writer.append_pending(staged.event_id)
        if writer_result.event_id != staged.event_id:
            raise RecoveryJournalError("authority writer response differs")
        acknowledgement = self._acknowledgements.acknowledge_authority(
            staged.event_id, head_digest=writer_result.event_digest
        )
        if (
            acknowledgement.event_id != staged.event_id
            or acknowledgement.state != "DURABLY_RECORDED"
        ):
            raise RecoveryJournalError("authority acknowledgement response differs")
        completed = transition(request)
        if completed.event_id != staged.event_id or completed.state != "DURABLY_RECORDED":
            raise RecoveryJournalError("authority transition did not become durable")
        return completed


class AuthorityJournalWriter:
    """Prepare and append one exact event without holding recovery credentials."""

    def __init__(self, transitions: AuthorityTransitionStore, journal: AuthorityJournal) -> None:
        self._transitions = transitions
        self._journal = journal

    def append_pending(self, event_id: UUID) -> RecoveryAppendAcknowledgementV1:
        pending = self._transitions.pending(event_id)
        live = self._journal.head()
        self._require_bound(pending, live)
        if pending.journal_sequence is None:
            event = self._event(pending, live.sequence + 1, live.event_digest, live)
            pending = self._transitions.prepare(
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
            raise RecoveryJournalError("prepared authority event digest differs")
        expected = live.model_copy(
            update={
                "sequence": event.sequence - 1,
                "event_digest": event.previous_digest,
            }
        )
        return self._journal.append(event, expected)

    @staticmethod
    def _require_bound(pending: PendingAuthorityEventV1, head: RecoveryJournalHeadV1) -> None:
        if (
            head.stream_kind is not RecoveryStreamKind.AUTHORITY
            or head.stream_id != pending.stream_id
            or head.authority_epoch != pending.authority_epoch
        ):
            raise RecoveryJournalError("pending authority event stream binding differs")

    @staticmethod
    def _event(
        pending: PendingAuthorityEventV1,
        sequence: int | None,
        previous_digest: str | None,
        bound_head: RecoveryJournalHeadV1,
    ) -> RecoveryJournalEventV1:
        if sequence is None or previous_digest is None:
            raise RecoveryJournalError("authority event has not been prepared")
        states: dict[str, tuple[AuthorityState, AuthorityState]] = {
            "membership_revoked": ("active", "revoked"),
            "publication_withdrawn": ("published", "withdrawn"),
            "channel_activated": ("inactive", "active"),
            "channel_withdrawn": ("active", "inactive"),
        }
        previous_state, new_state = states[pending.event_type]
        effect = AuthorityJournalEffectV1(
            transition=pending.event_type,
            security_realm_id=pending.security_realm_id,
            workspace_id=pending.workspace_id,
            subject_id=pending.subject_id,
            previous_generation=pending.previous_generation,
            new_generation=pending.new_generation,
            previous_state=previous_state,
            new_state=new_state,
        )
        unsigned = RecoveryJournalEventV1.model_construct(
            contract_version="1",
            event_id=pending.event_id,
            stream_kind=RecoveryStreamKind.AUTHORITY,
            stream_id=pending.stream_id,
            authority_epoch=pending.authority_epoch,
            independent_store_id=bound_head.independent_store_id,
            binding_manifest_digest=bound_head.binding_manifest_digest,
            sequence=sequence,
            previous_digest=previous_digest,
            operation_id=pending.event_id,
            idempotency_key=pending.idempotency_key,
            source_authority_ref=pending.source_authority_ref,
            source_authority_digest=pending.source_authority_digest,
            source_generation=pending.new_generation,
            occurred_at=pending.occurred_at,
            effect=effect,
            event_digest="0" * 64,
        )
        return RecoveryJournalEventV1(
            **unsigned.model_dump(exclude={"event_digest"}),
            event_digest=recovery_event_digest(unsigned),
        )


class PostgresAuthorityReplayStore:
    """Apply one exact restrictive journal suffix through an execute-only login."""

    def __init__(
        self,
        sessions: sessionmaker[Session],
        binding: RecoveryStreamBindingV1,
    ) -> None:
        if binding.stream_kind is not RecoveryStreamKind.AUTHORITY:
            raise ValueError("authority replay store requires an authority binding")
        self._sessions = sessions
        self._binding = binding

    def head(self) -> RecoveryJournalHeadV1:
        with self._sessions() as session:
            result = session.execute(
                text("SELECT lucy.restored_recovery_head_v1('authority')")
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
                    "SELECT lucy.apply_authority_recovery_event_v1("
                    "CAST(:expected AS jsonb),CAST(:event AS jsonb))"
                ),
                {
                    "expected": json.dumps(expected.model_dump(mode="json")),
                    "event": json.dumps(event.model_dump(mode="json")),
                },
            ).scalar_one()
        applied = RecoveryJournalHeadV1.model_validate(result)
        if applied != predicted:
            raise RecoveryJournalError("authority recovery applied an inexact event")
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
            value.stream_kind is not RecoveryStreamKind.AUTHORITY
            or value.stream_id != self._binding.stream_id
            or value.authority_epoch != self._binding.authority_epoch
            or value.independent_store_id != self._binding.independent_store_id
            or value.binding_manifest_digest != self._binding.binding_manifest_digest
        ):
            raise RecoveryJournalError("authority recovery stream binding differs")
