"""Execute-only PostgreSQL boundary for restrictive R1 authority changes.

Membership revocation and publication withdrawal take effect in the same
transaction that stages their content-free recovery event.  Only the separate
recovery identity may acknowledge that event as durably journaled.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

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
    event_type: Literal["membership_revoked", "publication_withdrawn"]
    security_realm_id: UUID
    workspace_id: UUID
    subject_id: UUID
    previous_generation: int = Field(ge=0)
    new_generation: int = Field(ge=1)
    transition_digest: str
    journal_sequence: int | None = Field(default=None, ge=1)
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
            self.journal_event_digest,
            self.journal_head_digest,
        )
        if self.state == "PERSISTENCE_PENDING" and any(
            value is not None for value in journal_values
        ):
            raise ValueError("pending authority transition contains an acknowledgement")
        if self.state == "DURABLY_RECORDED" and (
            self.journal_sequence is None
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
    event_type: Literal["membership_revoked", "publication_withdrawn"]
    security_realm_id: UUID
    workspace_id: UUID
    subject_id: UUID
    previous_generation: int = Field(ge=0)
    new_generation: int = Field(ge=1)
    source_authority_ref: str
    source_authority_digest: str
    transition_digest: str
    occurred_at: datetime

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

    def pending(self, event_id: UUID) -> PendingAuthorityEventV1:
        with self._sessions() as session:
            result = session.execute(
                text("SELECT lucy.get_pending_authority_event_v1(:event_id)"),
                {"event_id": event_id},
            ).scalar_one()
        if result is None:
            raise LookupError("pending authority event is unavailable")
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
