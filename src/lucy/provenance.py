"""Immutable multi-source support; callers hold the retention fence first."""

from collections.abc import Iterable
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from lucy.db.models import (
    CaptureReceiptRow,
    ClaimSourceRow,
    ConversationTurnRow,
    EvidenceDerivationRow,
    EvidencePayloadRow,
    EvidenceRow,
    EvidenceTombstoneRow,
)

MAX_SOURCES = 512


class DerivationSourcesV1(BaseModel):
    """Additional observed inputs, never model-authored authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    source_evidence_ids: tuple[UUID, ...] = Field(default=(), max_length=MAX_SOURCES)

    @field_validator("source_evidence_ids")
    @classmethod
    def canonical_sources(cls, values: tuple[UUID, ...]) -> tuple[UUID, ...]:
        return tuple(sorted(set(values)))


def evidence_ancestors(session: Session, sources: Iterable[UUID]) -> set[UUID]:
    found = set(sources)
    pending = found.copy()
    while pending:
        if len(found) > MAX_SOURCES:
            raise PermissionError("provenance source limit exceeded; a fresh context is required")
        parents = set(
            session.scalars(
                select(EvidenceDerivationRow.parent_id).where(
                    EvidenceDerivationRow.child_id.in_(pending),
                )
            )
        )
        pending = parents - found
        found.update(parents)
    return found


def active_sources(session: Session, sources: Iterable[UUID]) -> set[UUID]:
    found = evidence_ancestors(session, sources)
    if not found:
        raise PermissionError("retained artifacts require evidence provenance")
    present = set(session.scalars(select(EvidenceRow.id).where(EvidenceRow.id.in_(found))))
    if present != found:
        raise LookupError("immutable evidence does not exist")
    if (
        session.scalar(
            select(EvidenceTombstoneRow.evidence_id)
            .where(
                EvidenceTombstoneRow.evidence_id.in_(found),
            )
            .limit(1)
        )
        is not None
    ):
        raise PermissionError("source evidence was deleted")
    return found


def claim_sources(session: Session, claim_id: UUID) -> set[UUID]:
    return active_sources(
        session,
        session.scalars(
            select(ClaimSourceRow.evidence_id).where(
                ClaimSourceRow.claim_id == claim_id,
            )
        ),
    )


def conversation_sources(session: Session, conversation_id: str, turn_id: str) -> set[UUID]:
    """Conservative support: all retained prior history plus the current input.

    Caller already holds this conversation's lock. Excluded/incomplete/deleted
    prior turns require a clean runtime-history boundary, not inferred consent.
    """
    turns = {
        row.source_turn_id: row
        for row in session.scalars(
            select(ConversationTurnRow).where(
                ConversationTurnRow.platform == "telegram",
                ConversationTurnRow.source_conversation_id == conversation_id,
            )
        )
    }
    receipts = list(
        session.scalars(
            select(CaptureReceiptRow).where(
                CaptureReceiptRow.platform == "telegram",
                CaptureReceiptRow.source_conversation_id == conversation_id,
            )
        )
    )
    current = turns.get(turn_id)
    if current is None or current.user_evidence_id is None or current.status == "redacted":
        raise PermissionError("originating retained user evidence is required")
    sources: set[UUID] = {current.user_evidence_id}
    for receipt in receipts:
        if receipt.source_turn_id == turn_id:
            continue
        previous = turns.get(receipt.source_turn_id)
        if not receipt.capture_enabled or previous is None or previous.status != "committed":
            raise PermissionError("conversation history requires a verified clean boundary")
        sources.update(
            value
            for value in (
                previous.user_evidence_id,
                previous.assistant_evidence_id,
            )
            if value is not None
        )
    return active_sources(session, sources)


def evidence_descendants(session: Session, source: UUID) -> set[UUID]:
    """Unbounded by ingestion cap: deletion must not silently truncate closure."""
    found = {source}
    pending = found.copy()
    while pending:
        children = set(
            session.scalars(
                select(EvidenceDerivationRow.child_id).where(
                    EvidenceDerivationRow.parent_id.in_(pending),
                )
            )
        )
        pending = children - found
        found.update(children)
    return found


def verify_archive_provenance(session: Session, evidence_ids: set[UUID] | None = None) -> None:
    """Check sealed ancestry before destruction, or the archive during maintenance."""
    statement = select(EvidenceRow).where(
        EvidenceRow.source == "hermes",
        ~select(EvidenceTombstoneRow.evidence_id)
        .where(
            EvidenceTombstoneRow.evidence_id == EvidenceRow.id,
        )
        .exists(),
    )
    if evidence_ids is not None:
        statement = statement.where(EvidenceRow.id.in_(evidence_ids))
    for evidence in session.scalars(statement):
        metadata = evidence.content
        if metadata.get("contract_version") != "3":
            raise PermissionError("legacy encrypted evidence requires a provenance review")
        if metadata.get("role") not in {"user", "assistant"}:
            raise PermissionError("archive provenance manifest is invalid")
        values = metadata.get("source_evidence_ids")
        if not isinstance(values, list) or len(values) > MAX_SOURCES:
            raise PermissionError("archive provenance manifest is invalid")
        try:
            declared = {UUID(value) for value in values}
        except (ValueError, TypeError, AttributeError) as exc:
            raise PermissionError("archive provenance manifest is invalid") from exc
        if len(declared) != len(values):
            raise PermissionError("archive provenance manifest is invalid")
        recorded = set(
            session.scalars(
                select(EvidenceDerivationRow.parent_id).where(
                    EvidenceDerivationRow.child_id == evidence.id,
                )
            )
        )
        if declared != recorded or session.get(EvidencePayloadRow, evidence.id) is None:
            raise PermissionError("archive provenance coverage is incomplete")
        if metadata.get("role") == "user" and declared:
            raise PermissionError("inbound evidence cannot have derived parents")
        if metadata.get("role") == "assistant" and not declared:
            raise PermissionError("assistant evidence lacks source provenance")
        if declared and evidence.id in active_sources(session, declared):
            raise PermissionError("cyclic archive provenance is forbidden")
