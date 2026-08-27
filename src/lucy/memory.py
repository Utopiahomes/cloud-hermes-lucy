"""Provenance-preserving graph and bounded working-context projections."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from lucy.audit import append_audit
from lucy.contracts import OperationOutcome
from lucy.db.models import (
    EvidenceRow,
    MemoryClaimRow,
    MemoryEntityRow,
    MemoryRelationshipRow,
    OperationRow,
    WorkingContextRow,
)


class GraphResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    relationship_id: UUID
    claim_id: UUID
    replayed: bool = False


class WorkingContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    context_id: UUID
    query: str
    claims: list[dict[str, object]]
    read_only: bool = True
    expires_at: datetime


class MemoryService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def materialize_claim(self, claim_id: UUID) -> GraphResult:
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(str(claim_id)))))
            existing = session.scalar(
                select(MemoryRelationshipRow).where(MemoryRelationshipRow.claim_id == claim_id)
            )
            if existing is not None:
                return GraphResult(
                    relationship_id=existing.id, claim_id=claim_id, replayed=True
                )
            claim = session.get(MemoryClaimRow, claim_id)
            if claim is None:
                raise LookupError("claim does not exist")
            now = datetime.now(UTC)
            operation = OperationRow(
                id=uuid4(), idempotency_key=f"memory:materialize:{claim_id}",
                outcome=OperationOutcome.PENDING, result=None, created_at=now,
                completed_at=None,
            )
            session.add(operation)
            session.flush()
            append_audit(session, operation.id, "operation.started", {})
            subject = self._entity(session, "subject", claim.subject, now)
            object_entity = self._entity(session, "value", claim.object, now)
            relationship = MemoryRelationshipRow(
                id=uuid4(), subject_entity_id=subject.id, object_entity_id=object_entity.id,
                predicate=claim.predicate, claim_id=claim.id, evidence_id=claim.evidence_id,
                valid_from=claim.created_at, valid_to=None, version=1,
            )
            session.add(relationship)
            result = GraphResult(relationship_id=relationship.id, claim_id=claim.id)
            append_audit(
                session, operation.id, "memory.relationship_materialized",
                {"relationship_id": str(relationship.id), "claim_id": str(claim.id),
                 "evidence_id": str(claim.evidence_id)},
            )
            operation.outcome = OperationOutcome.SUCCEEDED
            operation.result = result.model_dump(mode="json")
            operation.completed_at = now
            append_audit(session, operation.id, "operation.succeeded", operation.result)
            return result

    def build_context(
        self, query: str, *, limit: int = 10, ttl_seconds: int = 300,
        persist: bool = False,
    ) -> WorkingContext:
        if not query.strip():
            raise ValueError("query must not be blank")
        if not 1 <= limit <= 50:
            raise ValueError("limit must be between 1 and 50")
        with self._sessions.begin() as session:
            pattern = f"%{query.strip()}%"
            rows = session.execute(
                select(MemoryRelationshipRow, MemoryClaimRow, EvidenceRow)
                .join(MemoryClaimRow, MemoryClaimRow.id == MemoryRelationshipRow.claim_id)
                .join(EvidenceRow, EvidenceRow.id == MemoryRelationshipRow.evidence_id)
                .where(
                    MemoryClaimRow.status != "superseded",
                    or_(
                        MemoryClaimRow.subject.ilike(pattern),
                        MemoryClaimRow.predicate.ilike(pattern),
                        MemoryClaimRow.object.ilike(pattern),
                    )
                )
                .order_by(MemoryClaimRow.confidence.desc(), MemoryClaimRow.created_at.desc())
                .limit(limit)
            ).all()
            claims: list[dict[str, object]] = [
                {
                    "claim_id": str(claim.id), "subject": claim.subject,
                    "predicate": claim.predicate, "object": claim.object,
                    "confidence": claim.confidence, "status": claim.status,
                    "evidence_id": str(evidence.id),
                    "evidence_sha256": evidence.content_sha256,
                    "relationship_version": relationship.version,
                }
                for relationship, claim, evidence in rows
            ]
            now = datetime.now(UTC)
            context = WorkingContext(
                context_id=uuid4(), query=query, claims=claims,
                expires_at=now + timedelta(seconds=ttl_seconds),
            )
            if persist:
                session.add(
                    WorkingContextRow(
                        id=context.context_id, query=query,
                        projection=context.model_dump(mode="json"), created_at=now,
                        expires_at=context.expires_at,
                    )
                )
            return context

    @staticmethod
    def _entity(
        session: Session, entity_type: str, canonical_name: str, now: datetime
    ) -> MemoryEntityRow:
        entity_key = f"{entity_type}:{canonical_name}"
        session.execute(select(func.pg_advisory_xact_lock(func.hashtext(entity_key))))
        entity = session.scalar(
            select(MemoryEntityRow).where(
                MemoryEntityRow.entity_type == entity_type,
                MemoryEntityRow.canonical_name == canonical_name,
            )
        )
        if entity is None:
            entity = MemoryEntityRow(
                id=uuid4(), canonical_name=canonical_name, entity_type=entity_type,
                version=1, created_at=now,
            )
            session.add(entity)
            session.flush()
        return entity
