"""First end-to-end Lucy operation, intentionally narrow and transactional."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from lucy.audit import append_audit
from lucy.contracts import ConversationEvidenceV1, OperationOutcome, RejoiningState
from lucy.db.models import (
    BudgetAccountRow,
    BudgetReservationRow,
    EvidenceRow,
    LifecycleRow,
    MemoryClaimRow,
    OperationRow,
)
from lucy.rejoining import can_transition


class ImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    idempotency_key: str = Field(min_length=1)
    evidence: ConversationEvidenceV1
    subject: str = Field(min_length=1)
    predicate: str = Field(min_length=1)
    object: str = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    budget_name: str = "model.daily"
    reserve_microusd: int = Field(gt=0)
    settle_microusd: int = Field(ge=0)


class ImportResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: UUID
    evidence_id: UUID
    claim_id: UUID
    reservation_id: UUID
    lifecycle_state: RejoiningState
    replayed: bool = False


class VerticalSliceService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def import_synthetic_conversation(self, request: ImportRequest) -> ImportResult:
        with self._sessions.begin() as session:
            # Serialize identical keys before checking. PostgreSQL holds this lock
            # until transaction end, including after a process restart/retry.
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(request.idempotency_key))))
            existing = session.scalar(
                select(OperationRow).where(
                    OperationRow.idempotency_key == request.idempotency_key
                )
            )
            if existing is not None:
                if existing.outcome != OperationOutcome.SUCCEEDED or existing.result is None:
                    raise RuntimeError(f"operation has non-replayable outcome: {existing.outcome}")
                return ImportResult.model_validate({**existing.result, "replayed": True})

            now = datetime.now(UTC)
            operation_id = uuid4()
            operation = OperationRow(
                id=operation_id,
                idempotency_key=request.idempotency_key,
                outcome=OperationOutcome.PENDING,
                result=None,
                created_at=now,
                completed_at=None,
            )
            session.add(operation)
            session.flush()
            append_audit(session, operation_id, "operation.started", {})

            evidence = EvidenceRow(
                id=request.evidence.evidence_id,
                source=request.evidence.source,
                source_conversation_id=request.evidence.source_conversation_id,
                captured_at=request.evidence.captured_at,
                content=request.evidence.model_dump(mode="json"),
                content_sha256=request.evidence.content_sha256,
                operation_id=operation_id,
            )
            session.add(evidence)
            append_audit(
                session,
                operation_id,
                "evidence.preserved",
                {"evidence_id": str(evidence.id), "content_sha256": evidence.content_sha256},
            )

            claim_id = uuid4()
            session.add(
                MemoryClaimRow(
                    id=claim_id,
                    evidence_id=evidence.id,
                    subject=request.subject,
                    predicate=request.predicate,
                    object=request.object,
                    confidence=request.confidence,
                    status="provisional",
                    supersedes_claim_id=None,
                    created_at=now,
                )
            )
            append_audit(
                session,
                operation_id,
                "memory.provisional_claim_created",
                {"claim_id": str(claim_id), "evidence_id": str(evidence.id)},
            )

            lifecycle = session.scalar(
                select(LifecycleRow).where(LifecycleRow.singleton).with_for_update()
            )
            if lifecycle is None or not can_transition(
                RejoiningState(lifecycle.state), RejoiningState.REJOINING
            ):
                raise RuntimeError("lifecycle cannot advance to rejoining")
            lifecycle.state = RejoiningState.REJOINING
            lifecycle.version += 1
            lifecycle.updated_at = now
            append_audit(
                session,
                operation_id,
                "lifecycle.transitioned",
                {"from": "offline", "to": "rejoining", "version": lifecycle.version},
            )

            budget = session.scalar(
                select(BudgetAccountRow)
                .where(BudgetAccountRow.name == request.budget_name)
                .with_for_update()
            )
            if budget is None:
                raise RuntimeError("budget account does not exist")
            available = budget.limit_microusd - budget.spent_microusd - budget.reserved_microusd
            if request.reserve_microusd > available:
                raise RuntimeError("budget limit exceeded")
            if request.settle_microusd > request.reserve_microusd:
                raise RuntimeError("settlement exceeds reservation")
            reservation_id = uuid4()
            budget.reserved_microusd += request.reserve_microusd
            session.add(
                BudgetReservationRow(
                    id=reservation_id,
                    operation_id=operation_id,
                    budget_name=budget.name,
                    reserved_microusd=request.reserve_microusd,
                    settled_microusd=None,
                    created_at=now,
                    settled_at=None,
                )
            )
            append_audit(
                session,
                operation_id,
                "budget.reserved",
                {"reservation_id": str(reservation_id), "microusd": request.reserve_microusd},
            )
            reservation = session.get(BudgetReservationRow, reservation_id)
            if reservation is None:
                raise RuntimeError("reservation was not persisted")
            budget.reserved_microusd -= request.reserve_microusd
            budget.spent_microusd += request.settle_microusd
            reservation.settled_microusd = request.settle_microusd
            reservation.settled_at = now
            append_audit(
                session,
                operation_id,
                "budget.settled",
                {"reservation_id": str(reservation_id), "microusd": request.settle_microusd},
            )

            result = ImportResult(
                operation_id=operation_id,
                evidence_id=evidence.id,
                claim_id=claim_id,
                reservation_id=reservation_id,
                lifecycle_state=RejoiningState.REJOINING,
            )
            operation.outcome = OperationOutcome.SUCCEEDED
            operation.result = result.model_dump(mode="json")
            operation.completed_at = now
            append_audit(session, operation_id, "operation.succeeded", operation.result)
            return result
