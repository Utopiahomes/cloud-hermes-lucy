"""Human-governed, provenance-preserving memory corrections."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from lucy.audit import append_audit
from lucy.contracts import ApprovalStatus, OperationOutcome
from lucy.db.models import (
    ApprovalRequestRow,
    ClaimSourceRow,
    CorrectionSourceRow,
    MemoryClaimRow,
    MemoryCorrectionRow,
    MemoryEntityRow,
    MemoryRelationshipRow,
    OperationRow,
)
from lucy.provenance import active_sources, claim_sources
from lucy.retention import require_active_evidence, retention_fence
from lucy.secret_filter import reject_memory_secrets


class CorrectionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    correction_id: UUID
    approval_id: UUID
    status: str
    new_claim_id: UUID | None = None
    replayed: bool = False


class CorrectionService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def propose(
        self, *, idempotency_key: str, old_claim_id: UUID, new_evidence_id: UUID,
        replacement_object: str, confidence: float,
    ) -> CorrectionResult:
        if not replacement_object.strip() or not 0 <= confidence <= 1:
            raise ValueError("replacement and confidence are invalid")
        reject_memory_secrets(replacement_object)
        with self._sessions.begin() as session:
            retention_fence(session)
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(idempotency_key))))
            require_active_evidence(session, new_evidence_id)
            old = session.get(MemoryClaimRow, old_claim_id)
            if old is None:
                raise LookupError("claim does not exist")
            require_active_evidence(session, old.evidence_id)
            sources = active_sources(session, {new_evidence_id, *claim_sources(session, old.id)})
            existing = session.scalar(
                select(MemoryCorrectionRow).where(
                    MemoryCorrectionRow.idempotency_key == idempotency_key
                )
            )
            if existing is not None:
                if (existing.old_claim_id, existing.new_evidence_id,
                    existing.replacement_object, existing.confidence) != (
                    old_claim_id, new_evidence_id, replacement_object, confidence
                ):
                    raise ValueError("idempotency key was already used for another correction")
                return self._result(existing, replayed=True)
            if old.status not in {"accepted", "provisional"} or old.object == replacement_object:
                raise ValueError("correction must contradict a current claim")
            now = datetime.now(UTC)
            operation = OperationRow(
                id=uuid4(), idempotency_key=f"correction-propose:{idempotency_key}",
                outcome=OperationOutcome.PENDING, result=None, created_at=now,
                completed_at=None,
            )
            session.add(operation)
            session.flush()
            approval = ApprovalRequestRow(
                id=uuid4(), request_operation_id=operation.id, action_type="memory.correct",
                action_payload={"old_claim_id": str(old_claim_id),
                                "new_evidence_id": str(new_evidence_id),
                                "replacement_object": replacement_object,
                                "confidence": confidence,
                                "source_evidence_ids": [str(value) for value in sorted(sources)]},
                status=ApprovalStatus.PENDING, requested_at=now, decided_at=None,
                decided_by=None, actor_type=None, decision_reason=None, version=0,
            )
            session.add(approval)
            row = MemoryCorrectionRow(
                id=uuid4(), idempotency_key=idempotency_key, old_claim_id=old_claim_id,
                new_evidence_id=new_evidence_id, replacement_object=replacement_object,
                confidence=confidence, approval_id=approval.id, status="pending",
                new_claim_id=None, created_at=datetime.now(UTC), applied_at=None,
            )
            session.add(row)
            session.flush()
            session.add_all(CorrectionSourceRow(correction_id=row.id, evidence_id=source)
                            for source in sorted(sources))
            result = self._result(row)
            operation.outcome = OperationOutcome.SUCCEEDED
            operation.result = result.model_dump(mode="json")
            operation.completed_at = now
            append_audit(session, operation.id, "memory.correction_proposed", {
                "correction_id": str(row.id), "approval_id": str(approval.id),
            })
            return result

    def apply(self, correction_id: UUID) -> CorrectionResult:
        with self._sessions.begin() as session:
            retention_fence(session)
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(str(correction_id)))))
            correction = session.scalar(select(MemoryCorrectionRow).where(
                MemoryCorrectionRow.id == correction_id).with_for_update())
            if correction is None:
                raise LookupError("correction does not exist")
            require_active_evidence(session, correction.new_evidence_id)
            old = session.get(MemoryClaimRow, correction.old_claim_id)
            if old is None:
                raise LookupError("original claim does not exist")
            require_active_evidence(session, old.evidence_id)
            sources = active_sources(session, session.scalars(
                select(CorrectionSourceRow.evidence_id).where(
                    CorrectionSourceRow.correction_id == correction.id,
                ),
            ))
            if correction.status == "applied":
                return self._result(correction, replayed=True)
            if correction.status != "pending":
                raise PermissionError("correction is no longer eligible for promotion")
            approval = session.get(ApprovalRequestRow, correction.approval_id)
            if approval is None or approval.status != ApprovalStatus.APPROVED:
                raise PermissionError("correction requires human approval")
            if approval.action_type != "memory.correct" or approval.action_payload != {
                "old_claim_id": str(correction.old_claim_id),
                "new_evidence_id": str(correction.new_evidence_id),
                "replacement_object": correction.replacement_object,
                "confidence": correction.confidence,
                "source_evidence_ids": [str(value) for value in sorted(sources)],
            }:
                raise PermissionError("approval does not match the proposed correction")
            old = session.scalar(select(MemoryClaimRow).where(
                MemoryClaimRow.id == correction.old_claim_id).with_for_update())
            if old is None or old.status not in {"accepted", "provisional"}:
                raise RuntimeError("original claim is no longer current")
            now = datetime.now(UTC)
            operation = OperationRow(
                id=uuid4(), idempotency_key=f"correction:apply:{correction.id}",
                outcome=OperationOutcome.PENDING, result=None, created_at=now,
                completed_at=None,
            )
            session.add(operation)
            session.flush()
            append_audit(session, operation.id, "operation.started", {})
            new_claim = MemoryClaimRow(
                id=uuid4(), evidence_id=correction.new_evidence_id, subject=old.subject,
                predicate=old.predicate, object=correction.replacement_object,
                confidence=correction.confidence, status="accepted",
                supersedes_claim_id=old.id, created_at=now,
            )
            session.add(new_claim)
            session.flush()
            session.add_all(ClaimSourceRow(claim_id=new_claim.id, evidence_id=source)
                            for source in sorted(sources))
            old.status = "superseded"
            relationship = session.scalar(select(MemoryRelationshipRow).where(
                MemoryRelationshipRow.claim_id == old.id).with_for_update())
            if relationship is None:
                raise RuntimeError("original claim has not been materialized")
            relationship.valid_to = now
            entity_key = f"value:{correction.replacement_object}"
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(entity_key))))
            object_entity = session.scalar(select(MemoryEntityRow).where(
                MemoryEntityRow.entity_type == "value",
                MemoryEntityRow.canonical_name == correction.replacement_object,
            ))
            if object_entity is None:
                object_entity = MemoryEntityRow(
                    id=uuid4(), entity_type="value",
                    canonical_name=correction.replacement_object, version=1,
                    created_at=now,
                )
                session.add(object_entity)
                session.flush()
            session.add(MemoryRelationshipRow(
                id=uuid4(), subject_entity_id=relationship.subject_entity_id,
                object_entity_id=object_entity.id, predicate=old.predicate,
                claim_id=new_claim.id, evidence_id=new_claim.evidence_id,
                valid_from=now, valid_to=None, version=relationship.version + 1,
            ))
            correction.status = "applied"
            correction.new_claim_id = new_claim.id
            correction.applied_at = now
            append_audit(session, operation.id, "memory.claim_superseded", {
                "old_claim_id": str(old.id), "new_claim_id": str(new_claim.id),
                "evidence_id": str(new_claim.evidence_id),
            })
            result = self._result(correction)
            operation.outcome = OperationOutcome.SUCCEEDED
            operation.result = result.model_dump(mode="json")
            operation.completed_at = now
            append_audit(session, operation.id, "operation.succeeded", operation.result)
            return result

    @staticmethod
    def _result(row: MemoryCorrectionRow, replayed: bool = False) -> CorrectionResult:
        return CorrectionResult(
            correction_id=row.id, approval_id=row.approval_id, status=row.status,
            new_claim_id=row.new_claim_id, replayed=replayed,
        )
