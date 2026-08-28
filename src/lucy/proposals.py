"""Governed model-originated memory proposals."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from lucy.audit import append_audit
from lucy.contracts import ApprovalStatus, OperationOutcome
from lucy.db.models import (
    ApprovalRequestRow,
    EvidenceRow,
    MemoryClaimRow,
    MemoryWriteProposalRow,
    OperationRow,
)


class MemoryProposalInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    evidence_id: UUID
    subject: str = Field(min_length=1, max_length=200)
    predicate: str = Field(min_length=1, max_length=200)
    object: str = Field(min_length=1, max_length=2000)
    confidence: float = Field(ge=0, le=1)


class MemoryProposalResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    proposal_id: UUID
    approval_id: UUID
    status: str
    claim_id: UUID | None = None
    replayed: bool = False


class MemoryProposalService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def submit(self, idempotency_key: str, candidate: MemoryProposalInput) -> MemoryProposalResult:
        if not idempotency_key.strip():
            raise ValueError("idempotency key must not be blank")
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(idempotency_key))))
            existing = session.scalar(select(MemoryWriteProposalRow).where(
                MemoryWriteProposalRow.idempotency_key == idempotency_key))
            if existing is not None:
                return self._result(existing, replayed=True)
            if session.get(EvidenceRow, candidate.evidence_id) is None:
                raise LookupError("immutable evidence does not exist")
            now = datetime.now(UTC)
            operation = OperationRow(
                id=uuid4(), idempotency_key=f"memory-proposal:{idempotency_key}",
                outcome=OperationOutcome.PENDING, result=None, created_at=now,
                completed_at=None,
            )
            session.add(operation)
            session.flush()
            append_audit(session, operation.id, "operation.started", {})
            approval = ApprovalRequestRow(
                id=uuid4(), request_operation_id=operation.id,
                action_type="memory.write", action_payload=candidate.model_dump(mode="json"),
                status=ApprovalStatus.PENDING, requested_at=now, decided_at=None,
                decided_by=None, actor_type=None, decision_reason=None, version=0,
            )
            session.add(approval)
            proposal = MemoryWriteProposalRow(
                id=uuid4(), idempotency_key=idempotency_key,
                evidence_id=candidate.evidence_id, subject=candidate.subject,
                predicate=candidate.predicate, object=candidate.object,
                confidence=candidate.confidence, status="pending", approval_id=approval.id,
                claim_id=None, created_at=now, applied_at=None,
            )
            session.add(proposal)
            append_audit(session, operation.id, "memory.write_proposed", {
                "proposal_id": str(proposal.id), "evidence_id": str(candidate.evidence_id),
                "approval_id": str(approval.id),
            })
            result = self._result(proposal)
            operation.outcome = OperationOutcome.SUCCEEDED
            operation.result = result.model_dump(mode="json")
            operation.completed_at = now
            append_audit(session, operation.id, "operation.succeeded", operation.result)
            return result

    def apply(self, proposal_id: UUID) -> MemoryProposalResult:
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(str(proposal_id)))))
            proposal = session.scalar(select(MemoryWriteProposalRow).where(
                MemoryWriteProposalRow.id == proposal_id).with_for_update())
            if proposal is None:
                raise LookupError("proposal does not exist")
            if proposal.status == "applied":
                return self._result(proposal, replayed=True)
            approval = session.get(ApprovalRequestRow, proposal.approval_id)
            if approval is None or approval.status != ApprovalStatus.APPROVED:
                raise PermissionError("proposal requires human approval")
            now = datetime.now(UTC)
            operation = OperationRow(
                id=uuid4(), idempotency_key=f"memory-proposal:apply:{proposal.id}",
                outcome=OperationOutcome.PENDING, result=None, created_at=now,
                completed_at=None,
            )
            session.add(operation)
            session.flush()
            append_audit(session, operation.id, "operation.started", {})
            claim = MemoryClaimRow(
                id=uuid4(), evidence_id=proposal.evidence_id, subject=proposal.subject,
                predicate=proposal.predicate, object=proposal.object,
                confidence=proposal.confidence, status="accepted",
                supersedes_claim_id=None, created_at=now,
            )
            session.add(claim)
            proposal.status = "applied"
            proposal.claim_id = claim.id
            proposal.applied_at = now
            append_audit(session, operation.id, "memory.write_applied", {
                "proposal_id": str(proposal.id), "claim_id": str(claim.id),
            })
            result = self._result(proposal)
            operation.outcome = OperationOutcome.SUCCEEDED
            operation.result = result.model_dump(mode="json")
            operation.completed_at = now
            append_audit(session, operation.id, "operation.succeeded", operation.result)
            return result

    @staticmethod
    def _result(row: MemoryWriteProposalRow, replayed: bool = False) -> MemoryProposalResult:
        return MemoryProposalResult(
            proposal_id=row.id, approval_id=row.approval_id, status=row.status,
            claim_id=row.claim_id, replayed=replayed,
        )
