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
    ClaimSourceRow,
    MemoryClaimRow,
    MemoryWriteProposalRow,
    OperationRow,
    ProposalSourceRow,
)
from lucy.provenance import DerivationSourcesV1, active_sources, conversation_sources
from lucy.retention import require_active_evidence, require_capturable_turn, retention_fence
from lucy.secret_filter import MemorySecretDetected, detect_memory_secrets


class MemoryProposalInput(DerivationSourcesV1):
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


class GatewayMemoryProposalInput(MemoryProposalInput):
    source_conversation_id: str = Field(min_length=1, max_length=512)
    source_turn_id: str = Field(min_length=1, max_length=512)


class MemoryProposalService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def submit(self, idempotency_key: str, candidate: MemoryProposalInput) -> MemoryProposalResult:
        if not idempotency_key.strip():
            raise ValueError("idempotency key must not be blank")
        findings = detect_memory_secrets(
            candidate.subject, candidate.predicate, candidate.object
        )
        if findings:
            categories = tuple(finding.category for finding in findings)
            self._record_sensitive_rejection(idempotency_key, categories)
            raise MemorySecretDetected(categories)
        with self._sessions.begin() as session:
            retention_fence(session)
            sources = active_sources(
                session, {candidate.evidence_id, *candidate.source_evidence_ids},
            )
            if isinstance(candidate, GatewayMemoryProposalInput):
                require_capturable_turn(
                    session, candidate.source_conversation_id, candidate.source_turn_id
                )
                sources = active_sources(session, sources | conversation_sources(
                    session, candidate.source_conversation_id, candidate.source_turn_id,
                ))
            require_active_evidence(session, candidate.evidence_id)
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(idempotency_key))))
            existing = session.scalar(select(MemoryWriteProposalRow).where(
                MemoryWriteProposalRow.idempotency_key == idempotency_key))
            if existing is not None:
                if any(getattr(existing, field) != getattr(candidate, field) for field in (
                    "evidence_id", "subject", "predicate", "object", "confidence",
                )):
                    raise ValueError("idempotency key was already used for another proposal")
                stored_sources = set(session.scalars(select(ProposalSourceRow.evidence_id).where(
                    ProposalSourceRow.proposal_id == existing.id,
                )))
                if stored_sources != sources:
                    raise ValueError("idempotency key was already used with other provenance")
                return self._result(existing, replayed=True)
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
                action_type="memory.write", action_payload={
                    **candidate.model_dump(mode="json"),
                    "source_evidence_ids": [str(value) for value in sorted(sources)],
                },
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
            session.flush()
            session.add_all(ProposalSourceRow(proposal_id=proposal.id, evidence_id=source)
                            for source in sorted(sources))
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

    def _record_sensitive_rejection(
        self, idempotency_key: str, categories: tuple[str, ...]
    ) -> None:
        operation_key = f"memory-proposal:rejected:{idempotency_key}"
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(operation_key))))
            existing = session.scalar(
                select(OperationRow).where(OperationRow.idempotency_key == operation_key)
            )
            if existing is not None:
                return
            now = datetime.now(UTC)
            operation = OperationRow(
                id=uuid4(),
                idempotency_key=operation_key,
                outcome=OperationOutcome.FAILED,
                result={"rejected": True, "categories": list(categories)},
                created_at=now,
                completed_at=now,
            )
            session.add(operation)
            session.flush()
            append_audit(
                session,
                operation.id,
                "memory.write_rejected_sensitive",
                {"categories": list(categories)},
            )

    def apply(self, proposal_id: UUID) -> MemoryProposalResult:
        with self._sessions.begin() as session:
            retention_fence(session)
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(str(proposal_id)))))
            proposal = session.scalar(select(MemoryWriteProposalRow).where(
                MemoryWriteProposalRow.id == proposal_id).with_for_update())
            if proposal is None:
                raise LookupError("proposal does not exist")
            require_active_evidence(session, proposal.evidence_id)
            sources = active_sources(session, session.scalars(select(ProposalSourceRow.evidence_id)
                                     .where(ProposalSourceRow.proposal_id == proposal.id)))
            if proposal.status == "applied":
                return self._result(proposal, replayed=True)
            if proposal.status != "pending":
                raise PermissionError("proposal is no longer eligible for promotion")
            approval = session.get(ApprovalRequestRow, proposal.approval_id)
            if approval is None or approval.status != ApprovalStatus.APPROVED:
                raise PermissionError("proposal requires human approval")
            expected = {
                "evidence_id": str(proposal.evidence_id), "subject": proposal.subject,
                "predicate": proposal.predicate, "object": proposal.object,
                "confidence": proposal.confidence,
                "source_evidence_ids": [str(value) for value in sorted(sources)],
            }
            if approval.action_type != "memory.write" or any(
                approval.action_payload.get(field) != value for field, value in expected.items()
            ):
                raise PermissionError("approval does not match the proposed memory")
            # A proposal may not be promoted after its originating consent
            # generation is revoked, even when it cites older retained evidence.
            origin = approval.action_payload
            if "source_conversation_id" in origin or "source_turn_id" in origin:
                require_capturable_turn(
                    session, origin.get("source_conversation_id", ""),
                    origin.get("source_turn_id", ""),
                )
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
            session.flush()
            session.add_all(ClaimSourceRow(claim_id=claim.id, evidence_id=source)
                            for source in sorted(sources))
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
