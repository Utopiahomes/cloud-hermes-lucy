"""Durable human-only approval workflow."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from lucy.audit import append_audit
from lucy.contracts import ApprovalDecision, ApprovalStatus, HumanActorType, OperationOutcome
from lucy.db.models import ApprovalRequestRow, OperationRow


class ApprovalResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    approval_id: UUID
    status: ApprovalStatus
    replayed: bool = False


class ApprovalService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def request(
        self, *, idempotency_key: str, action_type: str, action_payload: dict[str, object]
    ) -> ApprovalResult:
        if not idempotency_key or not action_type:
            raise ValueError("idempotency_key and action_type must not be blank")
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(idempotency_key))))
            existing = session.scalar(
                select(OperationRow).where(OperationRow.idempotency_key == idempotency_key)
            )
            if existing is not None:
                if existing.outcome != OperationOutcome.SUCCEEDED or existing.result is None:
                    raise RuntimeError(f"operation has non-replayable outcome: {existing.outcome}")
                return ApprovalResult.model_validate({**existing.result, "replayed": True})

            now = datetime.now(UTC)
            operation = OperationRow(
                id=uuid4(), idempotency_key=idempotency_key, outcome=OperationOutcome.PENDING,
                result=None, created_at=now, completed_at=None,
            )
            session.add(operation)
            session.flush()
            append_audit(session, operation.id, "operation.started", {})
            approval = ApprovalRequestRow(
                id=uuid4(), request_operation_id=operation.id, action_type=action_type,
                action_payload=action_payload, status=ApprovalStatus.PENDING,
                requested_at=now, decided_at=None, decided_by=None, actor_type=None,
                decision_reason=None, version=0,
            )
            session.add(approval)
            append_audit(
                session, operation.id, "approval.requested",
                {"approval_id": str(approval.id), "action_type": action_type},
            )
            result = ApprovalResult(approval_id=approval.id, status=ApprovalStatus.PENDING)
            operation.outcome = OperationOutcome.SUCCEEDED
            operation.result = result.model_dump(mode="json")
            operation.completed_at = now
            append_audit(session, operation.id, "operation.succeeded", operation.result)
            return result

    def decide(
        self, *, idempotency_key: str, approval_id: UUID, decision: ApprovalDecision,
        decided_by: str, actor_type: HumanActorType, reason: str | None = None,
    ) -> ApprovalResult:
        if not idempotency_key or not decided_by:
            raise ValueError("idempotency_key and decided_by must not be blank")
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(idempotency_key))))
            existing = session.scalar(
                select(OperationRow).where(OperationRow.idempotency_key == idempotency_key)
            )
            if existing is not None:
                if existing.outcome != OperationOutcome.SUCCEEDED or existing.result is None:
                    raise RuntimeError(f"operation has non-replayable outcome: {existing.outcome}")
                return ApprovalResult.model_validate({**existing.result, "replayed": True})

            approval = session.scalar(
                select(ApprovalRequestRow)
                .where(ApprovalRequestRow.id == approval_id)
                .with_for_update()
            )
            if approval is None:
                raise LookupError("approval request does not exist")
            target = (
                ApprovalStatus.APPROVED
                if decision == ApprovalDecision.APPROVE
                else ApprovalStatus.DENIED
            )
            if approval.status != ApprovalStatus.PENDING:
                if approval.status == target:
                    return ApprovalResult(approval_id=approval.id, status=target, replayed=True)
                raise RuntimeError(f"approval already has conflicting status: {approval.status}")

            now = datetime.now(UTC)
            operation = OperationRow(
                id=uuid4(), idempotency_key=idempotency_key, outcome=OperationOutcome.PENDING,
                result=None, created_at=now, completed_at=None,
            )
            session.add(operation)
            session.flush()
            append_audit(session, operation.id, "operation.started", {})
            approval.status = target
            approval.decided_at = now
            approval.decided_by = decided_by
            approval.actor_type = actor_type
            approval.decision_reason = reason
            approval.version += 1
            append_audit(
                session, operation.id, f"approval.{target.value}",
                {"approval_id": str(approval.id), "actor_type": actor_type.value,
                 "decided_by": decided_by, "reason": reason},
            )
            result = ApprovalResult(approval_id=approval.id, status=target)
            operation.outcome = OperationOutcome.SUCCEEDED
            operation.result = result.model_dump(mode="json")
            operation.completed_at = now
            append_audit(session, operation.id, "operation.succeeded", operation.result)
            return result
