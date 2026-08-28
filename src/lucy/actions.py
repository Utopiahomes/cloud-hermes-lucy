"""Durable action policy, approval, and budget gate."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from lucy.audit import append_audit
from lucy.contracts import ApprovalStatus, OperationOutcome
from lucy.db.models import (
    ActionExecutionRow,
    ApprovalRequestRow,
    BudgetAccountRow,
    BudgetReservationRow,
    OperationRow,
)
from lucy.policy import ActionDisposition, ActionIntent, classify_action


class ActionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    action_id: UUID
    status: str
    disposition: ActionDisposition
    approval_id: UUID | None = None
    reservation_id: UUID | None = None
    replayed: bool = False


class ActionControlService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def submit(
        self, *, idempotency_key: str, intent: ActionIntent,
        payload: dict[str, object],
    ) -> ActionResult:
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(idempotency_key))))
            existing = session.scalar(select(ActionExecutionRow).where(
                ActionExecutionRow.idempotency_key == idempotency_key))
            if existing is not None:
                return self._result(existing, replayed=True)
            decision = classify_action(intent)
            now = datetime.now(UTC)
            control_operation = OperationRow(
                id=uuid4(), idempotency_key=f"action:control:{idempotency_key}",
                outcome=OperationOutcome.PENDING, result=None, created_at=now,
                completed_at=None,
            )
            session.add(control_operation)
            session.flush()
            append_audit(session, control_operation.id, "operation.started", {
                "kind": "action_control"})
            row = ActionExecutionRow(
                id=uuid4(), idempotency_key=idempotency_key,
                action_type=intent.action_type, action_payload=payload,
                estimated_microusd=intent.estimated_microusd,
                status=(
                    "denied"
                    if decision.disposition == ActionDisposition.DENY
                    else "awaiting_approval"
                    if decision.disposition == ActionDisposition.REQUIRE_APPROVAL
                    else "reserved"
                ),
                disposition=decision.disposition,
                control_operation_id=control_operation.id,
                approval_id=None, reservation_id=None,
                execution_operation_id=None, result={"reason": decision.reason}
                if decision.disposition == ActionDisposition.DENY else None,
                created_at=now, completed_at=now
                if decision.disposition == ActionDisposition.DENY else None,
            )
            session.add(row)
            session.flush()
            if decision.disposition == ActionDisposition.REQUIRE_APPROVAL:
                approval = ApprovalRequestRow(
                    id=uuid4(), request_operation_id=control_operation.id,
                    action_type=intent.action_type, action_payload=payload,
                    status=ApprovalStatus.PENDING, requested_at=now, decided_at=None,
                    decided_by=None, actor_type=None, decision_reason=None, version=0,
                )
                session.add(approval)
                session.flush()
                row.approval_id = approval.id
            elif decision.disposition == ActionDisposition.ALLOW:
                row.reservation_id = self._reserve(
                    session, control_operation.id, decision.budget_name,
                    intent.estimated_microusd, now
                )
            result = self._result(row)
            control_operation.outcome = OperationOutcome.SUCCEEDED
            control_operation.result = result.model_dump(mode="json")
            control_operation.completed_at = now
            append_audit(session, control_operation.id, "operation.succeeded",
                         control_operation.result)
            return result

    def authorize(self, action_id: UUID) -> ActionResult:
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(str(action_id)))))
            row = session.scalar(select(ActionExecutionRow).where(
                ActionExecutionRow.id == action_id).with_for_update())
            if row is None:
                raise LookupError("action does not exist")
            if row.status == "reserved":
                return self._result(row, replayed=True)
            if row.status != "awaiting_approval" or row.approval_id is None:
                raise RuntimeError(f"action cannot be authorized from {row.status}")
            approval = session.get(ApprovalRequestRow, row.approval_id)
            if approval is None or approval.status != ApprovalStatus.APPROVED:
                raise PermissionError("action requires human approval")
            decision = classify_action(ActionIntent(
                action_type=row.action_type, estimated_microusd=row.estimated_microusd))
            row.reservation_id = self._reserve(
                session, row.control_operation_id, decision.budget_name,
                row.estimated_microusd,
                datetime.now(UTC),
            )
            row.status = "reserved"
            return self._result(row)

    def begin_execution(self, action_id: UUID) -> ActionResult:
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(str(action_id)))))
            row = session.scalar(select(ActionExecutionRow).where(
                ActionExecutionRow.id == action_id).with_for_update())
            if row is not None and row.status == "executing":
                return self._result(row, replayed=True)
            if (
                row is None
                or row.status != "reserved"
                or (row.reservation_id is None and row.estimated_microusd != 0)
            ):
                raise RuntimeError("action is not reserved")
            now = datetime.now(UTC)
            operation = OperationRow(
                id=uuid4(), idempotency_key=f"action:execute:{row.id}",
                outcome=OperationOutcome.PENDING, result=None, created_at=now,
                completed_at=None,
            )
            session.add(operation)
            session.flush()
            append_audit(session, operation.id, "action.execution_started", {
                "action_id": str(row.id), "reservation_id": str(row.reservation_id)})
            row.execution_operation_id = operation.id
            row.status = "executing"
            return self._result(row)

    def settle(
        self, action_id: UUID, *, actual_microusd: int, succeeded: bool,
        result: dict[str, object],
    ) -> ActionResult:
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(str(action_id)))))
            row = session.scalar(select(ActionExecutionRow).where(
                ActionExecutionRow.id == action_id).with_for_update())
            if row is None:
                raise LookupError("action does not exist")
            if row.status in {"succeeded", "failed"}:
                return self._result(row, replayed=True)
            if row.status != "executing":
                raise RuntimeError("action is not executing")
            operation = session.get(OperationRow, row.execution_operation_id)
            if operation is None:
                raise RuntimeError("action execution operation is missing")
            if row.reservation_id is None:
                if actual_microusd != 0:
                    raise ValueError("unbudgeted action must have zero actual cost")
                now = datetime.now(UTC)
                row.status = "succeeded" if succeeded else "failed"
                row.result = result
                row.completed_at = now
                operation.outcome = (
                    OperationOutcome.SUCCEEDED if succeeded else OperationOutcome.FAILED
                )
                operation.result = result
                operation.completed_at = now
                append_audit(session, operation.id, f"action.{row.status}", {
                    "action_id": str(row.id), "actual_microusd": 0})
                return self._result(row)
            reservation = session.get(BudgetReservationRow, row.reservation_id)
            if (
                reservation is None
                or actual_microusd < 0
                or actual_microusd > reservation.reserved_microusd
            ):
                raise ValueError("actual cost is outside reservation")
            budget = session.scalar(select(BudgetAccountRow).where(
                BudgetAccountRow.name == reservation.budget_name).with_for_update())
            if budget is None or operation is None:
                raise RuntimeError("action accounting state is missing")
            now = datetime.now(UTC)
            budget.reserved_microusd -= reservation.reserved_microusd
            budget.spent_microusd += actual_microusd
            reservation.settled_microusd = actual_microusd
            reservation.settled_at = now
            row.status = "succeeded" if succeeded else "failed"
            row.result = result
            row.completed_at = now
            operation.outcome = OperationOutcome.SUCCEEDED if succeeded else OperationOutcome.FAILED
            operation.result = result
            operation.completed_at = now
            append_audit(session, operation.id, f"action.{row.status}", {
                "action_id": str(row.id), "actual_microusd": actual_microusd})
            return self._result(row)

    @staticmethod
    def _reserve(
        session: Session, action_id: UUID, budget_name: str | None,
        amount: int, now: datetime,
    ) -> UUID | None:
        if budget_name is None:
            return None
        budget = session.scalar(select(BudgetAccountRow).where(
            BudgetAccountRow.name == budget_name).with_for_update())
        if budget is None:
            raise RuntimeError("budget account does not exist")
        available = budget.limit_microusd - budget.spent_microusd - budget.reserved_microusd
        if amount > available:
            raise RuntimeError("budget limit exceeded")
        reservation = BudgetReservationRow(
            id=uuid4(), operation_id=action_id, budget_name=budget.name,
            reserved_microusd=amount, settled_microusd=None,
            created_at=now, settled_at=None,
        )
        session.add(reservation)
        session.flush()
        budget.reserved_microusd += amount
        return reservation.id

    @staticmethod
    def _result(row: ActionExecutionRow, replayed: bool = False) -> ActionResult:
        return ActionResult(
            action_id=row.id, status=row.status,
            disposition=ActionDisposition(row.disposition), approval_id=row.approval_id,
            reservation_id=row.reservation_id, replayed=replayed,
        )


def mark_action_ambiguous(session: Session, operation_id: UUID, now: datetime) -> None:
    """Conservatively settle an uncertain action at its full reservation."""
    row = session.scalar(select(ActionExecutionRow).where(
        ActionExecutionRow.execution_operation_id == operation_id).with_for_update())
    if row is None or row.status != "executing":
        return
    if row.reservation_id is None:
        row.status = "ambiguous"
        row.result = {
            "reason": "outcome_unknown_after_restart",
            "charged_full_reservation": False,
        }
        row.completed_at = now
        return
    reservation = session.get(BudgetReservationRow, row.reservation_id)
    if reservation is None:
        raise RuntimeError("ambiguous action reservation is missing")
    budget = session.scalar(select(BudgetAccountRow).where(
        BudgetAccountRow.name == reservation.budget_name).with_for_update())
    if budget is None:
        raise RuntimeError("ambiguous action budget is missing")
    budget.reserved_microusd -= reservation.reserved_microusd
    budget.spent_microusd += reservation.reserved_microusd
    reservation.settled_microusd = reservation.reserved_microusd
    reservation.settled_at = now
    row.status = "ambiguous"
    row.result = {"reason": "outcome_unknown_after_restart", "charged_full_reservation": True}
    row.completed_at = now
