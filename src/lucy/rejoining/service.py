"""Deterministic startup verification and reconciliation gate."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from lucy.actions import mark_action_ambiguous
from lucy.audit import append_audit, verify_audit_chain
from lucy.contracts import OperationOutcome, RejoiningState
from lucy.db.models import (
    AuditHeadRow,
    BudgetAccountRow,
    LifecycleRow,
    OperationRow,
    StartupRunRow,
)
from lucy.rejoining.transitions import can_transition


class StartupResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    run_id: str
    state: RejoiningState
    checks: dict[str, str]
    ambiguous_count: int = 0


class RejoiningService:
    def __init__(
        self, sessions: sessionmaker[Session], *, expected_hermes_commit: str
    ) -> None:
        if re.fullmatch(r"[0-9a-f]{40}", expected_hermes_commit) is None:
            raise ValueError("expected Hermes commit must be a full lowercase SHA-1")
        self._sessions = sessions
        self._expected_commit = expected_hermes_commit

    def run(self, *, observed_hermes_commit: str) -> StartupResult:
        started = datetime.now(UTC)
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(0x4C554359)))
            lifecycle = session.scalar(
                select(LifecycleRow).where(LifecycleRow.singleton).with_for_update()
            )
            checks = self._checks(session, lifecycle, observed_hermes_commit)
            audit_error = checks["audit_chain"] if checks["audit_chain"] != "ok" else None
            if lifecycle is None:
                raise RuntimeError("lifecycle is missing; startup diagnostics cannot be persisted")
            pending = list(
                session.scalars(
                    select(OperationRow)
                    .where(OperationRow.outcome == OperationOutcome.PENDING)
                    .with_for_update()
                )
            )
            run_id = uuid4()
            failures = [name for name, value in checks.items() if value != "ok"]
            if audit_error is not None:
                lifecycle.state = RejoiningState.DEGRADED
                lifecycle.version += 1
                lifecycle.updated_at = started
                checks["startup"] = "degraded_without_audit_append"
                session.add(
                    StartupRunRow(
                        id=run_id, outcome_state=RejoiningState.DEGRADED,
                        checks=checks, started_at=started, completed_at=datetime.now(UTC),
                    )
                )
                return StartupResult(
                    run_id=str(run_id), state=RejoiningState.DEGRADED, checks=checks
                )

            operation = OperationRow(
                id=uuid4(), idempotency_key=f"startup:{run_id}",
                outcome=OperationOutcome.PENDING, result=None, created_at=started,
                completed_at=None,
            )
            session.add(operation)
            session.flush()
            append_audit(session, operation.id, "operation.started", {"kind": "startup"})
            current = RejoiningState(lifecycle.state)
            if current == RejoiningState.READY:
                self._transition(session, lifecycle, operation.id, RejoiningState.OFFLINE)
                current = RejoiningState.OFFLINE
            if current in {RejoiningState.OFFLINE, RejoiningState.DEGRADED}:
                self._transition(session, lifecycle, operation.id, RejoiningState.REJOINING)
            elif current != RejoiningState.REJOINING:
                failures.append("invalid_initial_state")

            ambiguous = 0
            if not failures:
                self._transition(session, lifecycle, operation.id, RejoiningState.RECONCILING)
                for pending_operation in pending:
                    mark_action_ambiguous(session, pending_operation.id, started)
                    pending_operation.outcome = OperationOutcome.AMBIGUOUS
                    pending_operation.result = {
                        "reason": "outcome_unknown_after_restart", "retried": False
                    }
                    pending_operation.completed_at = started
                    append_audit(
                        session, pending_operation.id, "operation.ambiguous",
                        {"reason": "outcome_unknown_after_restart", "retried": False},
                    )
                    ambiguous += 1
                if ambiguous:
                    failures.append("pending_operations")
                    checks["pending_operations"] = f"ambiguous:{ambiguous}"
                else:
                    checks["pending_operations"] = "ok"
            target = RejoiningState.DEGRADED if failures else RejoiningState.READY
            self._transition(session, lifecycle, operation.id, target)
            operation.outcome = OperationOutcome.SUCCEEDED
            operation.result = {
                "state": target.value, "checks": checks, "ambiguous_count": ambiguous
            }
            operation.completed_at = datetime.now(UTC)
            append_audit(session, operation.id, "operation.succeeded", operation.result)
            session.add(
                StartupRunRow(
                    id=run_id, outcome_state=target, checks=checks,
                    started_at=started, completed_at=operation.completed_at,
                )
            )
            return StartupResult(
                run_id=str(run_id), state=target, checks=checks,
                ambiguous_count=ambiguous,
            )

    def _checks(
        self, session: Session, lifecycle: LifecycleRow | None, observed_commit: str
    ) -> dict[str, str]:
        audit_error = verify_audit_chain(session)
        budgets = list(session.scalars(select(BudgetAccountRow).with_for_update()))
        budget_ok = bool(budgets) and all(
            row.limit_microusd >= row.spent_microusd + row.reserved_microusd
            and row.spent_microusd >= 0 and row.reserved_microusd >= 0
            for row in budgets
        )
        return {
            "hermes_pin": "ok" if observed_commit == self._expected_commit else "mismatch",
            "lifecycle": "ok" if lifecycle is not None else "missing",
            "audit_head": "ok" if session.get(AuditHeadRow, True) is not None else "missing",
            "audit_chain": "ok" if audit_error is None else audit_error,
            "budgets": "ok" if budget_ok else "invalid",
        }

    @staticmethod
    def _transition(
        session: Session, lifecycle: LifecycleRow, operation_id: UUID,
        target: RejoiningState,
    ) -> None:
        current = RejoiningState(lifecycle.state)
        if not can_transition(current, target):
            raise RuntimeError(f"invalid lifecycle transition: {current.value}->{target.value}")
        lifecycle.state = target
        lifecycle.version += 1
        lifecycle.updated_at = datetime.now(UTC)
        append_audit(
            session, operation_id, "lifecycle.transitioned",
            {"from": current.value, "to": target.value, "version": lifecycle.version},
        )
