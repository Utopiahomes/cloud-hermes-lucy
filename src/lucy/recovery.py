"""Conservative recovery for operations whose external outcome is unknowable."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from lucy.actions import mark_action_ambiguous
from lucy.audit import append_audit
from lucy.contracts import OperationOutcome, RejoiningState
from lucy.db.models import LifecycleRow, OperationRow


class RecoveryService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def mark_ambiguous_pending(self) -> int:
        """Mark uncertain work ambiguous; never replay its external effect."""
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(0x4C554359)))
            lifecycle = session.scalar(
                select(LifecycleRow).where(LifecycleRow.singleton).with_for_update()
            )
            if lifecycle is None:
                raise RuntimeError("lifecycle is missing")
            pending = list(
                session.scalars(
                    select(OperationRow)
                    .where(OperationRow.outcome == OperationOutcome.PENDING)
                    .with_for_update()
                )
            )
            if not pending:
                return 0
            current = RejoiningState(lifecycle.state)
            if current not in {RejoiningState.REJOINING, RejoiningState.RECONCILING}:
                raise RuntimeError(f"ambiguous recovery is invalid from {current.value}")

            now = datetime.now(UTC)
            recovery = OperationRow(
                id=uuid4(), idempotency_key=f"recovery:ambiguous:{uuid4()}",
                outcome=OperationOutcome.PENDING, result=None, created_at=now, completed_at=None,
            )
            session.add(recovery)
            session.flush()
            append_audit(session, recovery.id, "operation.started", {"kind": "recovery"})
            for operation in pending:
                mark_action_ambiguous(session, operation.id, now)
                operation.outcome = OperationOutcome.AMBIGUOUS
                operation.result = {"reason": "outcome_unknown_after_restart", "retried": False}
                operation.completed_at = now
                append_audit(
                    session, operation.id, "operation.ambiguous",
                    {"reason": "outcome_unknown_after_restart", "retried": False},
                )
            lifecycle.state = RejoiningState.DEGRADED
            lifecycle.version += 1
            lifecycle.updated_at = now
            append_audit(
                session, recovery.id, "lifecycle.transitioned",
                {"from": current.value, "to": RejoiningState.DEGRADED.value,
                 "version": lifecycle.version},
            )
            recovery.outcome = OperationOutcome.SUCCEEDED
            recovery.result = {"ambiguous_count": len(pending)}
            recovery.completed_at = now
            append_audit(session, recovery.id, "operation.succeeded", recovery.result)
            return len(pending)
