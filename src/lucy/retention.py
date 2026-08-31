"""Content-free consent receipts and a transaction-wide deletion fence.

Acquire this fence before any operation-specific lock. Ordinary readers/writers
share it; deletion exclusively holds it through key destruction and redaction.
This deliberately simple single-owner boundary can later become scope-specific.
"""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from lucy.db.models import (
    CaptureReceiptRow,
    ConversationCaptureStateRow,
)
from lucy.provenance import active_sources

RETENTION_LOCK = 0x4C5543595254


def retention_fence(session: Session, *, deleting: bool = False) -> None:
    lock = func.pg_advisory_xact_lock if deleting else func.pg_advisory_xact_lock_shared
    session.execute(select(lock(RETENTION_LOCK)))


def lock_conversation(session: Session, platform: str, conversation_id: str) -> None:
    session.execute(select(func.pg_advisory_xact_lock(
        func.hashtextextended(f"capture:{platform}:{conversation_id}", 0)
    )))


def require_active_evidence(session: Session, evidence_id: UUID) -> None:
    active_sources(session, {evidence_id})


def require_capturable_turn(session: Session, conversation_id: str, turn_id: str) -> None:
    lock_conversation(session, "telegram", conversation_id)
    receipt = session.get(CaptureReceiptRow, {
        "platform": "telegram", "source_conversation_id": conversation_id,
        "source_turn_id": turn_id,
    })
    mode = session.get(ConversationCaptureStateRow, {
        "platform": "telegram", "source_conversation_id": conversation_id,
    })
    if (
        receipt is None or not receipt.capture_enabled
        or (mode is not None and not mode.capture_enabled)
        or receipt.capture_version != (0 if mode is None else mode.version)
    ):
        raise PermissionError("turn is not authorized for retention")
