"""Transactional tamper-evident audit append operation."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from lucy.db.models import AuditEventRow, AuditHeadRow


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def append_audit(
    session: Session, operation_id: UUID, event_type: str, payload: dict[str, Any]
) -> None:
    head = session.scalar(select(AuditHeadRow).where(AuditHeadRow.singleton).with_for_update())
    if head is None:
        raise RuntimeError("audit head is missing")
    sequence = head.last_sequence + 1
    occurred_at = datetime.now(UTC)
    material = {
        "sequence": sequence,
        "operation_id": str(operation_id),
        "event_type": event_type,
        "occurred_at": occurred_at.isoformat(),
        "payload": payload,
        "previous_hash": head.last_hash,
    }
    event_hash = hashlib.sha256(_canonical_json(material).encode()).hexdigest()
    session.add(
        AuditEventRow(
            id=uuid4(),
            sequence=sequence,
            operation_id=operation_id,
            event_type=event_type,
            occurred_at=occurred_at,
            payload=payload,
            previous_hash=head.last_hash,
            event_hash=event_hash,
        )
    )
    head.last_sequence = sequence
    head.last_hash = event_hash
