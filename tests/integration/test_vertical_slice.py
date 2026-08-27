from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, func, select, text

from lucy.contracts.v1 import ConversationEvidenceV1, ConversationMessageV1
from lucy.db import create_session_factory
from lucy.db.models import AuditEventRow, BudgetAccountRow, EvidenceRow, MemoryClaimRow
from lucy.vertical_slice import ImportRequest, VerticalSliceService

DATABASE_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_DATABASE_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="requires PostgreSQL integration database")


@pytest.fixture(autouse=True)
def reset_synthetic_database() -> None:
    if OWNER_DATABASE_URL is None:
        pytest.skip("requires PostgreSQL owner URL for isolated test reset")
    engine = create_engine(OWNER_DATABASE_URL)
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE lucy.audit_events, lucy.budget_reservations, lucy.memory_claims, "
                "lucy.evidence, lucy.operations, lucy.audit_head, lucy.lifecycle, "
                "lucy.budget_accounts CASCADE"
            )
        )
        connection.execute(
            text(
                "INSERT INTO lucy.lifecycle (singleton, state, version, updated_at) "
                "VALUES (true, 'offline', 0, now())"
            )
        )
        connection.execute(
            text(
                "INSERT INTO lucy.audit_head (singleton, last_sequence, last_hash) "
                "VALUES (true, 0, repeat('0', 64))"
            )
        )
        connection.execute(
            text(
                "INSERT INTO lucy.budget_accounts "
                "(name, limit_microusd, reserved_microusd, spent_microusd) "
                "VALUES ('model.daily', 1000000, 0, 0)"
            )
        )
    engine.dispose()


def _request() -> ImportRequest:
    occurred_at = datetime(2026, 8, 26, 12, tzinfo=UTC)
    message = ConversationMessageV1(
        message_id="synthetic-1",
        role="user",
        content="My favorite tea is Earl Grey.",
        occurred_at=occurred_at,
    )
    messages = [message.model_dump(mode="json")]
    digest = hashlib.sha256(
        json.dumps(messages, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return ImportRequest(
        idempotency_key="acceptance:synthetic-conversation:1",
        evidence=ConversationEvidenceV1(
            evidence_id=uuid4(),
            source="synthetic",
            source_conversation_id="acceptance-1",
            captured_at=occurred_at,
            messages=(message,),
            content_sha256=digest,
        ),
        subject="user",
        predicate="favorite_tea",
        object="Earl Grey",
        confidence=0.9,
        reserve_microusd=5000,
        settle_microusd=3200,
    )


def test_import_restart_and_exactly_once_recovery() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    first = VerticalSliceService(sessions).import_synthetic_conversation(_request())

    # A new service instance represents a process restart. The same idempotency
    # key must return the durable result without repeating any side effect.
    restarted = VerticalSliceService(create_session_factory(DATABASE_URL))
    replay = restarted.import_synthetic_conversation(_request())
    assert replay.replayed is True
    assert replay.operation_id == first.operation_id

    with sessions() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceRow)) == 1
        assert session.scalar(select(func.count()).select_from(MemoryClaimRow)) == 1
        assert session.scalar(select(func.count()).select_from(AuditEventRow)) == 7
        budget = session.get(BudgetAccountRow, "model.daily")
        assert budget is not None
        assert budget.reserved_microusd == 0
        assert budget.spent_microusd == 3200

        events = list(session.scalars(select(AuditEventRow).order_by(AuditEventRow.sequence)))
        previous = "0" * 64
        for event in events:
            assert event.previous_hash == previous
            material = {
                "sequence": event.sequence,
                "operation_id": str(event.operation_id),
                "event_type": event.event_type,
                "occurred_at": event.occurred_at.isoformat(),
                "payload": event.payload,
                "previous_hash": event.previous_hash,
            }
            recomputed = hashlib.sha256(
                json.dumps(
                    material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode()
            ).hexdigest()
            assert event.event_hash == recomputed
            previous = event.event_hash
