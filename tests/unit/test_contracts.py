import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from lucy.contracts.v1 import ConversationEvidenceV1, ConversationMessageV1


def test_evidence_rejects_invalid_content_hash() -> None:
    with pytest.raises(ValidationError):
        ConversationEvidenceV1(
            evidence_id=uuid4(),
            source="synthetic",
            source_conversation_id="acceptance-1",
            captured_at=datetime.now(UTC),
            messages=(
                ConversationMessageV1(
                    message_id="m1",
                    role="user",
                    content="My favorite tea is Earl Grey.",
                    occurred_at=datetime.now(UTC),
                ),
            ),
            content_sha256="not-a-hash",
        )


def test_evidence_rejects_well_formed_but_incorrect_content_hash() -> None:
    with pytest.raises(ValidationError, match="does not match normalized messages"):
        ConversationEvidenceV1(
            evidence_id=uuid4(),
            source="synthetic",
            source_conversation_id="acceptance-1",
            captured_at=datetime.now(UTC),
            messages=(
                ConversationMessageV1(
                    message_id="m1",
                    role="user",
                    content="My favorite tea is Earl Grey.",
                    occurred_at=datetime.now(UTC),
                ),
            ),
            content_sha256="0" * 64,
        )


def test_evidence_accepts_hash_of_normalized_messages() -> None:
    message = ConversationMessageV1(
        message_id="m1",
        role="user",
        content="My favorite tea is Earl Grey.",
        occurred_at=datetime(2026, 8, 26, 12, tzinfo=UTC),
    )
    encoded = json.dumps(
        [message.model_dump(mode="json")],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    evidence = ConversationEvidenceV1(
        evidence_id=uuid4(),
        source="synthetic",
        source_conversation_id="acceptance-1",
        captured_at=datetime.now(UTC),
        messages=(message,),
        content_sha256=hashlib.sha256(encoded).hexdigest(),
    )
    assert evidence.content_sha256 == evidence.computed_content_sha256()
