from __future__ import annotations

from datetime import UTC, datetime

import pytest

from lucy.chatgpt_manifest import LocalChatGPTConversationV1, LocalChatGPTMessageV1
from lucy.hindsight_backfill import bounded_items, eligible_messages, hindsight_item

COMMITMENT = "a" * 64


def _message(source: str, *, role: str = "owner", displayed: bool = True) -> LocalChatGPTMessageV1:
    return LocalChatGPTMessageV1(
        source_record_id=source,
        conversation_id="conversation-1",
        native_node_id=source,
        native_message_id=source,
        parent_source_record_id=None,
        native_role="user" if role == "owner" else "assistant",
        role=role,  # type: ignore[arg-type]
        occurred_at=datetime(2025, 1, 2, tzinfo=UTC),
        displayed=displayed,
        content="A historical suggestion" if role == "assistant" else "A historical thought",
        inclusion_state="included",
    )


def test_backfill_preserves_attribution_and_excludes_deleted_and_alternate_sources() -> None:
    conversation = LocalChatGPTConversationV1(
        conversation_id="conversation-1",
        messages=(
            _message("owner-1"),
            _message("assistant-1", role="assistant"),
            _message("alternate-1", displayed=False),
            _message("deleted-1"),
        ),
    )
    selected = list(eligible_messages(
        (conversation,), deleted_source_ids=frozenset({"deleted-1"}),
    ))
    assert [item.source_record_id for item in selected] == ["owner-1", "assistant-1"]
    items = list(bounded_items(selected, archive_commitment=COMMITMENT, maximum_items=1))
    assert len(items) == 2
    assert items[0][0]["metadata"]["source_record_id"] == "owner-1"
    assert items[0][0]["metadata"]["archive_commitment"] == COMMITMENT
    assert items[1][0]["metadata"]["speaker_role"] == "assistant"
    assert "not Ray's endorsement" in items[1][0]["content"]
    assert items[0][0]["document_id"] != items[1][0]["document_id"]
    assert items[0][0]["timestamp"] == "2025-01-02T00:00:00+00:00"
    with pytest.raises(ValueError):
        hindsight_item(_message("alternate-1", displayed=False), archive_commitment=COMMITMENT)
