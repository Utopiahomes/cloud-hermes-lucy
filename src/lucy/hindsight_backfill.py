"""Source-linked historical documents for the approved ChatGPT backfill.

This is a transport adapter, not a second memory engine. The protected export,
reviewed interpretations, corrections, and deletion ledger remain authoritative.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from hashlib import sha256
from typing import Any

from lucy.chatgpt_manifest import LocalChatGPTConversationV1, LocalChatGPTMessageV1


def eligible_messages(
    conversations: Iterable[LocalChatGPTConversationV1],
    *,
    deleted_source_ids: frozenset[str] = frozenset(),
) -> Iterator[LocalChatGPTMessageV1]:
    """Select the displayed, supported history without restoring deleted sources."""

    seen: set[str] = set()
    for conversation in conversations:
        for message in conversation.messages:
            if (message.inclusion_state != "included" or not message.displayed
                    or message.source_record_id in deleted_source_ids):
                continue
            if message.source_record_id in seen:
                raise ValueError("duplicate ChatGPT source record ID")
            seen.add(message.source_record_id)
            yield message


def hindsight_item(
    message: LocalChatGPTMessageV1, *, archive_commitment: str,
) -> dict[str, Any]:
    """Represent a dated utterance as evidence, never as a current Ray belief."""

    if (message.inclusion_state != "included" or not message.displayed
            or not message.content or message.role == "unsupported"):
        raise ValueError("message is not eligible for Hindsight")
    if len(archive_commitment) != 64 or any(
        character not in "0123456789abcdef" for character in archive_commitment
    ):
        raise ValueError("source archive commitment is invalid")
    speaker = {
        "owner": "Ray",
        "assistant": "ChatGPT assistant",
        "system": "ChatGPT system",
    }[message.role]
    when = message.occurred_at.isoformat() if message.occurred_at else "date unavailable"
    content = (
        "Historical ChatGPT conversation evidence. This records a past utterance, "
        "not a verified present-day belief or decision. Assistant text is a "
        "suggestion or response, not Ray's endorsement.\n"
        f"Speaker: {speaker}. Historical timestamp: {when}.\n"
        f"Source record ID: {message.source_record_id}.\n"
        f"Utterance: {message.content}"
    )
    item: dict[str, Any] = {
        "document_id": "lucy-chatgpt:" + sha256(
            f"{message.source_record_id}:r{message.source_revision}".encode()
        ).hexdigest(),
        "content": content,
        "context": "Dated source evidence from Ray's approved ChatGPT export",
        "update_mode": "replace",
        "metadata": {
            "source": "approved_chatgpt_export",
            "archive_commitment": archive_commitment,
            "source_record_id": message.source_record_id,
            "source_conversation_id": message.conversation_id,
            "source_revision": str(message.source_revision),
            "speaker_role": message.role,
            "attribution": "historical_utterance",
        },
    }
    if message.occurred_at:
        item["timestamp"] = message.occurred_at.isoformat()
    return item


def bounded_items(
    messages: Iterable[LocalChatGPTMessageV1],
    *,
    archive_commitment: str,
    maximum_items: int = 1,
    maximum_content_bytes: int = 100_000,
) -> Iterator[tuple[dict[str, Any], ...]]:
    """Pack stable documents into small Hindsight retain requests."""

    if maximum_items < 1 or maximum_content_bytes < 1:
        raise ValueError("backfill batch bounds must be positive")
    batch: list[dict[str, Any]] = []
    size = 0
    for message in messages:
        item = hindsight_item(message, archive_commitment=archive_commitment)
        item_size = len(item["content"].encode("utf-8"))
        if item_size > maximum_content_bytes:
            raise ValueError("one source record exceeds the Hindsight batch bound")
        if batch and (len(batch) >= maximum_items
                      or size + item_size > maximum_content_bytes):
            yield tuple(batch)
            batch = []
            size = 0
        batch.append(item)
        size += item_size
    if batch:
        yield tuple(batch)
