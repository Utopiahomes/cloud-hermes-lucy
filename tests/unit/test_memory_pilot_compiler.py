from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from lucy.chatgpt_manifest import (
    LocalChatGPTConversationV1,
    LocalChatGPTMessageV1,
    LocalPilotBuildV1,
    PilotManifestBundleV1,
    manifest_record_for_local_message,
)
from lucy.memory_import import ImportManifestV2
from lucy.memory_pilot_compiler import compile_memory_pilot_batches

NOW = datetime(2026, 9, 12, tzinfo=UTC)
CAMPAIGN = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SCOPE = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")


def _build(count: int, *, input_ceiling: int = 1_000_000) -> LocalPilotBuildV1:
    messages = tuple(
        LocalChatGPTMessageV1(
            source_record_id=f"conversation:node-{index}:message-{index}",
            conversation_id="conversation",
            native_node_id=f"node-{index}",
            native_message_id=f"message-{index}",
            parent_source_record_id=None,
            native_role="user",
            role="owner",
            occurred_at=NOW,
            displayed=True,
            content=f"Record {index}: " + ("private synthetic history " * 40),
            inclusion_state="included",
        )
        for index in range(count)
    )
    records = tuple(manifest_record_for_local_message(item, b"f" * 32) for item in messages)
    manifest = ImportManifestV2(
        campaign_id=CAMPAIGN,
        destination_content_scope_id=SCOPE,
        source_namespace="raymond-private/chatgpt-export",
        source_conversation_id="pilot:selection",
        parser_version="parser-v1",
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="private-zdr-v1",
        model_route="openai/gpt-oss-20b",
        token_accounting_version="canonical-json-byte-upper-bound-v1",
        records=records,
        max_records=count,
        max_bytes=sum(item.byte_length for item in records),
        max_source_estimated_tokens=sum(item.estimated_tokens for item in records),
        max_request_input_tokens=input_ceiling,
        max_request_output_tokens=200,
        max_request_total_tokens=input_ceiling + 200,
        max_model_spend_microusd=10_000,
        max_attempts=4,
        expires_at=NOW + timedelta(days=1),
    )
    return LocalPilotBuildV1(
        bundle=PilotManifestBundleV1(
            selection_proposal_digest="a" * 64,
            archive_commitment="b" * 64,
            campaign_id=CAMPAIGN,
            destination_content_scope_id=SCOPE,
            manifest=manifest,
            included_record_count=count,
            excluded_record_count=0,
            included_source_bytes=manifest.max_bytes,
            estimated_source_tokens=manifest.max_source_estimated_tokens,
            excluded_attachment_reference_count=0,
        ),
        conversations=(
            LocalChatGPTConversationV1(
                conversation_id="conversation", messages=messages
            ),
        ),
    )


def test_compiler_packs_deterministically_and_covers_every_source_once() -> None:
    one = compile_memory_pilot_batches(
        _build(1), maximum_microusd_per_attempt=1_000, timeout_seconds=30
    )
    two = compile_memory_pilot_batches(
        _build(2, input_ceiling=one.batches[0].input_tokens),
        maximum_microusd_per_attempt=1_000,
        timeout_seconds=30,
    )
    replay = compile_memory_pilot_batches(
        _build(2, input_ceiling=one.batches[0].input_tokens),
        maximum_microusd_per_attempt=1_000,
        timeout_seconds=30,
    )

    assert two == replay
    assert len(two.batches) == 2
    assert two.covered_source_record_ids == tuple(
        source for batch in two.batches for source in batch.source_record_ids
    )
    assert len(set(two.covered_source_record_ids)) == 2
    assert all(batch.input_tokens == batch.request_bytes for batch in two.batches)


def test_compiler_blocks_oversized_record_and_attempt_or_cost_expansion() -> None:
    base = _build(1)
    base_manifest = base.bundle.manifest
    assert isinstance(base_manifest, ImportManifestV2)
    tight = base.model_copy(
        update={
            "bundle": base.bundle.model_copy(
                update={
                    "manifest": base_manifest.model_copy(
                        update={
                            "max_request_input_tokens": (
                                base_manifest.max_source_estimated_tokens
                            ),
                            "max_request_total_tokens": (
                                base_manifest.max_source_estimated_tokens + 200
                            ),
                        }
                    )
                }
            )
        }
    )
    with pytest.raises(ValueError, match="one selected record exceeds"):
        compile_memory_pilot_batches(
            tight,
            maximum_microusd_per_attempt=1_000,
            timeout_seconds=30,
        )
    base_two = _build(2)
    limited = base_two.model_copy(
        update={
            "bundle": base_two.bundle.model_copy(
                update={
                    "manifest": base_two.bundle.manifest.model_copy(
                        update={"max_attempts": 1}
                    )
                }
            )
        }
    )
    one_size = compile_memory_pilot_batches(
        _build(1), maximum_microusd_per_attempt=1_000, timeout_seconds=30
    ).batches[0].input_tokens
    limited = limited.model_copy(
        update={
            "bundle": limited.bundle.model_copy(
                update={
                    "manifest": limited.bundle.manifest.model_copy(
                        update={
                            "max_request_input_tokens": one_size,
                            "max_request_total_tokens": one_size + 200,
                        }
                    )
                }
            )
        }
    )
    with pytest.raises(ValueError, match="attempt ceiling"):
        compile_memory_pilot_batches(
            limited, maximum_microusd_per_attempt=1_000, timeout_seconds=30
        )
    with pytest.raises(ValueError, match="campaign ceiling"):
        compile_memory_pilot_batches(
            _build(1), maximum_microusd_per_attempt=10_001, timeout_seconds=30
        )
