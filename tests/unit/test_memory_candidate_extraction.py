from __future__ import annotations

import json
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
from lucy.memory_candidate_extraction import (
    MemoryExtractionOutputV1,
    materialize_pending_candidates,
    parse_memory_extraction_output,
)
from lucy.memory_import import ImportManifestV1, ProtectionClass
from lucy.secret_filter import MemorySecretDetected

NOW = datetime(2026, 9, 12, 21, 0, tzinfo=UTC)
CAMPAIGN = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SCOPE = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
JOB = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
EVIDENCE = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")


def _build(content: str = "Ray chose the café plan.") -> LocalPilotBuildV1:
    message = LocalChatGPTMessageV1(
        source_record_id="conversation-1:node-1:message-1",
        conversation_id="conversation-1",
        native_node_id="node-1",
        native_message_id="message-1",
        parent_source_record_id=None,
        native_role="user",
        role="owner",
        occurred_at=NOW,
        displayed=True,
        content=content,
        inclusion_state="included",
    )
    record = manifest_record_for_local_message(message, b"f" * 32)
    manifest = ImportManifestV1(
        campaign_id=CAMPAIGN,
        destination_content_scope_id=SCOPE,
        source_namespace="raymond-private/chatgpt-export",
        source_conversation_id="pilot:selection",
        parser_version="chatgpt-export-inventory-v1",
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="policy-v1",
        model_route="openrouter/private-model",
        records=(record,),
        max_records=1,
        max_bytes=record.byte_length,
        max_input_tokens=record.estimated_tokens,
        max_model_spend_microusd=10_000,
        max_attempts=2,
        expires_at=NOW + timedelta(days=1),
    )
    return LocalPilotBuildV1(
        bundle=PilotManifestBundleV1(
            selection_proposal_digest="a" * 64,
            archive_commitment="b" * 64,
            campaign_id=CAMPAIGN,
            destination_content_scope_id=SCOPE,
            manifest=manifest,
            included_record_count=1,
            excluded_record_count=0,
            included_source_bytes=record.byte_length,
            estimated_source_tokens=record.estimated_tokens,
            excluded_attachment_reference_count=0,
        ),
        conversations=(
            LocalChatGPTConversationV1(
                conversation_id="conversation-1", messages=(message,)
            ),
        ),
    )


def _output(*, quote: str = "café", object_text: str = "Use the café plan") -> str:
    return json.dumps(
        {
            "contract_version": "1",
            "candidates": [
                {
                    "subject": "Ray",
                    "predicate": "selected_plan",
                    "object": object_text,
                    "confidence_millionths": 900_000,
                    "memory_kind": "assertion",
                    "assertion_status": "decision",
                    "epistemic_status": "current",
                    "domain_tags": ["cloud-lucy"],
                    "event_time": NOW.isoformat(),
                    "sources": [
                        {
                            "source_record_id": "conversation-1:node-1:message-1",
                            "exact_quote": quote,
                        }
                    ],
                }
            ],
        }
    )


def test_model_output_is_strict_and_size_bounded() -> None:
    parsed = parse_memory_extraction_output(_output())
    assert isinstance(parsed, MemoryExtractionOutputV1)
    with pytest.raises(ValueError, match="valid v1 contract"):
        parse_memory_extraction_output('{"candidates":[],"unexpected":true}')
    with pytest.raises(ValueError, match="size limit"):
        parse_memory_extraction_output("x" * 5_000_001)


def test_materialization_assigns_stable_id_and_exact_utf8_span() -> None:
    output = parse_memory_extraction_output(_output())
    first = materialize_pending_candidates(
        output,
        build=_build(),
        fingerprint_key=b"f" * 32,
        evidence_by_source_record_id={
            "conversation-1:node-1:message-1": EVIDENCE
        },
        extraction_job_id=JOB,
    )
    replay = materialize_pending_candidates(
        output,
        build=_build(),
        fingerprint_key=b"f" * 32,
        evidence_by_source_record_id={
            "conversation-1:node-1:message-1": EVIDENCE
        },
        extraction_job_id=JOB,
    )

    assert first == replay and len(first) == 1
    candidate = first[0]
    assert candidate.candidate_id == replay[0].candidate_id
    assert candidate.protection_class == ProtectionClass.PROTECTED
    assert candidate.manifest_digest == _build().bundle.manifest.digest
    assert candidate.sources[0].byte_start == len(b"Ray chose the ")
    assert candidate.sources[0].byte_end == len("Ray chose the café".encode())


def test_quote_must_be_unique_and_bound_to_archived_evidence() -> None:
    repeated = _build("café then café")
    with pytest.raises(ValueError, match="exactly once"):
        materialize_pending_candidates(
            parse_memory_extraction_output(_output()),
            build=repeated,
            fingerprint_key=b"f" * 32,
            evidence_by_source_record_id={
                "conversation-1:node-1:message-1": EVIDENCE
            },
            extraction_job_id=JOB,
        )
    with pytest.raises(ValueError, match="outside the exact archived manifest"):
        materialize_pending_candidates(
            parse_memory_extraction_output(_output()),
            build=_build(),
            fingerprint_key=b"f" * 32,
            evidence_by_source_record_id={},
            extraction_job_id=JOB,
        )


def test_candidate_secrets_are_quarantined_before_staging() -> None:
    output = parse_memory_extraction_output(
        _output(object_text="api key: synthetic-secret-value-12345")
    )
    with pytest.raises(MemorySecretDetected):
        materialize_pending_candidates(
            output,
            build=_build(),
            fingerprint_key=b"f" * 32,
            evidence_by_source_record_id={
                "conversation-1:node-1:message-1": EVIDENCE
            },
            extraction_job_id=JOB,
        )
