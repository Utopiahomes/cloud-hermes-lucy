from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid5

from lucy.chatgpt_manifest import (
    LocalChatGPTConversationV1,
    LocalChatGPTMessageV1,
    LocalPilotBuildV1,
    PilotManifestBundleV1,
    manifest_record_for_local_message,
)
from lucy.governed_memory import (
    CandidateStageResultV1,
    ImportArchiveResultV1,
    ImportAttemptResultV1,
    ImportCompletionResultV1,
    ImportJobResultV1,
)
from lucy.memory_extraction import (
    MemoryExtractionDispatchV1,
    MemoryExtractionProviderOutcomeV1,
)
from lucy.memory_import import ImportManifestV2, MemoryCandidatePayloadV1
from lucy.memory_pilot_runner import MemoryPilotRunner

NOW = datetime(2026, 9, 12, 12, 0, tzinfo=UTC)
CAMPAIGN = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SCOPE = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
RESERVATION = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")


def _build() -> LocalPilotBuildV1:
    message = LocalChatGPTMessageV1(
        source_record_id="conversation:node:message",
        conversation_id="conversation",
        native_node_id="node",
        native_message_id="message",
        parent_source_record_id=None,
        native_role="user",
        role="owner",
        occurred_at=NOW,
        displayed=True,
        content="Ray chose the café plan.",
        inclusion_state="included",
    )
    record = manifest_record_for_local_message(message, b"f" * 32)
    manifest = ImportManifestV2(
        campaign_id=CAMPAIGN,
        destination_content_scope_id=SCOPE,
        source_namespace="private/test",
        source_conversation_id="pilot",
        parser_version="parser-v1",
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="private-zdr-v1",
        model_route="openai/test",
        token_accounting_version="canonical-json-byte-upper-bound-v1",
        records=(record,),
        max_records=1,
        max_bytes=record.byte_length,
        max_source_estimated_tokens=record.estimated_tokens,
        max_request_input_tokens=100_000,
        max_request_output_tokens=200,
        max_request_total_tokens=100_200,
        max_model_spend_microusd=1_000,
        max_attempts=1,
        expires_at=NOW + timedelta(hours=1),
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
                conversation_id="conversation", messages=(message,)
            ),
        ),
    )


class Dependencies:
    def __init__(self) -> None:
        self.events: list[str] = []

    def preserve(self, manifest, record, request) -> ImportArchiveResultV1:
        self.events.append("archive")
        return ImportArchiveResultV1(
            evidence_id=uuid5(CAMPAIGN, f"evidence:{record.source_record_id}:r1"),
            representation_id=uuid5(CAMPAIGN, "representation"),
            replayed=False,
        )

    def reserve_attempt(self, *args, **kwargs) -> ImportAttemptResultV1:
        self.events.append("reserve")
        return ImportAttemptResultV1(reservation_id=RESERVATION, replayed=False)

    def register_job(self, **values) -> ImportJobResultV1:
        self.events.append("job")
        dispatch = values["dispatch"]
        assert isinstance(dispatch, MemoryExtractionDispatchV1)
        return ImportJobResultV1(
            extraction_job_id=dispatch.extraction_job_id, replayed=False
        )

    def require_eligible(self, **values) -> None:
        self.events.append(f"eligible:{values['phase']}")

    def infer(self, **values) -> MemoryExtractionProviderOutcomeV1:
        self.events.append("provider")
        dispatch = values["dispatch"]
        assert isinstance(dispatch, MemoryExtractionDispatchV1)
        return MemoryExtractionProviderOutcomeV1(
            output=json.dumps(
                {
                    "contract_version": "1",
                    "candidates": [
                        {
                            "subject": "Ray",
                            "predicate": "selected_plan",
                            "object": "Use the café plan",
                            "confidence_millionths": 900_000,
                            "memory_kind": "assertion",
                            "assertion_status": "decision",
                            "epistemic_status": "current",
                            "domain_tags": ["cloud-lucy"],
                            "sources": [
                                {
                                    "source_record_id": dispatch.source_record_ids[0],
                                    "exact_quote": "café",
                                }
                            ],
                        }
                    ],
                }
            ),
            billed_microusd=400,
            provider_policy_id="private-zdr-v1",
            model_route="openai/test",
            provider_reference_commitment="e" * 64,
        )

    def record(self, **values) -> MemoryExtractionProviderOutcomeV1:
        self.events.append("outcome")
        outcome = values["outcome"]
        assert isinstance(outcome, MemoryExtractionProviderOutcomeV1)
        return outcome

    def load(self, **values) -> MemoryExtractionProviderOutcomeV1 | None:
        self.events.append("outcome-load")
        return None

    def complete_success(
        self,
        reservation_id: UUID,
        *,
        candidates: tuple[MemoryCandidatePayloadV1, ...],
        billed_microusd: int,
    ) -> ImportCompletionResultV1:
        self.events.append("complete")
        return ImportCompletionResultV1(
            reservation_id=reservation_id,
            candidates=tuple(
                CandidateStageResultV1(
                    candidate_id=candidate.candidate_id,
                    candidate_version=candidate.candidate_version,
                    candidate_digest=candidate.digest,
                    replayed=False,
                )
                for candidate in candidates
            ),
            settlement_replayed=False,
        )

    def settle_attempt(self, *args, **kwargs) -> ImportAttemptResultV1:
        raise AssertionError("successful completion must settle atomically")


def test_runner_archives_then_executes_and_returns_only_review_artifact() -> None:
    dependencies = Dependencies()
    result = MemoryPilotRunner(
        archive=dependencies,
        accounting=dependencies,
        eligibility=dependencies,
        provider=dependencies,
        outcomes=dependencies,
        candidate_store=dependencies,
        now=lambda: NOW,
    ).run(
        _build(),
        fingerprint_key=b"f" * 32,
        maximum_microusd_per_attempt=1_000,
        timeout_seconds=30,
    )

    assert result.archived_source_count == 1
    assert len(result.batches) == 1
    batch = result.batches[0]
    assert batch.state == "succeeded" and batch.candidate_count == 1
    assert batch.review_artifact is not None
    assert batch.review_artifact.bundle.items[0].source_excerpts[0].exact_quote == "café"
    assert dependencies.events == [
        "archive",
        "eligible:admission",
        "reserve",
        "job",
        "eligible:pre_dispatch",
        "provider",
        "outcome",
        "eligible:post_dispatch",
        "complete",
    ]
