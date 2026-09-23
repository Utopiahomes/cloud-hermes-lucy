from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4, uuid5

import pytest

from lucy.chatgpt_manifest import (
    AuthorizedPilotManifestV1,
    LocalChatGPTConversationV1,
    LocalChatGPTMessageV1,
    LocalPilotBuildV1,
    PilotManifestBundleV1,
    build_exact_archive_requests,
    manifest_record_for_local_message,
)
from lucy.governed_memory import (
    CandidateStageResultV1,
    ImportArchiveResultV1,
    ImportAttemptResultV1,
    ImportCompletionResultV1,
    ImportJobResultV1,
)
from lucy.memory_candidate_extraction import (
    ExtractedCandidateDraftV1,
    ExtractedSourceQuoteV1,
    MemoryExtractionOutputV1,
    materialize_verified_pending_candidates,
)
from lucy.memory_extraction import MemoryExtractionProviderOutcomeV1
from lucy.memory_import import ImportManifestV2, MemoryCandidatePayloadV1
from lucy.memory_pilot_transport import (
    AdmittedMemoryPilotTransportBatch,
    MemoryPilotTransportAdmissionReceiptV1,
    prepare_memory_pilot_transport,
)
from lucy.memory_pilot_transport_runner import (
    DeterministicFakeMemoryImportProvider,
    VerifiedMemoryPilotBatchExecutor,
    build_transport_archive_request,
)

NOW = datetime(2026, 9, 13, 12, tzinfo=UTC)
CAMPAIGN = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SCOPE = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
RESERVATION = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")


def _prepared():
    messages = tuple(
        LocalChatGPTMessageV1(
            source_record_id=f"conversation-{index}:node:message",
            conversation_id=f"conversation-{index}",
            native_node_id="node",
            native_message_id="message",
            parent_source_record_id=None,
            native_role="user",
            role="owner",
            occurred_at=NOW,
            displayed=True,
            content=f"Ray selected synthetic plan {index}.",
            inclusion_state="included",
        )
        for index in range(2)
    )
    records = tuple(manifest_record_for_local_message(item, b"f" * 32) for item in messages)
    manifest = ImportManifestV2(
        campaign_id=CAMPAIGN,
        destination_content_scope_id=SCOPE,
        source_namespace="synthetic/transport-execution",
        source_conversation_id="pilot-selection",
        parser_version="parser-v1",
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="local-synthetic-only",
        model_route="none",
        token_accounting_version="canonical-json-byte-upper-bound-v1",
        records=records,
        max_records=2,
        max_bytes=sum(item.byte_length for item in records),
        max_source_estimated_tokens=sum(item.estimated_tokens for item in records),
        max_request_input_tokens=10_000,
        max_request_output_tokens=200,
        max_request_total_tokens=10_200,
        max_model_spend_microusd=0,
        max_attempts=1,
        expires_at=NOW + timedelta(hours=1),
    )
    bundle = PilotManifestBundleV1(
        selection_proposal_digest="a" * 64,
        archive_commitment="b" * 64,
        campaign_id=CAMPAIGN,
        destination_content_scope_id=SCOPE,
        manifest=manifest,
        included_record_count=2,
        excluded_record_count=0,
        included_source_bytes=manifest.max_bytes,
        estimated_source_tokens=manifest.max_source_estimated_tokens,
        excluded_attachment_reference_count=0,
    )
    build = LocalPilotBuildV1(
        bundle=bundle,
        conversations=tuple(
            LocalChatGPTConversationV1(
                conversation_id=message.conversation_id, messages=(message,)
            )
            for message in messages
        ),
    )
    authorization = AuthorizedPilotManifestV1(
        bundle=bundle,
        bundle_digest=bundle.digest,
        owner_approval_ref=uuid4(),
        owner_actor_id="synthetic-owner",
        approved_at=NOW - timedelta(minutes=1),
    )
    prepared = prepare_memory_pilot_transport(
        build,
        authorization,
        expected_bundle_digest=bundle.digest,
        transfer_key=b"t" * 32,
        capability_token=b"c" * 32,
        maximum_microusd_per_attempt=0,
        timeout_seconds=30,
        expires_at=NOW + timedelta(minutes=30),
        now=NOW,
    )
    return prepared, manifest, build, authorization


class Dependencies:
    def __init__(
        self,
        manifest: ImportManifestV2,
        authorization: AuthorizedPilotManifestV1,
        *,
        fail_second_archive_once: bool = False,
    ) -> None:
        self.manifest = manifest
        self.authorization = authorization
        self.events: list[str] = []
        self.archived: set[str] = set()
        self.reserved = False
        self.job = False
        self.outcome: MemoryExtractionProviderOutcomeV1 | None = None
        self.provider_calls = 0
        self.fail_second_archive_once = fail_second_archive_once

    def admit_for_execution(self, batch, *, capability_token: bytes):
        assert capability_token == b"c" * 32
        self.events.append("admit")
        return AdmittedMemoryPilotTransportBatch(
            receipt=MemoryPilotTransportAdmissionReceiptV1(
                batch_id=batch.batch_id, admitted_at=NOW, replayed=True
            ),
            authorization=self.authorization,
            manifest=self.manifest,
            batch=batch,
        )

    def preserve(self, manifest, record, request) -> ImportArchiveResultV1:
        assert request.source_conversation_id.startswith("conversation-")
        if (
            self.fail_second_archive_once
            and len(self.archived) == 1
            and record.source_record_id not in self.archived
        ):
            self.fail_second_archive_once = False
            raise RuntimeError("synthetic archive interruption")
        replayed = record.source_record_id in self.archived
        self.archived.add(record.source_record_id)
        self.events.append("archive-replay" if replayed else "archive")
        evidence = uuid5(CAMPAIGN, f"evidence:{record.source_record_id}:r1")
        return ImportArchiveResultV1(
            evidence_id=evidence,
            representation_id=uuid5(CAMPAIGN, f"representation:{evidence}"),
            replayed=replayed,
        )

    def reserve_attempt(self, *args, **kwargs) -> ImportAttemptResultV1:
        replayed, self.reserved = self.reserved, True
        return ImportAttemptResultV1(reservation_id=RESERVATION, replayed=replayed)

    def register_job(self, **values) -> ImportJobResultV1:
        replayed, self.job = self.job, True
        return ImportJobResultV1(
            extraction_job_id=values["dispatch"].extraction_job_id, replayed=replayed
        )

    def require_eligible(self, **kwargs) -> None:
        self.events.append(f"eligible:{kwargs['phase']}")

    def infer(self, **kwargs) -> MemoryExtractionProviderOutcomeV1:
        self.provider_calls += 1
        return DeterministicFakeMemoryImportProvider(
            MemoryExtractionOutputV1(
                candidates=(
                    ExtractedCandidateDraftV1(
                        subject="Ray",
                        predicate="selected_plan",
                        object="synthetic plan 0",
                        confidence_millionths=900_000,
                        memory_kind="assertion",
                        assertion_status="decision",
                        epistemic_status="current",
                        domain_tags=("synthetic",),
                        sources=(
                            ExtractedSourceQuoteV1(
                                source_record_id="conversation-0:node:message",
                                exact_quote="synthetic plan 0",
                            ),
                        ),
                    ),
                )
            )
        ).infer(**kwargs)

    def record(self, **values) -> MemoryExtractionProviderOutcomeV1:
        self.outcome = values["outcome"]
        return self.outcome

    def load(self, **kwargs) -> MemoryExtractionProviderOutcomeV1 | None:
        return self.outcome

    def complete_success(
        self,
        reservation_id: UUID,
        *,
        candidates: tuple[MemoryCandidatePayloadV1, ...],
        billed_microusd: int,
    ) -> ImportCompletionResultV1:
        assert billed_microusd == 0
        return ImportCompletionResultV1(
            reservation_id=reservation_id,
            candidates=tuple(
                CandidateStageResultV1(
                    candidate_id=item.candidate_id,
                    candidate_version=item.candidate_version,
                    candidate_digest=item.digest,
                    replayed=self.job,
                )
                for item in candidates
            ),
            settlement_replayed=self.job,
        )

    def settle_attempt(self, *args, **kwargs) -> ImportAttemptResultV1:
        raise AssertionError("successful completion settles atomically")


def test_verified_transport_executes_and_replays_without_second_provider_call() -> None:
    prepared, exact_manifest, _build, authorization = _prepared()
    batch = prepared.batches[0]
    manifest = prepared.registration
    dependencies = Dependencies(exact_manifest, authorization)
    executor = VerifiedMemoryPilotBatchExecutor(
        admission=dependencies,
        archive=dependencies,
        accounting=dependencies,
        eligibility=dependencies,
        provider=dependencies,
        outcomes=dependencies,
        outcome_recovery=dependencies,
        candidate_store=dependencies,
        now=lambda: NOW,
    )

    first = executor.execute(batch, capability_token=b"c" * 32)
    replay = executor.execute(batch, capability_token=b"c" * 32)

    assert manifest.campaign_id == first.receipt.campaign_id
    assert first.receipt.state == replay.receipt.state == "succeeded"
    assert first.receipt.candidate_count == replay.receipt.candidate_count == 1
    assert first.review_artifact == replay.review_artifact
    assert dependencies.provider_calls == 1
    assert dependencies.events.count("archive") == len(batch.records)
    assert dependencies.events.count("archive-replay") == len(batch.records)
    serialized_status = first.receipt.model_dump_json()
    assert "Ray selected" not in serialized_status


def test_transport_keeps_exactly_quoted_candidates_when_another_draft_is_invalid() -> None:
    prepared, manifest, _build, authorization = _prepared()
    batch = prepared.batches[0]
    dependencies = Dependencies(manifest, authorization)
    valid = MemoryExtractionOutputV1.model_validate_json(
        dependencies.infer(manifest=manifest, dispatch=batch.dispatch).output
    ).candidates[0]
    invalid = valid.model_copy(
        update={
            "sources": (
                ExtractedSourceQuoteV1(
                    source_record_id=valid.sources[0].source_record_id,
                    exact_quote="paraphrased, absent quote",
                ),
            )
        }
    )
    dependencies.infer = lambda **kwargs: DeterministicFakeMemoryImportProvider(
        MemoryExtractionOutputV1(candidates=(invalid, valid))
    ).infer(**kwargs)
    executor = VerifiedMemoryPilotBatchExecutor(
        admission=dependencies,
        archive=dependencies,
        accounting=dependencies,
        eligibility=dependencies,
        provider=dependencies,
        outcomes=dependencies,
        outcome_recovery=dependencies,
        candidate_store=dependencies,
        now=lambda: NOW,
    )

    result = executor.execute(batch, capability_token=b"c" * 32)

    assert result.receipt.state == "succeeded"
    assert result.receipt.candidate_count == 1
    assert result.review_artifact is not None
    assert len(result.review_artifact.bundle.items) == 1


def test_partial_archive_retry_reuses_first_record_and_calls_provider_once() -> None:
    prepared, manifest, _build, authorization = _prepared()
    batch = prepared.batches[0]
    dependencies = Dependencies(
        manifest, authorization, fail_second_archive_once=True
    )
    executor = VerifiedMemoryPilotBatchExecutor(
        admission=dependencies,
        archive=dependencies,
        accounting=dependencies,
        eligibility=dependencies,
        provider=dependencies,
        outcomes=dependencies,
        outcome_recovery=dependencies,
        candidate_store=dependencies,
        now=lambda: NOW,
    )

    with pytest.raises(RuntimeError, match="archive interruption"):
        executor.execute(batch, capability_token=b"c" * 32)
    completed = executor.execute(batch, capability_token=b"c" * 32)

    assert completed.receipt.state == "succeeded"
    assert dependencies.provider_calls == 1
    assert dependencies.events.count("archive-replay") == 1


def test_transport_archive_requests_equal_verified_local_requests() -> None:
    prepared, manifest, build, _authorization = _prepared()
    local = {
        request.source_turn_id: request
        for request in build_exact_archive_requests(build, fingerprint_key=b"f" * 32)
    }
    manifest_records = {item.source_record_id: item for item in manifest.records}

    for batch in prepared.batches:
        for supplied in batch.records:
            request = build_transport_archive_request(
                manifest, manifest_records[supplied.source_record_id], supplied
            )
            assert request == local[supplied.source_record_id]


def test_materializer_rejects_quote_from_another_batch() -> None:
    prepared, manifest, _build, _authorization = _prepared()
    batch = prepared.batches[0]
    other_source = manifest.records[-1].source_record_id
    with pytest.raises(ValueError, match="outside the exact archived manifest"):
        materialize_verified_pending_candidates(
            MemoryExtractionOutputV1(
                candidates=(
                    ExtractedCandidateDraftV1(
                        subject="Ray",
                        predicate="selected_plan",
                        object="synthetic",
                        confidence_millionths=500_000,
                        memory_kind="assertion",
                        assertion_status="report",
                        epistemic_status="current",
                        sources=(
                            ExtractedSourceQuoteV1(
                                source_record_id=other_source,
                                exact_quote="synthetic plan 1",
                            ),
                        ),
                    ),
                )
            ),
            manifest=manifest,
            plaintext_by_source_record_id={other_source: "Ray selected synthetic plan 1."},
            permitted_source_record_ids=frozenset(
                {batch.dispatch.source_record_ids[0]}
            ),
            evidence_by_source_record_id={other_source: uuid4()},
            extraction_job_id=batch.dispatch.extraction_job_id,
        )
