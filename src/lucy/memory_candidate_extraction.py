"""Turn untrusted extraction JSON into provenance-bound pending candidates."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field

from lucy.chatgpt_manifest import LocalPilotBuildV1, build_exact_archive_requests
from lucy.contracts.canonical import canonical_sha256
from lucy.memory_candidate_review import (
    CandidateReviewBundleArtifactV1,
    CandidateReviewBundleV1,
    CandidateReviewItemV1,
    CandidateReviewSourceExcerptV1,
)
from lucy.memory_import import (
    AssertionStatus,
    EpistemicStatus,
    MemoryCandidatePayloadV1,
    MemoryKind,
    ProtectionClass,
    SourceSpanV1,
)
from lucy.secret_filter import MemorySecretDetected, detect_memory_secrets

_DRAFT_PREFIX = b"LUCY-MEMORY-EXTRACTION-DRAFT-V1\x00"


class ExtractedSourceQuoteV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_record_id: str = Field(min_length=1, max_length=512)
    exact_quote: str = Field(min_length=1, max_length=16_384)


class ExtractedCandidateDraftV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    subject: str = Field(min_length=1, max_length=200)
    predicate: str = Field(min_length=1, max_length=200)
    object: str = Field(min_length=1, max_length=4_000)
    confidence_millionths: int = Field(ge=0, le=1_000_000)
    memory_kind: MemoryKind
    assertion_status: AssertionStatus
    epistemic_status: EpistemicStatus
    domain_tags: tuple[str, ...] = Field(default=(), max_length=16)
    event_time: datetime | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    sources: tuple[ExtractedSourceQuoteV1, ...] = Field(min_length=1, max_length=32)


class MemoryExtractionOutputV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: str = Field(default="1", pattern=r"^1$")
    candidates: tuple[ExtractedCandidateDraftV1, ...] = Field(max_length=200)


def parse_memory_extraction_output(raw: str) -> MemoryExtractionOutputV1:
    if not raw or len(raw.encode("utf-8")) > 5_000_000:
        raise ValueError("memory extraction output is outside its size limit")
    try:
        return MemoryExtractionOutputV1.model_validate_json(raw)
    except Exception as exc:
        raise ValueError("memory extraction output is not a valid v1 contract") from exc


def materialize_pending_candidates(
    output: MemoryExtractionOutputV1,
    *,
    build: LocalPilotBuildV1,
    fingerprint_key: bytes,
    evidence_by_source_record_id: dict[str, UUID],
    extraction_job_id: UUID,
) -> tuple[MemoryCandidatePayloadV1, ...]:
    """Verify exact quotes and create protected candidate versions without approval."""

    build_exact_archive_requests(build, fingerprint_key=fingerprint_key)
    manifest = build.bundle.manifest
    local_messages = {
        message.source_record_id: message
        for conversation in build.conversations
        for message in conversation.messages
    }
    manifest_records = {
        record.source_record_id: record
        for record in manifest.records
        if record.included
    }
    candidates: list[MemoryCandidatePayloadV1] = []
    for index, draft in enumerate(output.candidates):
        findings = detect_memory_secrets(draft.subject, draft.predicate, draft.object)
        if findings:
            raise MemorySecretDetected(tuple(item.category for item in findings))
        spans: list[SourceSpanV1] = []
        for source in draft.sources:
            message = local_messages.get(source.source_record_id)
            record = manifest_records.get(source.source_record_id)
            evidence_id = evidence_by_source_record_id.get(source.source_record_id)
            if (
                message is None
                or message.content is None
                or record is None
                or evidence_id is None
            ):
                raise ValueError("candidate source is outside the exact archived manifest")
            content = message.content.encode("utf-8")
            quote = source.exact_quote.encode("utf-8")
            start = content.find(quote)
            if start < 0 or content.find(quote, start + 1) >= 0:
                raise ValueError("candidate quote must occur exactly once in its source")
            spans.append(
                SourceSpanV1(
                    source_record_id=record.source_record_id,
                    evidence_id=evidence_id,
                    record_version=record.source_revision,
                    byte_start=start,
                    byte_end=start + len(quote),
                )
            )
        draft_digest = canonical_sha256(draft, prefix=_DRAFT_PREFIX)
        candidates.append(
            MemoryCandidatePayloadV1(
                candidate_id=uuid5(
                    extraction_job_id, f"candidate:{index}:{draft_digest}"
                ),
                candidate_version=1,
                campaign_id=manifest.campaign_id,
                manifest_digest=manifest.digest,
                extraction_job_id=extraction_job_id,
                extractor_version=manifest.extractor_version,
                prompt_version=manifest.prompt_version,
                model_route=manifest.model_route,
                destination_content_scope_id=manifest.destination_content_scope_id,
                subject=draft.subject,
                predicate=draft.predicate,
                object=draft.object,
                confidence_millionths=draft.confidence_millionths,
                memory_kind=draft.memory_kind,
                assertion_status=draft.assertion_status,
                epistemic_status=draft.epistemic_status,
                protection_class=ProtectionClass.PROTECTED,
                domain_tags=draft.domain_tags,
                event_time=draft.event_time,
                valid_from=draft.valid_from,
                valid_to=draft.valid_to,
                sources=tuple(spans),
            )
        )
    return tuple(candidates)


def build_candidate_review_artifact(
    output: MemoryExtractionOutputV1,
    candidates: tuple[MemoryCandidatePayloadV1, ...],
) -> CandidateReviewBundleArtifactV1:
    """Bind verified model quotes to the exact candidates displayed for review."""

    if not candidates or len(output.candidates) != len(candidates):
        raise ValueError("review candidates do not match the extraction output")
    items: list[CandidateReviewItemV1] = []
    for draft, candidate in zip(output.candidates, candidates, strict=True):
        if len(draft.sources) != len(candidate.sources):
            raise ValueError("review excerpts do not match candidate provenance")
        excerpts: list[CandidateReviewSourceExcerptV1] = []
        for extracted, source in zip(draft.sources, candidate.sources, strict=True):
            if extracted.source_record_id != source.source_record_id:
                raise ValueError("review excerpt source does not match candidate provenance")
            excerpts.append(
                CandidateReviewSourceExcerptV1(
                    source_record_id=source.source_record_id,
                    evidence_id=source.evidence_id,
                    record_version=source.record_version,
                    byte_start=source.byte_start,
                    byte_end=source.byte_end,
                    exact_quote=extracted.exact_quote,
                )
            )
        items.append(
            CandidateReviewItemV1(
                candidate=candidate,
                candidate_digest=candidate.digest,
                source_excerpts=tuple(excerpts),
            )
        )
    bundle = CandidateReviewBundleV1(
        campaign_id=candidates[0].campaign_id,
        destination_content_scope_id=candidates[0].destination_content_scope_id,
        items=tuple(items),
    )
    return CandidateReviewBundleArtifactV1(bundle=bundle, bundle_digest=bundle.digest)
