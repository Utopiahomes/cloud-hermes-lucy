from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from lucy.memory_import import ImportManifestRecordV1, MemoryCandidatePayloadV1, SourceSpanV1
from lucy.memory_interpretation import (
    ConfirmationScope,
    CurrentApplicability,
    EvidenceRelation,
    IndependentAssessmentsV1,
    InterpretationEvidenceV1,
    InterpretationRecordV1,
    InterpretationVersionV1,
    Speaker,
    SpeechAct,
)
from lucy.memory_interpretation_promotion import build_interpreted_candidate

OWNER_ID = "conversation:owner-turn"
ASSISTANT_ID = "conversation:assistant-turn"
NOW = datetime(2026, 9, 23, tzinfo=UTC)


def _assessments() -> IndependentAssessmentsV1:
    return IndependentAssessmentsV1(
        support="Owner confirmed the first tag; the second tag remains ambiguous.",
        counterevidence="No later deck map was searched.",
        owner_endorsement="Explicit for the first tag; unclear for the second.",
        present_applicability="Not checked against the current deck.",
        remembering_value="Explains the deck design history.",
    )


def _evidence() -> tuple[InterpretationEvidenceV1, ...]:
    return (
        InterpretationEvidenceV1(
            source_record_id=OWNER_ID, role=Speaker.OWNER,
            relation=EvidenceRelation.PRIMARY,
            exact_excerpt="The first tag is Trial Gate.", occurred_at=NOW,
        ),
        InterpretationEvidenceV1(
            source_record_id=ASSISTANT_ID, role=Speaker.ASSISTANT,
            relation=EvidenceRelation.NEIGHBOR,
            exact_excerpt="What about Guardian Locked as a second tag?", occurred_at=NOW,
        ),
    )


def _version(**changes: object) -> InterpretationVersionV1:
    data = {
        "version": 1,
        "statement": "Ray agreed to Trial Gate as the first tag.",
        "material_qualifiers": (
            "Guardian Locked was discussed but its confirmation scope is unclear.",
        ),
        "source_utterance_at": NOW,
        "applicable_period": "September 2026 design session",
        "reassessed_at": NOW,
        "speech_act": SpeechAct.DECISION,
        "proposer": Speaker.OWNER,
        "confirmation_scope": ConfirmationScope.AMBIGUOUS,
        "confirmed_proposition": "Trial Gate first; second tag unresolved",
        "current_applicability": CurrentApplicability.NOT_CHECKED,
        "assessments": _assessments(),
        "evidence": _evidence(),
        "revision_reason": "Initial contextual interpretation",
    }
    data.update(changes)
    return InterpretationVersionV1.model_validate(data)


def test_historical_recall_keeps_material_uncertainty_without_current_status_noise() -> None:
    version = _version()
    historical = version.compact_recall(question_is_current=False)
    current = version.compact_recall(question_is_current=True)
    assert "Trial Gate" in historical
    assert "scope is unclear" in historical
    assert "Current applicability" not in historical
    assert current.endswith("Current applicability has not been checked.")


def test_owner_confirmation_cannot_be_inferred_from_assistant_evidence() -> None:
    with pytest.raises(ValidationError, match="owner confirmation needs owner evidence"):
        _version(evidence=(_evidence()[1],), proposer=Speaker.ASSISTANT)


def test_exact_date_attribution_must_match_the_cited_speaker() -> None:
    with pytest.raises(ValidationError, match="exact date attribution differs"):
        _version(exact_date_stated_by=Speaker.OWNER,
                 exact_date_source_record_id=ASSISTANT_ID)
    version = _version(exact_date_stated_by=Speaker.ASSISTANT,
                       exact_date_source_record_id=ASSISTANT_ID)
    assert version.exact_date_stated_by == Speaker.ASSISTANT


def test_answer_context_exposes_attribution_and_confirmation_scope() -> None:
    version = _version(exact_date_stated_by=Speaker.ASSISTANT,
                       exact_date_source_record_id=ASSISTANT_ID)
    context = version.answer_context(question_is_current=False)
    assert context["confirmation_scope"] == "ambiguous"
    assert context["proposer"] == "owner"
    assert context["exact_date_stated_by"] == "assistant"
    assert context["exact_date_source_record_id"] == ASSISTANT_ID
    assert "state in the source exchange" in str(context["temporal_boundary"])
    assert "Current applicability" not in str(context["historical_interpretation"])
    current = version.answer_context(question_is_current=True)
    assert "Current applicability has not been checked" in str(
        current["historical_interpretation"]
    )


def test_revision_preserves_history_and_separate_assessments() -> None:
    record = InterpretationRecordV1(
        candidate_id=UUID("00000000-0000-4000-8000-000000000001"),
        candidate_version=1,
        versions=(_version(),),
    )
    revision = record.current.model_copy(update={
        "version": 2,
        "statement": "A later owner correction changed the first tag to Blueprint Echo.",
        "current_applicability": CurrentApplicability.SUPPORTED,
        "assessments": record.current.assessments.model_copy(update={
            "present_applicability": "Owner correction supports current use.",
        }),
        "revision_reason": "Explicit later owner correction",
    })
    updated = record.with_revision(revision)
    assert record.current.version == 1
    assert updated.versions[0] == record.versions[0]
    assert updated.current.version == 2
    assert updated.current.assessments.support == record.current.assessments.support
    assert (
        updated.current.assessments.present_applicability
        != record.current.assessments.present_applicability
    )


def test_duplicate_evidence_and_nonconsecutive_versions_fail_closed() -> None:
    with pytest.raises(ValidationError, match="evidence source IDs must be unique"):
        _version(evidence=(*_evidence(), _evidence()[0]))
    with pytest.raises(ValidationError, match="consecutive"):
        InterpretationRecordV1(
            candidate_id=UUID("00000000-0000-4000-8000-000000000001"),
            candidate_version=1,
            versions=(_version(), _version(version=3)),
        )


def test_review_projection_creates_historical_version_with_neighbor_source() -> None:
    candidate_id = UUID("00000000-0000-4000-8000-000000000001")
    campaign_id = UUID("00000000-0000-4000-8000-000000000002")
    primary_id = UUID("00000000-0000-4000-8000-000000000003")
    original = MemoryCandidatePayloadV1(
        candidate_id=candidate_id, candidate_version=1,
        campaign_id=campaign_id, manifest_digest="a" * 64,
        extraction_job_id=UUID("00000000-0000-4000-8000-000000000004"),
        extractor_version="x", prompt_version="p", model_route="m",
        destination_content_scope_id=UUID("00000000-0000-4000-8000-000000000005"),
        subject="The Gate", predicate="has tags", object="Trial Gate and Guardian Locked",
        confidence_millionths=900_000, memory_kind="assertion",
        assertion_status="decision", epistemic_status="current",
        sources=(SourceSpanV1(source_record_id=OWNER_ID, evidence_id=primary_id,
                              record_version=1, byte_start=0, byte_end=30),),
    )
    record = InterpretationRecordV1(
        candidate_id=candidate_id, candidate_version=1, versions=(_version(),)
    )
    manifest = {
        OWNER_ID: ImportManifestRecordV1(
            source_record_id=OWNER_ID, content_commitment="b" * 64,
            byte_length=30, estimated_tokens=5, source_revision=1,
            role="owner", displayed=True,
        ),
        ASSISTANT_ID: ImportManifestRecordV1(
            source_record_id=ASSISTANT_ID, content_commitment="c" * 64,
            byte_length=80, estimated_tokens=12, source_revision=1,
            role="assistant", displayed=True,
        ),
    }
    promoted = build_interpreted_candidate(original, record, manifest)
    body = json.loads(promoted.object)
    assert promoted.candidate_version == 2
    assert promoted.epistemic_status == "historical"
    assert promoted.assertion_status == "attributed_interpretation"
    assert body["interpretation"]["confirmation_scope"] == "ambiguous"
    assert len(promoted.sources) == 2
    assert promoted.sources[0].evidence_id == primary_id
    assert promoted.sources[1].source_record_id == ASSISTANT_ID
    with pytest.raises(ValueError, match="outside the authorized manifest"):
        build_interpreted_candidate(original, record, {OWNER_ID: manifest[OWNER_ID]})
