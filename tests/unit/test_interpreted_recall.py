from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import UUID, uuid5

import pytest
from pydantic import ValidationError

from lucy.governed_memory import GovernedMemoryClaimV1
from lucy.interpreted_recall import (
    prepare_interpreted_answer_context,
    recall_interpreted_answer_context,
)

CAMPAIGN = UUID("00000000-0000-4000-8000-000000000001")
OWNER_ID = "chat:owner"
ASSISTANT_ID = "chat:assistant"


def _claim() -> GovernedMemoryClaimV1:
    body = {
        "kind": "lucy_versioned_interpretation_v1",
        "source_candidate_version": 1,
        "source_candidate_digest": "a" * 64,
        "interpretation": {
            "version": 1,
            "statement": "Ray agreed to the first tag in a past design conversation.",
            "material_qualifiers": ["The second tag remained uncertain."],
            "source_utterance_at": datetime(2026, 9, 22, tzinfo=UTC).isoformat(),
            "applicable_period": "That design conversation",
            "reassessed_at": datetime(2026, 9, 23, tzinfo=UTC).isoformat(),
            "speech_act": "decision",
            "proposer": "owner",
            "confirmation_scope": "partial",
            "confirmed_proposition": "First tag only",
            "exact_date_stated_by": "assistant",
            "exact_date_source_record_id": ASSISTANT_ID,
            "current_applicability": "not_checked",
            "assessments": {
                "support": "Owner source supports the first tag.",
                "counterevidence": "No later deck was checked.",
                "owner_endorsement": "Only the first tag is endorsed.",
                "present_applicability": "Unknown today.",
                "remembering_value": "Useful design history.",
            },
            "revision_reason": "Contextual review",
        },
        "evidence_refs": [
            {"source_record_id": OWNER_ID, "role": "owner", "relation": "primary"},
            {"source_record_id": ASSISTANT_ID, "role": "assistant", "relation": "neighbor"},
        ],
    }
    return GovernedMemoryClaimV1(
        claim_id=UUID("00000000-0000-4000-8000-000000000002"),
        candidate_id=UUID("00000000-0000-4000-8000-000000000003"),
        candidate_version=2,
        subject="The Gate",
        predicate="historical_interpretation",
        object=json.dumps(body),
        confidence_millionths=900_000,
        status="active",
        protection_class="protected",
        memory_kind="assertion",
        assertion_status="attributed_interpretation",
        epistemic_status="historical",
        domain_tags=(),
        source_evidence_ids=tuple(
            uuid5(CAMPAIGN, f"evidence:{source}:r1")
            for source in (OWNER_ID, ASSISTANT_ID)
        ),
    )


def test_cited_context_preserves_historical_boundary_and_exact_speaker() -> None:
    claim = _claim()
    historical = prepare_interpreted_answer_context(
        claim, campaign_id=CAMPAIGN, question_is_current=False
    )
    current = prepare_interpreted_answer_context(
        claim, campaign_id=CAMPAIGN, question_is_current=True
    )
    assert historical.confirmation_scope == "partial"
    assert historical.exact_date_stated_by == "assistant"
    assert historical.exact_date_source_label == "E2"
    assert [cite.evidence_id for cite in historical.citations] == list(claim.source_evidence_ids)
    assert "Current applicability" not in historical.historical_interpretation
    assert current.historical_interpretation.endswith("Current applicability has not been checked.")
    assert "present status is unverified" in str(current.temporal_boundary)


def test_citation_mismatch_and_unprotected_claim_fail_closed() -> None:
    claim = _claim()
    with pytest.raises(ValueError, match="citations differ"):
        prepare_interpreted_answer_context(
            claim.model_copy(update={"source_evidence_ids": (claim.source_evidence_ids[0],)}),
            campaign_id=CAMPAIGN,
            question_is_current=True,
        )
    with pytest.raises(ValueError, match="not an admitted"):
        prepare_interpreted_answer_context(
            claim.model_copy(update={"protection_class": "ordinary"}),
            campaign_id=CAMPAIGN,
            question_is_current=True,
        )


def test_exact_date_source_and_speaker_must_match_cited_evidence() -> None:
    claim = _claim()
    body = json.loads(claim.object)
    body["interpretation"]["exact_date_stated_by"] = "owner"
    with pytest.raises(ValidationError, match="exact date source and speaker differ"):
        prepare_interpreted_answer_context(
            claim.model_copy(update={"object": json.dumps(body)}),
            campaign_id=CAMPAIGN,
            question_is_current=False,
        )


def test_policy_recall_returns_only_cited_reviewed_interpretations() -> None:
    claim = _claim()
    policy = Mock()
    policy.protected_recall.return_value = (
        claim.model_copy(update={"candidate_version": 1}),
        claim,
    )
    interaction = UUID("00000000-0000-4000-8000-000000000004")
    contexts = recall_interpreted_answer_context(
        policy,
        "the first gate tag",
        owner_interaction_ref=interaction,
        reason_code="owner_pilot_answer",
        campaign_id=CAMPAIGN,
        question_is_current=True,
        limit=3,
    )
    assert len(contexts) == 1
    assert contexts[0].candidate_id == claim.candidate_id
    policy.protected_recall.assert_called_once_with(
        "the first gate tag",
        owner_interaction_ref=interaction,
        reason_code="owner_pilot_answer",
        limit=3,
    )
