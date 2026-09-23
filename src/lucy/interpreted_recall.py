"""Fail-closed answer context for governed, versioned private interpretations."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator

from lucy.governed_memory import GovernedMemoryClaimV1, GovernedMemoryPolicy
from lucy.memory_interpretation import (
    ConfirmationScope,
    CurrentApplicability,
    EvidenceRelation,
    IndependentAssessmentsV1,
    Speaker,
    SpeechAct,
)


class StoredEvidenceRefV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source_record_id: str = Field(min_length=1, max_length=512)
    role: Speaker
    relation: EvidenceRelation

    @model_validator(mode="after")
    def exact_source_speaker(self) -> StoredEvidenceRefV1:
        if self.role not in {Speaker.OWNER, Speaker.ASSISTANT}:
            raise ValueError("stored evidence requires an exact speaker")
        return self


class StoredInterpretationV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: int = Field(ge=1)
    statement: str = Field(min_length=1, max_length=4_000)
    material_qualifiers: tuple[str, ...] = ()
    source_utterance_at: datetime | None = None
    applicable_period: str | None = None
    reassessed_at: datetime
    speech_act: SpeechAct
    proposer: Speaker
    confirmation_scope: ConfirmationScope
    confirmed_proposition: str | None = None
    exact_date_stated_by: Speaker | None = None
    exact_date_source_record_id: str | None = None
    current_applicability: CurrentApplicability
    assessments: IndependentAssessmentsV1
    revision_reason: str = Field(min_length=1)


class StoredInterpretationEnvelopeV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["lucy_versioned_interpretation_v1"]
    source_candidate_version: int = Field(ge=1)
    source_candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    interpretation: StoredInterpretationV1
    evidence_refs: tuple[StoredEvidenceRefV1, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def source_attribution_is_coherent(self) -> StoredInterpretationEnvelopeV1:
        refs = self.evidence_refs
        if len({item.source_record_id for item in refs}) != len(refs):
            raise ValueError("stored evidence references are not unique")
        date_id = self.interpretation.exact_date_source_record_id
        date_role = self.interpretation.exact_date_stated_by
        if (date_id is None) != (date_role is None):
            raise ValueError("exact date attribution is incomplete")
        if date_id is not None and not any(
            item.source_record_id == date_id and item.role == date_role for item in refs
        ):
            raise ValueError("exact date source and speaker differ")
        if self.interpretation.proposer in {Speaker.OWNER, Speaker.ASSISTANT} and not any(
            item.role == self.interpretation.proposer for item in refs
        ):
            raise ValueError("proposer is absent from linked evidence")
        if self.interpretation.confirmation_scope in {
            ConfirmationScope.EXPLICIT, ConfirmationScope.PARTIAL, ConfirmationScope.AMBIGUOUS
        } and (not self.interpretation.confirmed_proposition
               or not any(item.role == Speaker.OWNER for item in refs)):
            raise ValueError("owner confirmation lacks scoped owner evidence")
        return self


class AnswerCitationV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    label: str = Field(pattern=r"^E[1-9][0-9]*$")
    evidence_id: UUID
    source_record_id: str
    role: Speaker
    relation: EvidenceRelation


class InterpretedAnswerContextV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    claim_id: UUID
    candidate_id: UUID
    candidate_version: int
    historical_interpretation: str
    speech_act: SpeechAct
    proposer: Speaker
    confirmation_scope: ConfirmationScope
    confirmed_proposition: str | None
    exact_date_stated_by: Speaker | None
    exact_date_source_label: str | None
    current_applicability: CurrentApplicability
    temporal_boundary: str | None
    assessments: IndependentAssessmentsV1
    citations: tuple[AnswerCitationV1, ...]


def prepare_interpreted_answer_context(
    claim: GovernedMemoryClaimV1, *, campaign_id: UUID,
    source_revision: int = 1, question_is_current: bool,
) -> InterpretedAnswerContextV1:
    """Map one pilot claim to cited context when every revision-1 source checks out.

    The source UUID convention is campaign-specific; future imports with mixed source
    revisions need an explicit source-ID map in the stored envelope.
    """
    if (claim.candidate_id is None or claim.candidate_version != 2
            or claim.protection_class != "protected"
            or claim.assertion_status != "attributed_interpretation"
            or claim.epistemic_status != "historical"
            or source_revision < 1):
        raise ValueError("claim is not an admitted reviewed interpretation")
    try:
        envelope = StoredInterpretationEnvelopeV1.model_validate(json.loads(claim.object))
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("stored interpretation is malformed") from exc
    if envelope.source_candidate_version + 1 != claim.candidate_version:
        raise ValueError("stored interpretation candidate version differs")
    citations = tuple(
        AnswerCitationV1(
            label=f"E{index}",
            evidence_id=uuid5(
                campaign_id,
                f"evidence:{ref.source_record_id}:r{source_revision}",
            ),
            source_record_id=ref.source_record_id,
            role=ref.role,
            relation=ref.relation,
        )
        for index, ref in enumerate(envelope.evidence_refs, 1)
    )
    if {item.evidence_id for item in citations} != set(claim.source_evidence_ids):
        raise ValueError("stored interpretation citations differ from protected claim sources")
    current = envelope.interpretation
    parts = [current.statement, *current.material_qualifiers]
    if question_is_current:
        if current.current_applicability == CurrentApplicability.NOT_CHECKED:
            parts.append("Current applicability has not been checked.")
        elif current.current_applicability == CurrentApplicability.UNKNOWN:
            parts.append("Current applicability is unknown.")
        elif current.current_applicability == CurrentApplicability.SUPERSEDED:
            parts.append("This interpretation has been superseded for current use.")
    date_label = next(
        (item.label for item in citations
         if item.source_record_id == current.exact_date_source_record_id), None
    )
    return InterpretedAnswerContextV1(
        claim_id=claim.claim_id,
        candidate_id=claim.candidate_id,
        candidate_version=claim.candidate_version,
        historical_interpretation=" ".join(part.strip() for part in parts),
        speech_act=current.speech_act,
        proposer=current.proposer,
        confirmation_scope=current.confirmation_scope,
        confirmed_proposition=current.confirmed_proposition,
        exact_date_stated_by=current.exact_date_stated_by,
        exact_date_source_label=date_label,
        current_applicability=current.current_applicability,
        temporal_boundary=(
            "Describe this as the state in the source exchange; present status is unverified."
            if current.current_applicability == CurrentApplicability.NOT_CHECKED
            else None
        ),
        assessments=current.assessments,
        citations=citations,
    )


def recall_interpreted_answer_context(
    policy: GovernedMemoryPolicy,
    query: str,
    *,
    owner_interaction_ref: UUID,
    reason_code: str,
    campaign_id: UUID,
    question_is_current: bool,
    limit: int = 5,
) -> tuple[InterpretedAnswerContextV1, ...]:
    """Read protected claims under the policy login and return cited interpretations.

    An authorized caller must supply an authenticated owner interaction. This
    function does not itself authorize a web or Telegram request.
    """
    claims = policy.protected_recall(
        query,
        owner_interaction_ref=owner_interaction_ref,
        reason_code=reason_code,
        limit=limit,
    )
    reviewed = (
        claim for claim in claims
        if claim.candidate_version == 2
        and claim.assertion_status == "attributed_interpretation"
        and claim.epistemic_status == "historical"
    )
    return tuple(
        prepare_interpreted_answer_context(
            claim, campaign_id=campaign_id, question_is_current=question_is_current
        )
        for claim in reviewed
    )
