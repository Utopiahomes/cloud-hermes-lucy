"""Versioned interpretations for evidence-backed private memory review.

This contract is independent of candidate promotion. It keeps historical meaning,
current applicability, attribution, and evidence in one revisable record.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Speaker(StrEnum):
    OWNER = "owner"
    ASSISTANT = "assistant"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class SpeechAct(StrEnum):
    REPORT = "report"
    QUESTION = "question"
    PROPOSAL = "proposal"
    HYPOTHESIS = "hypothesis"
    DECISION = "decision"
    RECOMMENDATION = "recommendation"
    DRAFT = "draft"
    CONVENTION = "convention"
    INTERPRETATION = "interpretation"


class ConfirmationScope(StrEnum):
    EXPLICIT = "explicit"
    PARTIAL = "partial"
    AMBIGUOUS = "ambiguous"
    NONE = "none"
    UNKNOWN = "unknown"


class CurrentApplicability(StrEnum):
    NOT_CHECKED = "not_checked"
    SUPPORTED = "supported"
    SUPERSEDED = "superseded"
    UNKNOWN = "unknown"


class EvidenceRelation(StrEnum):
    PRIMARY = "primary"
    NEIGHBOR = "neighbor"
    REVISION = "revision"


class InterpretationEvidenceV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source_record_id: str = Field(min_length=1, max_length=512)
    role: Speaker
    relation: EvidenceRelation
    exact_excerpt: str = Field(min_length=1, max_length=16_384)
    occurred_at: datetime | None = None

    @model_validator(mode="after")
    def evidence_role_is_source_role(self) -> InterpretationEvidenceV1:
        if self.role not in {Speaker.OWNER, Speaker.ASSISTANT}:
            raise ValueError("evidence needs an exact owner or assistant source role")
        return self


class IndependentAssessmentsV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    support: str = Field(min_length=1, max_length=2_000)
    counterevidence: str = Field(min_length=1, max_length=2_000)
    owner_endorsement: str = Field(min_length=1, max_length=2_000)
    present_applicability: str = Field(min_length=1, max_length=2_000)
    remembering_value: str = Field(min_length=1, max_length=2_000)


class InterpretationVersionV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: int = Field(ge=1)
    statement: str = Field(min_length=1, max_length=4_000)
    material_qualifiers: tuple[str, ...] = Field(default=(), max_length=12)
    source_utterance_at: datetime | None = None
    applicable_period: str | None = Field(default=None, max_length=300)
    reassessed_at: datetime
    speech_act: SpeechAct
    proposer: Speaker
    confirmation_scope: ConfirmationScope
    confirmed_proposition: str | None = Field(default=None, max_length=2_000)
    exact_date_stated_by: Speaker | None = None
    exact_date_source_record_id: str | None = Field(default=None, max_length=512)
    current_applicability: CurrentApplicability
    assessments: IndependentAssessmentsV1
    evidence: tuple[InterpretationEvidenceV1, ...] = Field(min_length=1, max_length=32)
    revision_reason: str = Field(min_length=1, max_length=2_000)

    @model_validator(mode="after")
    def attribution_has_exact_support(self) -> InterpretationVersionV1:
        if len({item.source_record_id for item in self.evidence}) != len(self.evidence):
            raise ValueError("interpretation evidence source IDs must be unique")
        roles = {item.role for item in self.evidence}
        if self.proposer in {Speaker.OWNER, Speaker.ASSISTANT} and self.proposer not in roles:
            raise ValueError("proposer role is absent from linked evidence")
        if (
            self.confirmation_scope in {
                ConfirmationScope.EXPLICIT,
                ConfirmationScope.AMBIGUOUS,
                ConfirmationScope.PARTIAL,
            }
            and (Speaker.OWNER not in roles or not self.confirmed_proposition)
        ):
            raise ValueError("owner confirmation needs owner evidence and a scoped proposition")
        if (self.exact_date_stated_by is None) != (self.exact_date_source_record_id is None):
            raise ValueError("exact date attribution requires role and source together")
        if self.exact_date_stated_by is not None:
            if self.exact_date_stated_by not in {Speaker.OWNER, Speaker.ASSISTANT}:
                raise ValueError("exact date speaker must be an exact source role")
            if not any(item.source_record_id == self.exact_date_source_record_id
                       and item.role == self.exact_date_stated_by
                       for item in self.evidence):
                raise ValueError("exact date attribution differs from linked source")
        return self

    def compact_recall(self, *, question_is_current: bool) -> str:
        parts = [self.statement, *self.material_qualifiers]
        if question_is_current:
            if self.current_applicability == CurrentApplicability.NOT_CHECKED:
                parts.append("Current applicability has not been checked.")
            elif self.current_applicability == CurrentApplicability.SUPERSEDED:
                parts.append("This interpretation has been superseded for current use.")
            elif self.current_applicability == CurrentApplicability.UNKNOWN:
                parts.append("Current applicability is unknown.")
        return " ".join(part.strip() for part in parts)

    def answer_context(self, *, question_is_current: bool) -> dict[str, str | list[str] | None]:
        """Expose material interpretation boundaries to an answer generator."""
        return {
            "historical_interpretation": self.compact_recall(
                question_is_current=question_is_current
            ),
            "speech_act": self.speech_act.value,
            "proposer": self.proposer.value,
            "confirmation_scope": self.confirmation_scope.value,
            "confirmed_proposition": self.confirmed_proposition,
            "exact_date_stated_by": (
                self.exact_date_stated_by.value if self.exact_date_stated_by else None
            ),
            "exact_date_source_record_id": self.exact_date_source_record_id,
            "current_applicability": self.current_applicability.value,
            "temporal_boundary": (
                "Describe this as the state in the source exchange; present status is unverified."
                if self.current_applicability == CurrentApplicability.NOT_CHECKED
                else None
            ),
            "material_qualifiers": list(self.material_qualifiers),
            "counterevidence": self.assessments.counterevidence,
            "owner_endorsement": self.assessments.owner_endorsement,
        }


class InterpretationRecordV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    candidate_id: UUID
    candidate_version: int = Field(ge=1)
    versions: tuple[InterpretationVersionV1, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def consecutive_versions(self) -> InterpretationRecordV1:
        if [version.version for version in self.versions] != list(
            range(1, len(self.versions) + 1)
        ):
            raise ValueError("interpretation versions must be consecutive")
        return self

    @property
    def current(self) -> InterpretationVersionV1:
        return self.versions[-1]

    def with_revision(self, revision: InterpretationVersionV1) -> InterpretationRecordV1:
        if revision.version != self.current.version + 1:
            raise ValueError("revision must append the next version")
        return self.model_copy(update={"versions": (*self.versions, revision)})
