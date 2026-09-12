"""Exact, two-step owner review contracts for private-memory candidates."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from lucy.contracts.canonical import canonical_sha256
from lucy.memory_import import (
    EpistemicStatus,
    MemoryCandidatePayloadV1,
    ProtectionClass,
)

_BUNDLE_PREFIX = b"LUCY-MEMORY-CANDIDATE-REVIEW-BUNDLE-V1\x00"
_PROPOSAL_PREFIX = b"LUCY-MEMORY-CANDIDATE-REVIEW-PROPOSAL-V1\x00"


class CandidateDisposition(StrEnum):
    ACCEPT_PROTECTED = "accept_protected"
    ACCEPT_ORDINARY_PRIVATE = "accept_ordinary_private"
    MARK_UNCERTAIN_PROTECTED = "mark_uncertain_protected"
    REJECT = "reject"
    DEFER = "defer"


class CandidateReviewBundleV1(BaseModel):
    """Finite exact candidate set shown by the local review console."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: str = Field(default="1", pattern=r"^1$")
    campaign_id: UUID
    destination_content_scope_id: UUID
    candidates: tuple[MemoryCandidatePayloadV1, ...] = Field(
        min_length=1, max_length=200
    )

    @model_validator(mode="after")
    def coherent_candidate_set(self) -> CandidateReviewBundleV1:
        identities: set[tuple[UUID, int]] = set()
        for candidate in self.candidates:
            if (
                candidate.campaign_id != self.campaign_id
                or candidate.destination_content_scope_id
                != self.destination_content_scope_id
            ):
                raise ValueError("review candidate is outside the exact campaign scope")
            identity = (candidate.candidate_id, candidate.candidate_version)
            if identity in identities:
                raise ValueError("review candidate versions must be unique")
            identities.add(identity)
        return self

    @property
    def digest(self) -> str:
        return canonical_sha256(self, prefix=_BUNDLE_PREFIX)


class CandidateReviewChoiceV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    candidate_id: UUID
    candidate_version: int = Field(ge=1)
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    disposition: CandidateDisposition


class CandidateReviewDecisionV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source_candidate_id: UUID
    source_candidate_version: int = Field(ge=1)
    source_candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    disposition: CandidateDisposition
    final_candidate: MemoryCandidatePayloadV1 | None = None
    final_candidate_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def exact_final_candidate(self) -> CandidateReviewDecisionV1:
        accepts = self.disposition in {
            CandidateDisposition.ACCEPT_PROTECTED,
            CandidateDisposition.ACCEPT_ORDINARY_PRIVATE,
            CandidateDisposition.MARK_UNCERTAIN_PROTECTED,
        }
        if accepts != (self.final_candidate is not None):
            raise ValueError("review disposition and final candidate disagree")
        if self.final_candidate is None:
            if self.final_candidate_digest is not None:
                raise ValueError("non-accepting decision cannot have a final digest")
        elif self.final_candidate_digest != self.final_candidate.digest:
            raise ValueError("final candidate digest does not match its exact bytes")
        elif self.final_candidate.candidate_id != self.source_candidate_id:
            raise ValueError("final candidate identity does not match its source")
        elif self.disposition == CandidateDisposition.ACCEPT_PROTECTED:
            if (
                self.final_candidate.candidate_version != self.source_candidate_version
                or self.final_candidate_digest != self.source_candidate_digest
                or self.final_candidate.protection_class != ProtectionClass.PROTECTED
            ):
                raise ValueError("protected acceptance must preserve exact candidate bytes")
        elif self.final_candidate.candidate_version != self.source_candidate_version + 1:
            raise ValueError("review transformation must create the next candidate version")
        elif (
            self.disposition == CandidateDisposition.ACCEPT_ORDINARY_PRIVATE
            and self.final_candidate.protection_class
            != ProtectionClass.ORDINARY_PRIVATE
        ):
            raise ValueError("ordinary acceptance must create an ordinary projection")
        elif (
            self.disposition == CandidateDisposition.MARK_UNCERTAIN_PROTECTED
            and (
                self.final_candidate.protection_class != ProtectionClass.PROTECTED
                or self.final_candidate.epistemic_status != EpistemicStatus.UNCERTAIN
            )
        ):
            raise ValueError("uncertain acceptance must remain protected and uncertain")
        return self


class CandidateReviewProposalV1(BaseModel):
    """Exact result displayed before the owner performs final authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: str = Field(default="1", pattern=r"^1$")
    bundle_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    campaign_id: UUID
    destination_content_scope_id: UUID
    decisions: tuple[CandidateReviewDecisionV1, ...] = Field(
        min_length=1, max_length=200
    )
    authorization_state: str = Field(
        default="proposed_not_authorized", pattern=r"^proposed_not_authorized$"
    )

    @model_validator(mode="after")
    def coherent_decisions(self) -> CandidateReviewProposalV1:
        identities: set[tuple[UUID, int]] = set()
        for decision in self.decisions:
            identity = (
                decision.source_candidate_id,
                decision.source_candidate_version,
            )
            if identity in identities:
                raise ValueError("review proposal candidate decisions must be unique")
            identities.add(identity)
            candidate = decision.final_candidate
            if candidate is not None and (
                candidate.campaign_id != self.campaign_id
                or candidate.destination_content_scope_id
                != self.destination_content_scope_id
            ):
                raise ValueError("review decision is outside the exact campaign scope")
        return self

    @property
    def digest(self) -> str:
        return canonical_sha256(self, prefix=_PROPOSAL_PREFIX)


class AuthorizedCandidateReviewV1(BaseModel):
    """Owner authorization bound to one exact proposal digest."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: str = Field(default="1", pattern=r"^1$")
    proposal: CandidateReviewProposalV1
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_approval_ref: UUID
    owner_actor_id: str = Field(min_length=1, max_length=512)
    approved_at: datetime
    authorization_state: str = Field(default="authorized", pattern=r"^authorized$")

    @model_validator(mode="after")
    def exact_proposal(self) -> AuthorizedCandidateReviewV1:
        if self.proposal_digest != self.proposal.digest:
            raise ValueError("owner authorization does not match the exact review proposal")
        if self.approved_at.tzinfo is None or self.approved_at.utcoffset() is None:
            raise ValueError("owner approval timestamp must be timezone-aware")
        return self


def propose_candidate_review(
    bundle: CandidateReviewBundleV1,
    choices: tuple[CandidateReviewChoiceV1, ...],
) -> CandidateReviewProposalV1:
    """Produce final exact candidate bytes without authorizing them."""

    if len(choices) != len(bundle.candidates):
        raise ValueError("review must decide every candidate in the exact bundle")
    by_identity = {
        (candidate.candidate_id, candidate.candidate_version): candidate
        for candidate in bundle.candidates
    }
    seen: set[tuple[UUID, int]] = set()
    decisions: list[CandidateReviewDecisionV1] = []
    for choice in choices:
        identity = (choice.candidate_id, choice.candidate_version)
        candidate = by_identity.get(identity)
        if identity in seen or candidate is None or candidate.digest != choice.candidate_digest:
            raise ValueError("review choice does not match one exact candidate version")
        seen.add(identity)
        final_candidate: MemoryCandidatePayloadV1 | None = None
        if choice.disposition == CandidateDisposition.ACCEPT_PROTECTED:
            final_candidate = candidate
        elif choice.disposition == CandidateDisposition.ACCEPT_ORDINARY_PRIVATE:
            final_candidate = MemoryCandidatePayloadV1.model_validate(
                {
                    **candidate.model_dump(),
                    "candidate_version": candidate.candidate_version + 1,
                    "protection_class": ProtectionClass.ORDINARY_PRIVATE,
                }
            )
        elif choice.disposition == CandidateDisposition.MARK_UNCERTAIN_PROTECTED:
            final_candidate = MemoryCandidatePayloadV1.model_validate(
                {
                    **candidate.model_dump(),
                    "candidate_version": candidate.candidate_version + 1,
                    "epistemic_status": EpistemicStatus.UNCERTAIN,
                    "protection_class": ProtectionClass.PROTECTED,
                }
            )
        decisions.append(
            CandidateReviewDecisionV1(
                source_candidate_id=candidate.candidate_id,
                source_candidate_version=candidate.candidate_version,
                source_candidate_digest=candidate.digest,
                disposition=choice.disposition,
                final_candidate=final_candidate,
                final_candidate_digest=(
                    final_candidate.digest if final_candidate is not None else None
                ),
            )
        )
    if seen != set(by_identity):
        raise ValueError("review omitted an exact candidate version")
    return CandidateReviewProposalV1(
        bundle_digest=bundle.digest,
        campaign_id=bundle.campaign_id,
        destination_content_scope_id=bundle.destination_content_scope_id,
        decisions=tuple(decisions),
    )


def authorize_candidate_review(
    proposal: CandidateReviewProposalV1,
    *,
    expected_proposal_digest: str,
    owner_approval_ref: UUID,
    owner_actor_id: str,
    approved_at: datetime,
) -> AuthorizedCandidateReviewV1:
    if expected_proposal_digest != proposal.digest:
        raise ValueError("displayed review proposal changed before authorization")
    return AuthorizedCandidateReviewV1(
        proposal=proposal,
        proposal_digest=expected_proposal_digest,
        owner_approval_ref=owner_approval_ref,
        owner_actor_id=owner_actor_id,
        approved_at=approved_at,
    )
