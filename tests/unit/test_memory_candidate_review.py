from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from lucy.memory_candidate_review import (
    CandidateDisposition,
    CandidateReviewBundleV1,
    CandidateReviewChoiceV1,
    CandidateReviewItemV1,
    CandidateReviewSourceExcerptV1,
    authorize_candidate_review,
    propose_candidate_review,
)
from lucy.memory_import import (
    AssertionStatus,
    EpistemicStatus,
    MemoryCandidatePayloadV1,
    MemoryKind,
    ProtectionClass,
    SourceSpanV1,
)

CAMPAIGN = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SCOPE = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
JOB = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
EVIDENCE = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
CANDIDATE = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
APPROVAL = UUID("ffffffff-ffff-4fff-8fff-ffffffffffff")
NOW = datetime(2026, 9, 12, 22, 0, tzinfo=UTC)


def _candidate(*, candidate_id: UUID = CANDIDATE) -> MemoryCandidatePayloadV1:
    return MemoryCandidatePayloadV1(
        candidate_id=candidate_id,
        candidate_version=1,
        campaign_id=CAMPAIGN,
        manifest_digest="a" * 64,
        extraction_job_id=JOB,
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        model_route="openrouter/private-model",
        destination_content_scope_id=SCOPE,
        subject="Ray",
        predicate="selected_plan",
        object="Use the café plan",
        confidence_millionths=900_000,
        memory_kind=MemoryKind.ASSERTION,
        assertion_status=AssertionStatus.DECISION,
        epistemic_status=EpistemicStatus.CURRENT,
        protection_class=ProtectionClass.PROTECTED,
        domain_tags=("cloud-lucy",),
        event_time=NOW,
        sources=(
            SourceSpanV1(
                source_record_id="conversation-1:node-1:message-1",
                evidence_id=EVIDENCE,
                record_version=1,
                byte_start=14,
                byte_end=19,
            ),
        ),
    )


def _bundle(*candidates: MemoryCandidatePayloadV1) -> CandidateReviewBundleV1:
    selected = candidates or (_candidate(),)
    return CandidateReviewBundleV1(
        campaign_id=CAMPAIGN,
        destination_content_scope_id=SCOPE,
        items=tuple(
            CandidateReviewItemV1(
                candidate=candidate,
                candidate_digest=candidate.digest,
                source_excerpts=tuple(
                    CandidateReviewSourceExcerptV1(
                        source_record_id=source.source_record_id,
                        evidence_id=source.evidence_id,
                        record_version=source.record_version,
                        byte_start=source.byte_start,
                        byte_end=source.byte_end,
                        exact_quote="café",
                    )
                    for source in candidate.sources
                ),
            )
            for candidate in selected
        ),
    )


def _choice(
    candidate: MemoryCandidatePayloadV1,
    disposition: CandidateDisposition,
) -> CandidateReviewChoiceV1:
    return CandidateReviewChoiceV1(
        candidate_id=candidate.candidate_id,
        candidate_version=candidate.candidate_version,
        candidate_digest=candidate.digest,
        disposition=disposition,
    )


@pytest.mark.parametrize(
    ("disposition", "protection", "epistemic", "version"),
    [
        (
            CandidateDisposition.ACCEPT_PROTECTED,
            ProtectionClass.PROTECTED,
            EpistemicStatus.CURRENT,
            1,
        ),
        (
            CandidateDisposition.ACCEPT_ORDINARY_PRIVATE,
            ProtectionClass.ORDINARY_PRIVATE,
            EpistemicStatus.CURRENT,
            2,
        ),
        (
            CandidateDisposition.MARK_UNCERTAIN_PROTECTED,
            ProtectionClass.PROTECTED,
            EpistemicStatus.UNCERTAIN,
            2,
        ),
    ],
)
def test_accepting_review_proposes_final_exact_bytes_before_authorization(
    disposition: CandidateDisposition,
    protection: ProtectionClass,
    epistemic: EpistemicStatus,
    version: int,
) -> None:
    candidate = _candidate()
    proposal = propose_candidate_review(_bundle(candidate), (_choice(candidate, disposition),))

    assert proposal.authorization_state == "proposed_not_authorized"
    decision = proposal.decisions[0]
    assert decision.final_candidate is not None
    assert decision.final_candidate.protection_class == protection
    assert decision.final_candidate.epistemic_status == epistemic
    assert decision.final_candidate.candidate_version == version
    assert decision.final_candidate_digest == decision.final_candidate.digest

    authorized = authorize_candidate_review(
        proposal,
        expected_proposal_digest=proposal.digest,
        owner_approval_ref=APPROVAL,
        owner_actor_id="owner:ray",
        approved_at=NOW,
    )
    assert authorized.authorization_state == "authorized"
    assert authorized.proposal_digest == proposal.digest


@pytest.mark.parametrize(
    "disposition", [CandidateDisposition.REJECT, CandidateDisposition.DEFER]
)
def test_non_accepting_review_never_contains_approvable_candidate(
    disposition: CandidateDisposition,
) -> None:
    candidate = _candidate()
    proposal = propose_candidate_review(_bundle(candidate), (_choice(candidate, disposition),))
    decision = proposal.decisions[0]
    assert decision.final_candidate is None
    assert decision.final_candidate_digest is None


def test_review_rejects_stale_duplicate_or_incomplete_choices() -> None:
    first = _candidate()
    second = _candidate(candidate_id=UUID("11111111-1111-4111-8111-111111111111"))
    bundle = _bundle(first, second)
    stale = _choice(first, CandidateDisposition.ACCEPT_PROTECTED).model_copy(
        update={"candidate_digest": "0" * 64}
    )

    with pytest.raises(ValueError, match="exact candidate version"):
        propose_candidate_review(bundle, (stale, _choice(second, CandidateDisposition.DEFER)))
    with pytest.raises(ValueError, match="decide every candidate"):
        propose_candidate_review(bundle, (_choice(first, CandidateDisposition.DEFER),))
    with pytest.raises(ValueError, match="exact candidate version"):
        propose_candidate_review(
            bundle,
            (
                _choice(first, CandidateDisposition.DEFER),
                _choice(first, CandidateDisposition.DEFER),
            ),
        )


def test_authorization_rejects_changed_proposal_or_naive_timestamp() -> None:
    candidate = _candidate()
    proposal = propose_candidate_review(
        _bundle(candidate), (_choice(candidate, CandidateDisposition.ACCEPT_PROTECTED),)
    )
    with pytest.raises(ValueError, match="changed before authorization"):
        authorize_candidate_review(
            proposal,
            expected_proposal_digest="0" * 64,
            owner_approval_ref=APPROVAL,
            owner_actor_id="owner:ray",
            approved_at=NOW,
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        authorize_candidate_review(
            proposal,
            expected_proposal_digest=proposal.digest,
            owner_approval_ref=APPROVAL,
            owner_actor_id="owner:ray",
            approved_at=datetime(2026, 9, 12, 22, 0),
        )
