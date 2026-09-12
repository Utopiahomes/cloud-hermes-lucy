from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient

from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_candidate_review import (
    CandidateReviewBundleArtifactV1,
    CandidateReviewBundleV1,
    CandidateReviewItemV1,
    CandidateReviewSourceExcerptV1,
)
from lucy.memory_candidate_review_console import (
    CandidateReviewConsoleSettingsV1,
    create_candidate_review_console,
)
from lucy.memory_import import (
    AssertionStatus,
    EpistemicStatus,
    MemoryCandidatePayloadV1,
    MemoryKind,
    ProtectionClass,
    SourceSpanV1,
)

TOKEN = "candidate-review-token-that-is-long-enough"
CAMPAIGN = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SCOPE = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
JOB = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
EVIDENCE = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
CANDIDATE = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
APPROVAL = UUID("ffffffff-ffff-4fff-8fff-ffffffffffff")


def _candidate() -> MemoryCandidatePayloadV1:
    return MemoryCandidatePayloadV1(
        candidate_id=CANDIDATE,
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
        object="Use the café plan <script>alert(1)</script>",
        confidence_millionths=900_000,
        memory_kind=MemoryKind.ASSERTION,
        assertion_status=AssertionStatus.DECISION,
        epistemic_status=EpistemicStatus.CURRENT,
        protection_class=ProtectionClass.PROTECTED,
        domain_tags=("cloud-lucy",),
        event_time=datetime(2026, 9, 12, tzinfo=UTC),
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


def _client(tmp_path: Path) -> tuple[TestClient, Path, Path, CandidateReviewBundleV1]:
    intake = tmp_path / "intake"
    intake.mkdir()
    bundle = CandidateReviewBundleV1(
        campaign_id=CAMPAIGN,
        destination_content_scope_id=SCOPE,
        items=(_item(),),
    )
    artifact = CandidateReviewBundleArtifactV1(bundle=bundle, bundle_digest=bundle.digest)
    bundle_path = intake / "candidates.v1.json"
    bundle_path.write_bytes(canonical_json_bytes(artifact) + b"\n")
    proposal_path = intake / "review-proposal.v1.json"
    authorization_path = intake / "review-authorization.v1.json"
    app = create_candidate_review_console(
        CandidateReviewConsoleSettingsV1(
            intake_root=intake,
            bundle_path=bundle_path,
            proposal_path=proposal_path,
            authorization_path=authorization_path,
            session_token=TOKEN,
            owner_actor_id="owner:ray",
        )
    )
    return (
        TestClient(app, base_url="http://127.0.0.1:8766"),
        proposal_path,
        authorization_path,
        bundle,
    )


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {TOKEN}",
        "Origin": "http://127.0.0.1:8766",
    }


def _proposal_payload(bundle: CandidateReviewBundleV1) -> dict[str, object]:
    candidate = bundle.items[0].candidate
    return {
        "bundle_digest": bundle.digest,
        "choices": [
            {
                "candidate_id": str(candidate.candidate_id),
                "candidate_version": candidate.candidate_version,
                "candidate_digest": candidate.digest,
                "disposition": "accept_ordinary_private",
            }
        ],
    }


def test_review_page_has_no_candidate_or_token_and_uses_safe_dom(tmp_path: Path) -> None:
    client, _, _, _ = _client(tmp_path)
    page = client.get("/review")
    script = client.get("/review/app.js")

    assert page.status_code == 200
    assert TOKEN not in page.text
    assert "<script>alert(1)</script>" not in page.text
    assert page.headers["cache-control"] == "no-store"
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert "textContent" in script.text
    assert "innerHTML" not in script.text
    assert "localStorage" not in script.text


def test_candidate_access_requires_token_and_trusted_host(tmp_path: Path) -> None:
    client, _, _, bundle = _client(tmp_path)
    assert client.get("/api/candidates").status_code == 401
    response = client.get(
        "/api/candidates", headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert response.status_code == 200
    assert response.json()["bundle_digest"] == bundle.digest
    untrusted = client.get(
        "/api/candidates",
        headers={"Authorization": f"Bearer {TOKEN}", "Host": "example.com"},
    )
    assert untrusted.status_code == 400


def test_two_step_review_is_exact_idempotent_and_content_safe(tmp_path: Path) -> None:
    client, proposal_path, authorization_path, bundle = _client(tmp_path)
    payload = _proposal_payload(bundle)

    no_origin = client.post(
        "/api/review-proposal",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json=payload,
    )
    assert no_origin.status_code == 403
    stale = client.post(
        "/api/review-proposal",
        headers=_headers(),
        json={**payload, "bundle_digest": "0" * 64},
    )
    assert stale.status_code == 409

    first = client.post("/api/review-proposal", headers=_headers(), json=payload)
    assert first.status_code == 200
    assert first.json()["proposal"]["authorization_state"] == "proposed_not_authorized"
    assert first.json()["proposal"]["decisions"][0]["final_candidate"][
        "candidate_version"
    ] == 2
    assert first.json()["proposal"]["decisions"][0]["final_candidate"][
        "protection_class"
    ] == "ordinary_private"
    assert proposal_path.exists()
    replay = client.post("/api/review-proposal", headers=_headers(), json=payload)
    assert replay.status_code == 200 and replay.json()["replayed"] is True

    wrong_phrase = client.post(
        "/api/review-authorization",
        headers=_headers(),
        json={
            "proposal_digest": first.json()["proposal_digest"],
            "owner_approval_ref": str(APPROVAL),
            "confirmation": "approve",
        },
    )
    assert wrong_phrase.status_code == 422
    assert not authorization_path.exists()

    approved = client.post(
        "/api/review-authorization",
        headers=_headers(),
        json={
            "proposal_digest": first.json()["proposal_digest"],
            "owner_approval_ref": str(APPROVAL),
            "confirmation": "AUTHORIZE EXACT PRIVATE MEMORY REVIEW",
        },
    )
    assert approved.status_code == 200
    assert approved.json()["authorized_review"]["owner_actor_id"] == "owner:ray"
    assert approved.json()["authorized_review"]["authorization_state"] == "authorized"
    assert authorization_path.exists()
    serialized = authorization_path.read_text(encoding="utf-8")
    assert TOKEN not in serialized
    assert "owner:ray" in serialized

    replayed = client.post(
        "/api/review-authorization",
        headers=_headers(),
        json={
            "proposal_digest": first.json()["proposal_digest"],
            "owner_approval_ref": str(APPROVAL),
            "confirmation": "AUTHORIZE EXACT PRIVATE MEMORY REVIEW",
        },
    )
    assert replayed.status_code == 200 and replayed.json()["replayed"] is True


def test_changed_review_or_approval_cannot_overwrite_artifact(tmp_path: Path) -> None:
    client, proposal_path, authorization_path, bundle = _client(tmp_path)
    payload = _proposal_payload(bundle)
    first = client.post("/api/review-proposal", headers=_headers(), json=payload)
    assert first.status_code == 200

    changed = json.loads(json.dumps(payload))
    changed["choices"][0]["disposition"] = "reject"
    conflict = client.post("/api/review-proposal", headers=_headers(), json=changed)
    assert conflict.status_code == 409
    assert proposal_path.exists()

    approved = client.post(
        "/api/review-authorization",
        headers=_headers(),
        json={
            "proposal_digest": first.json()["proposal_digest"],
            "owner_approval_ref": str(APPROVAL),
            "confirmation": "AUTHORIZE EXACT PRIVATE MEMORY REVIEW",
        },
    )
    assert approved.status_code == 200
    conflict = client.post(
        "/api/review-authorization",
        headers=_headers(),
        json={
            "proposal_digest": first.json()["proposal_digest"],
            "owner_approval_ref": "11111111-1111-4111-8111-111111111111",
            "confirmation": "AUTHORIZE EXACT PRIVATE MEMORY REVIEW",
        },
    )
    assert conflict.status_code == 409
    assert authorization_path.exists()


def test_review_outputs_cannot_escape_intake_root(tmp_path: Path) -> None:
    intake = tmp_path / "intake"
    intake.mkdir()
    bundle = CandidateReviewBundleV1(
        campaign_id=CAMPAIGN,
        destination_content_scope_id=SCOPE,
        items=(_item(),),
    )
    artifact = CandidateReviewBundleArtifactV1(bundle=bundle, bundle_digest=bundle.digest)
    bundle_path = intake / "candidates.v1.json"
    bundle_path.write_bytes(canonical_json_bytes(artifact))

    try:
        create_candidate_review_console(
            CandidateReviewConsoleSettingsV1(
                intake_root=intake,
                bundle_path=bundle_path,
                proposal_path=tmp_path / "escaped.json",
                authorization_path=intake / "authorization.json",
                session_token=TOKEN,
                owner_actor_id="owner:ray",
            )
        )
    except ValueError as exc:
        assert "inside the verified intake root" in str(exc)
    else:
        raise AssertionError("escaped review output path was accepted")


def _item() -> CandidateReviewItemV1:
    candidate = _candidate()
    source = candidate.sources[0]
    return CandidateReviewItemV1(
        candidate=candidate,
        candidate_digest=candidate.digest,
        source_excerpts=(
            CandidateReviewSourceExcerptV1(
                source_record_id=source.source_record_id,
                evidence_id=source.evidence_id,
                record_version=source.record_version,
                byte_start=source.byte_start,
                byte_end=source.byte_end,
                exact_quote="café",
            ),
        ),
    )
