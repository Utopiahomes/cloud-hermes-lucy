from __future__ import annotations

import json
from datetime import UTC, datetime
from io import BytesIO
from typing import Any

from fastapi.testclient import TestClient

from lucy.chatgpt_manifest import LocalChatGPTMessageV1
from lucy.contracts.canonical import canonical_json_bytes
from lucy.hindsight_backfill import hindsight_item
from lucy.hindsight_backfill_intake import BackfillBatch, ReviewedBatch, create_app

COMMITMENT = "a" * 64
TOKEN = "t" * 32


def _item() -> dict[str, Any]:
    message = LocalChatGPTMessageV1(
        source_record_id="conversation:node:message",
        conversation_id="conversation",
        native_node_id="node",
        native_message_id="message",
        parent_source_record_id=None,
        native_role="user",
        role="owner",
        occurred_at=datetime(2025, 1, 2, tzinfo=UTC),
        displayed=True,
        content="Historical thought",
        inclusion_state="included",
    )
    return hindsight_item(message, archive_commitment=COMMITMENT)


def test_backfill_intake_requires_capability_and_exact_source_identity(
    monkeypatch: Any,
) -> None:
    app = create_app(bearer_token=TOKEN, hindsight_key="h" * 32,
                     archive_commitment=COMMITMENT)
    client = TestClient(app)
    batch = BackfillBatch.model_validate({
        "archive_commitment": COMMITMENT, "items": [_item()],
    })
    body = canonical_json_bytes(batch)
    assert client.post("/v1/raymond/hindsight/backfill", content=body).status_code == 401

    class Response(BytesIO):
        status = 200

    calls: list[str] = []

    def fake_open(request: Any, *, timeout: int) -> Response:
        calls.append(request.full_url)
        assert timeout == 540
        return Response(json.dumps({"success": True}).encode())

    monkeypatch.setattr("lucy.hindsight_backfill_intake.urlopen", fake_open)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    response = client.post("/v1/raymond/hindsight/backfill", content=body, headers=headers)
    assert response.json() == {"accepted": True, "processed_count": 1}
    assert len(calls) == 1

    invalid = batch.model_dump()
    invalid["items"][0]["document_id"] = "lucy-chatgpt:" + "0" * 64
    response = client.post("/v1/raymond/hindsight/backfill",
                           content=json.dumps(invalid).encode(), headers=headers)
    assert response.status_code == 400
    assert len(calls) == 1


def test_reviewed_intake_checks_proposal_and_source_links(monkeypatch: Any) -> None:
    proposal = "fc2085b497de87d8da997159c2416cb1411e1f33b91007c0d4ea7558901fc36c"
    candidate = "9263c5f6-1cfe-581c-b038-96abcea82384"
    item = {
        "document_id": f"lucy-reviewed:{candidate}:v2",
        "content": "Reviewed historical interpretation.",
        "context": "Ray's reviewed Personal Lucy historical interpretation pilot",
        "update_mode": "replace",
        "metadata": {
            "source": "lucy_governed_reviewed_interpretation",
            "candidate_id": candidate,
            "candidate_version": "2",
            "object_sha256": "a" * 64,
            "source_record_ids": '["source-1"]',
            "source_evidence_ids": '["evidence-1"]',
            "campaign_id": "c1800ec3-1158-42f0-bb0b-46a04df7a65c",
            "proposal_sha256": proposal,
        },
    }
    batch = ReviewedBatch.model_validate({"proposal_sha256": proposal, "items": [item]})
    client = TestClient(create_app(bearer_token=TOKEN, hindsight_key="h" * 32,
                                   archive_commitment=COMMITMENT))
    endpoint = "/v1/raymond/hindsight/reviewed"
    body = canonical_json_bytes(batch)
    assert client.post(endpoint, content=body).status_code == 401

    class Response(BytesIO):
        status = 200

    calls = 0

    def fake_open(request: Any, *, timeout: int) -> Response:
        nonlocal calls
        calls += 1
        return Response(json.dumps({"success": True}).encode())

    monkeypatch.setattr("lucy.hindsight_backfill_intake.urlopen", fake_open)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    assert client.post(endpoint, content=body, headers=headers).json() == {
        "accepted": True, "processed_count": 1,
    }
    invalid = batch.model_dump()
    invalid["items"][0]["metadata"]["source_evidence_ids"] = "[]"
    assert client.post(endpoint, content=json.dumps(invalid).encode(),
                       headers=headers).status_code == 400
    assert calls == 1
