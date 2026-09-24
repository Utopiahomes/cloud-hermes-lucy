from __future__ import annotations

import json
from datetime import UTC, datetime
from io import BytesIO
from typing import Any

from fastapi.testclient import TestClient

from lucy.chatgpt_manifest import LocalChatGPTMessageV1
from lucy.contracts.canonical import canonical_json_bytes
from lucy.hindsight_backfill import hindsight_item
from lucy.hindsight_backfill_intake import BackfillBatch, create_app

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
