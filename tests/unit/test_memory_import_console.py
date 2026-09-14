from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient

from lucy.chatgpt_import import (
    ChatGPTExportInventoryV1,
    ExportConversationInventoryV1,
)
from lucy.memory_import_console import ImportConsoleSettingsV1, create_import_console

_SCOPE_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
_TOKEN = "local-console-token-that-is-long-enough"


def _inventory(*, title: str = "Cloud Lucy <script>alert(1)</script>") -> ChatGPTExportInventoryV1:
    return ChatGPTExportInventoryV1(
        archive_name="synthetic-export.zip",
        archive_commitment="a" * 64,
        archive_byte_length=123,
        entry_count=1,
        compressed_bytes=100,
        uncompressed_bytes=200,
        conversations=(
            ExportConversationInventoryV1(
                conversation_id="conversation-1",
                title=title,
                created_at=datetime(2026, 9, 1, tzinfo=UTC),
                updated_at=datetime(2026, 9, 2, tzinfo=UTC),
                message_count=12,
                displayed_message_count=10,
                alternate_message_count=2,
                missing_timestamp_count=0,
                missing_content_count=0,
                attachment_reference_count=1,
                supported_text_bytes=3_600,
                estimated_source_tokens=1_200,
                proposed_domain_tags=("cloud-lucy",),
            ),
        ),
        attachments=(),
        issues=(),
        inventoried_at=datetime(2026, 9, 12, tzinfo=UTC),
    )


def _client(tmp_path: Path) -> tuple[TestClient, Path]:
    intake = tmp_path / "intake"
    intake.mkdir()
    inventory_path = intake / "inventory.v1.json"
    inventory_path.write_text(_inventory().model_dump_json(), encoding="utf-8")
    selection_path = intake / "pilot-selection.v1.json"
    app = create_import_console(
        ImportConsoleSettingsV1(
            intake_root=intake,
            inventory_path=inventory_path,
            selection_path=selection_path,
            session_token=_TOKEN,
            destination_content_scope_id=_SCOPE_ID,
        )
    )
    return TestClient(app, base_url="http://127.0.0.1:8765"), selection_path


def _selection(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "inventory_archive_commitment": "a" * 64,
        "conversation_ids": ["conversation-1"],
        "max_model_spend_microusd": 2_000_000,
        "max_attempts": 20,
        "max_request_input_tokens": 60_000,
        "max_request_output_tokens": 4_000,
        "max_request_total_tokens": 64_000,
        "expires_at": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
    }
    value.update(overrides)
    return value


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_TOKEN}",
        "Origin": "http://127.0.0.1:8765",
    }


def test_review_page_embeds_neither_token_nor_inventory_content(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)

    response = client.get("/imports")

    assert response.status_code == 200
    assert _TOKEN not in response.text
    assert "<script>alert(1)</script>" not in response.text
    assert "does not authorize or upload data" in response.text
    assert response.headers["cache-control"] == "no-store"
    assert "script-src 'self'" in response.headers["content-security-policy"]

    script = client.get("/imports/app.js")
    assert script.status_code == 200
    assert "textContent" in script.text
    assert "innerHTML" not in script.text
    assert "localStorage" not in script.text
    assert _TOKEN not in script.text


def test_inventory_requires_session_token_and_rejects_untrusted_host(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)

    assert client.get("/api/inventory").status_code == 401
    response = client.get(
        "/api/inventory", headers={"Authorization": f"Bearer {_TOKEN}"}
    )
    assert response.status_code == 200
    assert response.json()["conversations"][0]["conversation_id"] == "conversation-1"
    untrusted = client.get(
        "/api/inventory",
        headers={"Authorization": f"Bearer {_TOKEN}", "Host": "example.com"},
    )
    assert untrusted.status_code == 400


def test_selection_requires_local_origin_and_exact_inventory(tmp_path: Path) -> None:
    client, selection_path = _client(tmp_path)

    no_origin = client.post(
        "/api/pilot-selection",
        headers={"Authorization": f"Bearer {_TOKEN}"},
        json=_selection(),
    )
    assert no_origin.status_code == 403
    wrong_origin = client.post(
        "/api/pilot-selection",
        headers={"Authorization": f"Bearer {_TOKEN}", "Origin": "https://example.com"},
        json=_selection(),
    )
    assert wrong_origin.status_code == 403
    stale = client.post(
        "/api/pilot-selection",
        headers=_headers(),
        json=_selection(inventory_archive_commitment="b" * 64),
    )
    assert stale.status_code == 409
    unknown = client.post(
        "/api/pilot-selection",
        headers=_headers(),
        json=_selection(conversation_ids=["conversation-missing"]),
    )
    assert unknown.status_code == 422
    assert not selection_path.exists()


def test_selection_is_non_authorizing_bound_and_idempotent(tmp_path: Path) -> None:
    client, selection_path = _client(tmp_path)
    selection = _selection()

    first = client.post("/api/pilot-selection", headers=_headers(), json=selection)

    assert first.status_code == 200
    result = first.json()
    assert result["replayed"] is False
    assert result["proposal"]["authorization_state"] == "proposed_not_authorized"
    assert result["proposal"]["destination_content_scope_id"] == str(_SCOPE_ID)
    assert result["proposal"]["selected_record_count"] == 12
    assert result["proposal"]["selected_source_bytes"] == 3_600
    assert result["proposal"]["estimated_source_tokens"] == 1_200
    assert result["proposal"]["default_protection"] == "protected"
    assert result["proposal"]["max_model_spend_microusd"] == 2_000_000
    assert result["proposal"]["max_request_total_tokens"] == 64_000
    assert result["proposal"]["token_accounting_version"] == (
        "canonical-json-byte-upper-bound-v1"
    )
    assert result["proposal_digest"]
    on_disk = json.loads(selection_path.read_text(encoding="utf-8"))
    assert on_disk["proposal"]["authorization_state"] == "proposed_not_authorized"
    assert "session_token" not in selection_path.read_text(encoding="utf-8")

    replay = client.post("/api/pilot-selection", headers=_headers(), json=selection)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["proposal_digest"] == result["proposal_digest"]

    conflict = client.post(
        "/api/pilot-selection",
        headers=_headers(),
        json=_selection(max_model_spend_microusd=2_000_001),
    )
    assert conflict.status_code == 409


def test_selection_output_cannot_escape_intake(tmp_path: Path) -> None:
    intake = tmp_path / "intake"
    intake.mkdir()
    inventory_path = intake / "inventory.v1.json"
    inventory_path.write_text(_inventory().model_dump_json(), encoding="utf-8")

    try:
        create_import_console(
            ImportConsoleSettingsV1(
                intake_root=intake,
                inventory_path=inventory_path,
                selection_path=tmp_path / "escaped.json",
                session_token=_TOKEN,
                destination_content_scope_id=_SCOPE_ID,
            )
        )
    except ValueError as exc:
        assert "inside the verified intake root" in str(exc)
    else:
        raise AssertionError("escaped proposal path was accepted")
