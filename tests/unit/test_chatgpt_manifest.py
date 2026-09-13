from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from lucy.chatgpt_import import ChatGPTExportInventoryV1, inventory_chatgpt_export
from lucy.chatgpt_manifest import (
    LocalChatGPTConversationV1,
    LocalPilotBuildV1,
    build_exact_archive_requests,
    build_exact_pilot_manifests,
)
from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_import_cli import main
from lucy.memory_import_console import (
    PilotConversationSelectionV1,
    PilotSelectionProposalV1,
)

_SCOPE = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
_CAMPAIGN = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")


def _export() -> list[object]:
    def message(message_id: str, role: str, text: object, created: object) -> dict[str, object]:
        return {
            "id": message_id,
            "author": {"role": role},
            "create_time": created,
            "content": {"content_type": "text", "parts": text},
            "metadata": {},
        }

    return [
        {
            "id": "conversation-1",
            "title": "Cloud Lucy architecture",
            "create_time": 1_757_683_200,
            "update_time": 1_757_686_800,
            "current_node": "shown",
            "mapping": {
                "root": {"id": "root", "parent": None, "message": None},
                "owner": {
                    "id": "owner",
                    "parent": "root",
                    "message": message("message-owner", "user", ["private canary"], 1_757_683_200),
                },
                "shown": {
                    "id": "shown",
                    "parent": "owner",
                    "message": message(
                        "message-shown", "assistant", ["shown answer"], 1_757_683_201
                    ),
                },
                "alternate": {
                    "id": "alternate",
                    "parent": "owner",
                    "message": message("message-alternate", "assistant", ["other answer"], None),
                },
                "tool": {
                    "id": "tool",
                    "parent": "shown",
                    "message": message("message-tool", "tool", ["tool payload"], 1_757_683_202),
                },
                "missing": {
                    "id": "missing",
                    "parent": "shown",
                    "message": message(
                        "message-missing",
                        "assistant",
                        {"unsupported": True},
                        1_757_683_203,
                    ),
                },
            },
        }
    ]


def _write_export(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("conversations.json", json.dumps(_export()))
        archive.writestr("file-1.png", b"synthetic-image")


def _selection(report: ChatGPTExportInventoryV1) -> PilotSelectionProposalV1:
    selected = report.conversations[0]
    return PilotSelectionProposalV1(
        inventory_archive_commitment=report.archive_commitment,
        destination_content_scope_id=_SCOPE,
        selected_conversations=(
            PilotConversationSelectionV1.model_validate(
                selected.model_dump(exclude={"selected"})
            ),
        ),
        selected_record_count=selected.message_count,
        selected_attachment_reference_count=selected.attachment_reference_count,
        selected_source_bytes=selected.supported_text_bytes,
        estimated_source_tokens=selected.estimated_source_tokens,
        max_model_spend_microusd=1_000_000,
        max_attempts=10,
        max_request_input_tokens=60_000,
        max_request_output_tokens=4_000,
        max_request_total_tokens=64_000,
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )


def test_exact_pilot_manifest_preserves_graph_and_excludes_unsupported_records(
    tmp_path: Path,
) -> None:
    intake = tmp_path / "intake"
    intake.mkdir()
    archive = intake / "export.zip"
    _write_export(archive)
    inventory = inventory_chatgpt_export(
        archive, intake_root=intake, fingerprint_key=b"f" * 32
    )

    result = build_exact_pilot_manifests(
        archive,
        intake_root=intake,
        fingerprint_key=b"f" * 32,
        reviewed_inventory=inventory,
        selection=_selection(inventory),
        campaign_id=_CAMPAIGN,
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="openrouter-private-v1",
        model_route="openrouter/test-model",
    )

    assert result.bundle.authorization_state == "proposed_not_authorized"
    assert result.bundle.included_record_count == 3
    assert result.bundle.excluded_record_count == 2
    assert result.bundle.excluded_attachment_reference_count == 0
    records = result.bundle.manifest.records
    assert result.bundle.manifest.campaign_id == _CAMPAIGN
    assert result.bundle.manifest.contract_version == "2"
    assert result.bundle.manifest.max_request_total_tokens == 64_000
    assert result.bundle.manifest.source_conversation_id.startswith("pilot:")
    assert {record.native_node_id for record in records if record.included} == {
        "owner",
        "shown",
        "alternate",
    }
    owner = next(record for record in records if record.native_node_id == "owner")
    shown = next(record for record in records if record.native_node_id == "shown")
    alternate = next(record for record in records if record.native_node_id == "alternate")
    assert owner.role == "owner" and owner.native_role == "user"
    assert owner.parent_source_record_id is None
    assert shown.parent_source_record_id == owner.source_record_id
    assert alternate.parent_source_record_id == owner.source_record_id
    assert shown.displayed is True and alternate.displayed is False
    assert alternate.occurred_at is None
    assert all(record.content_commitment for record in records)
    assert all(record.exclusion_reason for record in records if not record.included)
    serialized = result.model_dump_json()
    assert "private canary" not in serialized
    assert "shown answer" not in serialized
    assert "tool payload" not in serialized

    requests = build_exact_archive_requests(result, fingerprint_key=b"f" * 32)
    assert len(requests) == 3
    assert {request.source_conversation_id for request in requests} == {
        "conversation-1"
    }
    assert all(
        request.content_classification == "memory_import.protected"
        for request in requests
    )
    assert len({request.idempotency_key for request in requests}) == 3
    owner_message = result.conversations[0].messages[0].model_copy(
        update={"content": "changed after manifest review"}
    )
    changed_build = LocalPilotBuildV1(
        bundle=result.bundle,
        conversations=(
            LocalChatGPTConversationV1(
                conversation_id=result.conversations[0].conversation_id,
                messages=(owner_message, *result.conversations[0].messages[1:]),
            ),
        ),
    )
    with pytest.raises(ValueError, match="differs from the exact pilot manifest"):
        build_exact_archive_requests(changed_build, fingerprint_key=b"f" * 32)


def test_exact_pilot_manifest_rejects_changed_archive_or_selection(tmp_path: Path) -> None:
    intake = tmp_path / "intake"
    intake.mkdir()
    archive = intake / "export.zip"
    _write_export(archive)
    inventory = inventory_chatgpt_export(
        archive, intake_root=intake, fingerprint_key=b"f" * 32
    )
    selection = _selection(inventory)
    changed_conversation = selection.selected_conversations[0].model_copy(
        update={"title": "changed after review"}
    )
    with pytest.raises(ValueError, match="differs from reviewed inventory"):
        build_exact_pilot_manifests(
            archive,
            intake_root=intake,
            fingerprint_key=b"f" * 32,
            reviewed_inventory=inventory,
            selection=selection.model_copy(
                update={"selected_conversations": (changed_conversation,)}
            ),
            campaign_id=_CAMPAIGN,
            extractor_version="extractor-v1",
            prompt_version="prompt-v1",
            provider_policy_id="private-v1",
            model_route="none",
        )


def test_manifest_cli_writes_only_plaintext_free_non_authorizing_bundle(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    intake = tmp_path / "intake"
    intake.mkdir()
    archive = intake / "export.zip"
    key = intake / "fingerprint.key"
    inventory_path = intake / "inventory.v1.json"
    selection_path = intake / "pilot-selection.v1.json"
    output = intake / "pilot-manifest.v1.json"
    _write_export(archive)
    key.write_bytes(b"f" * 32)
    inventory = inventory_chatgpt_export(
        archive, intake_root=intake, fingerprint_key=key.read_bytes()
    )
    selection = _selection(inventory)
    inventory_path.write_bytes(canonical_json_bytes(inventory) + b"\n")
    selection_path.write_bytes(
        canonical_json_bytes(
            {"proposal": selection, "proposal_digest": selection.digest}
        )
        + b"\n"
    )

    assert main(
        [
            "manifest",
            "--zip",
            str(archive),
            "--intake-root",
            str(intake),
            "--fingerprint-key-file",
            str(key),
            "--inventory",
            str(inventory_path),
            "--selection",
            str(selection_path),
            "--output",
            str(output),
            "--campaign-id",
            str(_CAMPAIGN),
            "--extractor-version",
            "extractor-v1",
            "--prompt-version",
            "prompt-v1",
            "--provider-policy-id",
            "private-v1",
            "--model-route",
            "none",
        ]
    ) == 0
    serialized = output.read_text(encoding="utf-8")
    document = json.loads(serialized)
    assert document["bundle_digest"]
    assert document["bundle"]["authorization_state"] == "proposed_not_authorized"
    assert document["bundle"]["included_record_count"] == 3
    assert "private canary" not in serialized
    assert "shown answer" not in serialized
    assert "network calls: 0" in capsys.readouterr().out

    with zipfile.ZipFile(archive, "a", compression=zipfile.ZIP_STORED) as source:
        source.writestr("changed.txt", b"changed")
    with pytest.raises(ValueError, match="changed after inventory review"):
        build_exact_pilot_manifests(
            archive,
            intake_root=intake,
            fingerprint_key=b"f" * 32,
            reviewed_inventory=inventory,
            selection=selection,
            campaign_id=_CAMPAIGN,
            extractor_version="extractor-v1",
            prompt_version="prompt-v1",
            provider_policy_id="private-v1",
            model_route="none",
        )
