from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

import lucy.memory_import_cli as memory_import_cli
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


def test_authorize_and_preflight_cli_require_the_exact_rebuilt_bundle(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    intake = tmp_path / "intake"
    intake.mkdir()
    archive = intake / "export.zip"
    key = intake / "fingerprint.key"
    inventory_path = intake / "inventory.v1.json"
    selection_path = intake / "pilot-selection.v1.json"
    manifest_path = intake / "pilot-manifest.v1.json"
    authorization_path = intake / "pilot-authorization.v1.json"
    preflight_path = intake / "pilot-preflight.v1.json"
    _write_export(archive)
    key.write_bytes(b"f" * 32)
    inventory = inventory_chatgpt_export(
        archive, intake_root=intake, fingerprint_key=key.read_bytes()
    )
    selection = _selection(inventory)
    inventory_path.write_bytes(canonical_json_bytes(inventory) + b"\n")
    selection_path.write_bytes(
        canonical_json_bytes({"proposal": selection, "proposal_digest": selection.digest})
        + b"\n"
    )
    manifest_args = [
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
        str(manifest_path),
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
    assert main(manifest_args) == 0
    digest = json.loads(manifest_path.read_bytes())["bundle_digest"]
    approval_ref = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    authorize_args = [
        "authorize",
        "--intake-root",
        str(intake),
        "--manifest",
        str(manifest_path),
        "--expected-bundle-digest",
        digest,
        "--owner-approval-ref",
        str(approval_ref),
        "--owner-actor-id",
        "raymond-private-owner",
        "--approved-at",
        datetime.now(UTC).isoformat(),
        "--confirmation",
        f"AUTHORIZE PRIVATE LUCY PILOT {digest}",
        "--output",
        str(authorization_path),
    ]
    assert main(authorize_args) == 0
    serialized_authorization = authorization_path.read_text(encoding="utf-8")
    assert "private canary" not in serialized_authorization
    assert json.loads(serialized_authorization)["authorization_state"] == "authorized"
    with pytest.raises(FileExistsError):
        main(authorize_args)

    preflight_args = [
        "preflight",
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
        "--authorization",
        str(authorization_path),
        "--expected-bundle-digest",
        digest,
        "--output",
        str(preflight_path),
    ]
    assert main(preflight_args) == 0
    report = json.loads(preflight_path.read_bytes())
    assert report["ready_for_execution"] is True
    assert report["network_calls"] == 0
    assert report["bundle_digest"] == digest
    assert "private canary" not in preflight_path.read_text(encoding="utf-8")
    assert "execution performed: no" in capsys.readouterr().out

    registration_path = intake / "pilot-registration.v1.json"

    class RegistrationTransaction:
        def __enter__(self) -> RegistrationTransaction:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, statement: object, values: dict[str, str]) -> object:
            assert "register_memory_import_pilot_authorization_v1" in str(statement)
            assert "private canary" not in values["authorization"]
            return type(
                "Result",
                (),
                {"scalar_one": lambda self: {
                    "owner_approval_ref": str(approval_ref),
                    "replayed": False,
                }},
            )()

    class RegistrationSessions:
        def begin(self) -> RegistrationTransaction:
            return RegistrationTransaction()

    monkeypatch.setenv("LUCY_MIGRATION_DATABASE_URL", "synthetic://migration")
    monkeypatch.setattr(
        memory_import_cli,
        "create_session_factory",
        lambda _url: RegistrationSessions(),
    )
    register_args = [
        "register",
        "--intake-root",
        str(intake),
        "--authorization",
        str(authorization_path),
        "--preflight",
        str(preflight_path),
        "--expected-bundle-digest",
        digest,
        "--confirmation",
        f"REGISTER PRIVATE LUCY PILOT {digest}",
        "--output",
        str(registration_path),
    ]
    assert main(register_args) == 0
    registration = json.loads(registration_path.read_bytes())
    assert registration["bundle_digest"] == digest
    assert registration["owner_approval_ref"] == str(approval_ref)
    assert registration["provider_calls"] == 0
    assert registration["aws_calls"] == 0
    assert "private canary" not in registration_path.read_text(encoding="utf-8")

    wrong_confirmation = list(authorize_args)
    wrong_confirmation[wrong_confirmation.index("--confirmation") + 1] = "wrong"
    with pytest.raises(PermissionError, match="confirmation is not exact"):
        main(wrong_confirmation)
    wrong_digest = list(preflight_args)
    wrong_digest[wrong_digest.index("--expected-bundle-digest") + 1] = "0" * 64
    with pytest.raises(PermissionError, match="differs"):
        main(wrong_digest)
    wrong_registration = list(register_args)
    wrong_registration[wrong_registration.index("--confirmation") + 1] = "wrong"
    with pytest.raises(PermissionError, match="confirmation is not exact"):
        main(wrong_registration)
