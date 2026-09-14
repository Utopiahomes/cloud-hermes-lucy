from __future__ import annotations

import json
import stat
import zipfile
from pathlib import Path

import pytest

from lucy.chatgpt_import import (
    ExportArchiveLimitsV1,
    inventory_chatgpt_export,
    verified_intake_path,
)
from lucy.memory_import_cli import main


def _conversation_export() -> list[object]:
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
                    "message": {
                        "id": "message-owner",
                        "author": {"role": "user"},
                        "create_time": 1_757_683_200,
                        "content": {"content_type": "text", "parts": ["private canary"]},
                        "metadata": {"attachments": [{"id": "file-1"}]},
                    },
                },
                "shown": {
                    "id": "shown",
                    "parent": "owner",
                    "message": {
                        "id": "message-shown",
                        "author": {"role": "assistant"},
                        "create_time": 1_757_683_201,
                        "content": {"content_type": "text", "parts": ["shown answer"]},
                        "metadata": {},
                    },
                },
                "alternate": {
                    "id": "alternate",
                    "parent": "owner",
                    "message": {
                        "id": "message-alternate",
                        "author": {"role": "assistant"},
                        "create_time": None,
                        "content": {"content_type": "text", "parts": ["other answer"]},
                        "metadata": {},
                    },
                },
            },
        },
        "malformed",
    ]


def _write_export(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("conversations.json", json.dumps(_conversation_export()))
        archive.writestr("file-1.png", b"synthetic-image")
        archive.writestr("unsupported.bin", b"synthetic-unsupported")


def test_local_inventory_preserves_branch_counts_without_message_plaintext(tmp_path: Path) -> None:
    intake = tmp_path / "private-intake"
    intake.mkdir()
    archive = intake / "export.zip"
    _write_export(archive)

    report = inventory_chatgpt_export(
        archive,
        intake_root=intake,
        fingerprint_key=b"f" * 32,
        repository_roots=(tmp_path / "repository",),
    )

    assert report.network_calls_made == 0
    assert len(report.conversations) == 1
    conversation = report.conversations[0]
    assert conversation.message_count == 3
    assert conversation.displayed_message_count == 2
    assert conversation.alternate_message_count == 1
    assert conversation.missing_timestamp_count == 1
    assert conversation.attachment_reference_count == 1
    assert conversation.supported_text_bytes == 38
    assert conversation.estimated_source_tokens == 13
    assert conversation.proposed_domain_tags == ("cloud-lucy",)
    assert {item.media_kind for item in report.attachments} == {"image", "unsupported"}
    assert report.issues[0].code == "malformed_conversation"
    assert "private canary" not in report.model_dump_json()


def test_archive_commitment_is_keyed_and_archive_changes_are_visible(tmp_path: Path) -> None:
    intake = tmp_path / "intake"
    intake.mkdir()
    first = intake / "first.zip"
    second = intake / "second.zip"
    _write_export(first)
    _write_export(second)
    with zipfile.ZipFile(second, "a", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("extra.txt", b"changed")
    first_report = inventory_chatgpt_export(
        first, intake_root=intake, fingerprint_key=b"f" * 32
    )
    second_report = inventory_chatgpt_export(
        second, intake_root=intake, fingerprint_key=b"f" * 32
    )
    other_key = inventory_chatgpt_export(
        first, intake_root=intake, fingerprint_key=b"g" * 32
    )
    assert first_report.archive_commitment != second_report.archive_commitment
    assert first_report.archive_commitment != other_key.archive_commitment


@pytest.mark.parametrize("entry_name", ("../escape", "/absolute", "C:/drive"))
def test_unsafe_archive_paths_are_rejected(tmp_path: Path, entry_name: str) -> None:
    intake = tmp_path / "intake"
    intake.mkdir()
    archive_path = intake / "unsafe.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("conversations.json", "[]")
        archive.writestr(entry_name, "unsafe")
    with pytest.raises(ValueError, match="unsafe path"):
        inventory_chatgpt_export(
            archive_path, intake_root=intake, fingerprint_key=b"f" * 32
        )


def test_symbolic_links_and_suspicious_compression_are_rejected(tmp_path: Path) -> None:
    intake = tmp_path / "intake"
    intake.mkdir()
    link_archive = intake / "link.zip"
    with zipfile.ZipFile(link_archive, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("conversations.json", "[]")
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "target")
    with pytest.raises(ValueError, match="symbolic link"):
        inventory_chatgpt_export(
            link_archive, intake_root=intake, fingerprint_key=b"f" * 32
        )

    compressed = intake / "compressed.zip"
    with zipfile.ZipFile(compressed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("conversations.json", "[]")
        archive.writestr("bomb.txt", b"a" * 20_000)
    with pytest.raises(ValueError, match="compression ratio"):
        inventory_chatgpt_export(
            compressed,
            intake_root=intake,
            fingerprint_key=b"f" * 32,
            limits=ExportArchiveLimitsV1(max_compression_ratio=2),
        )


def test_intake_path_must_avoid_repositories_and_sync_roots(tmp_path: Path) -> None:
    intake = tmp_path / "intake"
    intake.mkdir()
    archive = intake / "export.zip"
    _write_export(archive)
    assert verified_intake_path(archive, intake_root=intake) == archive.resolve()
    with pytest.raises(ValueError, match="intersects"):
        verified_intake_path(
            archive,
            intake_root=intake,
            synchronization_roots=(tmp_path,),
        )


def test_inventory_cli_writes_only_the_bounded_local_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    intake = tmp_path / "intake"
    intake.mkdir()
    archive = intake / "export.zip"
    key = intake / "fingerprint.key"
    output = intake / "inventory.v1.json"
    _write_export(archive)
    key.write_bytes(b"f" * 32)

    assert main(
        [
            "inventory",
            "--zip",
            str(archive),
            "--intake-root",
            str(intake),
            "--fingerprint-key-file",
            str(key),
            "--output",
            str(output),
        ]
    ) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["network_calls_made"] == 0
    assert "private canary" not in output.read_text(encoding="utf-8")
    assert "Inventoried 1 conversations" in capsys.readouterr().out
