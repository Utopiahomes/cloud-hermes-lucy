"""Local-only bounded inventory for ChatGPT data-export archives."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ExportArchiveLimitsV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    max_entries: int = Field(default=50_000, ge=1, le=200_000)
    max_compressed_bytes: int = Field(default=2_000_000_000, ge=1)
    max_uncompressed_bytes: int = Field(default=8_000_000_000, ge=1)
    max_single_entry_bytes: int = Field(default=500_000_000, ge=1)
    max_conversations_json_bytes: int = Field(default=512_000_000, ge=1)
    max_compression_ratio: int = Field(default=100, ge=1, le=10_000)
    max_path_depth: int = Field(default=8, ge=1, le=64)


class ExportInventoryIssueV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    severity: Literal["warning", "quarantined"]
    code: str = Field(min_length=1, max_length=80)
    source_ref: str = Field(min_length=1, max_length=1024)
    detail: str = Field(min_length=1, max_length=500)


class ExportAttachmentInventoryV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    archive_path: str = Field(min_length=1, max_length=2048)
    byte_length: int = Field(ge=0)
    media_kind: Literal["text", "image", "audio", "video", "document", "unsupported"]
    selected: bool = False
    analyzed: bool = False


class ExportConversationInventoryV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    conversation_id: str = Field(min_length=1, max_length=512)
    title: str = Field(min_length=1, max_length=512)
    created_at: datetime | None
    updated_at: datetime | None
    message_count: int = Field(ge=0)
    displayed_message_count: int = Field(ge=0)
    alternate_message_count: int = Field(ge=0)
    missing_timestamp_count: int = Field(ge=0)
    missing_content_count: int = Field(ge=0)
    attachment_reference_count: int = Field(ge=0)
    supported_text_bytes: int = Field(default=0, ge=0)
    estimated_source_tokens: int = Field(default=0, ge=0)
    proposed_domain_tags: tuple[str, ...]
    selected: bool = False


class ChatGPTExportInventoryV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["1"] = "1"
    parser_version: Literal["chatgpt-export-inventory-v1"] = (
        "chatgpt-export-inventory-v1"
    )
    source_namespace: Literal["raymond-private/chatgpt-export"] = (
        "raymond-private/chatgpt-export"
    )
    archive_name: str = Field(min_length=1, max_length=512)
    archive_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    archive_byte_length: int = Field(ge=1)
    entry_count: int = Field(ge=1)
    compressed_bytes: int = Field(ge=0)
    uncompressed_bytes: int = Field(ge=0)
    conversations: tuple[ExportConversationInventoryV1, ...]
    attachments: tuple[ExportAttachmentInventoryV1, ...]
    issues: tuple[ExportInventoryIssueV1, ...]
    inventoried_at: datetime
    network_calls_made: Literal[0] = 0


def verified_intake_path(
    path: Path,
    *,
    intake_root: Path,
    repository_roots: tuple[Path, ...] = (),
    synchronization_roots: tuple[Path, ...] = (),
) -> Path:
    """Resolve a path below the intake root and outside repos/sync roots."""

    resolved_root = intake_root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(resolved_root):
        raise ValueError("import path is outside the verified intake root")
    for unsafe_root in (*repository_roots, *synchronization_roots):
        candidate = unsafe_root.resolve(strict=False)
        if resolved.is_relative_to(candidate) or candidate.is_relative_to(resolved):
            raise ValueError("import path intersects a repository or synchronization root")
    return resolved


def inventory_chatgpt_export(
    zip_path: Path,
    *,
    intake_root: Path,
    fingerprint_key: bytes,
    limits: ExportArchiveLimitsV1 | None = None,
    repository_roots: tuple[Path, ...] = (),
    synchronization_roots: tuple[Path, ...] = (),
) -> ChatGPTExportInventoryV1:
    """Inventory one export without extraction, network access, or content execution."""

    if len(fingerprint_key) != 32:
        raise ValueError("export fingerprint key must contain 32 bytes")
    archive = verified_intake_path(
        zip_path,
        intake_root=intake_root,
        repository_roots=repository_roots,
        synchronization_roots=synchronization_roots,
    )
    selected_limits = limits or ExportArchiveLimitsV1()
    if archive.suffix.lower() != ".zip" or not archive.is_file():
        raise ValueError("ChatGPT export must be a ZIP file")
    archive_size = archive.stat().st_size
    if not 0 < archive_size <= selected_limits.max_compressed_bytes:
        raise ValueError("export archive exceeds its compressed-size limit")
    archive_commitment = _hmac_file(archive, fingerprint_key)
    issues: list[ExportInventoryIssueV1] = []
    attachments: list[ExportAttachmentInventoryV1] = []
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        _validate_entries(entries, selected_limits)
        conversation_entry, conversations_value = _read_conversations(
            source, entries, selected_limits
        )
        conversations = _inventory_conversations(conversations_value, fingerprint_key, issues)
        metadata_names = {
            conversation_entry.filename,
            "user.json",
            "message_feedback.json",
            "shared_conversations.json",
        }
        for item in entries:
            if item.is_dir() or item.filename in metadata_names:
                continue
            attachments.append(
                ExportAttachmentInventoryV1(
                    archive_path=item.filename,
                    byte_length=item.file_size,
                    media_kind=_media_kind(item.filename),
                )
            )
    return ChatGPTExportInventoryV1(
        archive_name=archive.name,
        archive_commitment=archive_commitment,
        archive_byte_length=archive_size,
        entry_count=len(entries),
        compressed_bytes=sum(item.compress_size for item in entries),
        uncompressed_bytes=sum(item.file_size for item in entries),
        conversations=tuple(conversations),
        attachments=tuple(attachments),
        issues=tuple(issues),
        inventoried_at=datetime.now(UTC),
    )


def load_bounded_chatgpt_conversations(
    zip_path: Path,
    *,
    intake_root: Path,
    limits: ExportArchiveLimitsV1 | None = None,
    repository_roots: tuple[Path, ...] = (),
    synchronization_roots: tuple[Path, ...] = (),
) -> list[Any]:
    """Load bounded conversation JSON without extracting files or making network calls."""

    archive = verified_intake_path(
        zip_path,
        intake_root=intake_root,
        repository_roots=repository_roots,
        synchronization_roots=synchronization_roots,
    )
    selected_limits = limits or ExportArchiveLimitsV1()
    if archive.suffix.lower() != ".zip" or not archive.is_file():
        raise ValueError("ChatGPT export must be a ZIP file")
    archive_size = archive.stat().st_size
    if not 0 < archive_size <= selected_limits.max_compressed_bytes:
        raise ValueError("export archive exceeds its compressed-size limit")
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        _validate_entries(entries, selected_limits)
        _, conversations = _read_conversations(source, entries, selected_limits)
    return conversations


def _read_conversations(
    source: zipfile.ZipFile,
    entries: list[zipfile.ZipInfo],
    limits: ExportArchiveLimitsV1,
) -> tuple[zipfile.ZipInfo, list[Any]]:
    conversation_entries = [
        item for item in entries if PurePosixPath(item.filename).name == "conversations.json"
    ]
    if len(conversation_entries) != 1:
        raise ValueError("export must contain exactly one conversations.json")
    conversation_entry = conversation_entries[0]
    if conversation_entry.file_size > limits.max_conversations_json_bytes:
        raise ValueError("conversations.json exceeds its parsing limit")
    raw = source.read(conversation_entry)
    try:
        conversations_value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("conversations.json is not valid UTF-8 JSON") from exc
    if not isinstance(conversations_value, list):
        raise ValueError("conversations.json must contain a list")
    return conversation_entry, conversations_value


def configured_sync_roots(environment: dict[str, str] | None = None) -> tuple[Path, ...]:
    values = os.environ if environment is None else environment
    roots = {
        Path(value)
        for name in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")
        if (value := values.get(name))
    }
    return tuple(sorted(roots, key=lambda item: str(item).casefold()))


def _validate_entries(entries: list[zipfile.ZipInfo], limits: ExportArchiveLimitsV1) -> None:
    if not entries or len(entries) > limits.max_entries:
        raise ValueError("export archive entry count is outside its limit")
    compressed = 0
    uncompressed = 0
    names: set[str] = set()
    for item in entries:
        normalized = PurePosixPath(item.filename.replace("\\", "/"))
        if (
            normalized.is_absolute()
            or ".." in normalized.parts
            or not normalized.parts
            or len(normalized.parts) > limits.max_path_depth
            or ":" in normalized.parts[0]
        ):
            raise ValueError("export archive contains an unsafe path")
        canonical_name = normalized.as_posix().casefold()
        if canonical_name in names:
            raise ValueError("export archive contains duplicate normalized paths")
        names.add(canonical_name)
        mode = item.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise ValueError("export archive contains a symbolic link")
        if item.flag_bits & 0x1:
            raise ValueError("encrypted ZIP entries are unsupported")
        if item.file_size > limits.max_single_entry_bytes:
            raise ValueError("export archive contains an oversized entry")
        if item.file_size and item.compress_size == 0:
            raise ValueError("export archive contains an invalid compression ratio")
        if (
            item.compress_size
            and item.file_size / item.compress_size > limits.max_compression_ratio
        ):
            raise ValueError("export archive contains a suspicious compression ratio")
        compressed += item.compress_size
        uncompressed += item.file_size
    if compressed > limits.max_compressed_bytes or uncompressed > limits.max_uncompressed_bytes:
        raise ValueError("export archive exceeds its aggregate size limit")


def _inventory_conversations(
    values: list[Any], fingerprint_key: bytes, issues: list[ExportInventoryIssueV1]
) -> list[ExportConversationInventoryV1]:
    result: list[ExportConversationInventoryV1] = []
    seen_ids: set[str] = set()
    for index, value in enumerate(values):
        source_ref = f"conversation[{index}]"
        if not isinstance(value, dict):
            issues.append(_issue("quarantined", "malformed_conversation", source_ref))
            continue
        conversation_id = _native_or_fallback_id(
            value.get("id") or value.get("conversation_id"),
            fallback_material=f"conversation:{index}".encode(),
            fingerprint_key=fingerprint_key,
        )
        if conversation_id in seen_ids:
            issues.append(_issue("quarantined", "duplicate_conversation_id", conversation_id))
            continue
        seen_ids.add(conversation_id)
        mapping = value.get("mapping")
        if not isinstance(mapping, dict):
            issues.append(_issue("quarantined", "missing_message_mapping", conversation_id))
            mapping = {}
        displayed = displayed_chatgpt_node_ids(mapping, value.get("current_node"))
        message_count = displayed_count = missing_time = missing_content = attachment_refs = 0
        supported_text_bytes = 0
        for node_id, node in mapping.items():
            if not isinstance(node, dict) or not isinstance(node.get("message"), dict):
                continue
            message_count += 1
            if str(node_id) in displayed:
                displayed_count += 1
            message = node["message"]
            if _timestamp(message.get("create_time")) is None:
                missing_time += 1
            content = message.get("content")
            if not isinstance(content, dict) or not isinstance(content.get("parts"), list):
                missing_content += 1
            else:
                text_parts = [part for part in content["parts"] if isinstance(part, str)]
                supported_text_bytes += sum(len(part.encode("utf-8")) for part in text_parts)
                if len(text_parts) != len(content["parts"]):
                    missing_content += 1
            metadata = message.get("metadata")
            if isinstance(metadata, dict) and isinstance(metadata.get("attachments"), list):
                attachment_refs += len(metadata["attachments"])
        title = value.get("title")
        safe_title = (
            title.strip()
            if isinstance(title, str) and title.strip()
            else "Untitled conversation"
        )
        if len(safe_title) > 512:
            safe_title = safe_title[:512]
            issues.append(_issue("warning", "title_too_long", conversation_id))
        result.append(
            ExportConversationInventoryV1(
                conversation_id=conversation_id,
                title=safe_title,
                created_at=_timestamp(value.get("create_time")),
                updated_at=_timestamp(value.get("update_time")),
                message_count=message_count,
                displayed_message_count=displayed_count,
                alternate_message_count=max(0, message_count - displayed_count),
                missing_timestamp_count=missing_time,
                missing_content_count=missing_content,
                attachment_reference_count=attachment_refs,
                supported_text_bytes=supported_text_bytes,
                estimated_source_tokens=(supported_text_bytes + 2) // 3,
                proposed_domain_tags=_domain_tags(safe_title),
            )
        )
    return result


def displayed_chatgpt_node_ids(mapping: dict[str, Any], current_node: Any) -> set[str]:
    displayed: set[str] = set()
    cursor = str(current_node) if current_node is not None else ""
    while cursor and cursor not in displayed:
        displayed.add(cursor)
        node = mapping.get(cursor)
        if not isinstance(node, dict) or node.get("parent") is None:
            break
        cursor = str(node["parent"])
    return displayed


def _native_or_fallback_id(value: Any, *, fallback_material: bytes, fingerprint_key: bytes) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()[:512]
    digest = hmac.new(
        fingerprint_key,
        b"LUCY-CHATGPT-EXPORT-FALLBACK-ID-V1\x00" + fallback_material,
        hashlib.sha256,
    ).hexdigest()
    return f"fallback-{digest}"


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, (int, float)) and value >= 0:
        try:
            return datetime.fromtimestamp(value, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    return None


def _domain_tags(title: str) -> tuple[str, ...]:
    lowered = title.casefold()
    tags = tuple(
        tag
        for tag, needles in (
            ("siqm", ("siqm",)),
            ("stoin", ("stoin", "stoinnet")),
            ("cloud-lucy", ("cloud lucy", "hermes", "lucy")),
            ("accounting", ("accounting", "bookkeeping", "tax")),
            ("utopia", ("utopia",)),
            ("personal", ("personal", "family", "health")),
        )
        if any(needle in lowered for needle in needles)
    )
    return tags or ("unclassified",)


def _media_kind(
    name: str,
) -> Literal["text", "image", "audio", "video", "document", "unsupported"]:
    suffix = PurePosixPath(name).suffix.casefold()
    if suffix in {".txt", ".md", ".json", ".csv"}:
        return "text"
    if suffix in {".png", ".jpg", ".jpeg", ".webp", ".gif"}:
        return "image"
    if suffix in {".mp3", ".wav", ".m4a", ".ogg"}:
        return "audio"
    if suffix in {".mp4", ".mov", ".webm"}:
        return "video"
    if suffix in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}:
        return "document"
    return "unsupported"


def _issue(
    severity: Literal["warning", "quarantined"], code: str, ref: str
) -> ExportInventoryIssueV1:
    return ExportInventoryIssueV1(
        severity=severity,
        code=code,
        source_ref=ref,
        detail=code.replace("_", " "),
    )


def _hmac_file(path: Path, key: bytes) -> str:
    commitment = hmac.new(key, b"LUCY-CHATGPT-EXPORT-ZIP-V1\x00", hashlib.sha256)
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            commitment.update(chunk)
    return commitment.hexdigest()
