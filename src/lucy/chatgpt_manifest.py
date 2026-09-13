"""Exact, plaintext-free pilot manifests derived locally from ChatGPT exports."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from lucy.chatgpt_import import (
    ChatGPTExportInventoryV1,
    displayed_chatgpt_node_ids,
    inventory_chatgpt_export,
    load_bounded_chatgpt_conversations,
)
from lucy.contracts.canonical import canonical_json_bytes, canonical_sha256
from lucy.memory_import import ImportManifestRecordV1, ImportManifestV1, ImportManifestV2
from lucy.memory_import_console import PilotSelectionProposalV1
from lucy.realm_archive_commit import RealmArchiveCommitInputV1

_BUNDLE_PREFIX = b"LUCY-CHATGPT-PILOT-MANIFEST-BUNDLE-V1\x00"
_RECORD_PREFIX = b"LUCY-CHATGPT-RECORD-CONTENT-V1\x00"


class LocalChatGPTMessageV1(BaseModel):
    """A selected local representation; never serialize this as an approval artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    source_record_id: str
    conversation_id: str
    native_node_id: str
    native_message_id: str
    parent_source_record_id: str | None
    native_role: str
    role: Literal["owner", "assistant", "system", "unsupported"]
    occurred_at: datetime | None
    displayed: bool
    source_revision: int = 1
    content: str | None
    inclusion_state: Literal["included", "excluded"]
    exclusion_reason: str | None = None


class LocalChatGPTConversationV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    conversation_id: str
    messages: tuple[LocalChatGPTMessageV1, ...]


class PilotManifestBundleV1(BaseModel):
    """Reviewable exact records and limits; this is not execution authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["1"] = "1"
    selection_proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    archive_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    campaign_id: UUID
    destination_content_scope_id: UUID
    manifest: ImportManifestV1 | ImportManifestV2
    included_record_count: int = Field(ge=1)
    excluded_record_count: int = Field(ge=0)
    included_source_bytes: int = Field(ge=1)
    estimated_source_tokens: int = Field(ge=1)
    excluded_attachment_reference_count: int = Field(ge=0)
    authorization_state: Literal["proposed_not_authorized"] = "proposed_not_authorized"

    @property
    def digest(self) -> str:
        return canonical_sha256(self, prefix=_BUNDLE_PREFIX)


class LocalPilotBuildV1(BaseModel):
    """In-memory build result; only ``bundle`` is safe as a review artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    bundle: PilotManifestBundleV1
    conversations: tuple[LocalChatGPTConversationV1, ...] = Field(exclude=True)


def build_exact_pilot_manifests(
    zip_path: Path,
    *,
    intake_root: Path,
    fingerprint_key: bytes,
    reviewed_inventory: ChatGPTExportInventoryV1,
    selection: PilotSelectionProposalV1,
    campaign_id: UUID,
    extractor_version: str,
    prompt_version: str,
    provider_policy_id: str,
    model_route: str,
    repository_roots: tuple[Path, ...] = (),
    synchronization_roots: tuple[Path, ...] = (),
) -> LocalPilotBuildV1:
    """Expand a reviewed selection into exact local records without model/network access."""

    if len(fingerprint_key) != 32:
        raise ValueError("manifest fingerprint key must contain 32 bytes")
    selection = PilotSelectionProposalV1.model_validate(selection.model_dump())
    if selection.inventory_archive_commitment != reviewed_inventory.archive_commitment:
        raise ValueError("selection does not bind the reviewed inventory")
    current_inventory = inventory_chatgpt_export(
        zip_path,
        intake_root=intake_root,
        fingerprint_key=fingerprint_key,
        repository_roots=repository_roots,
        synchronization_roots=synchronization_roots,
    )
    if current_inventory.archive_commitment != reviewed_inventory.archive_commitment:
        raise ValueError("export archive changed after inventory review")
    inventory_by_id = {
        item.conversation_id: item for item in reviewed_inventory.conversations
    }
    for selected in selection.selected_conversations:
        inventoried = inventory_by_id.get(selected.conversation_id)
        if inventoried is None or selected.model_dump() != inventoried.model_dump(
            exclude={"selected"}
        ):
            raise ValueError("selection conversation differs from reviewed inventory")
    raw_conversations = load_bounded_chatgpt_conversations(
        zip_path,
        intake_root=intake_root,
        repository_roots=repository_roots,
        synchronization_roots=synchronization_roots,
    )
    selected_ids = {item.conversation_id for item in selection.selected_conversations}
    raw_by_id = {
        str(item.get("id") or item.get("conversation_id")): item
        for item in raw_conversations
        if isinstance(item, dict)
        and str(item.get("id") or item.get("conversation_id")) in selected_ids
    }
    if set(raw_by_id) != selected_ids:
        raise ValueError("selected conversations are missing from the export")

    parsed_conversations: list[LocalChatGPTConversationV1] = []
    all_records: list[ImportManifestRecordV1] = []
    for selected in selection.selected_conversations:
        parsed = _parse_conversation(raw_by_id[selected.conversation_id])
        records = tuple(
            manifest_record_for_local_message(message, fingerprint_key)
            for message in parsed.messages
        )
        included = tuple(record for record in records if record.included)
        if not included:
            raise ValueError("a selected conversation has no supported message content")
        all_records.extend(records)
        parsed_conversations.append(parsed)

    included_records = tuple(record for record in all_records if record.included)
    manifest = ImportManifestV2(
        campaign_id=campaign_id,
        destination_content_scope_id=selection.destination_content_scope_id,
        source_namespace="raymond-private/chatgpt-export",
        source_conversation_id=f"pilot:{selection.digest}",
        parser_version=reviewed_inventory.parser_version,
        extractor_version=extractor_version,
        prompt_version=prompt_version,
        provider_policy_id=provider_policy_id,
        model_route=model_route,
        records=tuple(all_records),
        max_records=len(included_records),
        max_bytes=sum(record.byte_length for record in included_records),
        token_accounting_version=selection.token_accounting_version,
        max_source_estimated_tokens=sum(
            record.estimated_tokens for record in included_records
        ),
        max_request_input_tokens=selection.max_request_input_tokens,
        max_request_output_tokens=selection.max_request_output_tokens,
        max_request_total_tokens=selection.max_request_total_tokens,
        max_model_spend_microusd=selection.max_model_spend_microusd,
        max_attempts=selection.max_attempts,
        expires_at=selection.expires_at,
    )
    bundle = PilotManifestBundleV1(
        selection_proposal_digest=selection.digest,
        archive_commitment=reviewed_inventory.archive_commitment,
        campaign_id=campaign_id,
        destination_content_scope_id=selection.destination_content_scope_id,
        manifest=manifest,
        included_record_count=sum(record.included for record in all_records),
        excluded_record_count=sum(not record.included for record in all_records),
        included_source_bytes=sum(
            record.byte_length for record in all_records if record.included
        ),
        estimated_source_tokens=sum(
            record.estimated_tokens for record in all_records if record.included
        ),
        excluded_attachment_reference_count=(
            selection.selected_attachment_reference_count
        ),
    )
    return LocalPilotBuildV1(
        bundle=bundle, conversations=tuple(parsed_conversations)
    )


def build_exact_archive_requests(
    build: LocalPilotBuildV1, *, fingerprint_key: bytes
) -> tuple[RealmArchiveCommitInputV1, ...]:
    """Recheck local plaintext against the exact manifest before protected intake."""

    if len(fingerprint_key) != 32:
        raise ValueError("manifest fingerprint key must contain 32 bytes")
    manifest = build.bundle.manifest
    local_by_id = {
        message.source_record_id: message
        for conversation in build.conversations
        for message in conversation.messages
    }
    requests: list[RealmArchiveCommitInputV1] = []
    for record in manifest.records:
        if not record.included:
            continue
        message = local_by_id.get(record.source_record_id)
        if (
            message is None
            or manifest_record_for_local_message(message, fingerprint_key) != record
        ):
            raise ValueError("local message content differs from the exact pilot manifest")
        if message.content is None:
            raise ValueError("included local message content is unavailable")
        header = canonical_json_bytes(
            {
                "contract_version": "1",
                "manifest_digest": manifest.digest,
                "source_namespace": manifest.source_namespace,
                "source_record_id": record.source_record_id,
                "content_commitment": record.content_commitment,
                "byte_length": record.byte_length,
                "source_revision": record.source_revision,
                "role": record.role,
                "parent_source_record_id": record.parent_source_record_id,
                "displayed": record.displayed,
                "destination_content_scope_id": manifest.destination_content_scope_id,
                "protection_class": manifest.default_protection,
            }
        )
        requests.append(
            RealmArchiveCommitInputV1(
                source_conversation_id=message.conversation_id,
                source_turn_id=message.source_record_id,
                idempotency_key=(
                    f"memory-import:{manifest.digest}:{record.source_record_id}:"
                    f"r{record.source_revision}"
                ),
                plaintext=message.content.encode("utf-8"),
                authenticated_header=header,
                content_classification="memory_import.protected",
                lineage_refs=(record.parent_source_record_id,)
                if record.parent_source_record_id
                else (),
            )
        )
    if len(requests) != build.bundle.included_record_count:
        raise ValueError("local message count differs from the exact pilot manifest")
    return tuple(requests)


def _parse_conversation(value: dict[str, Any]) -> LocalChatGPTConversationV1:
    conversation_id = str(value.get("id") or value.get("conversation_id"))
    mapping = value.get("mapping")
    if not isinstance(mapping, dict):
        raise ValueError("selected conversation has no message mapping")
    displayed = displayed_chatgpt_node_ids(mapping, value.get("current_node"))
    source_ids: dict[str, str] = {}
    for node_id, node in mapping.items():
        if isinstance(node, dict) and isinstance(node.get("message"), dict):
            message = node["message"]
            message_id = str(message.get("id") or node_id)
            source_ids[str(node_id)] = f"{conversation_id}:{node_id}:{message_id}"
    messages: list[LocalChatGPTMessageV1] = []
    for node_id, node in mapping.items():
        if not isinstance(node, dict) or not isinstance(node.get("message"), dict):
            continue
        message = node["message"]
        native_node_id = str(node_id)
        native_message_id = str(message.get("id") or node_id)
        native_role = _native_role(message)
        role = _normalized_role(native_role)
        content = _text_content(message)
        exclusion = None
        if role == "unsupported":
            exclusion = f"unsupported native role: {native_role[:100]}"
        elif content is None or not content:
            exclusion = "missing or unsupported message content"
        parent_source_id = _nearest_parent_source_id(node, mapping, source_ids)
        messages.append(
            LocalChatGPTMessageV1(
                source_record_id=source_ids[native_node_id],
                conversation_id=conversation_id,
                native_node_id=native_node_id,
                native_message_id=native_message_id,
                parent_source_record_id=parent_source_id,
                native_role=native_role[:100],
                role=role,
                occurred_at=_message_timestamp(message.get("create_time")),
                displayed=native_node_id in displayed,
                content=content,
                inclusion_state="excluded" if exclusion else "included",
                exclusion_reason=exclusion,
            )
        )
    return LocalChatGPTConversationV1(
        conversation_id=conversation_id, messages=tuple(messages)
    )


def manifest_record_for_local_message(
    message: LocalChatGPTMessageV1, fingerprint_key: bytes
) -> ImportManifestRecordV1:
    content = (message.content or "").encode("utf-8")
    commitment_material = (
        f"{message.source_record_id}:r{message.source_revision}\x00".encode() + content
    )
    return ImportManifestRecordV1(
        source_record_id=message.source_record_id,
        content_commitment=hmac.new(
            fingerprint_key, _RECORD_PREFIX + commitment_material, hashlib.sha256
        ).hexdigest(),
        byte_length=len(content),
        estimated_tokens=(len(content) + 2) // 3 if content else 0,
        source_revision=message.source_revision,
        role=message.role,
        native_role=message.native_role,
        native_message_id=message.native_message_id,
        native_node_id=message.native_node_id,
        occurred_at=message.occurred_at,
        parent_source_record_id=message.parent_source_record_id,
        displayed=message.displayed,
        included=message.inclusion_state == "included",
        exclusion_reason=message.exclusion_reason,
    )


def _native_role(message: dict[str, Any]) -> str:
    author = message.get("author")
    if isinstance(author, dict):
        role = author.get("role")
        if isinstance(role, str):
            return role
    return "unknown"


def _normalized_role(
    role: str,
) -> Literal["owner", "assistant", "system", "unsupported"]:
    if role == "user":
        return "owner"
    if role == "assistant":
        return "assistant"
    if role == "system":
        return "system"
    return "unsupported"


def _text_content(message: dict[str, Any]) -> str | None:
    content = message.get("content")
    if not isinstance(content, dict) or not isinstance(content.get("parts"), list):
        return None
    parts = content["parts"]
    if not all(isinstance(part, str) for part in parts):
        return None
    return "\n".join(parts)


def _nearest_parent_source_id(
    node: dict[str, Any], mapping: dict[str, Any], source_ids: dict[str, str]
) -> str | None:
    parent = node.get("parent")
    visited: set[str] = set()
    while parent is not None:
        parent_id = str(parent)
        if parent_id in visited:
            raise ValueError("message graph contains a parent cycle")
        visited.add(parent_id)
        if parent_id in source_ids:
            return source_ids[parent_id]
        parent_node = mapping.get(parent_id)
        if not isinstance(parent_node, dict):
            return None
        parent = parent_node.get("parent")
    return None


def _message_timestamp(value: Any) -> datetime | None:
    from datetime import UTC

    if isinstance(value, (int, float)) and value >= 0:
        try:
            return datetime.fromtimestamp(value, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    return None
