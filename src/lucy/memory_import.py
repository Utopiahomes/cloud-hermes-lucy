"""Contracts and bounded context assembly for governed private-memory imports."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from lucy.contracts.canonical import canonical_sha256
from lucy.realm_archive_commit import RealmArchiveCommitInputV1

_CANDIDATE_PREFIX = b"LUCY-MEMORY-CANDIDATE-V1\x00"
_MANIFEST_PREFIX = b"LUCY-MEMORY-IMPORT-MANIFEST-V1\x00"
_MANIFEST_V2_PREFIX = b"LUCY-MEMORY-IMPORT-MANIFEST-V2\x00"


class MemoryKind(StrEnum):
    EPISODE = "episode"
    ASSERTION = "assertion"
    PROJECT_STATE = "project_state"
    ENTITY = "entity"
    PROCEDURE = "procedure"


class AssertionStatus(StrEnum):
    REPORT = "report"
    PREFERENCE = "preference"
    PROPOSAL = "proposal"
    HYPOTHESIS = "hypothesis"
    DECISION = "decision"
    ASSISTANT_RECOMMENDATION = "assistant_recommendation"
    ATTRIBUTED_INTERPRETATION = "attributed_interpretation"


class ProtectionClass(StrEnum):
    ORDINARY_PRIVATE = "ordinary_private"
    PROTECTED = "protected"


class EpistemicStatus(StrEnum):
    UNCERTAIN = "uncertain"
    DISPUTED = "disputed"
    CURRENT = "current"
    HISTORICAL = "historical"
    CONTRADICTED = "contradicted"
    SUPERSEDED = "superseded"


class SourceSpanV1(BaseModel):
    """One exact UTF-8 byte span in an immutable evidence record version."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    source_record_id: str = Field(min_length=1, max_length=512)
    evidence_id: UUID
    record_version: int = Field(ge=1)
    byte_start: int = Field(ge=0)
    byte_end: int = Field(gt=0)

    @model_validator(mode="after")
    def ordered_span(self) -> SourceSpanV1:
        if self.byte_end <= self.byte_start:
            raise ValueError("source span end must be greater than its start")
        return self


class MemoryCandidatePayloadV1(BaseModel):
    """Exact candidate bytes reviewed by an owner before promotion."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: str = Field(default="1", pattern=r"^1$")
    candidate_id: UUID
    candidate_version: int = Field(ge=1)
    campaign_id: UUID
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    extraction_job_id: UUID
    extractor_version: str = Field(min_length=1, max_length=100)
    prompt_version: str = Field(min_length=1, max_length=100)
    model_route: str = Field(min_length=1, max_length=200)
    destination_content_scope_id: UUID
    subject: str = Field(min_length=1, max_length=200)
    predicate: str = Field(min_length=1, max_length=200)
    object: str = Field(min_length=1, max_length=4000)
    confidence_millionths: int = Field(ge=0, le=1_000_000)
    memory_kind: MemoryKind
    assertion_status: AssertionStatus
    epistemic_status: EpistemicStatus
    protection_class: ProtectionClass = ProtectionClass.PROTECTED
    domain_tags: tuple[str, ...] = Field(default=(), max_length=16)
    event_time: datetime | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    sources: tuple[SourceSpanV1, ...] = Field(min_length=1, max_length=32)
    supersedes_candidate_id: UUID | None = None

    @model_validator(mode="after")
    def deterministic_collections(self) -> MemoryCandidatePayloadV1:
        if len(set(self.domain_tags)) != len(self.domain_tags):
            raise ValueError("domain tags must be unique")
        source_keys = {
            (item.evidence_id, item.record_version, item.byte_start, item.byte_end)
            for item in self.sources
        }
        if len(source_keys) != len(self.sources):
            raise ValueError("source spans must be unique")
        if self.valid_from and self.valid_to and self.valid_to <= self.valid_from:
            raise ValueError("valid_to must be later than valid_from")
        return self

    @property
    def digest(self) -> str:
        return canonical_sha256(self, prefix=_CANDIDATE_PREFIX)


class SyntheticMessageV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    message_id: str = Field(min_length=1, max_length=512)
    parent_message_id: str | None = Field(default=None, max_length=512)
    role: str = Field(pattern=r"^(owner|assistant|system)$")
    occurred_at: datetime
    content: str = Field(min_length=1, max_length=65_536)
    displayed: bool = True
    source_revision: int = Field(default=1, ge=1)


class SyntheticConversationV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: str = Field(default="1", pattern=r"^1$")
    conversation_id: str = Field(min_length=1, max_length=512)
    title: str = Field(min_length=1, max_length=512)
    messages: tuple[SyntheticMessageV1, ...] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def valid_graph(self) -> SyntheticConversationV1:
        ids = [item.message_id for item in self.messages]
        if len(set(ids)) != len(ids):
            raise ValueError("synthetic message IDs must be unique")
        seen: set[str] = set()
        for item in self.messages:
            if item.parent_message_id is not None and item.parent_message_id not in seen:
                raise ValueError("a parent message must precede its child")
            seen.add(item.message_id)
        return self


class ImportManifestRecordV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source_record_id: str
    content_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    byte_length: int = Field(ge=0, le=1_000_000)
    estimated_tokens: int = Field(ge=0)
    source_revision: int = Field(ge=1)
    role: str = Field(pattern=r"^(owner|assistant|system|unsupported)$")
    native_role: str | None = Field(default=None, max_length=100)
    native_message_id: str | None = Field(default=None, max_length=512)
    native_node_id: str | None = Field(default=None, max_length=512)
    occurred_at: datetime | None = None
    parent_source_record_id: str | None = None
    displayed: bool
    included: bool = True
    exclusion_reason: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def explicit_inclusion(self) -> ImportManifestRecordV1:
        if self.included and (self.byte_length < 1 or self.estimated_tokens < 1):
            raise ValueError("included records must contain bounded content")
        if self.included and self.exclusion_reason is not None:
            raise ValueError("included records cannot have an exclusion reason")
        if not self.included and self.exclusion_reason is None:
            raise ValueError("excluded records require an exclusion reason")
        return self


class ImportManifestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: str = Field(default="1", pattern=r"^1$")
    campaign_id: UUID
    destination_content_scope_id: UUID
    source_namespace: str = Field(min_length=1, max_length=200)
    source_conversation_id: str = Field(min_length=1, max_length=512)
    parser_version: str = Field(min_length=1, max_length=100)
    extractor_version: str = Field(min_length=1, max_length=100)
    prompt_version: str = Field(min_length=1, max_length=100)
    provider_policy_id: str = Field(min_length=1, max_length=200)
    model_route: str = Field(min_length=1, max_length=200)
    default_protection: ProtectionClass = ProtectionClass.PROTECTED
    records: tuple[ImportManifestRecordV1, ...] = Field(min_length=1, max_length=10_000)
    max_records: int = Field(ge=1, le=10_000)
    max_bytes: int = Field(ge=1)
    max_input_tokens: int = Field(ge=1)
    max_model_spend_microusd: int = Field(ge=0)
    max_attempts: int = Field(ge=1, le=10_000)
    expires_at: datetime

    @model_validator(mode="after")
    def bounded_selection(self) -> ImportManifestV1:
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("manifest expiry must be timezone-aware")
        included = tuple(record for record in self.records if record.included)
        if len(included) > self.max_records:
            raise ValueError("manifest exceeds its record limit")
        if sum(record.byte_length for record in included) > self.max_bytes:
            raise ValueError("manifest exceeds its byte limit")
        if sum(record.estimated_tokens for record in included) > self.max_input_tokens:
            raise ValueError("manifest exceeds its input-token limit")
        return self

    @property
    def digest(self) -> str:
        return canonical_sha256(self, prefix=_MANIFEST_PREFIX)


class ImportManifestV2(BaseModel):
    """Executable manifest with separate source and complete-request budgets."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["2"] = "2"
    campaign_id: UUID
    destination_content_scope_id: UUID
    source_namespace: str = Field(min_length=1, max_length=200)
    source_conversation_id: str = Field(min_length=1, max_length=512)
    parser_version: str = Field(min_length=1, max_length=100)
    extractor_version: str = Field(min_length=1, max_length=100)
    prompt_version: str = Field(min_length=1, max_length=100)
    provider_policy_id: str = Field(min_length=1, max_length=200)
    model_route: str = Field(min_length=1, max_length=200)
    token_accounting_version: str = Field(min_length=1, max_length=100)
    default_protection: ProtectionClass = ProtectionClass.PROTECTED
    records: tuple[ImportManifestRecordV1, ...] = Field(min_length=1, max_length=10_000)
    max_records: int = Field(ge=1, le=10_000)
    max_bytes: int = Field(ge=1)
    max_source_estimated_tokens: int = Field(ge=1)
    max_request_input_tokens: int = Field(ge=1)
    max_request_output_tokens: int = Field(ge=1)
    max_request_total_tokens: int = Field(ge=2)
    max_model_spend_microusd: int = Field(ge=0)
    max_attempts: int = Field(ge=1, le=10_000)
    expires_at: datetime

    @model_validator(mode="after")
    def bounded_selection_and_request(self) -> ImportManifestV2:
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("manifest expiry must be timezone-aware")
        included = tuple(record for record in self.records if record.included)
        source_tokens = sum(record.estimated_tokens for record in included)
        if len(included) > self.max_records:
            raise ValueError("manifest exceeds its record limit")
        if sum(record.byte_length for record in included) > self.max_bytes:
            raise ValueError("manifest exceeds its byte limit")
        if source_tokens > self.max_source_estimated_tokens:
            raise ValueError("manifest exceeds its source-token limit")
        if (
            self.max_request_input_tokens + self.max_request_output_tokens
            > self.max_request_total_tokens
        ):
            raise ValueError("request input and output ceilings exceed the total ceiling")
        return self

    @property
    def digest(self) -> str:
        return canonical_sha256(self, prefix=_MANIFEST_V2_PREFIX)


ImportManifest = ImportManifestV1 | ImportManifestV2


def load_synthetic_conversation(path: Path) -> SyntheticConversationV1:
    """Load the intentionally narrow JSON format used before real export intake exists."""

    raw = path.read_bytes()
    if not raw or len(raw) > 1_000_000:
        raise ValueError("synthetic conversation file must contain 1 through 1000000 bytes")
    return SyntheticConversationV1.model_validate(json.loads(raw))


def build_synthetic_manifest(
    conversation: SyntheticConversationV1,
    *,
    campaign_id: UUID,
    destination_content_scope_id: UUID,
    fingerprint_key: bytes,
    expires_at: datetime,
    max_model_spend_microusd: int,
    max_attempts: int,
    parser_version: str = "synthetic-json-v1",
    extractor_version: str = "synthetic-extractor-v1",
    prompt_version: str = "synthetic-prompt-v1",
    provider_policy_id: str = "local-synthetic-only",
    model_route: str = "none",
) -> ImportManifestV1:
    """Bind every message and branch to one private-scope, protected manifest."""

    if len(fingerprint_key) != 32:
        raise ValueError("manifest fingerprint key must contain 32 bytes")
    records: list[ImportManifestRecordV1] = []
    for message in conversation.messages:
        source_id = f"{conversation.conversation_id}:{message.message_id}"
        parent_id = (
            f"{conversation.conversation_id}:{message.parent_message_id}"
            if message.parent_message_id
            else None
        )
        content = message.content.encode("utf-8")
        identity = (
            f"chatgpt-export:{source_id}:r{message.source_revision}\x00".encode()
        )
        records.append(
            ImportManifestRecordV1(
                source_record_id=source_id,
                content_commitment=hmac.new(
                    fingerprint_key, identity + content, hashlib.sha256
                ).hexdigest(),
                byte_length=len(content),
                estimated_tokens=max(1, (len(content) + 2) // 3),
                source_revision=message.source_revision,
                role=message.role,
                parent_source_record_id=parent_id,
                displayed=message.displayed,
            )
        )
    total_bytes = sum(record.byte_length for record in records)
    total_tokens = sum(record.estimated_tokens for record in records)
    return ImportManifestV1(
        campaign_id=campaign_id,
        destination_content_scope_id=destination_content_scope_id,
        source_namespace="raymond-private/chatgpt-export",
        source_conversation_id=conversation.conversation_id,
        parser_version=parser_version,
        extractor_version=extractor_version,
        prompt_version=prompt_version,
        provider_policy_id=provider_policy_id,
        model_route=model_route,
        records=tuple(records),
        max_records=len(records),
        max_bytes=total_bytes,
        max_input_tokens=total_tokens,
        max_model_spend_microusd=max_model_spend_microusd,
        max_attempts=max_attempts,
        expires_at=expires_at,
    )


def verify_synthetic_manifest(
    conversation: SyntheticConversationV1,
    manifest: ImportManifestV1,
    *,
    fingerprint_key: bytes,
) -> None:
    """Reject changed content, source revisions, branches, destinations, or limits."""

    rebuilt = build_synthetic_manifest(
        conversation,
        campaign_id=manifest.campaign_id,
        destination_content_scope_id=manifest.destination_content_scope_id,
        fingerprint_key=fingerprint_key,
        expires_at=manifest.expires_at,
        max_model_spend_microusd=manifest.max_model_spend_microusd,
        max_attempts=manifest.max_attempts,
        parser_version=manifest.parser_version,
        extractor_version=manifest.extractor_version,
        prompt_version=manifest.prompt_version,
        provider_policy_id=manifest.provider_policy_id,
        model_route=manifest.model_route,
    )
    if rebuilt != manifest:
        raise ValueError("synthetic input does not match its authorized manifest")


def build_archive_requests(
    conversation: SyntheticConversationV1,
    manifest: ImportManifestV1,
    *,
    fingerprint_key: bytes,
) -> tuple[RealmArchiveCommitInputV1, ...]:
    """Create one independently encryptable archive request per included message."""

    from lucy.contracts.canonical import canonical_json_bytes

    verify_synthetic_manifest(conversation, manifest, fingerprint_key=fingerprint_key)
    by_id = {message.message_id: message for message in conversation.messages}
    requests: list[RealmArchiveCommitInputV1] = []
    for record in manifest.records:
        if not record.included:
            continue
        message_id = record.source_record_id.rsplit(":", 1)[-1]
        message = by_id.get(message_id)
        if message is None:
            raise ValueError("manifest refers to a missing synthetic message")
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
                source_conversation_id=conversation.conversation_id,
                source_turn_id=message.message_id,
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
    return tuple(requests)


def extract_synthetic_candidate(
    conversation: SyntheticConversationV1,
    manifest: ImportManifestV1,
    *,
    fingerprint_key: bytes,
    evidence_by_source_record_id: Mapping[str, UUID],
    candidate_id: UUID,
    extraction_job_id: UUID,
    subject: str,
    predicate: str,
    object_text: str,
    memory_kind: MemoryKind,
    assertion_status: AssertionStatus,
    epistemic_status: EpistemicStatus,
    protection_class: ProtectionClass,
    source_quotes: tuple[tuple[str, str], ...],
    confidence_millionths: int = 1_000_000,
    domain_tags: tuple[str, ...] = (),
    event_time: datetime | None = None,
    supersedes_candidate_id: UUID | None = None,
) -> MemoryCandidatePayloadV1:
    """Create an exact candidate from unambiguous quotes without a model call."""

    verify_synthetic_manifest(conversation, manifest, fingerprint_key=fingerprint_key)
    messages = {
        f"{conversation.conversation_id}:{message.message_id}": message
        for message in conversation.messages
    }
    included = {record.source_record_id for record in manifest.records if record.included}
    spans: list[SourceSpanV1] = []
    for source_record_id, quote in source_quotes:
        message = messages.get(source_record_id)
        evidence_id = evidence_by_source_record_id.get(source_record_id)
        if message is None or evidence_id is None or source_record_id not in included:
            raise ValueError("synthetic candidate source is outside the manifest")
        content = message.content.encode("utf-8")
        needle = quote.encode("utf-8")
        start = content.find(needle)
        if not needle or start < 0 or content.find(needle, start + 1) >= 0:
            raise ValueError("synthetic candidate quote must occur exactly once")
        spans.append(
            SourceSpanV1(
                source_record_id=source_record_id,
                evidence_id=evidence_id,
                record_version=1,
                byte_start=start,
                byte_end=start + len(needle),
            )
        )
    return MemoryCandidatePayloadV1(
        candidate_id=candidate_id,
        candidate_version=1,
        campaign_id=manifest.campaign_id,
        manifest_digest=manifest.digest,
        extraction_job_id=extraction_job_id,
        extractor_version=manifest.extractor_version,
        prompt_version=manifest.prompt_version,
        model_route=manifest.model_route,
        destination_content_scope_id=manifest.destination_content_scope_id,
        subject=subject,
        predicate=predicate,
        object=object_text,
        confidence_millionths=confidence_millionths,
        memory_kind=memory_kind,
        assertion_status=assertion_status,
        epistemic_status=epistemic_status,
        protection_class=protection_class,
        domain_tags=domain_tags,
        event_time=event_time,
        sources=tuple(spans),
        supersedes_candidate_id=supersedes_candidate_id,
    )


class ContextItemV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    claim_id: UUID
    candidate_id: UUID
    candidate_version: int = Field(ge=1)
    protection_class: ProtectionClass
    text: str = Field(min_length=1)
    source_evidence_ids: tuple[UUID, ...] = Field(min_length=1)
    estimated_tokens: int = Field(ge=1)
    relevance_millionths: int = Field(ge=0, le=1_000_000)


class ContextBudgetV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    total_tokens: int = Field(ge=256)
    instructions_tokens: int = Field(ge=0)
    tools_tokens: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    recent_turn_tokens: int = Field(ge=0)
    output_reserve_tokens: int = Field(ge=1)
    reasoning_reserve_tokens: int = Field(ge=0)
    safety_headroom_tokens: int = Field(ge=0)

    @property
    def memory_tokens(self) -> int:
        fixed = (
            self.instructions_tokens
            + self.tools_tokens
            + self.input_tokens
            + self.recent_turn_tokens
            + self.output_reserve_tokens
            + self.reasoning_reserve_tokens
            + self.safety_headroom_tokens
        )
        return max(0, self.total_tokens - fixed)


class CompiledContextV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    items: tuple[ContextItemV1, ...]
    memory_tokens_used: int
    memory_tokens_available: int
    omitted_claim_ids: tuple[UUID, ...]


def compile_context(
    candidates: tuple[ContextItemV1, ...], budget: ContextBudgetV1
) -> CompiledContextV1:
    """Select relevant items under one total model-request budget."""

    available = budget.memory_tokens
    used = 0
    selected: list[ContextItemV1] = []
    omitted: list[UUID] = []
    ordered = sorted(
        candidates,
        key=lambda item: (-item.relevance_millionths, item.estimated_tokens, str(item.claim_id)),
    )
    for item in ordered:
        if used + item.estimated_tokens <= available:
            selected.append(item)
            used += item.estimated_tokens
        else:
            omitted.append(item.claim_id)
    return CompiledContextV1(
        items=tuple(selected),
        memory_tokens_used=used,
        memory_tokens_available=available,
        omitted_claim_ids=tuple(omitted),
    )
