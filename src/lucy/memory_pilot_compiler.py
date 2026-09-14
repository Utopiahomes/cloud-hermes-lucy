"""Deterministic, omission-free request compilation for private-memory pilots."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from lucy.chatgpt_manifest import LocalChatGPTMessageV1, LocalPilotBuildV1
from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_extraction import MemoryExtractionDispatchV1, memory_extraction_job_id
from lucy.memory_import import ImportManifestRecordV1, ImportManifestV2
from lucy.memory_openrouter import build_openrouter_memory_request
from lucy.memory_provider_request import MemoryProviderRequestV1


class MemoryPilotCompilationV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    campaign_id: UUID
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    batches: tuple[MemoryExtractionDispatchV1, ...] = Field(min_length=1)
    covered_source_record_ids: tuple[str, ...] = Field(min_length=1)


def compile_memory_pilot_batches(
    build: LocalPilotBuildV1,
    *,
    maximum_microusd_per_attempt: int,
    timeout_seconds: int,
) -> MemoryPilotCompilationV1:
    """Pack every included record once under one executable manifest's bounds."""

    manifest = build.bundle.manifest
    if not isinstance(manifest, ImportManifestV2):
        raise ValueError("real pilot compilation requires an executable v2 manifest")
    if maximum_microusd_per_attempt < 0:
        raise ValueError("per-attempt model cost ceiling is invalid")
    if not 1 <= timeout_seconds <= 600:
        raise ValueError("provider timeout is invalid")
    local = {
        message.source_record_id: message
        for conversation in build.conversations
        for message in conversation.messages
    }
    included = tuple(record for record in manifest.records if record.included)
    packed: list[tuple[ImportManifestRecordV1, ...]] = []
    current: tuple[ImportManifestRecordV1, ...] = ()
    for record in included:
        candidate = (*current, record)
        if _fits(manifest, candidate, local):
            current = candidate
            continue
        if not current:
            raise ValueError("one selected record exceeds the authorized request ceiling")
        packed.append(current)
        current = (record,)
        if not _fits(manifest, current, local):
            raise ValueError("one selected record exceeds the authorized request ceiling")
    if current:
        packed.append(current)
    if not packed or len(packed) > manifest.max_attempts:
        raise ValueError("compiled pilot exceeds the authorized attempt ceiling")
    if maximum_microusd_per_attempt > manifest.max_model_spend_microusd:
        raise ValueError("per-attempt cost ceiling exceeds the campaign ceiling")
    if len(packed) * maximum_microusd_per_attempt > manifest.max_model_spend_microusd:
        raise ValueError("compiled pilot reservations exceed the campaign spend ceiling")
    batches = tuple(
        _dispatch(
            manifest,
            records,
            local,
            batch_index=index,
            maximum_microusd=maximum_microusd_per_attempt,
            timeout_seconds=timeout_seconds,
        )
        for index, records in enumerate(packed, start=1)
    )
    coverage = tuple(source for batch in batches for source in batch.source_record_ids)
    expected = tuple(record.source_record_id for record in included)
    if coverage != expected or len(set(coverage)) != len(coverage):
        raise RuntimeError("compiled pilot source coverage is not exact")
    return MemoryPilotCompilationV1(
        campaign_id=manifest.campaign_id,
        manifest_digest=manifest.digest,
        batches=batches,
        covered_source_record_ids=coverage,
    )


def _fits(
    manifest: ImportManifestV2,
    records: tuple[ImportManifestRecordV1, ...],
    local: dict[str, LocalChatGPTMessageV1],
) -> bool:
    request = _request(manifest, records, local)
    return (
        request.input_token_upper_bound <= manifest.max_request_input_tokens
        and request.input_token_upper_bound + manifest.max_request_output_tokens
        <= manifest.max_request_total_tokens
    )


def _dispatch(
    manifest: ImportManifestV2,
    records: tuple[ImportManifestRecordV1, ...],
    local: dict[str, LocalChatGPTMessageV1],
    *,
    batch_index: int,
    maximum_microusd: int,
    timeout_seconds: int,
) -> MemoryExtractionDispatchV1:
    prompt = _prompt(records, local)
    request = build_openrouter_memory_request(
        model_route=manifest.model_route,
        prompt=prompt,
        output_tokens=manifest.max_request_output_tokens,
    )
    attempt_key = f"pilot:{manifest.campaign_id}:batch:{batch_index}:attempt:1"
    return MemoryExtractionDispatchV1(
        extraction_job_id=memory_extraction_job_id(
            manifest.campaign_id,
            attempt_key=attempt_key,
            request_commitment=request.request_commitment,
        ),
        attempt_key=attempt_key,
        source_record_ids=tuple(record.source_record_id for record in records),
        prompt=prompt,
        input_tokens=request.input_token_upper_bound,
        output_tokens=manifest.max_request_output_tokens,
        request_bytes=request.request_bytes,
        request_commitment=request.request_commitment,
        maximum_microusd=maximum_microusd,
        timeout_seconds=timeout_seconds,
    )


def _request(
    manifest: ImportManifestV2,
    records: tuple[ImportManifestRecordV1, ...],
    local: dict[str, LocalChatGPTMessageV1],
) -> MemoryProviderRequestV1:
    return build_openrouter_memory_request(
        model_route=manifest.model_route,
        prompt=_prompt(records, local),
        output_tokens=manifest.max_request_output_tokens,
    )


def _prompt(
    records: tuple[ImportManifestRecordV1, ...],
    local: dict[str, LocalChatGPTMessageV1],
) -> str:
    evidence: list[dict[str, object]] = []
    for record in records:
        message = local.get(record.source_record_id)
        if message is None or message.content is None:
            raise ValueError("selected pilot content is unavailable")
        evidence.append(
            {
                "source_record_id": record.source_record_id,
                "source_revision": record.source_revision,
                "role": record.role,
                "occurred_at": _time(record.occurred_at),
                "parent_source_record_id": record.parent_source_record_id,
                "displayed": record.displayed,
                "content": message.content,
            }
        )
    return canonical_json_bytes(
        {"contract_version": "1", "evidence_records": evidence}
    ).decode("utf-8")


def _time(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None
