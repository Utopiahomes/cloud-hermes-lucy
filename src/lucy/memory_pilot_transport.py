"""Exact, campaign-scoped transport contracts for private-memory pilot batches."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from lucy.chatgpt_manifest import (
    AuthorizedPilotManifestV1,
    LocalChatGPTMessageV1,
    LocalPilotBuildV1,
)
from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_extraction import MemoryExtractionDispatchV1
from lucy.memory_import import ImportManifestRecordV1, ImportManifestV2
from lucy.memory_pilot_compiler import (
    compile_memory_pilot_batches,
    compile_memory_pilot_dispatch,
)
from lucy.memory_pilot_runner import validate_authorized_memory_pilot

_BATCH_PREFIX = b"LUCY-MEMORY-PILOT-TRANSPORT-BATCH-V1\x00"
_TRANSFER_KEY_PREFIX = b"LUCY-MEMORY-PILOT-TRANSFER-KEY-V1\x00"
_CAPABILITY_PREFIX = b"LUCY-MEMORY-PILOT-CAPABILITY-V1\x00"
_BATCH_ID_NAMESPACE = UUID("1e41667a-bda5-5c1f-80a9-76ec16277fca")


class MemoryPilotTransportRecordV1(BaseModel):
    """One selected record. This object contains sensitive plaintext."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_record_id: str = Field(min_length=1, max_length=2_000)
    source_conversation_id: str = Field(min_length=1, max_length=512)
    source_revision: int = Field(ge=1)
    role: Literal["owner", "assistant", "system"]
    native_role: str | None = Field(default=None, max_length=100)
    native_message_id: str | None = Field(default=None, max_length=512)
    native_node_id: str | None = Field(default=None, max_length=512)
    occurred_at: datetime | None = None
    parent_source_record_id: str | None = Field(default=None, max_length=2_000)
    displayed: bool
    content: str = Field(min_length=1, max_length=65_536)


class MemoryPilotTransportBatchV1(BaseModel):
    """Sensitive wire payload for one exact, bounded extraction attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.memory-pilot-transport-batch.v1"] = (
        "lucy.memory-pilot-transport-batch.v1"
    )
    batch_id: UUID
    batch_index: int = Field(ge=1, le=10_000)
    owner_approval_ref: UUID
    campaign_id: UUID
    destination_content_scope_id: UUID
    bundle_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    dispatch: MemoryExtractionDispatchV1
    records: tuple[MemoryPilotTransportRecordV1, ...] = Field(
        min_length=1, max_length=10_000
    )

    @model_validator(mode="after")
    def exact_sources(self) -> MemoryPilotTransportBatchV1:
        sources = tuple(record.source_record_id for record in self.records)
        if sources != self.dispatch.source_record_ids or len(set(sources)) != len(sources):
            raise ValueError("transport records do not exactly match dispatch sources")
        return self

    @property
    def byte_length(self) -> int:
        return len(canonical_json_bytes(self))


class MemoryPilotTransportBatchCommitmentV1(BaseModel):
    """Content-free admission data for one sensitive transport batch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    batch_id: UUID
    batch_index: int = Field(ge=1, le=10_000)
    extraction_job_id: UUID
    attempt_key: str = Field(min_length=1, max_length=512)
    source_record_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    request_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    transport_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    transport_bytes: int = Field(ge=1)


class MemoryPilotTransportRegistrationV1(BaseModel):
    """Operator-registered, plaintext-free limits for a campaign upload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.memory-pilot-transport-registration.v1"] = (
        "lucy.memory-pilot-transport-registration.v1"
    )
    owner_approval_ref: UUID
    campaign_id: UUID
    destination_content_scope_id: UUID
    bundle_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    transfer_key_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    capability_token_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    maximum_transport_bytes: int = Field(ge=1)
    expires_at: datetime
    batches: tuple[MemoryPilotTransportBatchCommitmentV1, ...] = Field(
        min_length=1, max_length=10_000
    )

    @model_validator(mode="after")
    def exact_batches(self) -> MemoryPilotTransportRegistrationV1:
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("transport expiry must be timezone-aware")
        indexes = tuple(item.batch_index for item in self.batches)
        if indexes != tuple(range(1, len(self.batches) + 1)):
            raise ValueError("transport batch indexes must be contiguous")
        if len({item.batch_id for item in self.batches}) != len(self.batches):
            raise ValueError("transport batch IDs must be unique")
        if sum(item.transport_bytes for item in self.batches) > self.maximum_transport_bytes:
            raise ValueError("transport batches exceed the registered byte ceiling")
        return self


class PreparedMemoryPilotTransportV1(BaseModel):
    """In-memory preparation result; batches must never enter review artifacts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    registration: MemoryPilotTransportRegistrationV1
    batches: tuple[MemoryPilotTransportBatchV1, ...] = Field(exclude=True)


class MemoryPilotTransportAdmissionViewV1(BaseModel):
    """Content-free expected values returned for one capability-bound batch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    campaign_id: UUID
    owner_approval_ref: UUID
    destination_content_scope_id: UUID
    bundle_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    transfer_key_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: datetime
    authorization: AuthorizedPilotManifestV1
    manifest: ImportManifestV2
    batch: MemoryPilotTransportBatchCommitmentV1


class MemoryPilotTransportAdmissionReceiptV1(BaseModel):
    """Content-free durable acknowledgement of one admitted batch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    batch_id: UUID
    admitted_at: datetime
    replayed: bool


class MemoryPilotTransportUnavailable(PermissionError):
    """The batch cannot be admitted without weakening its transport boundary."""


@dataclass(frozen=True)
class AdmittedMemoryPilotTransportBatch:
    """Sensitive in-process context; never serialize this as a status response."""

    receipt: MemoryPilotTransportAdmissionReceiptV1
    authorization: AuthorizedPilotManifestV1
    manifest: ImportManifestV2
    batch: MemoryPilotTransportBatchV1


class PostgresMemoryPilotTransportAdmission:
    """Validate plaintext in memory, while PostgreSQL sees content-free commitments only."""

    def __init__(self, sessions: sessionmaker[Session], *, transfer_key: bytes) -> None:
        _require_secret(transfer_key, name="transfer key")
        self._sessions = sessions
        self._transfer_key = transfer_key

    def admit(
        self,
        batch: MemoryPilotTransportBatchV1,
        *,
        capability_token: bytes,
    ) -> MemoryPilotTransportAdmissionReceiptV1:
        return self.admit_for_execution(
            batch, capability_token=capability_token
        ).receipt

    def admit_for_execution(
        self,
        batch: MemoryPilotTransportBatchV1,
        *,
        capability_token: bytes,
    ) -> AdmittedMemoryPilotTransportBatch:
        digest = capability_token_digest(capability_token)
        try:
            with self._sessions.begin() as session:
                raw = session.execute(
                    text(
                        "SELECT lucy.read_memory_pilot_transport_admission_v1("
                        ":capability_digest,:batch_id)"
                    ),
                    {"capability_digest": digest, "batch_id": batch.batch_id},
                ).scalar_one()
            expected = MemoryPilotTransportAdmissionViewV1.model_validate(raw)
            if (
                expected.owner_approval_ref != batch.owner_approval_ref
                or expected.campaign_id != batch.campaign_id
                or expected.destination_content_scope_id
                != batch.destination_content_scope_id
                or expected.bundle_digest != batch.bundle_digest
                or expected.manifest_digest != batch.manifest_digest
                or expected.manifest.digest != expected.manifest_digest
                or expected.authorization.owner_approval_ref
                != expected.owner_approval_ref
                or expected.authorization.bundle_digest != expected.bundle_digest
                or expected.authorization.bundle.manifest != expected.manifest
                or not hmac.compare_digest(
                    expected.transfer_key_commitment,
                    transfer_key_commitment(self._transfer_key),
                )
            ):
                raise MemoryPilotTransportUnavailable(
                    "memory pilot transport admission unavailable"
                )
            validate_memory_pilot_transport_batch(
                batch,
                manifest=expected.manifest,
                expected=expected.batch,
                transfer_key=self._transfer_key,
            )
            with self._sessions.begin() as session:
                admitted = session.execute(
                    text(
                        "SELECT lucy.admit_memory_pilot_transport_v1("
                        ":capability_digest,:batch_id,:transport_commitment,"
                        ":transport_bytes,:extraction_job_id,:request_commitment)"
                    ),
                    {
                        "capability_digest": digest,
                        "batch_id": batch.batch_id,
                        "transport_commitment": expected.batch.transport_commitment,
                        "transport_bytes": expected.batch.transport_bytes,
                        "extraction_job_id": expected.batch.extraction_job_id,
                        "request_commitment": expected.batch.request_commitment,
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise MemoryPilotTransportUnavailable(
                "memory pilot transport admission unavailable"
            ) from exc
        except ValueError as exc:
            raise MemoryPilotTransportUnavailable(
                "memory pilot transport admission unavailable"
            ) from exc
        return AdmittedMemoryPilotTransportBatch(
            receipt=MemoryPilotTransportAdmissionReceiptV1.model_validate(admitted),
            authorization=expected.authorization,
            manifest=expected.manifest,
            batch=batch,
        )


def transfer_key_commitment(transfer_key: bytes) -> str:
    _require_secret(transfer_key, name="transfer key")
    return hashlib.sha256(_TRANSFER_KEY_PREFIX + transfer_key).hexdigest()


def capability_token_digest(capability_token: bytes) -> str:
    _require_secret(capability_token, name="capability token")
    return hashlib.sha256(_CAPABILITY_PREFIX + capability_token).hexdigest()


def transport_batch_commitment(
    batch: MemoryPilotTransportBatchV1, *, transfer_key: bytes
) -> str:
    _require_secret(transfer_key, name="transfer key")
    return hmac.new(
        transfer_key,
        _BATCH_PREFIX + canonical_json_bytes(batch),
        hashlib.sha256,
    ).hexdigest()


def prepare_memory_pilot_transport(
    build: LocalPilotBuildV1,
    authorization: AuthorizedPilotManifestV1,
    *,
    expected_bundle_digest: str,
    transfer_key: bytes,
    capability_token: bytes,
    maximum_microusd_per_attempt: int,
    timeout_seconds: int,
    expires_at: datetime,
    now: datetime,
) -> PreparedMemoryPilotTransportV1:
    """Prepare exact batches locally after fingerprint-key verification."""

    _require_secret(transfer_key, name="transfer key")
    _require_secret(capability_token, name="capability token")
    validate_authorized_memory_pilot(
        build, authorization, expected_bundle_digest=expected_bundle_digest, now=now
    )
    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        raise ValueError("transport expiry must be timezone-aware")
    if not now < expires_at <= authorization.bundle.manifest.expires_at:
        raise ValueError("transport expiry is outside the authorized campaign window")
    manifest = build.bundle.manifest
    if not isinstance(manifest, ImportManifestV2):
        raise ValueError("transport requires an executable v2 manifest")
    compilation = compile_memory_pilot_batches(
        build,
        maximum_microusd_per_attempt=maximum_microusd_per_attempt,
        timeout_seconds=timeout_seconds,
    )
    messages = {
        message.source_record_id: message
        for conversation in build.conversations
        for message in conversation.messages
    }
    records = {record.source_record_id: record for record in manifest.records}
    batches: list[MemoryPilotTransportBatchV1] = []
    commitments: list[MemoryPilotTransportBatchCommitmentV1] = []
    for index, dispatch in enumerate(compilation.batches, start=1):
        batch_id = uuid5(
            _BATCH_ID_NAMESPACE,
            f"{manifest.campaign_id}:{index}:{dispatch.extraction_job_id}",
        )
        payload_records = tuple(
            _transport_record(records[source], messages[source])
            for source in dispatch.source_record_ids
        )
        batch = MemoryPilotTransportBatchV1(
            batch_id=batch_id,
            batch_index=index,
            owner_approval_ref=authorization.owner_approval_ref,
            campaign_id=manifest.campaign_id,
            destination_content_scope_id=manifest.destination_content_scope_id,
            bundle_digest=authorization.bundle_digest,
            manifest_digest=manifest.digest,
            dispatch=dispatch,
            records=payload_records,
        )
        batches.append(batch)
        commitments.append(
            MemoryPilotTransportBatchCommitmentV1(
                batch_id=batch_id,
                batch_index=index,
                extraction_job_id=dispatch.extraction_job_id,
                attempt_key=dispatch.attempt_key,
                source_record_ids=dispatch.source_record_ids,
                request_commitment=dispatch.request_commitment,
                transport_commitment=transport_batch_commitment(
                    batch, transfer_key=transfer_key
                ),
                transport_bytes=batch.byte_length,
            )
        )
    return PreparedMemoryPilotTransportV1(
        registration=MemoryPilotTransportRegistrationV1(
            owner_approval_ref=authorization.owner_approval_ref,
            campaign_id=manifest.campaign_id,
            destination_content_scope_id=manifest.destination_content_scope_id,
            bundle_digest=authorization.bundle_digest,
            manifest_digest=manifest.digest,
            transfer_key_commitment=transfer_key_commitment(transfer_key),
            capability_token_digest=capability_token_digest(capability_token),
            maximum_transport_bytes=sum(item.transport_bytes for item in commitments),
            expires_at=expires_at,
            batches=tuple(commitments),
        ),
        batches=tuple(batches),
    )


def validate_memory_pilot_transport_batch(
    batch: MemoryPilotTransportBatchV1,
    *,
    manifest: ImportManifestV2,
    expected: MemoryPilotTransportBatchCommitmentV1,
    transfer_key: bytes,
) -> None:
    """Verify an uploaded batch without access to the permanent fingerprint key."""

    _require_secret(transfer_key, name="transfer key")
    if (
        batch.campaign_id != manifest.campaign_id
        or batch.destination_content_scope_id != manifest.destination_content_scope_id
        or batch.manifest_digest != manifest.digest
        or batch.batch_id != expected.batch_id
        or batch.batch_index != expected.batch_index
        or batch.dispatch.extraction_job_id != expected.extraction_job_id
        or batch.dispatch.attempt_key != expected.attempt_key
        or batch.dispatch.source_record_ids != expected.source_record_ids
        or batch.dispatch.request_commitment != expected.request_commitment
        or batch.byte_length != expected.transport_bytes
    ):
        raise ValueError("transport batch does not match registered admission")
    manifest_records = {record.source_record_id: record for record in manifest.records}
    local: dict[str, LocalChatGPTMessageV1] = {}
    exact_records: list[ImportManifestRecordV1] = []
    for supplied in batch.records:
        record = manifest_records.get(supplied.source_record_id)
        if record is None or not record.included:
            raise ValueError("transport source is not included in the exact manifest")
        if _transport_metadata(record) != supplied.model_dump(
            exclude={"content", "source_conversation_id"}
        ):
            raise ValueError("transport source metadata differs from the exact manifest")
        if len(supplied.content.encode("utf-8")) != record.byte_length:
            raise ValueError("transport source byte length differs from the exact manifest")
        exact_records.append(record)
        local[supplied.source_record_id] = LocalChatGPTMessageV1(
            source_record_id=supplied.source_record_id,
            conversation_id="transport-verified",
            native_node_id=supplied.native_node_id or supplied.source_record_id,
            native_message_id=supplied.native_message_id or supplied.source_record_id,
            parent_source_record_id=supplied.parent_source_record_id,
            native_role=supplied.native_role or supplied.role,
            role=supplied.role,
            occurred_at=supplied.occurred_at,
            displayed=supplied.displayed,
            source_revision=supplied.source_revision,
            content=supplied.content,
            inclusion_state="included",
        )
    rebuilt = compile_memory_pilot_dispatch(
        manifest,
        tuple(exact_records),
        local,
        batch_index=batch.batch_index,
        maximum_microusd=batch.dispatch.maximum_microusd,
        timeout_seconds=batch.dispatch.timeout_seconds,
    )
    if rebuilt != batch.dispatch:
        raise ValueError("transport dispatch is not the canonical selected-record request")
    actual = transport_batch_commitment(batch, transfer_key=transfer_key)
    if not hmac.compare_digest(actual, expected.transport_commitment):
        raise ValueError("transport batch commitment is invalid")


def _transport_record(
    record: ImportManifestRecordV1, message: LocalChatGPTMessageV1
) -> MemoryPilotTransportRecordV1:
    if message.content is None:
        raise ValueError("selected pilot content is unavailable")
    return MemoryPilotTransportRecordV1.model_validate(
        {
            **_transport_metadata(record),
            "source_conversation_id": message.conversation_id,
            "content": message.content,
        }
    )


def _transport_metadata(record: ImportManifestRecordV1) -> dict[str, object]:
    if record.role not in {"owner", "assistant", "system"}:
        raise ValueError("unsupported records cannot enter pilot transport")
    return {
        "source_record_id": record.source_record_id,
        "source_revision": record.source_revision,
        "role": record.role,
        "native_role": record.native_role,
        "native_message_id": record.native_message_id,
        "native_node_id": record.native_node_id,
        "occurred_at": record.occurred_at,
        "parent_source_record_id": record.parent_source_record_id,
        "displayed": record.displayed,
    }


def _require_secret(value: bytes, *, name: str) -> None:
    if len(value) != 32:
        raise ValueError(f"{name} must contain exactly 32 random bytes")
