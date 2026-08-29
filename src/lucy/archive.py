"""Encrypted, idempotent ingestion for Hermes conversation messages."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from lucy.archive_crypto import ArchiveCipher, ArchiveKeyStore
from lucy.audit import append_audit
from lucy.contracts import OperationOutcome
from lucy.contracts.v1 import ConversationMessageV1
from lucy.db.models import (
    ConversationCaptureStateRow,
    ConversationTurnRow,
    EvidencePayloadRow,
    EvidenceRow,
    OperationRow,
)


class ConversationMessageArchiveInput(BaseModel):
    """One normalized message from an authenticated Hermes conversation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: Literal["telegram"]
    source_conversation_id: str = Field(min_length=1, max_length=512)
    source_turn_id: str = Field(min_length=1, max_length=512)
    source_message_id: str = Field(min_length=1, max_length=512)
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=65_536)

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json"))


class ConversationMessageArchiveResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: UUID | None = None
    evidence_id: UUID | None = None
    keyed_commitment: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    request_commitment: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    archived: bool
    capture_enabled: bool
    turn_committed: bool = False
    replayed: bool = False


class CaptureModeInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: Literal["telegram"]
    source_conversation_id: str = Field(min_length=1, max_length=512)
    capture_enabled: bool


class CaptureModeResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: UUID | None = None
    platform: Literal["telegram"] = "telegram"
    source_conversation_id: str
    capture_enabled: bool
    version: int = Field(ge=0)
    replayed: bool = False


class LatestRetainedEvidenceResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: UUID


class ConversationArchiveService:
    """Preserve encrypted evidence without interpreting it as memory."""

    def __init__(
        self,
        sessions: sessionmaker[Session],
        cipher: ArchiveCipher,
        key_store: ArchiveKeyStore,
    ) -> None:
        self._sessions = sessions
        self._cipher = cipher
        self._key_store = key_store

    def capture_mode(self, platform: str, source_conversation_id: str) -> CaptureModeResult:
        with self._sessions() as session:
            row = session.get(
                ConversationCaptureStateRow,
                {"platform": platform, "source_conversation_id": source_conversation_id},
            )
            return CaptureModeResult(
                platform="telegram",
                source_conversation_id=source_conversation_id,
                capture_enabled=True if row is None else row.capture_enabled,
                version=0 if row is None else row.version,
            )

    def set_capture_mode(
        self, idempotency_key: str, request: CaptureModeInput
    ) -> CaptureModeResult:
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(idempotency_key))))
            existing = session.scalar(
                select(OperationRow).where(OperationRow.idempotency_key == idempotency_key)
            )
            if existing is not None:
                if existing.outcome != OperationOutcome.SUCCEEDED or existing.result is None:
                    raise RuntimeError(
                        f"capture-mode operation is not replayable: {existing.outcome}"
                    )
                if (
                    existing.result.get("source_conversation_id") != request.source_conversation_id
                    or existing.result.get("capture_enabled") is not request.capture_enabled
                ):
                    raise ValueError(
                        "idempotency key was already used for another capture transition"
                    )
                return CaptureModeResult.model_validate({**existing.result, "replayed": True})

            now = datetime.now(UTC)
            operation = OperationRow(
                id=uuid4(),
                idempotency_key=idempotency_key,
                outcome=OperationOutcome.PENDING,
                result=None,
                created_at=now,
                completed_at=None,
            )
            session.add(operation)
            session.flush()
            append_audit(
                session,
                operation.id,
                "operation.started",
                {"operation_type": "conversation.capture_mode"},
            )
            row = session.get(
                ConversationCaptureStateRow,
                {
                    "platform": request.platform,
                    "source_conversation_id": request.source_conversation_id,
                },
            )
            previous = True if row is None else row.capture_enabled
            if row is None:
                row = ConversationCaptureStateRow(
                    platform=request.platform,
                    source_conversation_id=request.source_conversation_id,
                    capture_enabled=request.capture_enabled,
                    version=1,
                    updated_at=now,
                )
                session.add(row)
            elif row.capture_enabled != request.capture_enabled:
                row.capture_enabled = request.capture_enabled
                row.version += 1
                row.updated_at = now
            append_audit(
                session,
                operation.id,
                "conversation.capture_mode_changed",
                {
                    "platform": request.platform,
                    "from": previous,
                    "to": row.capture_enabled,
                    "version": row.version,
                },
            )
            result = CaptureModeResult(
                operation_id=operation.id,
                platform="telegram",
                source_conversation_id=request.source_conversation_id,
                capture_enabled=row.capture_enabled,
                version=row.version,
            )
            operation.outcome = OperationOutcome.SUCCEEDED
            operation.result = result.model_dump(mode="json")
            operation.completed_at = now
            append_audit(
                session,
                operation.id,
                "operation.succeeded",
                {"operation_type": "conversation.capture_mode"},
            )
            return result

    def preserve_message(
        self,
        idempotency_key: str,
        request: ConversationMessageArchiveInput,
    ) -> ConversationMessageArchiveResult:
        request_commitment = self._cipher.commitment(request.canonical_bytes())
        try:
            with self._sessions.begin() as session:
                session.execute(select(func.pg_advisory_xact_lock(func.hashtext(idempotency_key))))
                existing = session.scalar(
                    select(OperationRow).where(OperationRow.idempotency_key == idempotency_key)
                )
                if existing is not None:
                    if existing.outcome != OperationOutcome.SUCCEEDED or existing.result is None:
                        raise RuntimeError(
                            f"archive operation has non-replayable outcome: {existing.outcome}"
                        )
                    replay = ConversationMessageArchiveResult.model_validate(
                        {**existing.result, "replayed": True}
                    )
                    if replay.request_commitment != request_commitment:
                        raise ValueError("idempotency key was already used for another message")
                    return replay

                capture = session.get(
                    ConversationCaptureStateRow,
                    {
                        "platform": request.platform,
                        "source_conversation_id": request.source_conversation_id,
                    },
                )
                if capture is not None and not capture.capture_enabled:
                    return ConversationMessageArchiveResult(
                        archived=False,
                        capture_enabled=False,
                    )

                now = datetime.now(UTC)
                operation_id = uuid4()
                operation = OperationRow(
                    id=operation_id,
                    idempotency_key=idempotency_key,
                    outcome=OperationOutcome.PENDING,
                    result=None,
                    created_at=now,
                    completed_at=None,
                )
                session.add(operation)
                session.flush()
                append_audit(
                    session,
                    operation_id,
                    "operation.started",
                    {"operation_type": "conversation.message_archive"},
                )

                message = ConversationMessageV1(
                    message_id=request.source_message_id,
                    role=request.role,
                    content=request.content,
                    occurred_at=now,
                )
                metadata = {
                    "contract_version": "2",
                    "encrypted": True,
                    "platform": request.platform,
                    "source_message_id": request.source_message_id,
                    "role": request.role,
                    "occurred_at": now.isoformat(),
                }
                plaintext = _canonical_json(message.model_dump(mode="json"))
                aad = _canonical_json(metadata)
                evidence_id = uuid4()
                key_ref = uuid4()
                encrypted = self._cipher.encrypt(evidence_id, plaintext, aad)
                self._key_store.put(key_ref, encrypted.wrapped_key)

                session.add(
                    EvidenceRow(
                        id=evidence_id,
                        source="hermes",
                        source_conversation_id=(
                            f"{request.platform}:{request.source_conversation_id}"
                        ),
                        captured_at=now,
                        content=metadata,
                        content_commitment=encrypted.keyed_commitment,
                        operation_id=operation_id,
                    )
                )
                session.flush()
                turn = session.get(
                    ConversationTurnRow,
                    {
                        "platform": request.platform,
                        "source_conversation_id": request.source_conversation_id,
                        "source_turn_id": request.source_turn_id,
                    },
                )
                if turn is None:
                    turn = ConversationTurnRow(
                        platform=request.platform,
                        source_conversation_id=request.source_conversation_id,
                        source_turn_id=request.source_turn_id,
                        user_evidence_id=None,
                        assistant_evidence_id=None,
                        status="capturing",
                        committed_at=None,
                        updated_at=now,
                    )
                    session.add(turn)
                field = "user_evidence_id" if request.role == "user" else "assistant_evidence_id"
                current_evidence_id = getattr(turn, field)
                if current_evidence_id is not None and current_evidence_id != evidence_id:
                    raise ValueError("conversation turn role already has different evidence")
                setattr(turn, field, evidence_id)
                turn.updated_at = now
                if turn.user_evidence_id is not None and turn.assistant_evidence_id is not None:
                    turn.status = "committed"
                    turn.committed_at = now
                turn_committed = turn.status == "committed"
                session.add(
                    EvidencePayloadRow(
                        evidence_id=evidence_id,
                        ciphertext=encrypted.ciphertext,
                        content_nonce=encrypted.content_nonce,
                        key_ref=key_ref,
                        algorithm=self._cipher.algorithm,
                        created_at=now,
                    )
                )
                append_audit(
                    session,
                    operation_id,
                    "evidence.encrypted_payload_preserved",
                    {
                        "evidence_id": str(evidence_id),
                        "platform": request.platform,
                        "role": request.role,
                        "algorithm": self._cipher.algorithm,
                    },
                )

                result = ConversationMessageArchiveResult(
                    operation_id=operation_id,
                    evidence_id=evidence_id,
                    keyed_commitment=encrypted.keyed_commitment,
                    request_commitment=request_commitment,
                    archived=True,
                    capture_enabled=True,
                    turn_committed=turn_committed,
                )
                operation.outcome = OperationOutcome.SUCCEEDED
                operation.result = result.model_dump(mode="json")
                operation.completed_at = now
                append_audit(
                    session,
                    operation_id,
                    "operation.succeeded",
                    {
                        "operation_type": "conversation.message_archive",
                        "evidence_id": str(evidence_id),
                    },
                )
                return result
        except Exception:
            # The writer role deliberately cannot delete wrapped keys. If the
            # PostgreSQL transaction fails after PutItem, the orphan contains
            # no message ciphertext and is removed by an out-of-band janitor.
            raise


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
