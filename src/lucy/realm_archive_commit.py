"""Retry-safe PostgreSQL/AWS commit protocol for realm archive capture."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from lucy.archive import (
    CaptureModeInput,
    CaptureModeResult,
    ConversationMessageArchiveInput,
    ConversationMessageArchiveResult,
    TurnCaptureInput,
    TurnCaptureResult,
)
from lucy.contracts.canonical import canonical_json_bytes, canonical_sha256
from lucy.db import create_session_factory
from lucy.realm_archive import RealmArchiveEncryptor, RealmArchiveEnvelopeV1
from lucy.realm_archive_aws import realm_archive_from_environment


class RealmArchiveCommitUnavailable(PermissionError):
    """The staged archive operation could not cross its realm boundary."""


class RealmArchiveCommitInputV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_conversation_id: str = Field(min_length=1, max_length=512)
    source_turn_id: str = Field(min_length=1, max_length=512)
    idempotency_key: str = Field(min_length=1, max_length=512)
    plaintext: bytes = Field(min_length=1, max_length=65_536)
    authenticated_header: bytes = Field(max_length=24_576)
    content_classification: str = Field(min_length=1, max_length=200)
    lineage_refs: tuple[str, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def unique_lineage(self) -> RealmArchiveCommitInputV1:
        if len(set(self.lineage_refs)) != len(self.lineage_refs):
            raise ValueError("realm archive lineage references must be unique")
        return self


class RealmArchiveClaimV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: UUID
    evidence_id: UUID
    representation_id: UUID
    wrapped_key_ref: UUID
    stage: Literal["INTENT_RECORDED", "AWS_COMMITTED", "RECONCILED"]
    replayed: bool


class RealmArchiveOutcomeV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: UUID
    envelope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    replayed: bool


class RealmArchiveCommitResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: UUID
    evidence_id: UUID
    representation_id: UUID
    replayed: bool


class RealmArchiveCommitStore(Protocol):
    def claim(
        self, request: RealmArchiveCommitInputV1, *, request_commitment: str
    ) -> RealmArchiveClaimV1: ...

    def record_outcome(
        self, operation_id: UUID, envelope: RealmArchiveEnvelopeV1
    ) -> RealmArchiveOutcomeV1: ...

    def reconcile(self, operation_id: UUID) -> RealmArchiveCommitResultV1: ...


class RealmConversationArchiveStore(RealmArchiveCommitStore, Protocol):
    def accept_turn(self, request: TurnCaptureInput) -> TurnCaptureResult: ...

    def capture_mode(self, source_conversation_id: str) -> CaptureModeResult: ...

    def set_capture_mode(
        self, idempotency_key: str, request: CaptureModeInput
    ) -> CaptureModeResult: ...


class PostgresRealmArchiveCommitStore:
    """Execute-only adapter; the database derives realm scope from session_user."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def claim(
        self, request: RealmArchiveCommitInputV1, *, request_commitment: str
    ) -> RealmArchiveClaimV1:
        try:
            with self._sessions.begin() as session:
                value = session.execute(
                    text(
                        "SELECT lucy.claim_capturable_scoped_archive_v1("
                        ":conversation,:turn,:key,:commitment,:classification,:lineage)"
                    ),
                    {
                        "conversation": request.source_conversation_id,
                        "turn": request.source_turn_id,
                        "key": request.idempotency_key,
                        "commitment": request_commitment,
                        "classification": request.content_classification,
                        "lineage": json.dumps(request.lineage_refs),
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise RealmArchiveCommitUnavailable("realm archive claim is unavailable") from exc
        return RealmArchiveClaimV1.model_validate(value)

    def record_outcome(
        self, operation_id: UUID, envelope: RealmArchiveEnvelopeV1
    ) -> RealmArchiveOutcomeV1:
        envelope_value = envelope.model_dump(mode="json")
        try:
            with self._sessions.begin() as session:
                value = session.execute(
                    text(
                        "SELECT lucy.record_scoped_archive_aws_outcome_v1("
                        ":operation,:envelope,:digest)"
                    ),
                    {
                        "operation": operation_id,
                        "envelope": envelope.model_dump_json(),
                        "digest": canonical_sha256(envelope_value),
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise RealmArchiveCommitUnavailable("realm archive outcome is unavailable") from exc
        return RealmArchiveOutcomeV1.model_validate(value)

    def reconcile(self, operation_id: UUID) -> RealmArchiveCommitResultV1:
        try:
            with self._sessions.begin() as session:
                value = session.execute(
                    text("SELECT lucy.reconcile_capturable_scoped_archive_v1(:operation)"),
                    {"operation": operation_id},
                ).scalar_one()
        except DBAPIError as exc:
            raise RealmArchiveCommitUnavailable(
                "realm archive reconciliation is unavailable"
            ) from exc
        return RealmArchiveCommitResultV1.model_validate(value)

    def accept_turn(self, request: TurnCaptureInput) -> TurnCaptureResult:
        try:
            with self._sessions.begin() as session:
                value = session.execute(
                    text(
                        "SELECT lucy.accept_scoped_capture_turn_v1("
                        ":conversation,:turn)"
                    ),
                    {
                        "conversation": request.source_conversation_id,
                        "turn": request.source_turn_id,
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise RealmArchiveCommitUnavailable("realm capture receipt is unavailable") from exc
        return TurnCaptureResult.model_validate(value)

    def capture_mode(self, source_conversation_id: str) -> CaptureModeResult:
        try:
            with self._sessions() as session:
                value = session.execute(
                    text("SELECT lucy.get_scoped_capture_mode_v1(:conversation)"),
                    {"conversation": source_conversation_id},
                ).scalar_one()
        except DBAPIError as exc:
            raise RealmArchiveCommitUnavailable("realm capture state is unavailable") from exc
        return CaptureModeResult.model_validate(
            {
                **value,
                "platform": "telegram",
                "source_conversation_id": source_conversation_id,
            }
        )

    def set_capture_mode(
        self, idempotency_key: str, request: CaptureModeInput
    ) -> CaptureModeResult:
        try:
            with self._sessions.begin() as session:
                value = session.execute(
                    text(
                        "SELECT lucy.set_scoped_capture_mode_v1("
                        ":conversation,:enabled,:key)"
                    ),
                    {
                        "conversation": request.source_conversation_id,
                        "enabled": request.capture_enabled,
                        "key": idempotency_key,
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise RealmArchiveCommitUnavailable("realm capture transition is unavailable") from exc
        return CaptureModeResult.model_validate(
            {
                **value,
                "platform": "telegram",
                "source_conversation_id": request.source_conversation_id,
            }
        )


class RealmArchiveCommitService:
    """Resume one archive operation from its last durable PostgreSQL/AWS stage."""

    def __init__(
        self,
        store: RealmArchiveCommitStore,
        encryptor: RealmArchiveEncryptor,
        *,
        request_commitment_key: bytes,
    ) -> None:
        if len(request_commitment_key) != 32:
            raise ValueError("archive request commitment key must contain 32 bytes")
        self._store = store
        self._encryptor = encryptor
        self._request_commitment_key = request_commitment_key

    def preserve(self, request: RealmArchiveCommitInputV1) -> RealmArchiveCommitResultV1:
        commitment = self._request_commitment(request)
        claim = self._store.claim(request, request_commitment=commitment)
        if claim.stage == "RECONCILED":
            return self._store.reconcile(claim.operation_id)
        if claim.stage == "INTENT_RECORDED":
            envelope = self._encryptor.recover(
                evidence_id=claim.evidence_id,
                representation_id=claim.representation_id,
                key_ref=claim.wrapped_key_ref,
                request_commitment=commitment,
            )
            if envelope is None:
                envelope = self._encryptor.encrypt(
                    evidence_id=claim.evidence_id,
                    representation_id=claim.representation_id,
                    key_ref=claim.wrapped_key_ref,
                    plaintext=request.plaintext,
                    authenticated_header=request.authenticated_header,
                    request_commitment=commitment,
                )
            outcome = self._store.record_outcome(claim.operation_id, envelope)
            if outcome.operation_id != claim.operation_id:
                raise RealmArchiveCommitUnavailable("realm archive outcome changed operation")
        return self._store.reconcile(claim.operation_id)

    def _request_commitment(self, request: RealmArchiveCommitInputV1) -> str:
        metadata = {
            "source_conversation_id": request.source_conversation_id,
            "source_turn_id": request.source_turn_id,
            "idempotency_key": request.idempotency_key,
            "authenticated_header": request.authenticated_header.hex(),
            "content_classification": request.content_classification,
            "lineage_refs": request.lineage_refs,
        }
        material = b"LUCY-REALM-ARCHIVE-REQUEST-V1\x00" + canonical_json_bytes(metadata)
        material += b"\x00" + request.plaintext
        return hmac.new(self._request_commitment_key, material, hashlib.sha256).hexdigest()


class RealmConversationArchiveService:
    """Preserve the existing Hermes HTTP contract over the V1.3 realm protocol."""

    def __init__(
        self,
        store: RealmConversationArchiveStore,
        commit_service: RealmArchiveCommitService,
        *,
        capture_authorized: bool,
    ) -> None:
        self._store = store
        self._commit_service = commit_service
        self._capture_authorized = capture_authorized

    def accept_turn(self, request: TurnCaptureInput) -> TurnCaptureResult:
        if not self._capture_authorized:
            return TurnCaptureResult(capture_enabled=False, version=0)
        return self._store.accept_turn(request)

    def capture_mode(self, platform: str, source_conversation_id: str) -> CaptureModeResult:
        if platform != "telegram":
            raise ValueError("realm capture platform is invalid")
        result = self._store.capture_mode(source_conversation_id)
        if self._capture_authorized:
            return result
        return result.model_copy(update={"capture_enabled": False})

    def set_capture_mode(
        self, idempotency_key: str, request: CaptureModeInput
    ) -> CaptureModeResult:
        if request.capture_enabled and not self._capture_authorized:
            raise PermissionError("live capture has not been authorized")
        return self._store.set_capture_mode(idempotency_key, request)

    def preserve_message(
        self,
        idempotency_key: str,
        request: ConversationMessageArchiveInput,
    ) -> ConversationMessageArchiveResult:
        if not self._capture_authorized:
            raise PermissionError("live capture has not been authorized")
        if request.role == "user" and request.source_evidence_ids:
            raise ValueError("inbound user evidence is an independent source")
        lineage = tuple(str(value) for value in sorted(request.source_evidence_ids))
        authenticated_header = canonical_json_bytes(
            {
                "contract_version": "realm-archive-message-v1",
                "platform": request.platform,
                "source_conversation_id": request.source_conversation_id,
                "source_turn_id": request.source_turn_id,
                "source_message_id": request.source_message_id,
                "role": request.role,
                "lineage_refs": lineage,
            }
        )
        result = self._commit_service.preserve(
            RealmArchiveCommitInputV1(
                source_conversation_id=request.source_conversation_id,
                source_turn_id=request.source_turn_id,
                idempotency_key=idempotency_key,
                plaintext=request.content.encode("utf-8"),
                authenticated_header=authenticated_header,
                content_classification="owner_conversation",
                lineage_refs=lineage,
            )
        )
        return ConversationMessageArchiveResult(
            operation_id=result.operation_id,
            evidence_id=result.evidence_id,
            archived=True,
            capture_enabled=True,
            replayed=result.replayed,
        )


def realm_archive_commit_from_environment(
    environment: Mapping[str, str] | None = None,
    *,
    encryptor: RealmArchiveEncryptor | None = None,
) -> RealmArchiveCommitService:
    """Construct one realm-bound archive workflow from deployment-owned settings."""

    values = os.environ if environment is None else environment
    database_url, request_key = _commit_configuration(values)
    archive_encryptor = encryptor or realm_archive_from_environment(values)
    return RealmArchiveCommitService(
        PostgresRealmArchiveCommitStore(create_session_factory(database_url)),
        archive_encryptor,
        request_commitment_key=request_key,
    )


def realm_conversation_archive_from_environment(
    environment: Mapping[str, str] | None = None,
) -> RealmConversationArchiveService:
    """Compose the V1.3 realm archive behind the existing Hermes API contract."""

    values = os.environ if environment is None else environment
    database_url, request_key = _commit_configuration(values)
    store = PostgresRealmArchiveCommitStore(create_session_factory(database_url))
    commit = RealmArchiveCommitService(
        store,
        realm_archive_from_environment(values),
        request_commitment_key=request_key,
    )
    return RealmConversationArchiveService(
        store,
        commit,
        capture_authorized=values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") == "true",
    )


def _commit_configuration(values: Mapping[str, str]) -> tuple[str, bytes]:
    database_url = values.get("LUCY_DATABASE_URL", "").strip()
    encoded_key = values.get("LUCY_ARCHIVE_REQUEST_COMMITMENT_KEY_B64", "").strip()
    if not database_url or not encoded_key:
        raise ValueError("realm archive commit configuration is incomplete")
    try:
        request_key = base64.b64decode(encoded_key, validate=True)
    except ValueError as exc:
        raise ValueError("realm archive request commitment key is invalid") from exc
    if len(request_key) != 32:
        raise ValueError("realm archive request commitment key must contain 32 bytes")
    return database_url, request_key
