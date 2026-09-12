"""Execute-only clients for the governed realm-scoped memory path."""

from __future__ import annotations

import hashlib
import hmac
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_import import (
    ImportManifestRecordV1,
    ImportManifestV1,
    MemoryCandidatePayloadV1,
    ProtectionClass,
)
from lucy.realm_archive import RealmArchiveEncryptor
from lucy.realm_archive_commit import RealmArchiveCommitInputV1
from lucy.secret_filter import MemorySecretDetected, detect_memory_secrets


class GovernedMemoryUnavailable(PermissionError):
    pass


class CandidateStageResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    candidate_id: UUID
    candidate_version: int = Field(ge=1)
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    replayed: bool


class CandidateApprovalResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    approval_id: UUID
    replayed: bool


class CandidatePromotionResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    claim_id: UUID
    replayed: bool


class ImportCampaignResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    campaign_id: UUID
    replayed: bool


class ImportAttemptResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    reservation_id: UUID
    replayed: bool


class ImportArchiveResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    evidence_id: UUID
    representation_id: UUID
    replayed: bool


class GovernedMemoryClaimV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    claim_id: UUID
    candidate_id: UUID | None
    candidate_version: int | None
    subject: str
    predicate: str
    object: str
    confidence_millionths: int
    status: str
    protection_class: ProtectionClass
    memory_kind: str | None
    assertion_status: str | None
    epistemic_status: str | None
    domain_tags: tuple[str, ...]
    source_evidence_ids: tuple[UUID, ...] = Field(min_length=1)


class GovernedMemoryExtractor:
    """A realm-bound extractor may stage protected candidates, never approve them."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def stage(self, candidate: MemoryCandidatePayloadV1) -> CandidateStageResultV1:
        findings = detect_memory_secrets(candidate.subject, candidate.predicate, candidate.object)
        if findings:
            raise MemorySecretDetected(tuple(item.category for item in findings))
        try:
            with self._sessions.begin() as session:
                result = session.execute(
                    text("SELECT lucy.stage_memory_import_candidate_v1(CAST(:candidate AS jsonb))"),
                    {"candidate": canonical_json_bytes(candidate).decode("utf-8")},
                ).scalar_one()
        except DBAPIError as exc:
            raise GovernedMemoryUnavailable("memory candidate staging is unavailable") from exc
        return CandidateStageResultV1.model_validate(result)

    def reserve_attempt(
        self, campaign_id: UUID, *, attempt_key: str, reserved_microusd: int
    ) -> ImportAttemptResultV1:
        try:
            with self._sessions.begin() as session:
                result = session.execute(
                    text(
                        "SELECT lucy.reserve_memory_import_attempt_v1("
                        ":campaign,:attempt_key,:reserved)"
                    ),
                    {
                        "campaign": campaign_id,
                        "attempt_key": attempt_key,
                        "reserved": reserved_microusd,
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise GovernedMemoryUnavailable(
                "memory import attempt reservation unavailable"
            ) from exc
        return ImportAttemptResultV1.model_validate(result)

    def settle_attempt(
        self, reservation_id: UUID, *, billed_microusd: int, result: str
    ) -> ImportAttemptResultV1:
        try:
            with self._sessions.begin() as session:
                value = session.execute(
                    text(
                        "SELECT lucy.settle_memory_import_attempt_v1("
                        ":reservation,:billed,:result)"
                    ),
                    {
                        "reservation": reservation_id,
                        "billed": billed_microusd,
                        "result": result,
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise GovernedMemoryUnavailable("memory import attempt settlement unavailable") from exc
        return ImportAttemptResultV1.model_validate(value)


class GovernedMemoryArchive:
    """Encrypt and register only exact records in one authorized import manifest."""

    def __init__(
        self,
        sessions: sessionmaker[Session],
        encryptor: RealmArchiveEncryptor,
        *,
        request_commitment_key: bytes,
    ) -> None:
        if len(request_commitment_key) != 32:
            raise ValueError("import archive request commitment key must contain 32 bytes")
        self._sessions = sessions
        self._encryptor = encryptor
        self._request_commitment_key = request_commitment_key

    def preserve(
        self,
        manifest: ImportManifestV1,
        record: ImportManifestRecordV1,
        request: RealmArchiveCommitInputV1,
    ) -> ImportArchiveResultV1:
        expected_key = (
            f"memory-import:{manifest.digest}:{record.source_record_id}:"
            f"r{record.source_revision}"
        )
        if (
            record not in manifest.records
            or not record.included
            or request.idempotency_key != expected_key
            or len(request.plaintext) != record.byte_length
        ):
            raise ValueError("import archive request is outside its manifest")
        evidence_id = uuid5(
            manifest.campaign_id,
            f"evidence:{record.source_record_id}:r{record.source_revision}",
        )
        representation_id = uuid5(manifest.campaign_id, f"representation:{evidence_id}")
        key_ref = uuid5(manifest.campaign_id, f"wrapped-key:{evidence_id}")
        request_commitment = hmac.new(
            self._request_commitment_key,
            b"LUCY-MEMORY-IMPORT-ARCHIVE-V1\x00"
            + request.idempotency_key.encode("utf-8")
            + b"\x00"
            + request.plaintext,
            hashlib.sha256,
        ).hexdigest()
        envelope = self._encryptor.recover(
            evidence_id=evidence_id,
            representation_id=representation_id,
            key_ref=key_ref,
            request_commitment=request_commitment,
        )
        if envelope is None:
            envelope = self._encryptor.encrypt(
                evidence_id=evidence_id,
                representation_id=representation_id,
                key_ref=key_ref,
                plaintext=request.plaintext,
                authenticated_header=request.authenticated_header,
                request_commitment=request_commitment,
            )
        try:
            with self._sessions.begin() as session:
                value = session.execute(
                    text(
                        "SELECT lucy.register_memory_import_evidence_v1("
                        ":campaign,:source,CAST(:payload AS jsonb),CAST(:wrapper AS jsonb))"
                    ),
                    {
                        "campaign": manifest.campaign_id,
                        "source": record.source_record_id,
                        "payload": envelope.payload_binding.model_dump_json(),
                        "wrapper": envelope.wrapper_binding.model_dump_json(),
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise GovernedMemoryUnavailable("memory import archive unavailable") from exc
        return ImportArchiveResultV1.model_validate(value)


class GovernedMemoryPolicy:
    """A separately bound policy process approves, promotes, and audits protected recall."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def approve(
        self,
        candidate: MemoryCandidatePayloadV1,
        *,
        owner_approval_ref: UUID,
        owner_actor_id: str,
    ) -> CandidateApprovalResultV1:
        try:
            with self._sessions.begin() as session:
                result = session.execute(
                    text(
                        "SELECT lucy.approve_scoped_memory_candidate_v1("
                        ":candidate,:version,:digest,:owner_ref,:owner_actor)"
                    ),
                    {
                        "candidate": candidate.candidate_id,
                        "version": candidate.candidate_version,
                        "digest": candidate.digest,
                        "owner_ref": owner_approval_ref,
                        "owner_actor": owner_actor_id,
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise GovernedMemoryUnavailable("memory candidate approval is unavailable") from exc
        return CandidateApprovalResultV1.model_validate(result)

    def authorize_campaign(self, manifest: ImportManifestV1) -> ImportCampaignResultV1:
        try:
            with self._sessions.begin() as session:
                result = session.execute(
                    text(
                        "SELECT lucy.authorize_memory_import_campaign_v1("
                        ":campaign,CAST(:manifest AS jsonb),:digest,:spend,:attempts,:expires,"
                        ":extractor,:prompt,:model_route)"
                    ),
                    {
                        "campaign": manifest.campaign_id,
                        "manifest": canonical_json_bytes(manifest).decode("utf-8"),
                        "digest": manifest.digest,
                        "spend": manifest.max_model_spend_microusd,
                        "attempts": manifest.max_attempts,
                        "expires": manifest.expires_at,
                        "extractor": manifest.extractor_version,
                        "prompt": manifest.prompt_version,
                        "model_route": manifest.model_route,
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise GovernedMemoryUnavailable(
                "memory import campaign authorization unavailable"
            ) from exc
        return ImportCampaignResultV1.model_validate(result)

    def promote(
        self, approval_id: UUID, *, expected_digest: str
    ) -> CandidatePromotionResultV1:
        try:
            with self._sessions.begin() as session:
                result = session.execute(
                    text("SELECT lucy.promote_scoped_memory_candidate_v1(:approval,:digest)"),
                    {"approval": approval_id, "digest": expected_digest},
                ).scalar_one()
        except DBAPIError as exc:
            raise GovernedMemoryUnavailable("memory candidate promotion is unavailable") from exc
        return CandidatePromotionResultV1.model_validate(result)

    def protected_recall(
        self,
        query: str,
        *,
        owner_interaction_ref: UUID,
        reason_code: str,
        limit: int = 5,
    ) -> tuple[GovernedMemoryClaimV1, ...]:
        if not query.strip() or len(query) > 200 or not 1 <= limit <= 20:
            raise ValueError("protected memory query is invalid")
        try:
            with self._sessions.begin() as session:
                result = session.execute(
                    text(
                        "SELECT lucy.search_protected_scoped_memory_v1("
                        ":query,:limit,:interaction,:reason)"
                    ),
                    {
                        "query": query,
                        "limit": limit,
                        "interaction": owner_interaction_ref,
                        "reason": reason_code,
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise GovernedMemoryUnavailable("protected memory recall is unavailable") from exc
        return tuple(GovernedMemoryClaimV1.model_validate(item) for item in result)


class GovernedMemoryReader:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def ordinary_recall(
        self, query: str, *, limit: int = 10
    ) -> tuple[GovernedMemoryClaimV1, ...]:
        if not query.strip() or len(query) > 200 or not 1 <= limit <= 50:
            raise ValueError("ordinary memory query is invalid")
        try:
            with self._sessions() as session:
                result = session.execute(
                    text("SELECT lucy.search_governed_scoped_memory_v1(:query,:limit)"),
                    {"query": query, "limit": limit},
                ).scalar_one()
        except DBAPIError as exc:
            raise GovernedMemoryUnavailable("ordinary memory recall is unavailable") from exc
        return tuple(GovernedMemoryClaimV1.model_validate(item) for item in result)
