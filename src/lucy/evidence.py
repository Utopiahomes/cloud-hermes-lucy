"""Governed encrypted-evidence retrieval and owner-sovereign deletion."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from lucy.archive_crypto import (
    ALGORITHM,
    ArchiveKeyStore,
    EncryptedPayload,
    EnvelopeCipher,
)
from lucy.audit import append_audit
from lucy.contracts import ApprovalStatus, OperationOutcome
from lucy.contracts.v1 import ConversationMessageV1
from lucy.db.models import (
    ApprovalRequestRow,
    ConversationTurnRow,
    EvidencePayloadRow,
    EvidenceRow,
    EvidenceTombstoneRow,
    MemoryClaimRow,
    MemoryCorrectionRow,
    MemoryEntityRow,
    MemoryRelationshipRow,
    MemoryWriteProposalRow,
    OperationRow,
    WorkingContextRow,
)

EvidenceAccessReason = Literal[
    "verify_exact_wording",
    "resolve_ambiguity",
    "recover_missing_context",
    "owner_review",
    "owner_export",
]
DeletionReason = Literal["owner_request", "sensitive_data", "retention_expired"]


class EvidenceRetrievalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: UUID
    claim_id: UUID | None = None
    reason: EvidenceAccessReason


class EvidenceRetrievalResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: UUID
    message: ConversationMessageV1
    reason: EvidenceAccessReason
    autonomous: bool
    audited: bool = True
    replayed: bool = False


class EvidenceDeletionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: UUID
    reason: DeletionReason


class ForgetLastRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: Literal["telegram"]
    source_conversation_id: str
    reason: DeletionReason = "owner_request"


class EvidenceDeletionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: UUID
    deleted: bool
    key_destroyed: bool
    derived_summary: dict[str, int]
    replayed: bool = False


class EvidenceService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        cipher: EnvelopeCipher,
        key_store: ArchiveKeyStore,
    ) -> None:
        self._sessions = sessions
        self._cipher = cipher
        self._key_store = key_store

    def retrieve(
        self,
        idempotency_key: str,
        request: EvidenceRetrievalRequest,
        *,
        owner: bool,
    ) -> EvidenceRetrievalResult:
        if owner and request.reason not in {"owner_review", "owner_export"}:
            raise ValueError("owner retrieval requires an owner reason")
        if not owner and request.reason in {"owner_review", "owner_export"}:
            raise PermissionError("autonomous retrieval cannot use an owner reason")
        with self._sessions.begin() as session:
            session.execute(
                select(
                    func.pg_advisory_xact_lock(func.hashtext(str(request.evidence_id)))
                )
            )
            evidence = session.get(EvidenceRow, request.evidence_id)
            if evidence is None:
                raise LookupError("evidence does not exist")
            if session.get(EvidenceTombstoneRow, evidence.id) is not None:
                raise LookupError("evidence payload was deleted")
            payload = session.get(EvidencePayloadRow, evidence.id)
            if payload is None or payload.algorithm != ALGORITHM:
                raise LookupError("encrypted evidence payload is unavailable")
            if not owner:
                if request.claim_id is None:
                    raise PermissionError(
                        "autonomous retrieval requires a current provenance-linked claim"
                    )
                claim = session.get(MemoryClaimRow, request.claim_id)
                if (
                    claim is None
                    or claim.evidence_id != evidence.id
                    or claim.status in {"superseded", "invalidated"}
                ):
                    raise PermissionError(
                        "autonomous retrieval requires a current provenance-linked claim"
                    )

            wrapped_key = self._key_store.get(payload.key_ref)
            if wrapped_key is None:
                raise LookupError("evidence decryption key was destroyed")
            encrypted = EncryptedPayload(
                ciphertext=payload.ciphertext,
                content_nonce=payload.content_nonce,
                wrapped_key=wrapped_key,
                keyed_commitment=evidence.content_sha256,
            )
            plaintext = self._cipher.decrypt(
                evidence.id,
                encrypted,
                _canonical_json(evidence.content),
            )
            message = ConversationMessageV1.model_validate_json(plaintext)

            session.execute(
                select(func.pg_advisory_xact_lock(func.hashtext(idempotency_key)))
            )
            operation = session.scalar(
                select(OperationRow).where(
                    OperationRow.idempotency_key == idempotency_key
                )
            )
            replayed = operation is not None
            if operation is None:
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
                    {"operation_type": "evidence.retrieve"},
                )
                append_audit(
                    session,
                    operation.id,
                    "evidence.retrieved",
                    {
                        "evidence_id": str(evidence.id),
                        "claim_id": str(request.claim_id) if request.claim_id else None,
                        "reason": request.reason,
                        "autonomous": not owner,
                    },
                )
                operation.outcome = OperationOutcome.SUCCEEDED
                operation.result = {
                    "evidence_id": str(evidence.id),
                    "reason": request.reason,
                    "autonomous": not owner,
                }
                operation.completed_at = now
                append_audit(
                    session,
                    operation.id,
                    "operation.succeeded",
                    {"operation_type": "evidence.retrieve"},
                )
            else:
                if (
                    operation.outcome != OperationOutcome.SUCCEEDED
                    or operation.result is None
                ):
                    raise RuntimeError("evidence retrieval operation is not replayable")
                expected = {
                    "evidence_id": str(evidence.id),
                    "reason": request.reason,
                    "autonomous": not owner,
                }
                if operation.result != expected:
                    raise ValueError(
                        "idempotency key was already used for another evidence retrieval"
                    )
            return EvidenceRetrievalResult(
                evidence_id=evidence.id,
                message=message,
                reason=request.reason,
                autonomous=not owner,
                replayed=replayed,
            )

    def delete(
        self,
        idempotency_key: str,
        request: EvidenceDeletionRequest,
    ) -> EvidenceDeletionResult:
        with self._sessions.begin() as session:
            session.execute(
                select(func.pg_advisory_xact_lock(func.hashtext(idempotency_key)))
            )
            existing = session.scalar(
                select(OperationRow).where(
                    OperationRow.idempotency_key == idempotency_key
                )
            )
            if existing is not None:
                if existing.outcome != OperationOutcome.SUCCEEDED or existing.result is None:
                    raise RuntimeError("evidence deletion operation is not replayable")
                if (
                    existing.result.get("evidence_id") != str(request.evidence_id)
                    or existing.result.get("request_reason") != request.reason
                ):
                    raise ValueError(
                        "idempotency key was already used for another evidence deletion"
                    )
                return EvidenceDeletionResult.model_validate(
                    {
                        key: value
                        for key, value in existing.result.items()
                        if key != "request_reason"
                    }
                    | {"replayed": True}
                )

            session.execute(
                select(
                    func.pg_advisory_xact_lock(func.hashtext(str(request.evidence_id)))
                )
            )
            evidence = session.get(EvidenceRow, request.evidence_id)
            if evidence is None:
                raise LookupError("evidence does not exist")
            tombstone = session.get(EvidenceTombstoneRow, evidence.id)
            if tombstone is not None:
                return EvidenceDeletionResult(
                    evidence_id=evidence.id,
                    deleted=True,
                    key_destroyed=True,
                    derived_summary={
                        str(key): int(value)
                        for key, value in tombstone.derived_summary.items()
                    },
                    replayed=True,
                )
            payload = session.get(EvidencePayloadRow, evidence.id)
            if payload is None:
                raise LookupError("encrypted evidence payload is unavailable")

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
                {"operation_type": "evidence.delete"},
            )

            key_destroyed = self._key_store.delete(payload.key_ref)
            if not key_destroyed:
                # A prior crash may have happened after external key destruction
                # but before this PostgreSQL transaction committed. Treat an
                # already-absent key as destroyed and finish the durable cascade.
                key_destroyed = self._key_store.get(payload.key_ref) is None
            if not key_destroyed:
                raise RuntimeError("evidence key destruction was not confirmed")
            session.delete(payload)
            summary = self._invalidate_derived(session, evidence.id, now)
            session.add(
                EvidenceTombstoneRow(
                    evidence_id=evidence.id,
                    deletion_operation_id=operation.id,
                    reason_category=request.reason,
                    deleted_at=now,
                    derived_summary=summary,
                )
            )
            append_audit(
                session,
                operation.id,
                "evidence.deleted",
                {
                    "evidence_id": str(evidence.id),
                    "reason": request.reason,
                    "key_destroyed": key_destroyed,
                    "derived_summary": summary,
                },
            )
            result = EvidenceDeletionResult(
                evidence_id=evidence.id,
                deleted=True,
                key_destroyed=key_destroyed,
                derived_summary=summary,
            )
            operation.outcome = OperationOutcome.SUCCEEDED
            operation.result = {
                **result.model_dump(mode="json"),
                "request_reason": request.reason,
            }
            operation.completed_at = now
            append_audit(
                session,
                operation.id,
                "operation.succeeded",
                {"operation_type": "evidence.delete"},
            )
            return result

    def reconcile_missing_keys(self) -> int:
        """Finish crypto-shredding transactions interrupted after key deletion."""

        with self._sessions() as session:
            candidates = list(
                session.execute(
                    select(EvidencePayloadRow.evidence_id, EvidencePayloadRow.key_ref)
                )
            )
        missing = [
            evidence_id
            for evidence_id, key_ref in candidates
            if self._key_store.get(key_ref) is None
        ]
        for evidence_id in missing:
            self.delete(
                f"archive-reconcile-missing-key:{evidence_id}",
                EvidenceDeletionRequest(
                    evidence_id=evidence_id,
                    reason="sensitive_data",
                ),
            )
        return len(missing)

    def delete_last_message(
        self, idempotency_key: str, request: ForgetLastRequest
    ) -> EvidenceDeletionResult:
        source_id = f"{request.platform}:{request.source_conversation_id}"
        with self._sessions() as session:
            evidence_id = session.scalar(
                select(EvidenceRow.id)
                .join(
                    EvidencePayloadRow,
                    EvidencePayloadRow.evidence_id == EvidenceRow.id,
                )
                .where(
                    EvidenceRow.source == "hermes",
                    EvidenceRow.source_conversation_id == source_id,
                )
                .order_by(EvidenceRow.captured_at.desc())
                .limit(1)
            )
        if evidence_id is None:
            raise LookupError("conversation has no retained message")
        return self.delete(
            idempotency_key,
            EvidenceDeletionRequest(evidence_id=evidence_id, reason=request.reason),
        )

    @staticmethod
    def _invalidate_derived(
        session: Session, evidence_id: UUID, now: datetime
    ) -> dict[str, int]:
        claims = list(
            session.scalars(
                select(MemoryClaimRow).where(MemoryClaimRow.evidence_id == evidence_id)
            )
        )
        claim_ids = {claim.id for claim in claims}
        while claim_ids:
            descendants = set(
                session.scalars(
                    select(MemoryClaimRow.id).where(
                        MemoryClaimRow.supersedes_claim_id.in_(claim_ids)
                    )
                )
            )
            new_ids = descendants - claim_ids
            if not new_ids:
                break
            claim_ids.update(new_ids)
        all_claims = (
            list(
                session.scalars(
                    select(MemoryClaimRow).where(MemoryClaimRow.id.in_(claim_ids))
                )
            )
            if claim_ids
            else []
        )
        relationships = (
            list(
                session.scalars(
                    select(MemoryRelationshipRow).where(
                        or_(
                            MemoryRelationshipRow.evidence_id == evidence_id,
                            MemoryRelationshipRow.claim_id.in_(claim_ids),
                        )
                    )
                )
            )
            if claim_ids
            else list(
                session.scalars(
                    select(MemoryRelationshipRow).where(
                        MemoryRelationshipRow.evidence_id == evidence_id
                    )
                )
            )
        )
        entity_ids: set[UUID] = set()
        for relationship in relationships:
            relationship.predicate = "[redacted]"
            relationship.valid_to = relationship.valid_to or now
            entity_ids.update(
                {relationship.subject_entity_id, relationship.object_entity_id}
            )
        for claim in all_claims:
            claim.subject = "[redacted]"
            claim.predicate = "[redacted]"
            claim.object = "[redacted]"
            claim.status = "invalidated"

        proposals = list(
            session.scalars(
                select(MemoryWriteProposalRow).where(
                    or_(
                        MemoryWriteProposalRow.evidence_id == evidence_id,
                        MemoryWriteProposalRow.claim_id.in_(claim_ids),
                    )
                )
            )
        )
        corrections = list(
            session.scalars(
                select(MemoryCorrectionRow).where(
                    or_(
                        MemoryCorrectionRow.new_evidence_id == evidence_id,
                        MemoryCorrectionRow.old_claim_id.in_(claim_ids),
                        MemoryCorrectionRow.new_claim_id.in_(claim_ids),
                    )
                )
            )
        )
        approval_ids: set[UUID] = set()
        for proposal in proposals:
            proposal.subject = "[redacted]"
            proposal.predicate = "[redacted]"
            proposal.object = "[redacted]"
            proposal.status = "rejected"
            approval_ids.add(proposal.approval_id)
        for correction in corrections:
            correction.replacement_object = "[redacted]"
            correction.status = "rejected"
            approval_ids.add(correction.approval_id)
        if approval_ids:
            approvals = session.scalars(
                select(ApprovalRequestRow).where(ApprovalRequestRow.id.in_(approval_ids))
            )
            for approval in approvals:
                approval.action_payload = {"redacted": True}
                if approval.status == ApprovalStatus.PENDING:
                    approval.status = ApprovalStatus.DENIED
                    approval.decided_at = now
                    approval.decided_by = "owner-evidence-deletion"
                    approval.actor_type = "human_owner"
                    approval.decision_reason = "source evidence deleted"
                    approval.version += 1

        redacted_entities = 0
        for entity_id in entity_ids:
            active_reference = session.scalar(
                select(func.count())
                .select_from(MemoryRelationshipRow)
                .join(MemoryClaimRow, MemoryClaimRow.id == MemoryRelationshipRow.claim_id)
                .where(
                    or_(
                        MemoryRelationshipRow.subject_entity_id == entity_id,
                        MemoryRelationshipRow.object_entity_id == entity_id,
                    ),
                    MemoryClaimRow.status != "invalidated",
                )
            )
            if not active_reference:
                entity = session.get(MemoryEntityRow, entity_id)
                if entity is not None:
                    entity.canonical_name = f"[redacted]:{entity.id}"
                    entity.version += 1
                    redacted_entities += 1

        working_contexts = (
            session.scalar(select(func.count()).select_from(WorkingContextRow)) or 0
        )
        session.execute(delete(WorkingContextRow))
        turns = list(
            session.scalars(
                select(ConversationTurnRow).where(
                    or_(
                        ConversationTurnRow.user_evidence_id == evidence_id,
                        ConversationTurnRow.assistant_evidence_id == evidence_id,
                    )
                )
            )
        )
        for turn in turns:
            turn.status = "redacted"
            turn.updated_at = now
        return {
            "claims_invalidated": len(all_claims),
            "relationships_invalidated": len(relationships),
            "proposals_rejected": len(proposals),
            "corrections_rejected": len(corrections),
            "entities_redacted": redacted_entities,
            "working_contexts_purged": working_contexts,
            "turns_redacted": len(turns),
        }


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
