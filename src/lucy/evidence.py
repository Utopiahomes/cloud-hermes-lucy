"""Governed encrypted-evidence retrieval and owner-sovereign deletion."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete, func, or_, select, text
from sqlalchemy.orm import Session, sessionmaker

from lucy.archive_crypto import ArchiveCipher, ArchiveKeyStore, EncryptedPayload
from lucy.audit import append_audit
from lucy.authorization import (
    SensitiveAction,
    SensitiveActionPermitV1,
    SensitiveActionPermitVerifier,
)
from lucy.contracts import ApprovalStatus, OperationOutcome
from lucy.contracts.v1 import ConversationMessageV1
from lucy.db.models import (
    ApprovalRequestRow,
    ClaimSourceRow,
    ConversationTurnRow,
    CorrectionSourceRow,
    DeletionJournalReceiptRow,
    EvidencePayloadRow,
    EvidenceRow,
    EvidenceTombstoneRow,
    MemoryClaimRow,
    MemoryCorrectionRow,
    MemoryEntityRow,
    MemoryRelationshipRow,
    MemoryWriteProposalRow,
    OperationRow,
    ProposalSourceRow,
    SensitiveActionPermitRow,
    WorkingContextRow,
)
from lucy.deletion_journal import (
    DeletionIntentV1,
    DeletionJournal,
    DeletionJournalError,
    DeletionTargetV1,
    JournalEntry,
    check_journal_admission,
)
from lucy.provenance import (
    active_sources,
    claim_sources,
    evidence_descendants,
    verify_archive_provenance,
)
from lucy.readiness import ADMISSION_LOCK
from lucy.retention import retention_fence

EvidenceAccessReason = Literal[
    "verify_exact_wording",
    "resolve_ambiguity",
    "recover_missing_context",
    "owner_review",
]
DeletionReason = Literal["owner_request", "sensitive_data", "retention_expired"]


class EvidenceRetrievalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: UUID
    claim_id: UUID | None = None
    reason: EvidenceAccessReason
    permit: SensitiveActionPermitV1


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
    permit: SensitiveActionPermitV1


class ForgetLastRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: Literal["telegram"]
    source_conversation_id: str
    reason: DeletionReason = "owner_request"
    permit: SensitiveActionPermitV1


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
        cipher: ArchiveCipher | None,
        key_store: ArchiveKeyStore,
        permit_verifier: SensitiveActionPermitVerifier,
        *,
        journal: DeletionJournal | None = None,
    ) -> None:
        self._sessions = sessions
        self._cipher = cipher
        self._key_store = key_store
        self._permit_verifier = permit_verifier
        self._journal = journal

    def latest_retained_evidence(self, platform: str, source_conversation_id: str) -> UUID:
        source_id = f"{platform}:{source_conversation_id}"
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
            raise LookupError("conversation has no retained evidence")
        return evidence_id

    def retrieve(
        self,
        idempotency_key: str,
        request: EvidenceRetrievalRequest,
        *,
        owner: bool,
    ) -> EvidenceRetrievalResult:
        try:
            return self._retrieve(idempotency_key, request, owner=owner)
        except (PermissionError, LookupError, ValueError):
            # The failing transaction has rolled back. Commit a sanitized denial
            # independently; never serialize unverified permit text or content.
            with self._sessions.begin() as session:
                now = datetime.now(UTC)
                operation = OperationRow(
                    id=uuid4(),
                    idempotency_key=f"evidence-denial:{uuid4()}",
                    outcome=OperationOutcome.FAILED,
                    result={"denied": True},
                    created_at=now,
                    completed_at=now,
                )
                session.add(operation)
                session.flush()
                append_audit(
                    session,
                    operation.id,
                    "evidence.retrieval_denied",
                    {
                        "evidence_id": str(request.evidence_id),
                        "owner_endpoint": owner,
                    },
                )
            raise

    def _retrieve(
        self,
        idempotency_key: str,
        request: EvidenceRetrievalRequest,
        *,
        owner: bool,
    ) -> EvidenceRetrievalResult:
        if owner and request.reason != "owner_review":
            raise ValueError("owner retrieval requires an owner reason")
        if not owner and request.reason == "owner_review":
            raise PermissionError("autonomous retrieval cannot use an owner reason")
        with self._sessions.begin() as session:
            retention_fence(session)
            session.execute(
                select(func.pg_advisory_xact_lock(func.hashtext(str(request.evidence_id))))
            )
            evidence = session.get(EvidenceRow, request.evidence_id)
            if evidence is None:
                raise LookupError("evidence does not exist")
            if session.get(EvidenceTombstoneRow, evidence.id) is not None:
                raise LookupError("evidence payload was deleted")
            active_sources(session, {evidence.id})
            payload = session.get(EvidencePayloadRow, evidence.id)
            if self._cipher is None:
                raise PermissionError("this service has no evidence-decryption capability")
            if payload is None or payload.algorithm != self._cipher.algorithm:
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
                claim_sources(session, claim.id)

            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(idempotency_key))))
            operation = session.scalar(
                select(OperationRow).where(OperationRow.idempotency_key == idempotency_key)
            )
            expected = {
                "evidence_id": str(evidence.id),
                "reason": request.reason,
                "autonomous": not owner,
            }
            if operation is not None:
                if operation.outcome != OperationOutcome.SUCCEEDED or operation.result is None:
                    raise RuntimeError("evidence retrieval operation is not replayable")
                if operation.result != expected:
                    raise ValueError(
                        "idempotency key was already used for another evidence retrieval"
                    )
                raise PermissionError("disclosure already completed; a new permit is required")

            self._permit_verifier.authorize(
                session,
                request.permit,
                idempotency_key=idempotency_key,
                action=SensitiveAction.EVIDENCE_RETRIEVE,
                evidence_id=evidence.id,
                reason=request.reason,
                allow_replay=False,
            )

            wrapped_key = self._key_store.get(payload.key_ref)
            if wrapped_key is None:
                raise LookupError("evidence decryption key was destroyed")
            encrypted = EncryptedPayload(
                ciphertext=payload.ciphertext,
                content_nonce=payload.content_nonce,
                wrapped_key=wrapped_key,
                keyed_commitment=evidence.content_commitment,
            )
            plaintext = self._cipher.decrypt(
                evidence.id,
                encrypted,
                _canonical_json(evidence.content),
            )
            if len(plaintext) > request.permit.max_bytes:
                raise PermissionError("source record exceeds the permit byte limit")
            message = ConversationMessageV1.model_validate_json(plaintext)

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
                        "permit_id": str(request.permit.permit_id),
                        "disclosed_bytes": len(plaintext),
                        "owner_subject": request.permit.owner_subject,
                        "owner_interaction_id": request.permit.owner_interaction_id,
                    },
                )
                operation.outcome = OperationOutcome.SUCCEEDED
                operation.result = expected
                operation.completed_at = now
                append_audit(
                    session,
                    operation.id,
                    "operation.succeeded",
                    {"operation_type": "evidence.retrieve"},
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
        if self._journal is None:
            raise DeletionJournalError("independent deletion journal is required")
        with self._sessions.begin() as session:
            # Set before the first SQL statement: never upgrade a shared lock.
            # Normal transactions drain before intent publication, then wait
            # until commit/rollback and recheck the independent journal head.
            session.info["deletion_execution"] = True
            session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": ADMISSION_LOCK})
            head = check_journal_admission(session.connection(), self._journal)
            assert head is not None
            if self._key_store.registry_identity != head.registry_id:
                raise DeletionJournalError("archive registry identity mismatch")
            retention_fence(session, deleting=True)
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(idempotency_key))))
            existing = session.scalar(
                select(OperationRow).where(OperationRow.idempotency_key == idempotency_key)
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
                self._permit_verifier.authorize(
                    session,
                    request.permit,
                    idempotency_key=idempotency_key,
                    action=SensitiveAction.EVIDENCE_DELETE,
                    evidence_id=request.evidence_id,
                    reason=request.reason,
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
                select(func.pg_advisory_xact_lock(func.hashtext(str(request.evidence_id))))
            )
            evidence = session.get(EvidenceRow, request.evidence_id)
            if evidence is None:
                raise LookupError("evidence does not exist")
            tombstone = session.get(EvidenceTombstoneRow, evidence.id)
            if tombstone is not None:
                self._permit_verifier.authorize(
                    session,
                    request.permit,
                    idempotency_key=idempotency_key,
                    action=SensitiveAction.EVIDENCE_DELETE,
                    evidence_id=evidence.id,
                    reason=request.reason,
                )
                return EvidenceDeletionResult(
                    evidence_id=evidence.id,
                    deleted=True,
                    key_destroyed=True,
                    derived_summary={
                        str(key): int(value) for key, value in tombstone.derived_summary.items()
                    },
                    replayed=True,
                )
            payload = session.get(EvidencePayloadRow, evidence.id)
            if payload is None:
                raise LookupError("encrypted evidence payload is unavailable")

            self._permit_verifier.authorize(
                session,
                request.permit,
                idempotency_key=idempotency_key,
                action=SensitiveAction.EVIDENCE_DELETE,
                evidence_id=evidence.id,
                reason=request.reason,
            )

            closure = evidence_descendants(session, evidence.id)
            # A routine SQL writer can INSERT edges but cannot rewrite sealed
            # evidence metadata. Reject forged late edges before destroying any
            # key, so they cannot expand an owner's permit to unrelated records.
            verify_archive_provenance(session, closure)
            payloads = list(
                session.scalars(
                    select(EvidencePayloadRow)
                    .where(
                        EvidencePayloadRow.evidence_id.in_(closure),
                    )
                    .order_by(EvidencePayloadRow.evidence_id)
                )
            )
            already_deleted = set(
                session.scalars(
                    select(EvidenceTombstoneRow.evidence_id).where(
                        EvidenceTombstoneRow.evidence_id.in_(closure),
                    )
                )
            )
            if {item.evidence_id for item in payloads} | already_deleted != closure:
                raise RuntimeError("derivative payload coverage is incomplete; recovery required")
            # Absence is not authority: a FIRST attempt requires every key to
            # exist in the identity-bound registry. Only accepted-intent recovery
            # can treat a missing key as an already completed destruction.
            if any(self._key_store.get(item.key_ref) is None for item in payloads):
                raise DeletionJournalError("unexplained missing archive key; review required")
            refs = {item.evidence_id: item.key_ref for item in payloads}
            intent = DeletionIntentV1(
                intent_id=uuid4(),
                journal_id=head.journal_id,
                registry_id=head.registry_id,
                operation_id=uuid4(),
                idempotency_key=idempotency_key,
                evidence_id=evidence.id,
                reason=request.reason,
                accepted_at=datetime.now(UTC),
                permit=request.permit,
                targets=tuple(
                    DeletionTargetV1(evidence_id=target, key_ref=refs.get(target))
                    for target in sorted(closure)
                ),
            )
            # This commit is OUTSIDE PostgreSQL. From this point even a rollback
            # or process kill leaves an unmatched head that fences service access.
            entry = self._journal.append(intent, head)
            return self._apply_accepted_deletion(session, entry)

    def _apply_accepted_deletion(
        self,
        session: Session,
        entry: JournalEntry,
    ) -> EvidenceDeletionResult:
        """Internal offline recovery primitive, never an HTTP authorization path.

        Caller holds exclusive admission + retention locks and verifies journal
        ordering/binding. Authority is the trusted journal's already accepted
        signed owner permit, not key absence or a new model-generated request.
        """
        intent = entry.intent
        self._permit_verifier.verify_signature(intent.permit)
        if self._key_store.registry_identity != intent.registry_id:
            raise DeletionJournalError("archive registry identity mismatch")
        permit_row = session.get(SensitiveActionPermitRow, intent.permit.permit_id)
        if permit_row is not None:
            if permit_row.serialized_permit != intent.permit.model_dump(
                mode="json"
            ) or permit_row.consumed_by_idempotency_key not in {None, intent.idempotency_key}:
                raise DeletionJournalError("accepted deletion permit conflicts with storage")
            permit_row.consumed_by_idempotency_key = intent.idempotency_key
            permit_row.consumed_at = intent.accepted_at
        if (
            session.scalar(
                select(OperationRow.id).where(
                    or_(
                        OperationRow.id == intent.operation_id,
                        OperationRow.idempotency_key == intent.idempotency_key,
                    ),
                )
            )
            is not None
        ):
            raise DeletionJournalError("unacknowledged deletion operation conflicts with storage")

        targets = {target.evidence_id: target.key_ref for target in intent.targets}
        present = set(session.scalars(select(EvidenceRow.id).where(EvidenceRow.id.in_(targets))))
        if present:
            if (
                intent.evidence_id not in present
                or evidence_descendants(session, intent.evidence_id) != present
            ):
                raise DeletionJournalError("deletion closure changed; offline review required")
            verify_archive_provenance(session, present)
        payloads = list(
            session.scalars(
                select(EvidencePayloadRow).where(
                    EvidencePayloadRow.evidence_id.in_(present),
                )
            )
        )
        tombstoned = set(
            session.scalars(
                select(EvidenceTombstoneRow.evidence_id).where(
                    EvidenceTombstoneRow.evidence_id.in_(present),
                )
            )
        )
        if {item.evidence_id for item in payloads} | tombstoned != present:
            raise DeletionJournalError("deletion payload coverage changed")
        if any(targets[item.evidence_id] != item.key_ref for item in payloads):
            raise DeletionJournalError("deletion key reference changed")
        now = datetime.now(UTC)
        operation = OperationRow(
            id=intent.operation_id,
            idempotency_key=intent.idempotency_key,
            outcome=OperationOutcome.PENDING,
            result=None,
            created_at=now,
            completed_at=None,
        )
        session.add(operation)
        session.flush()
        append_audit(
            session, operation.id, "operation.started", {"operation_type": "evidence.delete"}
        )
        # Never decrypt and never contact/administer the KMS master key. A lost
        # delete response is safe to retry, but registry unavailability is not
        # interpreted as absence. Always read back, even after a true response.
        for target in intent.targets:
            if target.key_ref is not None:
                self._key_store.delete(target.key_ref)
                if self._key_store.get(target.key_ref) is not None:
                    raise DeletionJournalError("evidence key destruction was not confirmed")
        for payload in payloads:
            session.delete(payload)
        summary = self._invalidate_derived(session, present, now)
        summary["evidence_records_deleted"] = len(present - tombstoned)
        for target_id in sorted(present - tombstoned):
            session.add(
                EvidenceTombstoneRow(
                    evidence_id=target_id,
                    deletion_operation_id=operation.id,
                    reason_category=intent.reason,
                    deleted_at=now,
                    derived_summary=summary,
                )
            )
        append_audit(
            session,
            operation.id,
            "evidence.deleted",
            {
                "evidence_id": str(intent.evidence_id),
                "reason": intent.reason,
                "key_destroyed": True,
                "derived_summary": summary,
                "permit_id": str(intent.permit.permit_id),
                "owner_subject": intent.permit.owner_subject,
                "journal_intent_id": str(intent.intent_id),
                "journal_sequence": entry.sequence,
            },
        )
        result = EvidenceDeletionResult(
            evidence_id=intent.evidence_id,
            deleted=True,
            key_destroyed=True,
            derived_summary=summary,
        )
        operation.outcome = OperationOutcome.SUCCEEDED
        operation.result = {**result.model_dump(mode="json"), "request_reason": intent.reason}
        operation.completed_at = now
        append_audit(
            session, operation.id, "operation.succeeded", {"operation_type": "evidence.delete"}
        )
        session.add(
            DeletionJournalReceiptRow(
                sequence=entry.sequence,
                intent_id=intent.intent_id,
                digest=entry.digest,
                operation_id=operation.id,
            )
        )
        return result

    def reconcile_missing_keys(self) -> int:
        """Fail closed on missing keys; absence alone never authorizes deletion.

        A missing item could mean a wrong registry, an outage, or an interrupted
        deletion. Automatic recovery needs an independent durable deletion-intent
        ledger and a compound restore gate. Until those exist, stop startup and
        require a new owner-authorized deletion or controlled registry recovery.
        """

        with self._sessions.begin() as session:
            retention_fence(session)
            candidates = list(
                session.execute(select(EvidencePayloadRow.evidence_id, EvidencePayloadRow.key_ref))
            )
            if any(self._key_store.get(key_ref) is None for _, key_ref in candidates):
                raise RuntimeError("archive registry mismatch; controlled recovery required")
        return 0

    def delete_last_message(
        self, idempotency_key: str, request: ForgetLastRequest
    ) -> EvidenceDeletionResult:
        source_id = f"{request.platform}:{request.source_conversation_id}"
        if len(request.permit.evidence_ids) != 1:
            raise PermissionError("forget requires an exact-record permit")
        evidence_id = request.permit.evidence_ids[0]
        with self._sessions() as session:
            belongs_to_conversation = session.scalar(
                select(EvidenceRow.id).where(
                    EvidenceRow.id == evidence_id,
                    EvidenceRow.source == "hermes",
                    EvidenceRow.source_conversation_id == source_id,
                )
            )
        if belongs_to_conversation is None:
            raise PermissionError("permit evidence does not belong to this conversation")
        return self.delete(
            idempotency_key,
            EvidenceDeletionRequest(
                evidence_id=evidence_id,
                reason=request.reason,
                permit=request.permit,
            ),
        )

    @staticmethod
    def _invalidate_derived(
        session: Session,
        evidence_ids: set[UUID],
        now: datetime,
    ) -> dict[str, int]:
        claims = list(
            session.scalars(
                select(MemoryClaimRow).where(
                    or_(
                        MemoryClaimRow.evidence_id.in_(evidence_ids),
                        MemoryClaimRow.id.in_(
                            select(ClaimSourceRow.claim_id).where(
                                ClaimSourceRow.evidence_id.in_(evidence_ids),
                            )
                        ),
                    )
                )
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
            list(session.scalars(select(MemoryClaimRow).where(MemoryClaimRow.id.in_(claim_ids))))
            if claim_ids
            else []
        )
        relationships = (
            list(
                session.scalars(
                    select(MemoryRelationshipRow).where(
                        or_(
                            MemoryRelationshipRow.evidence_id.in_(evidence_ids),
                            MemoryRelationshipRow.claim_id.in_(claim_ids),
                        )
                    )
                )
            )
            if claim_ids
            else list(
                session.scalars(
                    select(MemoryRelationshipRow).where(
                        MemoryRelationshipRow.evidence_id.in_(evidence_ids)
                    )
                )
            )
        )
        entity_ids: set[UUID] = set()
        for relationship in relationships:
            relationship.predicate = "[redacted]"
            relationship.valid_to = relationship.valid_to or now
            entity_ids.update({relationship.subject_entity_id, relationship.object_entity_id})
        for claim in all_claims:
            claim.subject = "[redacted]"
            claim.predicate = "[redacted]"
            claim.object = "[redacted]"
            claim.status = "invalidated"

        proposals = list(
            session.scalars(
                select(MemoryWriteProposalRow).where(
                    or_(
                        MemoryWriteProposalRow.evidence_id.in_(evidence_ids),
                        MemoryWriteProposalRow.claim_id.in_(claim_ids),
                        MemoryWriteProposalRow.id.in_(
                            select(ProposalSourceRow.proposal_id).where(
                                ProposalSourceRow.evidence_id.in_(evidence_ids),
                            )
                        ),
                    )
                )
            )
        )
        corrections = list(
            session.scalars(
                select(MemoryCorrectionRow).where(
                    or_(
                        MemoryCorrectionRow.new_evidence_id.in_(evidence_ids),
                        MemoryCorrectionRow.old_claim_id.in_(claim_ids),
                        MemoryCorrectionRow.new_claim_id.in_(claim_ids),
                        MemoryCorrectionRow.id.in_(
                            select(CorrectionSourceRow.correction_id).where(
                                CorrectionSourceRow.evidence_id.in_(evidence_ids),
                            )
                        ),
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
                approval.decision_reason = "source_evidence_deleted"
                if approval.status == ApprovalStatus.PENDING:
                    approval.status = ApprovalStatus.DENIED
                    approval.decided_at = now
                    approval.decided_by = "owner-evidence-deletion"
                    approval.actor_type = "human_owner"
                    approval.decision_reason = "source_evidence_deleted"
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

        working_contexts = session.scalar(select(func.count()).select_from(WorkingContextRow)) or 0
        session.execute(delete(WorkingContextRow))
        turns = list(
            session.scalars(
                select(ConversationTurnRow).where(
                    or_(
                        ConversationTurnRow.user_evidence_id.in_(evidence_ids),
                        ConversationTurnRow.assistant_evidence_id.in_(evidence_ids),
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
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
