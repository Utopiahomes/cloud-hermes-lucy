"""SQLAlchemy mappings for Lucy's durable state."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class OperationRow(Base):
    __tablename__ = "operations"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    idempotency_key: Mapped[str] = mapped_column(Text, unique=True)
    outcome: Mapped[str] = mapped_column(Text)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeletionJournalBindingRow(Base):
    __tablename__ = "deletion_journal_binding"
    __table_args__ = {"schema": "lucy"}
    singleton: Mapped[bool] = mapped_column(Boolean, primary_key=True)
    journal_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    registry_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))


class DeletionJournalReceiptRow(Base):
    __tablename__ = "deletion_journal_receipts"
    __table_args__ = {"schema": "lucy"}
    sequence: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    intent_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), unique=True)
    digest: Mapped[str] = mapped_column(String(64))
    operation_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.operations.id"), unique=True)


class EvidenceRow(Base):
    __tablename__ = "evidence"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    source: Mapped[str] = mapped_column(Text)
    source_conversation_id: Mapped[str] = mapped_column(Text)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    content: Mapped[dict[str, Any]] = mapped_column(JSONB)
    content_commitment: Mapped[str] = mapped_column(String(64), unique=True)
    operation_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.operations.id"))


class EvidencePayloadRow(Base):
    __tablename__ = "evidence_payloads"
    __table_args__ = {"schema": "lucy"}
    evidence_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.evidence.id"), primary_key=True
    )
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    content_nonce: Mapped[bytes] = mapped_column(LargeBinary)
    key_ref: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), unique=True)
    algorithm: Mapped[str] = mapped_column(Text)
    encryption_context_version: Mapped[int] = mapped_column(default=1)
    record_version: Mapped[int] = mapped_column(BigInteger, default=1)
    storage_epoch: Mapped[int] = mapped_column(BigInteger, default=1)
    registry_epoch: Mapped[int] = mapped_column(BigInteger, default=1)
    key_epoch: Mapped[int] = mapped_column(BigInteger, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EvidenceTombstoneRow(Base):
    __tablename__ = "evidence_tombstones"
    __table_args__ = {"schema": "lucy"}
    evidence_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.evidence.id"), primary_key=True
    )
    deletion_operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.operations.id")
    )
    reason_category: Mapped[str] = mapped_column(Text)
    deleted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    derived_summary: Mapped[dict[str, Any]] = mapped_column(JSONB)


class SensitiveActionPermitRow(Base):
    __tablename__ = "sensitive_action_permits"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    nonce: Mapped[str] = mapped_column(Text, unique=True)
    action: Mapped[str] = mapped_column(Text)
    owner_subject: Mapped[str] = mapped_column(Text)
    owner_interaction_id: Mapped[str] = mapped_column(Text)
    serialized_permit: Mapped[dict[str, Any]] = mapped_column(JSONB)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    issued_operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.operations.id"), unique=True
    )
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_by_idempotency_key: Mapped[str | None] = mapped_column(Text, unique=True)


class SecurityContractEpochRow(Base):
    __tablename__ = "security_contract_epochs"
    __table_args__ = {"schema": "lucy"}
    singleton: Mapped[bool] = mapped_column(Boolean, primary_key=True)
    storage_epoch: Mapped[int] = mapped_column(BigInteger)
    registry_epoch: Mapped[int] = mapped_column(BigInteger)
    key_epoch: Mapped[int] = mapped_column(BigInteger)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OwnerInteractionAssertionRow(Base):
    __tablename__ = "owner_interaction_assertions_v1"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    nonce: Mapped[str] = mapped_column(Text, unique=True)
    anti_replay_id: Mapped[str] = mapped_column(Text, unique=True)
    action: Mapped[str] = mapped_column(Text)
    evidence_id: Mapped[UUID | None] = mapped_column(ForeignKey("lucy.evidence.id"))
    owner_subject: Mapped[str] = mapped_column(Text)
    issuer: Mapped[str] = mapped_column(Text)
    environment: Mapped[str] = mapped_column(Text)
    assertion_digest: Mapped[str] = mapped_column(String(64), unique=True)
    serialized_assertion: Mapped[dict[str, Any]] = mapped_column(JSONB)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    storage_epoch: Mapped[int] = mapped_column(BigInteger)
    registry_epoch: Mapped[int] = mapped_column(BigInteger)
    key_epoch: Mapped[int] = mapped_column(BigInteger)
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SensitiveActionPermitV2Row(Base):
    __tablename__ = "sensitive_action_permits_v2"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    nonce: Mapped[str] = mapped_column(Text, unique=True)
    action: Mapped[str] = mapped_column(Text)
    owner_subject: Mapped[str] = mapped_column(Text)
    owner_assertion_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.owner_interaction_assertions_v1.id"), unique=True
    )
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.evidence.id"))
    reason: Mapped[str] = mapped_column(Text)
    max_records: Mapped[int]
    max_bytes: Mapped[int]
    record_version: Mapped[int] = mapped_column(BigInteger)
    permit_digest: Mapped[str] = mapped_column(String(64), unique=True)
    serialized_permit: Mapped[dict[str, Any]] = mapped_column(JSONB)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    permit_claim_deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    storage_epoch: Mapped[int] = mapped_column(BigInteger)
    registry_epoch: Mapped[int] = mapped_column(BigInteger)
    key_epoch: Mapped[int] = mapped_column(BigInteger)
    issuance_idempotency_key: Mapped[str] = mapped_column(Text, unique=True)
    issued_operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.operations.id"), unique=True
    )
    state: Mapped[str] = mapped_column(Text)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_operation_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    claimed_idempotency_key: Mapped[str | None] = mapped_column(Text, unique=True)
    claimed_session_user: Mapped[str | None] = mapped_column(Text)


class DeletionTargetManifestRow(Base):
    __tablename__ = "deletion_target_manifests_v1"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    permit_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.sensitive_action_permits_v2.id"), unique=True
    )
    root_evidence_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.evidence.id"))
    idempotency_key: Mapped[str] = mapped_column(Text, unique=True)
    scope_version: Mapped[int] = mapped_column(BigInteger)
    target_count: Mapped[int]
    targets_digest: Mapped[str | None] = mapped_column(String(64))
    unsigned_manifest_digest: Mapped[str | None] = mapped_column(String(64))
    unsigned_manifest: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    signed_manifest_digest: Mapped[str | None] = mapped_column(String(64), unique=True)
    signed_manifest: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    permit_claim_deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    execution_deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    state: Mapped[str] = mapped_column(Text)
    prepared_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeletionManifestTargetRow(Base):
    __tablename__ = "deletion_manifest_targets_v1"
    __table_args__ = {"schema": "lucy"}
    manifest_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.deletion_target_manifests_v1.id"), primary_key=True
    )
    evidence_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.evidence.id"), primary_key=True
    )
    key_ref: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    record_version: Mapped[int] = mapped_column(BigInteger)
    key_epoch: Mapped[int] = mapped_column(BigInteger)


class ExecutorBindingRow(Base):
    __tablename__ = "executor_bindings_v1"
    __table_args__ = {"schema": "lucy"}
    action: Mapped[str] = mapped_column(Text, primary_key=True)
    environment: Mapped[str] = mapped_column(Text, primary_key=True)
    executor_identity: Mapped[str] = mapped_column(Text)
    executor_alias_arn: Mapped[str] = mapped_column(Text, unique=True)
    executor_version: Mapped[int] = mapped_column(BigInteger)
    receipt_key_id: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean)
    configured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SensitiveOperationV1Row(Base):
    __tablename__ = "sensitive_operations_v1"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    permit_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.sensitive_action_permits_v2.id"), unique=True
    )
    action: Mapped[str] = mapped_column(Text)
    evidence_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    manifest_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("lucy.deletion_target_manifests_v1.id"), unique=True
    )
    idempotency_key: Mapped[str] = mapped_column(Text, unique=True)
    caller_session_user: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text)
    encrypted_package: Mapped[dict[str, Any]] = mapped_column(JSONB)
    package_digest: Mapped[str] = mapped_column(String(64), unique=True)
    package_size_bytes: Mapped[int]
    record_version: Mapped[int] = mapped_column(BigInteger)
    storage_epoch: Mapped[int] = mapped_column(BigInteger)
    registry_epoch: Mapped[int] = mapped_column(BigInteger)
    key_epoch: Mapped[int] = mapped_column(BigInteger)
    permit_claim_deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    execution_deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    executor_receipt_digest: Mapped[str | None] = mapped_column(String(64))


class SensitiveExecutionGrantRow(Base):
    __tablename__ = "sensitive_execution_grants_v1"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.sensitive_operations_v1.id"), unique=True
    )
    grant_digest: Mapped[str] = mapped_column(String(64), unique=True)
    serialized_grant: Mapped[dict[str, Any]] = mapped_column(JSONB)
    executor_identity: Mapped[str] = mapped_column(Text)
    executor_alias_arn: Mapped[str] = mapped_column(Text)
    executor_version: Mapped[int] = mapped_column(BigInteger)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    execution_deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    stored_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ExecutorReceiptAttestationRow(Base):
    __tablename__ = "executor_receipt_attestations_v1"
    __table_args__ = {"schema": "lucy"}
    receipt_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.sensitive_operations_v1.id"), unique=True
    )
    execution_grant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    receipt_digest: Mapped[str] = mapped_column(String(64), unique=True)
    result: Mapped[str] = mapped_column(Text)
    receipt_key_id: Mapped[str] = mapped_column(Text)
    executor_identity: Mapped[str] = mapped_column(Text)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    policy_session_user: Mapped[str] = mapped_column(Text)


class EvidenceDeletionFenceRow(Base):
    __tablename__ = "evidence_deletion_fences_v1"
    __table_args__ = {"schema": "lucy"}
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.evidence.id"), primary_key=True)
    permit_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    operation_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    state: Mapped[str] = mapped_column(Text)
    fenced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    effective_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeletionFinalityRow(Base):
    __tablename__ = "deletion_finality_v1"
    __table_args__ = {"schema": "lucy"}
    operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.sensitive_operations_v1.id"), primary_key=True
    )
    deletion_effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finality_not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finality_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finality_status: Mapped[str] = mapped_column(Text)
    metadata_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    earliest_restorable_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    latest_restorable_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recoverable_copy_count: Mapped[int | None]
    metadata_inventory_digest: Mapped[str | None] = mapped_column(String(64))


class AuthorizedDeletionRecoveryRow(Base):
    __tablename__ = "authorized_deletion_recoveries_v1"
    __table_args__ = {"schema": "lucy"}
    operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.operations.id"), primary_key=True
    )
    permit_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    manifest_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), unique=True)
    receipt_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), unique=True)
    permit_digest: Mapped[str] = mapped_column(String(64), unique=True)
    manifest_digest: Mapped[str] = mapped_column(String(64), unique=True)
    grant_digest: Mapped[str] = mapped_column(String(64), unique=True)
    receipt_digest: Mapped[str] = mapped_column(String(64), unique=True)
    targets_digest: Mapped[str] = mapped_column(String(64))
    target_count: Mapped[int] = mapped_column(BigInteger)
    original_storage_epoch: Mapped[int] = mapped_column(BigInteger)
    original_registry_epoch: Mapped[int] = mapped_column(BigInteger)
    original_key_epoch: Mapped[int] = mapped_column(BigInteger)
    recovered_storage_epoch: Mapped[int] = mapped_column(BigInteger)
    executor_identity: Mapped[str] = mapped_column(Text)
    executor_alias_arn: Mapped[str] = mapped_column(Text)
    executor_version: Mapped[int] = mapped_column(BigInteger)
    receipt_key_id: Mapped[str] = mapped_column(Text)
    deletion_effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finality_not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finality_status: Mapped[str] = mapped_column(Text)
    finality_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    earliest_restorable_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    latest_restorable_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recoverable_copy_count: Mapped[int | None] = mapped_column(BigInteger)
    metadata_inventory_digest: Mapped[str | None] = mapped_column(String(64))
    recovery_digest: Mapped[str] = mapped_column(String(64), unique=True)
    authority_evidence_digest: Mapped[str] = mapped_column(String(64))
    recovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    derived_summary: Mapped[dict[str, Any]] = mapped_column(JSONB)


class AuthorizedDeletionRecoveryTargetRow(Base):
    __tablename__ = "authorized_deletion_recovery_targets_v1"
    __table_args__ = {"schema": "lucy"}
    operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.authorized_deletion_recoveries_v1.operation_id"), primary_key=True
    )
    evidence_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.evidence.id"), primary_key=True
    )
    key_ref: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    record_version: Mapped[int] = mapped_column(BigInteger)
    key_epoch: Mapped[int] = mapped_column(BigInteger)


class SensitiveOperationEventRow(Base):
    __tablename__ = "sensitive_operation_events_v1"
    __table_args__ = {"schema": "lucy"}
    sequence: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    event_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), unique=True)
    operation_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    event_type: Mapped[str] = mapped_column(Text)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB)


class ConversationCaptureStateRow(Base):
    __tablename__ = "conversation_capture_states"
    __table_args__ = {"schema": "lucy"}
    platform: Mapped[str] = mapped_column(Text, primary_key=True)
    source_conversation_id: Mapped[str] = mapped_column(Text, primary_key=True)
    capture_enabled: Mapped[bool] = mapped_column(Boolean)
    version: Mapped[int] = mapped_column(BigInteger)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CaptureReceiptRow(Base):
    """Never contains message content or a fingerprint of excluded content."""

    __tablename__ = "capture_receipts"
    __table_args__ = {"schema": "lucy"}
    platform: Mapped[str] = mapped_column(Text, primary_key=True)
    source_conversation_id: Mapped[str] = mapped_column(Text, primary_key=True)
    source_turn_id: Mapped[str] = mapped_column(Text, primary_key=True)
    capture_enabled: Mapped[bool] = mapped_column(Boolean)
    capture_version: Mapped[int] = mapped_column(BigInteger)
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ConversationTurnRow(Base):
    __tablename__ = "conversation_turns"
    __table_args__ = {"schema": "lucy"}
    platform: Mapped[str] = mapped_column(Text, primary_key=True)
    source_conversation_id: Mapped[str] = mapped_column(Text, primary_key=True)
    source_turn_id: Mapped[str] = mapped_column(Text, primary_key=True)
    user_evidence_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("lucy.evidence.id"), unique=True
    )
    assistant_evidence_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("lucy.evidence.id"), unique=True
    )
    status: Mapped[str] = mapped_column(Text)
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class MemoryClaimRow(Base):
    __tablename__ = "memory_claims"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.evidence.id"))
    subject: Mapped[str] = mapped_column(Text)
    predicate: Mapped[str] = mapped_column(Text)
    object: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(Text)
    supersedes_claim_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("lucy.memory_claims.id")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EvidenceDerivationRow(Base):
    __tablename__ = "evidence_derivations"
    __table_args__ = {"schema": "lucy"}
    parent_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.evidence.id"), primary_key=True)
    child_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.evidence.id"), primary_key=True)


class ClaimSourceRow(Base):
    __tablename__ = "claim_sources"
    __table_args__ = {"schema": "lucy"}
    claim_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.memory_claims.id"), primary_key=True)
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.evidence.id"), primary_key=True)


class ProposalSourceRow(Base):
    __tablename__ = "proposal_sources"
    __table_args__ = {"schema": "lucy"}
    proposal_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.memory_write_proposals.id"), primary_key=True,
    )
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.evidence.id"), primary_key=True)


class CorrectionSourceRow(Base):
    __tablename__ = "correction_sources"
    __table_args__ = {"schema": "lucy"}
    correction_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.memory_corrections.id"), primary_key=True,
    )
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.evidence.id"), primary_key=True)


class RuntimeAdmissionRow(Base):
    __tablename__ = "runtime_admission"
    __table_args__ = {"schema": "lucy"}
    singleton: Mapped[bool] = mapped_column(Boolean, primary_key=True)
    state: Mapped[str] = mapped_column(Text)
    storage_epoch: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class LifecycleRow(Base):
    __tablename__ = "lifecycle"
    __table_args__ = {"schema": "lucy"}
    singleton: Mapped[bool] = mapped_column(Boolean, primary_key=True)
    state: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(BigInteger)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class BudgetAccountRow(Base):
    __tablename__ = "budget_accounts"
    __table_args__ = {"schema": "lucy"}
    name: Mapped[str] = mapped_column(Text, primary_key=True)
    limit_microusd: Mapped[int] = mapped_column(BigInteger)
    reserved_microusd: Mapped[int] = mapped_column(BigInteger)
    spent_microusd: Mapped[int] = mapped_column(BigInteger)


class BudgetReservationRow(Base):
    __tablename__ = "budget_reservations"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    operation_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.operations.id"), unique=True)
    budget_name: Mapped[str] = mapped_column(ForeignKey("lucy.budget_accounts.name"))
    reserved_microusd: Mapped[int] = mapped_column(BigInteger)
    settled_microusd: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditHeadRow(Base):
    __tablename__ = "audit_head"
    __table_args__ = {"schema": "lucy"}
    singleton: Mapped[bool] = mapped_column(Boolean, primary_key=True)
    last_sequence: Mapped[int] = mapped_column(BigInteger)
    last_hash: Mapped[str] = mapped_column(String(64))


class AuditEventRow(Base):
    __tablename__ = "audit_events"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    sequence: Mapped[int] = mapped_column(BigInteger, unique=True)
    operation_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.operations.id"))
    event_type: Mapped[str] = mapped_column(Text)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)


class ApprovalRequestRow(Base):
    __tablename__ = "approval_requests"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    request_operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.operations.id"), unique=True
    )
    action_type: Mapped[str] = mapped_column(Text)
    action_payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_by: Mapped[str | None] = mapped_column(Text)
    actor_type: Mapped[str | None] = mapped_column(Text)
    decision_reason: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(BigInteger)


class MemoryEntityRow(Base):
    __tablename__ = "memory_entities"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    canonical_name: Mapped[str] = mapped_column(Text)
    entity_type: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class MemoryRelationshipRow(Base):
    __tablename__ = "memory_relationships"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    subject_entity_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.memory_entities.id"))
    object_entity_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.memory_entities.id"))
    predicate: Mapped[str] = mapped_column(Text)
    claim_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.memory_claims.id"), unique=True)
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.evidence.id"))
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(BigInteger)


class WorkingContextRow(Base):
    __tablename__ = "working_contexts"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    query: Mapped[str] = mapped_column(Text)
    projection: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class StartupRunRow(Base):
    __tablename__ = "startup_runs"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    outcome_state: Mapped[str] = mapped_column(Text)
    checks: Mapped[dict[str, Any]] = mapped_column(JSONB)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class MemoryCorrectionRow(Base):
    __tablename__ = "memory_corrections"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    idempotency_key: Mapped[str] = mapped_column(Text, unique=True)
    old_claim_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.memory_claims.id"))
    new_evidence_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.evidence.id"))
    replacement_object: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    approval_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.approval_requests.id"), unique=True)
    status: Mapped[str] = mapped_column(Text)
    new_claim_id: Mapped[UUID | None] = mapped_column(ForeignKey("lucy.memory_claims.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MemoryWriteProposalRow(Base):
    __tablename__ = "memory_write_proposals"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    idempotency_key: Mapped[str] = mapped_column(Text, unique=True)
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.evidence.id"))
    subject: Mapped[str] = mapped_column(Text)
    predicate: Mapped[str] = mapped_column(Text)
    object: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(Text)
    approval_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.approval_requests.id"), unique=True)
    claim_id: Mapped[UUID | None] = mapped_column(ForeignKey("lucy.memory_claims.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ActionExecutionRow(Base):
    __tablename__ = "action_executions"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    idempotency_key: Mapped[str] = mapped_column(Text, unique=True)
    action_type: Mapped[str] = mapped_column(Text)
    action_payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    estimated_microusd: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(Text)
    disposition: Mapped[str] = mapped_column(Text)
    control_operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.operations.id"), unique=True
    )
    approval_id: Mapped[UUID | None] = mapped_column(ForeignKey("lucy.approval_requests.id"))
    reservation_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("lucy.budget_reservations.id")
    )
    execution_operation_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("lucy.operations.id"), unique=True
    )
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TenantAccountRow(Base):
    __tablename__ = "tenant_accounts"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    slug: Mapped[str] = mapped_column(String(80), unique=True)
    display_name: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class NodeRow(Base):
    __tablename__ = "nodes"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    slug: Mapped[str] = mapped_column(String(80), unique=True)
    display_name: Mapped[str] = mapped_column(Text)
    node_kind: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class NodeTenureRow(Base):
    __tablename__ = "node_tenures"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    node_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.nodes.id"))
    account_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.tenant_accounts.id"))
    sequence: Mapped[int] = mapped_column(BigInteger)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SecurityRealmRow(Base):
    __tablename__ = "security_realms"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    slug: Mapped[str] = mapped_column(String(80), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RealmBindingRow(Base):
    __tablename__ = "realm_bindings"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenure_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.node_tenures.id"))
    realm_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.security_realms.id"))
    binding_version: Mapped[int] = mapped_column(BigInteger)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PrincipalRow(Base):
    __tablename__ = "principals"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    issuer: Mapped[str] = mapped_column(Text)
    subject: Mapped[str] = mapped_column(Text)
    principal_kind: Mapped[str] = mapped_column(String(40))
    display_name: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class WorkspaceRow(Base):
    __tablename__ = "workspaces"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    node_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.nodes.id"))
    tenure_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.node_tenures.id"))
    slug: Mapped[str] = mapped_column(String(80))
    workspace_kind: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class NodeMembershipRow(Base):
    __tablename__ = "node_memberships"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    principal_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.principals.id"))
    workspace_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.workspaces.id"))
    role: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ChannelBindingRow(Base):
    __tablename__ = "channel_bindings"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(253), unique=True)
    node_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.nodes.id"))
    tenure_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.node_tenures.id"))
    workspace_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.workspaces.id"))
    channel_kind: Mapped[str] = mapped_column(String(40))
    active: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class LucyInstanceRow(Base):
    __tablename__ = "lucy_instances"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    node_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.nodes.id"))
    tenure_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.node_tenures.id"))
    principal_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.principals.id"))
    workspace_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.workspaces.id"))
    purpose: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class WalletRegistrationRow(Base):
    __tablename__ = "wallet_registrations"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    node_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.nodes.id"), unique=True)
    tenure_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.node_tenures.id"))
    status: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PublicProjectionCandidateRow(Base):
    __tablename__ = "public_projection_candidates"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    channel_binding_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.channel_bindings.id"))
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)
    snapshot_digest: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20))
    created_by: Mapped[UUID] = mapped_column(ForeignKey("lucy.principals.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PublicProjectionApprovalRow(Base):
    __tablename__ = "public_projection_approvals"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    candidate_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.public_projection_candidates.id"), unique=True
    )
    approved_digest: Mapped[str] = mapped_column(String(64))
    approved_by: Mapped[UUID] = mapped_column(ForeignKey("lucy.principals.id"))
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PublicProjectionVersionRow(Base):
    __tablename__ = "public_projection_versions"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    channel_binding_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.channel_bindings.id"))
    candidate_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.public_projection_candidates.id"), unique=True
    )
    version: Mapped[int] = mapped_column(BigInteger)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)
    snapshot_digest: Mapped[str] = mapped_column(String(64))
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PublicProjectionRouteRow(Base):
    __tablename__ = "public_projection_routes"
    __table_args__ = {"schema": "lucy"}
    channel_binding_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.channel_bindings.id"), primary_key=True
    )
    active_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("lucy.public_projection_versions.id")
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PublicProjectionEventRow(Base):
    __tablename__ = "public_projection_events"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    channel_binding_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.channel_bindings.id"))
    event_type: Mapped[str] = mapped_column(String(40))
    candidate_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("lucy.public_projection_candidates.id")
    )
    version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("lucy.public_projection_versions.id")
    )
    actor_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.principals.id"))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RealmContentScopeRow(Base):
    __tablename__ = "realm_content_scopes_v1"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_account_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.tenant_accounts.id"))
    node_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.nodes.id"))
    node_tenure_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.node_tenures.id"))
    tenure_epoch: Mapped[int] = mapped_column(BigInteger)
    security_realm_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.security_realms.id"))
    storage_epoch: Mapped[int] = mapped_column(BigInteger)
    realm_binding_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.realm_bindings.id"))
    workspace_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.workspaces.id"))
    deployment_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RealmServiceBindingRow(Base):
    __tablename__ = "realm_service_bindings_v1"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    session_login: Mapped[str] = mapped_column(String(63), unique=True)
    service_principal_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.principals.id"))
    content_scope_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.realm_content_scopes_v1.id"))
    service_role: Mapped[str] = mapped_column(String(40))
    allowed_actions: Mapped[list[str]] = mapped_column(JSONB)
    binding_generation: Mapped[int] = mapped_column(BigInteger)
    node_authz_epoch: Mapped[int] = mapped_column(BigInteger)
    active: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ScopedMemoryClaimRow(Base):
    __tablename__ = "scoped_memory_claims_v1"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    content_scope_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.realm_content_scopes_v1.id"))
    service_binding_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.realm_service_bindings_v1.id")
    )
    idempotency_key: Mapped[str] = mapped_column(Text)
    subject: Mapped[str] = mapped_column(Text)
    predicate: Mapped[str] = mapped_column(Text)
    object: Mapped[str] = mapped_column(Text)
    confidence_millionths: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ScopedMemoryEventRow(Base):
    __tablename__ = "scoped_memory_events_v1"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    content_scope_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.realm_content_scopes_v1.id"))
    service_binding_id: Mapped[UUID] = mapped_column(
        ForeignKey("lucy.realm_service_bindings_v1.id")
    )
    event_type: Mapped[str] = mapped_column(String(40))
    claim_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.scoped_memory_claims_v1.id"))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
