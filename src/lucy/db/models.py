"""SQLAlchemy mappings for Lucy's durable state."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, String, Text
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


class EvidenceRow(Base):
    __tablename__ = "evidence"
    __table_args__ = {"schema": "lucy"}
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    source: Mapped[str] = mapped_column(Text)
    source_conversation_id: Mapped[str] = mapped_column(Text)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    content: Mapped[dict[str, Any]] = mapped_column(JSONB)
    content_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    operation_id: Mapped[UUID] = mapped_column(ForeignKey("lucy.operations.id"))


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
