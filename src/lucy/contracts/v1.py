"""Critical v1 domain contracts for the first vertical slice."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

ContractVersion = Literal["1"]
NonBlank = Annotated[str, Field(min_length=1)]


class StrictContract(BaseModel):
    """Base contract that rejects silently ignored fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class RejoiningState(StrEnum):
    OFFLINE = "offline"
    REJOINING = "rejoining"
    RECONCILING = "reconciling"
    READY = "ready"
    DEGRADED = "degraded"


class OperationOutcome(StrEnum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"


class ConversationMessageV1(StrictContract):
    message_id: NonBlank
    role: Literal["user", "assistant", "system", "tool"]
    content: NonBlank
    occurred_at: datetime


class ConversationEvidenceV1(StrictContract):
    contract_version: ContractVersion = "1"
    evidence_id: UUID
    source: Literal["synthetic", "hermes"]
    source_conversation_id: NonBlank
    captured_at: datetime
    messages: tuple[ConversationMessageV1, ...] = Field(min_length=1)
    content_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    def computed_content_sha256(self) -> str:
        normalized = [message.model_dump(mode="json") for message in self.messages]
        encoded = json.dumps(
            normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        return hashlib.sha256(encoded).hexdigest()

    @model_validator(mode="after")
    def verify_content_hash(self) -> ConversationEvidenceV1:
        if self.content_sha256 != self.computed_content_sha256():
            raise ValueError("content_sha256 does not match normalized messages")
        return self


class MemoryClaimV1(StrictContract):
    contract_version: ContractVersion = "1"
    claim_id: UUID
    evidence_id: UUID
    subject: NonBlank
    predicate: NonBlank
    object: NonBlank
    confidence: Annotated[float, Field(ge=0, le=1)]
    status: Literal["provisional", "accepted", "superseded"] = "provisional"
    supersedes_claim_id: UUID | None = None
    created_at: datetime


class BudgetReservationV1(StrictContract):
    contract_version: ContractVersion = "1"
    reservation_id: UUID
    operation_id: UUID
    budget_name: NonBlank
    reserved_microusd: Annotated[int, Field(gt=0)]
    settled_microusd: Annotated[int | None, Field(ge=0)] = None
    created_at: datetime
    settled_at: datetime | None = None


class AuditEventV1(StrictContract):
    contract_version: ContractVersion = "1"
    event_id: UUID
    sequence: Annotated[int, Field(gt=0)]
    operation_id: UUID
    event_type: NonBlank
    occurred_at: datetime
    payload: dict[str, Any]
    previous_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    event_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
