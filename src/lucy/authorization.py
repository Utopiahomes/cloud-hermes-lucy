"""Signed, single-use authorization for sensitive owner-intent actions."""

from __future__ import annotations

import base64
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from lucy.audit import append_audit
from lucy.contracts import OperationOutcome
from lucy.db.models import OperationRow, SensitiveActionPermitRow

PERMIT_TTL_SECONDS = 300


class SensitiveAction(StrEnum):
    EVIDENCE_RETRIEVE = "evidence.retrieve"
    EVIDENCE_DELETE = "evidence.delete"


class SensitiveActionPermitV1(BaseModel):
    """Owner-intent capability signed by a policy service with no AWS role."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    permit_id: UUID
    action: SensitiveAction
    owner_subject: str = Field(min_length=1, max_length=200)
    owner_interaction_id: str = Field(min_length=1, max_length=512)
    evidence_ids: tuple[UUID, ...] = Field(min_length=1, max_length=10)
    reason: str = Field(min_length=1, max_length=100)
    max_records: int = Field(ge=1, le=10)
    max_bytes: int = Field(ge=1, le=65_536)
    issued_at: datetime
    expires_at: datetime
    nonce: str = Field(min_length=32, max_length=128)
    signature: str

    @model_validator(mode="after")
    def validate_bounds(self) -> SensitiveActionPermitV1:
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("permit timestamps must be timezone-aware")
        lifetime = self.expires_at - self.issued_at
        if lifetime <= timedelta(0) or lifetime > timedelta(seconds=PERMIT_TTL_SECONDS):
            raise ValueError("permit lifetime exceeds the Phase 1 maximum")
        if self.max_records > len(self.evidence_ids):
            raise ValueError("permit record limit exceeds its evidence scope")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("permit evidence scope contains duplicates")
        return self

    def unsigned_bytes(self) -> bytes:
        value = self.model_dump(mode="json", exclude={"signature"})
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class SensitiveActionPermitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: SensitiveAction
    owner_subject: str = Field(min_length=1, max_length=200)
    owner_interaction_id: str = Field(min_length=1, max_length=512)
    evidence_ids: tuple[UUID, ...] = Field(min_length=1, max_length=10)
    reason: str = Field(min_length=1, max_length=100)
    max_records: int = Field(default=1, ge=1, le=10)
    max_bytes: int = Field(default=65_536, ge=1, le=65_536)

    @model_validator(mode="after")
    def validate_scope(self) -> SensitiveActionPermitRequest:
        if self.max_records > len(self.evidence_ids):
            raise ValueError("record limit exceeds evidence scope")
        return self


class GatewaySensitiveActionPermitRequest(BaseModel):
    """Content-free attestation from the allowlisted Telegram gateway."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: SensitiveAction
    platform: Literal["telegram"]
    source_conversation_id: str = Field(min_length=1, max_length=512)
    source_turn_id: str = Field(min_length=1, max_length=512)
    evidence_ids: tuple[UUID, ...] = Field(min_length=1, max_length=1)
    reason: str = Field(min_length=1, max_length=100)
    max_bytes: int = Field(default=65_536, ge=1, le=65_536)

    def to_owner_request(self, owner_subject: str) -> SensitiveActionPermitRequest:
        return SensitiveActionPermitRequest(
            action=self.action,
            owner_subject=owner_subject,
            owner_interaction_id=(
                f"{self.platform}:{self.source_conversation_id}:{self.source_turn_id}"
            ),
            evidence_ids=self.evidence_ids,
            reason=self.reason,
            max_records=1,
            max_bytes=self.max_bytes,
        )


class SensitiveActionPermitSigner:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def from_environment(cls) -> SensitiveActionPermitSigner:
        raw = _decode_fixed_key("LUCY_PERMIT_SIGNING_PRIVATE_KEY_B64")
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    @property
    def public_key_b64(self) -> str:
        raw = self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode()

    def sign(self, unsigned: SensitiveActionPermitV1) -> SensitiveActionPermitV1:
        if unsigned.signature:
            raise ValueError("unsigned permit unexpectedly contains a signature")
        signature = self._private_key.sign(unsigned.unsigned_bytes())
        return unsigned.model_copy(update={"signature": base64.b64encode(signature).decode()})


class SensitiveActionPermitVerifier:
    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key

    @classmethod
    def from_environment(cls) -> SensitiveActionPermitVerifier:
        raw = _decode_fixed_key("LUCY_PERMIT_SIGNING_PUBLIC_KEY_B64")
        return cls(Ed25519PublicKey.from_public_bytes(raw))

    def verify_signature(self, permit: SensitiveActionPermitV1) -> None:
        try:
            signature = base64.b64decode(permit.signature, validate=True)
            self._public_key.verify(signature, permit.unsigned_bytes())
        except (ValueError, InvalidSignature) as exc:
            raise PermissionError("sensitive-action permit signature is invalid") from exc

    def authorize(
        self,
        session: Session,
        permit: SensitiveActionPermitV1,
        *,
        idempotency_key: str,
        action: SensitiveAction,
        evidence_id: UUID,
        reason: str,
        requested_bytes: int = 65_536,
    ) -> None:
        self.verify_signature(permit)
        now = datetime.now(UTC)
        if permit.issued_at > now + timedelta(seconds=30) or permit.expires_at <= now:
            raise PermissionError("sensitive-action permit is not currently valid")
        if (
            permit.action != action
            or permit.evidence_ids != (evidence_id,)
            or permit.max_records != 1
            or permit.reason != reason
            or requested_bytes > permit.max_bytes
        ):
            raise PermissionError("sensitive-action permit does not match the request")

        row = session.scalar(
            select(SensitiveActionPermitRow)
            .where(SensitiveActionPermitRow.id == permit.permit_id)
            .with_for_update()
        )
        if row is None or row.serialized_permit != permit.model_dump(mode="json"):
            raise PermissionError("sensitive-action permit was not issued by this policy store")
        if row.consumed_by_idempotency_key not in {None, idempotency_key}:
            raise PermissionError("sensitive-action permit was already consumed")
        if row.consumed_by_idempotency_key is None:
            row.consumed_at = now
            row.consumed_by_idempotency_key = idempotency_key


class SensitiveActionPermitService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        signer: SensitiveActionPermitSigner,
    ) -> None:
        self._sessions = sessions
        self._signer = signer

    def issue(
        self,
        idempotency_key: str,
        request: SensitiveActionPermitRequest,
    ) -> SensitiveActionPermitV1:
        if not idempotency_key.strip():
            raise ValueError("idempotency key must not be blank")
        with self._sessions.begin() as session:
            session.execute(select(func.pg_advisory_xact_lock(func.hashtext(idempotency_key))))
            existing = session.scalar(
                select(OperationRow).where(OperationRow.idempotency_key == idempotency_key)
            )
            if existing is not None:
                if existing.outcome != OperationOutcome.SUCCEEDED or existing.result is None:
                    raise RuntimeError("permit issuance is not replayable")
                permit = SensitiveActionPermitV1.model_validate(existing.result["permit"])
                expected = (
                    request.action,
                    request.owner_subject,
                    request.owner_interaction_id,
                    request.evidence_ids,
                    request.reason,
                    request.max_records,
                    request.max_bytes,
                )
                observed = (
                    permit.action,
                    permit.owner_subject,
                    permit.owner_interaction_id,
                    permit.evidence_ids,
                    permit.reason,
                    permit.max_records,
                    permit.max_bytes,
                )
                if observed != expected:
                    raise ValueError(
                        "idempotency key was already used for another permit request"
                    )
                return permit

            now = datetime.now(UTC)
            unsigned = SensitiveActionPermitV1(
                permit_id=uuid4(),
                action=request.action,
                owner_subject=request.owner_subject,
                owner_interaction_id=request.owner_interaction_id,
                evidence_ids=request.evidence_ids,
                reason=request.reason,
                max_records=request.max_records,
                max_bytes=request.max_bytes,
                issued_at=now,
                expires_at=now + timedelta(seconds=PERMIT_TTL_SECONDS),
                nonce=secrets.token_urlsafe(32),
                signature="",
            )
            permit = self._signer.sign(unsigned)
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
                "sensitive_action.permit_issued",
                {
                    "permit_id": str(permit.permit_id),
                    "action": permit.action,
                    "owner_subject": permit.owner_subject,
                    "owner_interaction_id": permit.owner_interaction_id,
                    "evidence_ids": [str(value) for value in permit.evidence_ids],
                    "reason": permit.reason,
                    "expires_at": permit.expires_at.isoformat(),
                },
            )
            session.add(
                SensitiveActionPermitRow(
                    id=permit.permit_id,
                    nonce=permit.nonce,
                    action=permit.action,
                    owner_subject=permit.owner_subject,
                    owner_interaction_id=permit.owner_interaction_id,
                    serialized_permit=permit.model_dump(mode="json"),
                    issued_at=permit.issued_at,
                    expires_at=permit.expires_at,
                    issued_operation_id=operation.id,
                    consumed_at=None,
                    consumed_by_idempotency_key=None,
                )
            )
            operation.outcome = OperationOutcome.SUCCEEDED
            operation.result = {"permit": permit.model_dump(mode="json")}
            operation.completed_at = now
            return permit


def _decode_fixed_key(name: str) -> bytes:
    value = os.environ.get(name, "")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError(f"{name} must be valid base64") from exc
    if len(raw) != 32:
        raise ValueError(f"{name} must decode to exactly 32 bytes")
    return raw
