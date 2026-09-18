"""Exact-byte verification for Tiamat recovery witnesses and anchor records."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from lucy.shared_execution.recovery_anchor import (
    RecoveryAnchorIdentity,
    VerifiedAnchorTransition,
    VerifiedRecoveryWitness,
)
from lucy.shared_execution.recovery_anchor_jws import verify_anchor_transition
from lucy.shared_execution.signed_releases import SignedReleaseRejected, _verify_compact

RECOVERY_WITNESS_TYP = "stoin-tiamat-recovery-witness+jws"
RECOVERY_WITNESS_INVENTORY_TYP = "stoin-tiamat-recovery-witness-trust-inventory+jws"
_UUID4 = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"


class RecoveryWitnessSignatureRejected(ValueError):
    """A witness failed its strict signature, scope, inventory, or time checks."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _WitnessPayload(_StrictModel):
    format_version: Literal["1"]
    witness_id: str = Field(pattern=_UUID4)
    issuer: Literal["stoin:control"]
    environment: str = Field(min_length=1, max_length=128)
    ledger_id: str = Field(pattern=_UUID4)
    storage_epoch: str = Field(pattern=_UUID4)
    recovery_generation: int = Field(ge=1, le=9_007_199_254_740_991)
    witness_revision: int = Field(ge=1, le=9_007_199_254_740_991)
    status: Literal["reconciled", "quarantined"]
    issued_at: str
    not_before: str
    not_after: str
    inventory_generation: int = Field(ge=1, le=9_007_199_254_740_991)
    inventory_jws_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_heads_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_settlement_position_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class _WitnessInventoryKey(_StrictModel):
    kid: str = Field(min_length=1, max_length=128)
    issuer: Literal["stoin:control"]
    environment: str = Field(min_length=1, max_length=128)
    purpose: Literal["policy_notary_v13"]
    use: Literal["tiamat-recovery-witness"]
    algorithm: Literal["EdDSA"]
    public_key_b64: str
    status: Literal["staged", "active", "retired", "revoked"]
    ledger_id: str = Field(pattern=_UUID4)
    valid_from: str
    issuance_not_after: str
    verify_not_after: str
    revoked_at: str | None
    active_release_policy: Literal["invalidate_immediately", "honor_active_until_expiry"]


class _WitnessInventoryPayload(_StrictModel):
    format_version: Literal["1"]
    inventory_generation: int = Field(ge=1, le=9_007_199_254_740_991)
    previous_inventory_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    issued_at: str
    environment: str = Field(min_length=1, max_length=128)
    ledger_id: str = Field(pattern=_UUID4)
    root_key_id: str = Field(min_length=1, max_length=128)
    keys: list[_WitnessInventoryKey] = Field(min_length=1)


@dataclass(frozen=True)
class RecoveryWitnessVerificationContext:
    identity: RecoveryAnchorIdentity
    key_id: str
    public_key: Ed25519PublicKey
    inventory_generation: int
    inventory_jws_sha256: str
    key_valid_from: datetime
    key_issuance_not_after: datetime
    key_verify_not_after: datetime

    def __post_init__(self) -> None:
        if (
            not self.key_id
            or not 1 <= self.inventory_generation <= 9_007_199_254_740_991
            or not _is_digest(self.inventory_jws_sha256)
            or self.key_valid_from.tzinfo is None
            or self.key_issuance_not_after.tzinfo is None
            or self.key_verify_not_after.tzinfo is None
            or not (
                self.key_valid_from
                <= self.key_issuance_not_after
                <= self.key_verify_not_after
            )
        ):
            raise ValueError("recovery witness verification context is invalid")


def verify_recovery_witness_inventory(
    exact_jws: bytes,
    *,
    root_key_id: str,
    root_public_key: Ed25519PublicKey,
    identity: RecoveryAnchorIdentity,
    witness_key_id: str,
    now: datetime,
) -> RecoveryWitnessVerificationContext:
    """Verify a root-signed, purpose-distinct witness inventory and select one active key."""

    try:
        raw = _verify_compact(
            exact_jws,
            expected_kid=root_key_id,
            public_key=root_public_key,
            expected_typ=RECOVERY_WITNESS_INVENTORY_TYP,
        )
        payload = _WitnessInventoryPayload.model_validate(raw)
        issued_at = _parse_time(payload.issued_at)
        if (
            payload.root_key_id != root_key_id
            or payload.environment != identity.environment
            or _canonical_uuid4(payload.ledger_id) != identity.ledger_id
            or issued_at > now
            or len({item.kid for item in payload.keys}) != len(payload.keys)
            or (payload.inventory_generation == 1) != (payload.previous_inventory_digest is None)
        ):
            raise RecoveryWitnessSignatureRejected("recovery_witness_inventory_scope_invalid")
        for item in payload.keys:
            _parse_time(item.valid_from)
            _parse_time(item.issuance_not_after)
            _parse_time(item.verify_not_after)
            if (item.status == "revoked") != (item.revoked_at is not None):
                raise RecoveryWitnessSignatureRejected(
                    "recovery_witness_inventory_revocation_invalid"
                )
            if item.revoked_at is not None:
                _parse_time(item.revoked_at)
        selected = next(
            (
                item
                for item in payload.keys
                if item.kid == witness_key_id and item.status == "active"
            ),
            None,
        )
        if selected is None:
            raise RecoveryWitnessSignatureRejected("recovery_witness_inventory_key_unavailable")
        if (
            selected.environment != identity.environment
            or _canonical_uuid4(selected.ledger_id) != identity.ledger_id
        ):
            raise RecoveryWitnessSignatureRejected("recovery_witness_inventory_scope_invalid")
        valid_from = _parse_time(selected.valid_from)
        issuance_not_after = _parse_time(selected.issuance_not_after)
        verify_not_after = _parse_time(selected.verify_not_after)
        if not (valid_from <= now <= issuance_not_after <= verify_not_after):
            raise RecoveryWitnessSignatureRejected("recovery_witness_inventory_key_not_current")
        public_bytes = base64.b64decode(selected.public_key_b64, validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        return RecoveryWitnessVerificationContext(
            identity=identity,
            key_id=selected.kid,
            public_key=public_key,
            inventory_generation=payload.inventory_generation,
            inventory_jws_sha256=hashlib.sha256(exact_jws).hexdigest(),
            key_valid_from=valid_from,
            key_issuance_not_after=issuance_not_after,
            key_verify_not_after=verify_not_after,
        )
    except (
        RecoveryWitnessSignatureRejected,
        SignedReleaseRejected,
        ValidationError,
        ValueError,
    ) as exc:
        if isinstance(exc, RecoveryWitnessSignatureRejected):
            raise
        raise RecoveryWitnessSignatureRejected("recovery_witness_inventory_invalid") from exc


def verify_recovery_witness(
    exact_jws: bytes,
    *,
    context: RecoveryWitnessVerificationContext,
) -> VerifiedRecoveryWitness:
    """Verify strict signed witness bytes against a separately accepted trust inventory."""

    try:
        raw = _verify_compact(
            exact_jws,
            expected_kid=context.key_id,
            public_key=context.public_key,
            expected_typ=RECOVERY_WITNESS_TYP,
        )
        payload = _WitnessPayload.model_validate(raw)
        identity = RecoveryAnchorIdentity(
            payload.environment,
            _canonical_uuid4(payload.ledger_id),
            _canonical_uuid4(payload.storage_epoch),
        )
        _canonical_uuid4(payload.witness_id)
        if identity != context.identity:
            raise RecoveryWitnessSignatureRejected("recovery_witness_identity_invalid")
        if (
            payload.inventory_generation != context.inventory_generation
            or payload.inventory_jws_sha256 != context.inventory_jws_sha256
        ):
            raise RecoveryWitnessSignatureRejected("recovery_witness_inventory_binding_invalid")
        issued_at = _parse_time(payload.issued_at)
        not_before = _parse_time(payload.not_before)
        not_after = _parse_time(payload.not_after)
        if (
            issued_at > not_before
            or not_before >= not_after
            or not_after - not_before > timedelta(hours=24)
            or not (
                context.key_valid_from <= issued_at <= context.key_issuance_not_after
                and context.key_valid_from <= not_before
                and not_after <= context.key_verify_not_after
            )
        ):
            raise RecoveryWitnessSignatureRejected("recovery_witness_time_window_invalid")
        return VerifiedRecoveryWitness(
            identity=identity,
            recovery_generation=payload.recovery_generation,
            witness_revision=payload.witness_revision,
            status=payload.status,
            checkpoint_digest=payload.checkpoint_digest,
            release_heads_sha256=payload.release_heads_sha256,
            checkpoint_settlement_position_sha256=(
                payload.checkpoint_settlement_position_sha256
            ),
            witness_inventory_digest=payload.inventory_jws_sha256,
            exact_jws=exact_jws,
            not_before=not_before,
            not_after=not_after,
        )
    except (
        RecoveryWitnessSignatureRejected,
        SignedReleaseRejected,
        ValidationError,
        ValueError,
    ) as exc:
        if isinstance(exc, RecoveryWitnessSignatureRejected):
            raise
        raise RecoveryWitnessSignatureRejected("recovery_witness_invalid") from exc


@dataclass(frozen=True)
class RecoveryAnchorRecordDecoder:
    """Concrete DynamoDB decoder joining witness and root transition verification."""

    witness_context: RecoveryWitnessVerificationContext
    anchor_root_key_id: str
    anchor_root_public_key: Ed25519PublicKey

    def __call__(
        self, exact_transition_jws: bytes, exact_witness_jws: bytes
    ) -> VerifiedAnchorTransition:
        witness = verify_recovery_witness(exact_witness_jws, context=self.witness_context)
        return verify_anchor_transition(
            exact_transition_jws,
            root_key_id=self.anchor_root_key_id,
            root_public_key=self.anchor_root_public_key,
            witness=witness,
        )


def _parse_time(value: str) -> datetime:
    try:
        if len(value) != 20 or not value.endswith("Z"):
            raise ValueError
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise RecoveryWitnessSignatureRejected("recovery_witness_timestamp_invalid") from exc


def _canonical_uuid4(value: str) -> UUID:
    parsed = UUID(value)
    if str(parsed) != value or parsed.version != 4:
        raise RecoveryWitnessSignatureRejected("recovery_witness_uuid_invalid")
    return parsed


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def recovery_witness_sha256(exact_jws: bytes) -> str:
    return hashlib.sha256(exact_jws).hexdigest()
