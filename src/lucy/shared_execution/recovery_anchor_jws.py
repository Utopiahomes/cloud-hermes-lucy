"""Exact-byte verification for root-authorized external recovery-anchor transitions."""

from __future__ import annotations

import hashlib
from typing import Literal
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from lucy.shared_execution.recovery_anchor import (
    PostgresContinuityBeacon,
    RecoveryAnchorIdentity,
    VerifiedAnchorTransition,
    VerifiedRecoveryWitness,
)
from lucy.shared_execution.signed_releases import SignedReleaseRejected, _verify_compact

ANCHOR_TRANSITION_TYP = "stoin-tiamat-recovery-anchor-transition+jws"


class RecoveryAnchorSignatureRejected(ValueError):
    """A root-authorized anchor transition failed exact-byte verification."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _BeaconPayload(_StrictModel):
    system_identifier: str = Field(min_length=1, max_length=128)
    timeline_id: int = Field(ge=1, le=9_007_199_254_740_991)
    flushed_wal_lsn: str = Field(pattern=r"^[0-9A-F]+/[0-9A-F]+$")
    checkpoint_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class _AnchorPayload(_StrictModel):
    format_version: Literal["1"]
    transition_version: int = Field(ge=1, le=9_007_199_254_740_991)
    previous_transition_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    environment: str = Field(min_length=1, max_length=128)
    ledger_id: str = Field(pattern=r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
    storage_epoch: str = Field(pattern=r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
    recovery_generation: int = Field(ge=1, le=9_007_199_254_740_991)
    witness_revision: int = Field(ge=1, le=9_007_199_254_740_991)
    witness_jws_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    continuity: Literal["recovery_pending", "continuity_established", "quarantined"]
    beacon: _BeaconPayload | None


def verify_anchor_transition(
    exact_jws: bytes,
    *,
    root_key_id: str,
    root_public_key: Ed25519PublicKey,
    witness: VerifiedRecoveryWitness,
) -> VerifiedAnchorTransition:
    """Verify a transition and bind every signed field to its verified witness."""

    try:
        raw = _verify_compact(
            exact_jws,
            expected_kid=root_key_id,
            public_key=root_public_key,
            expected_typ=ANCHOR_TRANSITION_TYP,
        )
        payload = _AnchorPayload.model_validate(raw)
        identity = RecoveryAnchorIdentity(
            payload.environment,
            _canonical_uuid(payload.ledger_id),
            _canonical_uuid(payload.storage_epoch),
        )
        if (
            identity != witness.identity
            or payload.recovery_generation != witness.recovery_generation
            or payload.witness_revision != witness.witness_revision
            or payload.witness_jws_sha256 != witness.exact_sha256
        ):
            raise RecoveryAnchorSignatureRejected("anchor_transition_witness_binding_invalid")
        beacon = None
        if payload.beacon is not None:
            beacon = PostgresContinuityBeacon(
                payload.beacon.system_identifier,
                payload.beacon.timeline_id,
                payload.beacon.flushed_wal_lsn,
                payload.beacon.checkpoint_digest,
            )
        return VerifiedAnchorTransition(
            witness=witness,
            transition_version=payload.transition_version,
            previous_transition_sha256=payload.previous_transition_sha256,
            continuity=payload.continuity,
            beacon=beacon,
            exact_jws=exact_jws,
        )
    except (
        RecoveryAnchorSignatureRejected,
        SignedReleaseRejected,
        ValidationError,
        ValueError,
    ) as exc:
        if isinstance(exc, RecoveryAnchorSignatureRejected):
            raise
        raise RecoveryAnchorSignatureRejected("anchor_transition_invalid") from exc


def _canonical_uuid(value: str) -> UUID:
    parsed = UUID(value)
    if str(parsed) != value:
        raise RecoveryAnchorSignatureRejected("anchor_transition_identity_invalid")
    return parsed


def anchor_transition_sha256(exact_jws: bytes) -> str:
    """Digest used by the externally durable predecessor chain."""

    return hashlib.sha256(exact_jws).hexdigest()
