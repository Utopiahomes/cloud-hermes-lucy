"""Signed external recovery-anchor state machine for Tiamat.

The production adapter must persist its exact signed transition bytes in storage outside PostgreSQL
and the database host/VM snapshot boundary. This module does not choose that product. Its
in-memory implementation is a deterministic local test double, never a deployment anchor.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID


class RecoveryAnchorRejected(RuntimeError):
    """An anchor transition or attempted restart would weaken recovery authority."""


AnchorContinuity = Literal["recovery_pending", "continuity_established", "quarantined"]
WitnessStatus = Literal["reconciled", "quarantined"]
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_LSN = re.compile(r"^[0-9A-F]+/[0-9A-F]+$")


def _hex_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _lsn_value(value: str) -> int:
    if _LSN.fullmatch(value) is None:
        raise ValueError("PostgreSQL LSN is invalid")
    high, low = value.split("/")
    return (int(high, 16) << 32) + int(low, 16)


@dataclass(frozen=True)
class RecoveryAnchorKey:
    environment: str
    ledger_id: UUID

    def __post_init__(self) -> None:
        if not self.environment:
            raise ValueError("recovery anchor key is incomplete")


@dataclass(frozen=True)
class RecoveryAnchorIdentity:
    environment: str
    ledger_id: UUID
    storage_epoch: UUID

    @property
    def key(self) -> RecoveryAnchorKey:
        return RecoveryAnchorKey(self.environment, self.ledger_id)


@dataclass(frozen=True)
class PostgresContinuityBeacon:
    """A database identity and durable-WAL observation bound into an anchor transition."""

    system_identifier: str
    timeline_id: int
    flushed_wal_lsn: str
    checkpoint_digest: str

    def __post_init__(self) -> None:
        if (
            not self.system_identifier
            or not 1 <= self.timeline_id <= _MAX_SAFE_INTEGER
            or not _hex_digest(self.checkpoint_digest)
        ):
            raise ValueError("PostgreSQL continuity beacon is invalid")
        _lsn_value(self.flushed_wal_lsn)

    def covers(self, observed: PostgresContinuityBeacon) -> bool:
        """Whether an attached database has reached this signed continuity observation."""

        return (
            self.system_identifier == observed.system_identifier
            and self.timeline_id == observed.timeline_id
            and self.checkpoint_digest == observed.checkpoint_digest
            and _lsn_value(observed.flushed_wal_lsn) >= _lsn_value(self.flushed_wal_lsn)
        )


@dataclass(frozen=True)
class VerifiedRecoveryWitness:
    """Recovery witness after exact-byte signature/inventory verification."""

    identity: RecoveryAnchorIdentity
    recovery_generation: int
    witness_revision: int
    status: WitnessStatus
    checkpoint_digest: str
    witness_inventory_digest: str
    exact_jws: bytes
    not_before: datetime
    not_after: datetime

    def __post_init__(self) -> None:
        if (
            not 1 <= self.recovery_generation <= _MAX_SAFE_INTEGER
            or not 1 <= self.witness_revision <= _MAX_SAFE_INTEGER
            or not _hex_digest(self.checkpoint_digest)
            or not _hex_digest(self.witness_inventory_digest)
            or not self.exact_jws
            or self.not_before.tzinfo is None
            or self.not_after.tzinfo is None
            or self.not_before >= self.not_after
        ):
            raise ValueError("recovery witness is invalid")

    @property
    def exact_sha256(self) -> str:
        return hashlib.sha256(self.exact_jws).hexdigest()

    @property
    def ordering(self) -> tuple[int, int]:
        return self.recovery_generation, self.witness_revision

    def valid_at(self, now: datetime) -> bool:
        if now.tzinfo is None:
            raise ValueError("recovery time must be aware")
        return self.not_before <= now < self.not_after


@dataclass(frozen=True)
class VerifiedAnchorTransition:
    """Root-authorized anchor state after exact-byte signature verification.

    ``exact_jws`` signs every member, including predecessor, continuity, storage epoch and beacon.
    TLS authenticates transport only; it is not authority for a transition.
    """

    witness: VerifiedRecoveryWitness
    transition_version: int
    previous_transition_sha256: str | None
    continuity: AnchorContinuity
    beacon: PostgresContinuityBeacon | None
    exact_jws: bytes

    def __post_init__(self) -> None:
        if (
            not 1 <= self.transition_version <= _MAX_SAFE_INTEGER
            or (
                self.previous_transition_sha256 is not None
                and not _hex_digest(self.previous_transition_sha256)
            )
            or not self.exact_jws
        ):
            raise ValueError("recovery anchor transition is invalid")
        if self.continuity == "continuity_established":
            if self.witness.status != "reconciled" or self.beacon is None:
                raise ValueError("established continuity requires reconciled witness and beacon")
        elif self.continuity == "quarantined":
            if self.witness.status != "quarantined" or self.beacon is not None:
                raise ValueError("quarantine requires quarantined witness without a beacon")
        elif self.beacon is not None:
            raise ValueError("recovery pending does not assert continuity")

    @property
    def exact_sha256(self) -> str:
        return hashlib.sha256(self.exact_jws).hexdigest()


class ExternalRecoveryAnchor(Protocol):
    """Durable, signed compare-and-swap authority outside the restore boundary."""

    def read(self, key: RecoveryAnchorKey) -> VerifiedAnchorTransition: ...

    def install(
        self,
        transition: VerifiedAnchorTransition,
        *,
        expected_transition_sha256: str | None,
        now: datetime,
    ) -> VerifiedAnchorTransition: ...


class InMemoryExternalRecoveryAnchor:
    """Thread-safe local behavioral model of an external anchor service."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[RecoveryAnchorKey, VerifiedAnchorTransition] = {}

    def read(self, key: RecoveryAnchorKey) -> VerifiedAnchorTransition:
        with self._lock:
            try:
                return self._records[key]
            except KeyError as exc:
                raise RecoveryAnchorRejected("recovery_anchor_unavailable") from exc

    def install(
        self,
        transition: VerifiedAnchorTransition,
        *,
        expected_transition_sha256: str | None,
        now: datetime,
    ) -> VerifiedAnchorTransition:
        if now.tzinfo is None:
            raise ValueError("recovery time must be aware")
        if not transition.witness.valid_at(now):
            raise RecoveryAnchorRejected("recovery_witness_not_current")
        key = transition.witness.identity.key
        with self._lock:
            previous = self._records.get(key)
            if previous is None:
                if (
                    expected_transition_sha256 is not None
                    or transition.transition_version != 1
                    or transition.previous_transition_sha256 is not None
                ):
                    raise RecoveryAnchorRejected("recovery_anchor_compare_failed")
            else:
                if expected_transition_sha256 != previous.exact_sha256:
                    raise RecoveryAnchorRejected("recovery_anchor_compare_failed")
                self._validate_successor(previous, transition)
            self._records[key] = transition
            return transition

    @staticmethod
    def _validate_successor(
        previous: VerifiedAnchorTransition,
        candidate: VerifiedAnchorTransition,
    ) -> None:
        if (
            candidate.transition_version != previous.transition_version + 1
            or candidate.previous_transition_sha256 != previous.exact_sha256
        ):
            raise RecoveryAnchorRejected("recovery_anchor_transition_chain_invalid")
        current_witness = previous.witness
        next_witness = candidate.witness
        if next_witness.identity.key != current_witness.identity.key:
            raise RecoveryAnchorRejected("recovery_anchor_identity_changed")
        if next_witness.identity.storage_epoch != current_witness.identity.storage_epoch:
            if candidate.continuity != "quarantined" or next_witness.witness_revision != 1:
                raise RecoveryAnchorRejected("recovery_epoch_change_requires_quarantine")
            return
        if next_witness.ordering < current_witness.ordering:
            raise RecoveryAnchorRejected("recovery_witness_rollback")
        if next_witness.ordering == current_witness.ordering:
            if next_witness.exact_jws != current_witness.exact_jws:
                raise RecoveryAnchorRejected("recovery_witness_conflicting_replay")
        elif next_witness.recovery_generation == current_witness.recovery_generation:
            if (
                next_witness.witness_revision != current_witness.witness_revision + 1
                or current_witness.status != "reconciled"
                or next_witness.status != "reconciled"
                or next_witness.checkpoint_digest != current_witness.checkpoint_digest
            ):
                raise RecoveryAnchorRejected("recovery_witness_invalid_renewal")
        elif next_witness.witness_revision != 1:
            raise RecoveryAnchorRejected("recovery_witness_generation_requires_first_revision")

    def require_dispatch_authority(
        self,
        identity: RecoveryAnchorIdentity,
        *,
        observed_beacon: PostgresContinuityBeacon,
        now: datetime,
    ) -> VerifiedRecoveryWitness:
        transition = self.read(identity.key)
        witness = transition.witness
        if witness.identity != identity:
            raise RecoveryAnchorRejected("recovery_anchor_identity_mismatch")
        if transition.continuity != "continuity_established":
            raise RecoveryAnchorRejected("recovery_continuity_not_established")
        if witness.status != "reconciled" or not witness.valid_at(now):
            raise RecoveryAnchorRejected("recovery_dispatch_not_authorized")
        assert transition.beacon is not None
        if not transition.beacon.covers(observed_beacon):
            raise RecoveryAnchorRejected("recovery_continuity_beacon_mismatch")
        return witness
