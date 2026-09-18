"""Strict, independently reproducible recovery checkpoint construction for Tiamat."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from lucy.shared_execution.canonical import canonical_json_bytes
from lucy.shared_execution.recovery_anchor import RecoveryAnchorIdentity

_UUID4 = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_DIGEST = r"^[0-9a-f]{64}$"


class RecoveryCheckpointRejected(ValueError):
    """A checkpoint is not a closed, canonical, context-bound recovery checkpoint."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _NotInstalledInventory(_Strict):
    state: Literal["not_installed"]


class _InstalledInventory(_Strict):
    generation: int = Field(ge=1, le=9_007_199_254_740_991)
    jws_sha256: str = Field(pattern=_DIGEST)


class _ReleaseHead(_Strict):
    issuer: str = Field(min_length=1, max_length=128)
    caller_id: str = Field(min_length=1, max_length=128)
    realm: str = Field(min_length=1, max_length=64)
    release_type: Literal["execution_profile", "privacy_policy", "spending_grant", "revocation"]
    subject_id: str = Field(min_length=1, max_length=128)
    active_jws_sha256: str = Field(pattern=_DIGEST)
    head_state: Literal["active"]

    def key(self) -> tuple[str, str, str, str, str]:
        return self.issuer, self.caller_id, self.realm, self.release_type, self.subject_id


class _SettlementPosition(_Strict):
    partition_id: str = Field(min_length=1, max_length=128)
    budget_period_id: str = Field(min_length=1, max_length=128)
    settled_microusd: int = Field(ge=0, le=9_007_199_254_740_991)
    reserved_microusd: int = Field(ge=0, le=9_007_199_254_740_991)
    pending_reconciliation_count: int = Field(ge=0, le=9_007_199_254_740_991)
    forfeited_microusd: int = Field(ge=0, le=9_007_199_254_740_991)
    contingency_used_microusd: int = Field(ge=0, le=9_007_199_254_740_991)
    external_liability_marker: Literal["none", "represented_pending"]

    def key(self) -> tuple[str, str]:
        return self.partition_id, self.budget_period_id


class _Checkpoint(_Strict):
    environment: str = Field(min_length=1, max_length=128)
    ledger_id: str = Field(pattern=_UUID4)
    storage_epoch: str = Field(pattern=_UUID4)
    recovery_generation: int = Field(ge=1, le=9_007_199_254_740_991)
    release_inventory: dict[str, object]
    release_heads: list[_ReleaseHead]
    settlement_position: list[_SettlementPosition]


@dataclass(frozen=True)
class RecoveryCheckpoint:
    object: dict[str, object]
    release_heads_sha256: str
    settlement_position_sha256: str
    checkpoint_sha256: str
    release_inventory_installed: bool


def construct_recovery_checkpoint(
    raw: dict[str, object], *, identity: RecoveryAnchorIdentity
) -> RecoveryCheckpoint:
    """Validate, sort, canonicalize and hash one complete checkpoint object."""

    try:
        checkpoint = _Checkpoint.model_validate(raw)
        if (
            checkpoint.environment != identity.environment
            or _uuid4(checkpoint.ledger_id) != identity.ledger_id
            or _uuid4(checkpoint.storage_epoch) != identity.storage_epoch
        ):
            raise RecoveryCheckpointRejected("checkpoint_identity_mismatch")
        inventory, installed = _inventory(checkpoint.release_inventory)
        heads = sorted(checkpoint.release_heads, key=lambda item: _scalar_key(item.key()))
        positions = sorted(checkpoint.settlement_position, key=lambda item: _scalar_key(item.key()))
        if len({item.key() for item in heads}) != len(heads):
            raise RecoveryCheckpointRejected("checkpoint_duplicate_release_head")
        if len({item.key() for item in positions}) != len(positions):
            raise RecoveryCheckpointRejected("checkpoint_duplicate_settlement_position")
        for position in positions:
            if (
                position.external_liability_marker == "represented_pending"
                and position.pending_reconciliation_count == 0
            ):
                raise RecoveryCheckpointRejected("checkpoint_liability_marker_invalid")
        object_value: dict[str, object] = {
            "environment": checkpoint.environment,
            "ledger_id": checkpoint.ledger_id,
            "storage_epoch": checkpoint.storage_epoch,
            "recovery_generation": checkpoint.recovery_generation,
            "release_inventory": inventory,
            "release_heads": [item.model_dump(mode="json") for item in heads],
            "settlement_position": [item.model_dump(mode="json") for item in positions],
        }
        release_heads = object_value["release_heads"]
        settlement_position = object_value["settlement_position"]
        return RecoveryCheckpoint(
            object=object_value,
            release_heads_sha256=_sha256(release_heads),
            settlement_position_sha256=_sha256(settlement_position),
            checkpoint_sha256=_sha256(object_value),
            release_inventory_installed=installed,
        )
    except (RecoveryCheckpointRejected, ValidationError, TypeError, ValueError) as exc:
        if isinstance(exc, RecoveryCheckpointRejected):
            raise
        raise RecoveryCheckpointRejected("checkpoint_invalid") from exc


def require_day_zero_quarantine_checkpoint(checkpoint: RecoveryCheckpoint) -> None:
    """Permit the `not_installed` inventory only for the unique empty quarantine bootstrap."""

    object_value = checkpoint.object
    if (
        checkpoint.release_inventory_installed
        or object_value["recovery_generation"] != 1
        or object_value["release_heads"] != []
        or object_value["settlement_position"] != []
    ):
        raise RecoveryCheckpointRejected("checkpoint_day_zero_constraints_invalid")


def _inventory(value: dict[str, object]) -> tuple[dict[str, object], bool]:
    try:
        if set(value) == {"state"}:
            return _NotInstalledInventory.model_validate(value).model_dump(mode="json"), False
        return _InstalledInventory.model_validate(value).model_dump(mode="json"), True
    except (ValidationError, TypeError, ValueError) as exc:
        raise RecoveryCheckpointRejected("checkpoint_release_inventory_invalid") from exc


def _uuid4(value: str) -> UUID:
    parsed = UUID(value)
    if str(parsed) != value or parsed.version != 4:
        raise RecoveryCheckpointRejected("checkpoint_uuid_invalid")
    return parsed


def _scalar_key(values: tuple[str, ...]) -> tuple[str, ...]:
    for value in values:
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise RecoveryCheckpointRejected("checkpoint_unicode_invalid")
    return values


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
