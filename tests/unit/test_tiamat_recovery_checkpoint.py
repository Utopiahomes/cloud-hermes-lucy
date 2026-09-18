from __future__ import annotations

from copy import deepcopy
from uuid import uuid4

import pytest

from lucy.shared_execution.recovery_anchor import RecoveryAnchorIdentity
from lucy.shared_execution.recovery_checkpoint import (
    RecoveryCheckpointRejected,
    construct_recovery_checkpoint,
    require_day_zero_quarantine_checkpoint,
)


def _identity() -> RecoveryAnchorIdentity:
    return RecoveryAnchorIdentity("staging", uuid4(), uuid4())


def _checkpoint(identity: RecoveryAnchorIdentity) -> dict[str, object]:
    return {
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "storage_epoch": str(identity.storage_epoch),
        "recovery_generation": 1,
        "release_inventory": {"state": "not_installed"},
        "release_heads": [],
        "settlement_position": [],
    }


def test_day_zero_checkpoint_has_computed_digest_and_empty_component_digests() -> None:
    identity = _identity()

    checkpoint = construct_recovery_checkpoint(_checkpoint(identity), identity=identity)

    assert checkpoint.object["release_inventory"] == {"state": "not_installed"}
    assert checkpoint.release_heads_sha256 == checkpoint.settlement_position_sha256
    assert len(checkpoint.checkpoint_sha256) == 64
    require_day_zero_quarantine_checkpoint(checkpoint)


def test_checkpoint_order_is_canonical_but_duplicate_keys_are_rejected() -> None:
    identity = _identity()
    raw = _checkpoint(identity)
    raw["release_inventory"] = {"generation": 2, "jws_sha256": "a" * 64}
    raw["release_heads"] = [
        {
            "issuer": "stoin:control",
            "caller_id": "homes",
            "realm": "utopia-homes",
            "release_type": "execution_profile",
            "subject_id": "zebra",
            "active_jws_sha256": "b" * 64,
            "head_state": "active",
        },
        {
            "issuer": "stoin:control",
            "caller_id": "homes",
            "realm": "utopia-homes",
            "release_type": "execution_profile",
            "subject_id": "alpha-😀",
            "active_jws_sha256": "c" * 64,
            "head_state": "active",
        },
    ]
    first = construct_recovery_checkpoint(raw, identity=identity)
    reordered = deepcopy(raw)
    reordered["release_heads"] = list(reversed(raw["release_heads"]))
    second = construct_recovery_checkpoint(reordered, identity=identity)
    assert first.checkpoint_sha256 == second.checkpoint_sha256

    duplicate = deepcopy(raw)
    duplicate["release_heads"] = [raw["release_heads"][0], raw["release_heads"][0]]
    with pytest.raises(RecoveryCheckpointRejected, match="duplicate_release_head"):
        construct_recovery_checkpoint(duplicate, identity=identity)


@pytest.mark.parametrize(
    ("field", "value"),
    [("recovery_generation", True), ("recovery_generation", 1.0), ("extra", "no")],
)
def test_checkpoint_rejects_noncanonical_or_untyped_values(field: str, value: object) -> None:
    identity = _identity()
    raw = _checkpoint(identity)
    raw[field] = value

    with pytest.raises(RecoveryCheckpointRejected):
        construct_recovery_checkpoint(raw, identity=identity)


def test_day_zero_rejects_uninstalled_inventory_with_authority_or_obligations() -> None:
    identity = _identity()
    raw = _checkpoint(identity)
    raw["settlement_position"] = [
        {
            "partition_id": "homes-public",
            "budget_period_id": "2026-09-18",
            "settled_microusd": 0,
            "reserved_microusd": 0,
            "pending_reconciliation_count": 0,
            "forfeited_microusd": 0,
            "contingency_used_microusd": 0,
            "external_liability_marker": "none",
        }
    ]
    checkpoint = construct_recovery_checkpoint(raw, identity=identity)

    with pytest.raises(RecoveryCheckpointRejected, match="day_zero"):
        require_day_zero_quarantine_checkpoint(checkpoint)
