"""The offline reconciliation signer, driven through its public inputs as an operator would."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from datetime import timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.recovery_anchor_reconciliation import verify_reconciliation_package
from tests.unit.test_tiamat_anchor_writer import NOW, ROOT_KEY_ID, _bootstrap
from tests.unit.test_tiamat_recovery_reconciliation import _checkpoint, _identity

ROOT = Path(__file__).resolve().parents[2]
PENDING_AT = NOW + timedelta(hours=1)
ESTABLISHED_AT = NOW + timedelta(hours=2)


def _script() -> ModuleType:
    path = ROOT / "deploy/aws/prepare_tiamat_reconciliation_step_v1.py"
    spec = importlib.util.spec_from_file_location("prepare_reconciliation", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _private(kind: str, key_id: str, key: Ed25519PrivateKey) -> dict[str, object]:
    return {
        "format_version": "1",
        f"{kind}_key_id": key_id,
        f"{kind}_private_key_b64": base64.b64encode(key.private_bytes_raw()).decode(),
    }


@pytest.fixture
def world() -> dict[str, Any]:
    identity, root = _identity(), Ed25519PrivateKey.generate()
    bootstrap = _bootstrap(identity, root)
    return {
        "identity": identity,
        "root": root,
        "pin": hashlib.sha256(root.public_key().public_bytes_raw()).hexdigest(),
        "head_package": bootstrap.public_package(identity),
        "checkpoint": _checkpoint(identity).object,
    }


def _pending(world: dict[str, Any], **changes: Any) -> dict[str, object]:
    arguments: dict[str, Any] = {
        "head_package": world["head_package"],
        "checkpoint": world["checkpoint"],
        "root_private_identity": _private("root", ROOT_KEY_ID, world["root"]),
        "witness_private_identity": _private(
            "witness", "tiamat-recovery-witness.reconciled.1", Ed25519PrivateKey.generate()
        ),
        "expected_root_public_sha256": world["pin"],
        "now": PENDING_AT,
    }
    arguments.update(changes)
    package: dict[str, object] = _script().build_pending_package(**arguments)
    return package


def test_the_signer_produces_packages_the_installer_verifies(world: dict[str, Any]) -> None:
    pending = _pending(world)
    assert "private" not in json.dumps(pending).lower()
    verified = verify_reconciliation_package(
        pending,
        now=PENDING_AT,
        expected_root_public_sha256=world["pin"],
        expected_ceremony="recovery_pending",
    )
    beacon = {
        "system_identifier": "7310000000000000001",
        "timeline_id": 1,
        "flushed_wal_lsn": "0/16B3748",
        "checkpoint_digest": verified.step.checkpoint.checkpoint_sha256,
    }
    established, trust = _script().build_established_package(
        pending_package=pending,
        beacon=beacon,
        root_private_identity=_private("root", ROOT_KEY_ID, world["root"]),
        expected_root_public_sha256=world["pin"],
        now=ESTABLISHED_AT,
    )
    verified_established = verify_reconciliation_package(
        established,
        now=ESTABLISHED_AT,
        expected_root_public_sha256=world["pin"],
        expected_ceremony="continuity_established",
    )
    assert verified_established.head.exact_sha256 == verified.candidate.exact_sha256
    assert trust["inventory_jws_b64"] == pending["inventory_jws_b64"]
    assert trust["witness_key_id"] == pending["witness_key_id"]
    assert "private" not in json.dumps([established, trust]).lower()


def test_the_signer_refuses_a_root_other_than_the_pinned_one(world: dict[str, Any]) -> None:
    other = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="pinned root"):
        _pending(world, root_private_identity=_private("root", ROOT_KEY_ID, other))


def test_the_signer_refuses_an_unreconcilable_checkpoint(world: dict[str, Any]) -> None:
    day_zero = {**world["checkpoint"], "release_inventory": {"state": "not_installed"}}
    with pytest.raises(ValueError, match="inventory_not_installed"):
        _pending(world, checkpoint=day_zero)


def test_the_signer_refuses_a_malformed_beacon(world: dict[str, Any]) -> None:
    pending = _pending(world)
    with pytest.raises(ValueError, match="beacon"):
        _script().build_established_package(
            pending_package=pending,
            beacon={
                "system_identifier": "1",
                "timeline_id": True,
                "flushed_wal_lsn": "0/1",
                "checkpoint_digest": "a" * 64,
            },
            root_private_identity=_private("root", ROOT_KEY_ID, world["root"]),
            expected_root_public_sha256=world["pin"],
            now=ESTABLISHED_AT,
        )


def _ledger_tool() -> ModuleType:
    path = ROOT / "deploy/postgres/tiamat_reconciliation_ledger_v1.py"
    spec = importlib.util.spec_from_file_location("reconciliation_ledger_tool", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pin(key: Ed25519PrivateKey, **changes: object) -> dict[str, object]:
    pin: dict[str, object] = {
        "format_version": "1",
        "environment": "staging",
        "root_key_id": "tiamat-release-root.staging.1",
        "root_public_key_sha256": hashlib.sha256(key.public_key().public_bytes_raw()).hexdigest(),
    }
    pin.update(changes)
    return pin


def test_the_release_root_is_authenticated_by_the_approved_pin() -> None:
    key = Ed25519PrivateKey.generate()
    supplied = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    root = _ledger_tool().release_root_from_pin(
        _pin(key),
        environment="staging",
        root_key_id="tiamat-release-root.staging.1",
        public_key_b64=supplied,
    )
    assert root.public_bytes_raw() == key.public_key().public_bytes_raw()


@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("other_key", "does not match the approved pin"),
        ("other_environment", "does not name this environment"),
        ("other_key_id", "does not name this environment"),
        ("extra_member", "shape is invalid"),
    ],
)
def test_a_key_the_pin_does_not_approve_is_refused(case: str, reason: str) -> None:
    approved = Ed25519PrivateKey.generate()
    supplied = approved
    pin = _pin(approved)
    environment, key_id = "staging", "tiamat-release-root.staging.1"
    if case == "other_key":
        # The supplied key's own digest is never the authority: a different key fails the pin.
        supplied = Ed25519PrivateKey.generate()
    elif case == "other_environment":
        environment = "production"
    elif case == "other_key_id":
        key_id = "tiamat-release-root.staging.2"
    else:
        pin = {**pin, "approved_by": "anyone"}
    with pytest.raises(ValueError, match=reason):
        _ledger_tool().release_root_from_pin(
            pin,
            environment=environment,
            root_key_id=key_id,
            public_key_b64=base64.b64encode(supplied.public_key().public_bytes_raw()).decode(),
        )
