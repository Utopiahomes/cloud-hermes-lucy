from __future__ import annotations

import base64
import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.recovery_anchor import RecoveryAnchorIdentity
from lucy.shared_execution.recovery_anchor_commissioning import (
    build_quarantined_bootstrap,
    verify_bootstrap_package,
)
from lucy.shared_execution.recovery_witness_jws import (
    RecoveryWitnessSignatureRejected,
    verify_recovery_witness_inventory,
)

NOW = datetime(2026, 9, 18, 12, tzinfo=UTC)
ROOT = Path(__file__).parents[2]


def _deploy_module(name: str) -> ModuleType:
    path = ROOT / "deploy" / "aws" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_offline_bootstrap_builds_self_verified_quarantined_authority() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    root = Ed25519PrivateKey.generate()
    witness = Ed25519PrivateKey.generate()

    artifacts, transition = build_quarantined_bootstrap(
        identity=identity,
        root_key_id="tiamat-recovery-root.staging.1",
        root_private_key=root,
        witness_key_id="tiamat-recovery-witness.staging.1",
        witness_private_key=witness,
        checkpoint_digest="a" * 64,
        release_heads_sha256="b" * 64,
        checkpoint_settlement_position_sha256="c" * 64,
        now=NOW,
    )

    assert transition.continuity == "quarantined"
    assert transition.transition_version == 1
    assert transition.previous_transition_sha256 is None
    assert transition.witness.status == "quarantined"
    assert transition.exact_jws == artifacts.transition_jws
    assert base64.b64decode(artifacts.root_public_key_b64) == root.public_key().public_bytes_raw()
    package = artifacts.public_package(identity)
    packaged_identity, packaged_transition = verify_bootstrap_package(
        package,
        now=NOW,
        expected_root_public_sha256=str(package["root_public_key_sha256"]),
    )
    assert packaged_identity == identity
    assert packaged_transition == transition


def test_witness_inventory_rejects_wrong_root_scope_and_duplicate_keys() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    root = Ed25519PrivateKey.generate()
    witness = Ed25519PrivateKey.generate()
    artifacts, _ = build_quarantined_bootstrap(
        identity=identity,
        root_key_id="tiamat-recovery-root.staging.1",
        root_private_key=root,
        witness_key_id="tiamat-recovery-witness.staging.1",
        witness_private_key=witness,
        checkpoint_digest="a" * 64,
        release_heads_sha256="b" * 64,
        checkpoint_settlement_position_sha256="c" * 64,
        now=NOW,
    )

    with pytest.raises(RecoveryWitnessSignatureRejected):
        verify_recovery_witness_inventory(
            artifacts.inventory_jws,
            root_key_id="wrong-root",
            root_public_key=root.public_key(),
            identity=identity,
            witness_key_id=artifacts.witness_key_id,
            now=NOW,
        )


@pytest.mark.parametrize("digest", ["", "A" * 64, "0" * 63, "g" * 64])
def test_bootstrap_rejects_noncanonical_digest(digest: str) -> None:
    with pytest.raises(ValueError, match="digest"):
        build_quarantined_bootstrap(
            identity=RecoveryAnchorIdentity("staging", uuid4(), uuid4()),
            root_key_id="tiamat-recovery-root.staging.1",
            root_private_key=Ed25519PrivateKey.generate(),
            witness_key_id="tiamat-recovery-witness.staging.1",
            witness_private_key=Ed25519PrivateKey.generate(),
            checkpoint_digest=digest,
            release_heads_sha256="b" * 64,
            checkpoint_settlement_position_sha256="c" * 64,
            now=NOW,
        )


def test_identity_generator_and_package_builder_keep_private_keys_out_of_package() -> None:
    generator = _deploy_module("generate_tiamat_recovery_identity_v1")
    preparer = _deploy_module("prepare_tiamat_recovery_bootstrap_v1")
    root_secret, root_public, witness_secret, _witness_public = generator.generate_identities(
        root_key_id="tiamat-recovery-root.staging.1",
        witness_key_id="tiamat-recovery-witness.staging.1",
    )
    ledger_id = str(uuid4())
    storage_epoch = str(uuid4())
    package = preparer.build_package(
        root_private_identity=root_secret,
        witness_private_identity=witness_secret,
        environment="staging",
        ledger_id=ledger_id,
        storage_epoch=storage_epoch,
        checkpoint_digest="a" * 64,
        release_heads_sha256="b" * 64,
        checkpoint_settlement_position_sha256="c" * 64,
        now=NOW,
        validity_hours=12,
    )

    assert "private" not in str(package).lower()
    assert package["root_public_key_b64"] == root_public["root_public_key_b64"]
    identity, transition = verify_bootstrap_package(
        package,
        now=NOW,
        expected_root_public_sha256=str(package["root_public_key_sha256"]),
    )
    assert str(identity.ledger_id) == ledger_id
    assert transition.continuity == "quarantined"


def test_package_tampering_is_rejected_before_online_write() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    artifacts, _ = build_quarantined_bootstrap(
        identity=identity,
        root_key_id="tiamat-recovery-root.staging.1",
        root_private_key=Ed25519PrivateKey.generate(),
        witness_key_id="tiamat-recovery-witness.staging.1",
        witness_private_key=Ed25519PrivateKey.generate(),
        checkpoint_digest="a" * 64,
        release_heads_sha256="b" * 64,
        checkpoint_settlement_position_sha256="c" * 64,
        now=NOW,
    )
    package = artifacts.public_package(identity)
    package["transition_sha256"] = "0" * 64

    with pytest.raises(ValueError, match="digest"):
        verify_bootstrap_package(
            package,
            now=NOW,
            expected_root_public_sha256=str(package["root_public_key_sha256"]),
        )


def test_package_rejects_unpinned_root_even_when_self_consistent() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    artifacts, _ = build_quarantined_bootstrap(
        identity=identity,
        root_key_id="tiamat-recovery-root.staging.1",
        root_private_key=Ed25519PrivateKey.generate(),
        witness_key_id="tiamat-recovery-witness.staging.1",
        witness_private_key=Ed25519PrivateKey.generate(),
        checkpoint_digest="a" * 64,
        release_heads_sha256="b" * 64,
        checkpoint_settlement_position_sha256="c" * 64,
        now=NOW,
    )
    package = artifacts.public_package(identity)

    with pytest.raises(ValueError, match="root trust pin"):
        verify_bootstrap_package(
            package,
            now=NOW,
            expected_root_public_sha256="0" * 64,
        )
