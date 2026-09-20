from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.recovery_anchor import (
    RecoveryAnchorIdentity,
    RecoveryAnchorRejected,
)
from lucy.shared_execution.recovery_anchor_commissioning import build_quarantined_bootstrap
from lucy.shared_execution.recovery_anchor_trust import (
    AnchorTrustRejected,
    load_anchor_trust,
    verified_anchor_reader,
)

NOW = datetime(2026, 9, 20, 12, tzinfo=UTC)
STORE_ENVIRONMENT = {
    "TIAMAT_RECOVERY_ANCHOR_TABLE": "stoin-staging-tiamat-recovery-anchor-v1",
    "AWS_REGION": "us-east-1",
}


class _FakeDynamoDb:
    """Return exactly the stored item shape the deployed adapter writes and reads."""

    def __init__(self, item: dict[str, Any] | None = None) -> None:
        self.item = item

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        return {} if self.item is None else {"Item": self.item}

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("a reading launcher must never write the anchor")


def _day_zero_checkpoint(identity: RecoveryAnchorIdentity) -> dict[str, object]:
    return {
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "storage_epoch": str(identity.storage_epoch),
        "recovery_generation": 1,
        "release_inventory": {"state": "not_installed"},
        "release_heads": [],
        "settlement_position": [],
    }


def _bootstrap(
    identity: RecoveryAnchorIdentity, *, root: Ed25519PrivateKey | None = None
) -> dict[str, object]:
    artifacts, _ = build_quarantined_bootstrap(
        identity=identity,
        root_key_id="tiamat-recovery-root.staging.1",
        root_private_key=root or Ed25519PrivateKey.generate(),
        witness_key_id="tiamat-recovery-witness.staging.1",
        witness_private_key=Ed25519PrivateKey.generate(),
        checkpoint=_day_zero_checkpoint(identity),
        now=NOW,
    )
    return artifacts.public_package(identity)


def _stored_item(identity: RecoveryAnchorIdentity, package: dict[str, object]) -> dict[str, Any]:
    transition_jws = base64.b64decode(str(package["transition_jws_b64"]), validate=True)
    witness_jws = base64.b64decode(str(package["witness_jws_b64"]), validate=True)
    return {
        "anchor_key": {"S": f"ENV#{identity.environment}#LEDGER#{identity.ledger_id}"},
        "transition_sha256": {"S": str(package["transition_sha256"])},
        "transition_version": {"N": "1"},
        "transition_jws": {"B": transition_jws},
        "witness_jws": {"B": witness_jws},
    }


def _reader(package: dict[str, object], client: _FakeDynamoDb) -> Any:
    return verified_anchor_reader(
        load_anchor_trust(package),
        now=NOW,
        environment=STORE_ENVIRONMENT,
        client_factory=lambda *_args, **_kwargs: client,
    )


def test_pinned_trust_reads_and_verifies_the_stored_signed_transition() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    package = _bootstrap(identity)
    reader = _reader(package, _FakeDynamoDb(_stored_item(identity, package)))

    transition = reader.read(identity.key)

    assert transition.exact_sha256 == package["transition_sha256"]
    assert transition.continuity == "quarantined"
    assert transition.witness.identity == identity


def test_a_record_signed_by_a_foreign_root_is_not_authority() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    pinned = _bootstrap(identity)
    foreign = _bootstrap(identity)
    reader = _reader(pinned, _FakeDynamoDb(_stored_item(identity, foreign)))

    with pytest.raises(RecoveryAnchorRejected, match="recovery_anchor_record_invalid"):
        reader.read(identity.key)


def test_tampered_signed_bytes_fail_closed() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    package = _bootstrap(identity)
    item = _stored_item(identity, package)
    item["transition_jws"] = {"B": bytes(item["transition_jws"]["B"]) + b"x"}
    reader = _reader(package, _FakeDynamoDb(item))

    with pytest.raises(RecoveryAnchorRejected, match="recovery_anchor_record_invalid"):
        reader.read(identity.key)


def test_an_absent_record_is_unavailable_rather_than_empty_authority() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    reader = _reader(_bootstrap(identity), _FakeDynamoDb(None))

    with pytest.raises(RecoveryAnchorRejected, match="recovery_anchor_unavailable"):
        reader.read(identity.key)


def test_a_mismatched_root_digest_pin_is_rejected_before_any_read() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    package = _bootstrap(identity)
    package["root_public_key_sha256"] = hashlib.sha256(b"a different root").hexdigest()

    with pytest.raises(AnchorTrustRejected, match="root_trust_pin_mismatch"):
        _reader(package, _FakeDynamoDb(None))


def test_a_tampered_witness_inventory_is_rejected_before_any_read() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    package = _bootstrap(identity)
    inventory = bytearray(base64.b64decode(str(package["inventory_jws_b64"]), validate=True))
    inventory[-1] = inventory[-1] ^ 0x01
    package["inventory_jws_b64"] = base64.b64encode(bytes(inventory)).decode("ascii")

    with pytest.raises(AnchorTrustRejected, match="witness_inventory_rejected"):
        _reader(package, _FakeDynamoDb(None))


def test_trust_for_another_ledger_cannot_verify_this_one() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    package = _bootstrap(identity)
    package["ledger_id"] = str(uuid4())

    with pytest.raises(AnchorTrustRejected, match="witness_inventory_rejected"):
        _reader(package, _FakeDynamoDb(None))


@pytest.mark.parametrize("field", ["root_key_id", "inventory_jws_b64", "storage_epoch"])
def test_incomplete_trust_configuration_is_rejected(field: str) -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    package = _bootstrap(identity)
    del package[field]

    with pytest.raises(AnchorTrustRejected, match="trust_incomplete"):
        load_anchor_trust(package)


def test_an_unusable_store_configuration_is_rejected() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    package = _bootstrap(identity)

    with pytest.raises(AnchorTrustRejected, match="store_configuration_invalid"):
        verified_anchor_reader(
            load_anchor_trust(package),
            now=NOW,
            environment={"TIAMAT_RECOVERY_ANCHOR_TABLE": "", "AWS_REGION": "us-east-1"},
            client_factory=lambda *_args, **_kwargs: _FakeDynamoDb(None),
        )


def test_identity_round_trips_from_the_published_package() -> None:
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    configuration = load_anchor_trust(_bootstrap(identity))

    assert configuration.identity == identity
    assert UUID(str(configuration.identity.ledger_id)) == identity.ledger_id
