from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.recovery_anchor import RecoveryAnchorIdentity
from lucy.shared_execution.recovery_anchor_jws import ANCHOR_TRANSITION_TYP
from lucy.shared_execution.recovery_witness_jws import (
    RECOVERY_WITNESS_TYP,
    RecoveryAnchorRecordDecoder,
    RecoveryWitnessSignatureRejected,
    RecoveryWitnessVerificationContext,
    recovery_witness_sha256,
    verify_recovery_witness,
)

NOW = datetime(2026, 9, 18, 12, tzinfo=UTC)


def b64url(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def sign(
    payload: dict[str, object],
    key: Ed25519PrivateKey,
    *,
    typ: str = RECOVERY_WITNESS_TYP,
    kid: str = "witness-key-1",
) -> bytes:
    header = {"alg": "EdDSA", "kid": kid, "typ": typ}
    signing_input = b64url(json.dumps(header, separators=(",", ":")).encode()) + b"." + b64url(
        json.dumps(payload, separators=(",", ":")).encode()
    )
    return signing_input + b"." + b64url(key.sign(signing_input))


def payload(identity: RecoveryAnchorIdentity) -> dict[str, object]:
    return {
        "format_version": "1",
        "witness_id": str(uuid4()),
        "issuer": "stoin:control",
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "storage_epoch": str(identity.storage_epoch),
        "recovery_generation": 7,
        "witness_revision": 2,
        "status": "reconciled",
        "issued_at": "2026-09-18T11:59:00Z",
        "not_before": "2026-09-18T12:00:00Z",
        "not_after": "2026-09-19T00:00:00Z",
        "inventory_generation": 3,
        "inventory_jws_sha256": "a" * 64,
        "release_heads_sha256": "b" * 64,
        "checkpoint_settlement_position_sha256": "c" * 64,
        "checkpoint_digest": "d" * 64,
    }


def context(
    identity: RecoveryAnchorIdentity, key: Ed25519PrivateKey
) -> RecoveryWitnessVerificationContext:
    return RecoveryWitnessVerificationContext(
        identity=identity,
        key_id="witness-key-1",
        public_key=key.public_key(),
        inventory_generation=3,
        inventory_jws_sha256="a" * 64,
        key_valid_from=datetime(2026, 9, 18, 11, tzinfo=UTC),
        key_issuance_not_after=datetime(2026, 9, 18, 23, tzinfo=UTC),
        key_verify_not_after=datetime(2026, 9, 19, 1, tzinfo=UTC),
    )


def test_witness_verifier_binds_identity_inventory_and_exact_bytes() -> None:
    key = Ed25519PrivateKey.generate()
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    exact = sign(payload(identity), key)

    verified = verify_recovery_witness(exact, context=context(identity, key))

    assert verified.identity == identity
    assert verified.recovery_generation == 7
    assert verified.witness_revision == 2
    assert verified.exact_jws == exact
    assert recovery_witness_sha256(exact) == verified.exact_sha256


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("environment", "production", "identity"),
        ("inventory_generation", 4, "inventory"),
        ("inventory_jws_sha256", "e" * 64, "inventory"),
        ("issuer", "other", "invalid"),
        ("unknown", "member", "invalid"),
    ],
)
def test_witness_rejects_scope_inventory_and_unknown_member_changes(
    field: str, value: object, reason: str
) -> None:
    key = Ed25519PrivateKey.generate()
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    candidate = payload(identity)
    candidate[field] = value

    with pytest.raises(RecoveryWitnessSignatureRejected, match=reason):
        verify_recovery_witness(sign(candidate, key), context=context(identity, key))


@pytest.mark.parametrize(
    ("not_before", "not_after"),
    [
        ("2026-09-18T12:00:00.1Z", "2026-09-19T00:00:00Z"),
        ("2026-09-19T00:00:00Z", "2026-09-18T12:00:00Z"),
        ("2026-09-18T12:00:00Z", "2026-09-19T12:00:01Z"),
    ],
)
def test_witness_rejects_invalid_or_overlong_time_windows(
    not_before: str, not_after: str
) -> None:
    key = Ed25519PrivateKey.generate()
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    candidate = payload(identity)
    candidate["not_before"] = not_before
    candidate["not_after"] = not_after

    with pytest.raises(RecoveryWitnessSignatureRejected, match="timestamp|time_window"):
        verify_recovery_witness(sign(candidate, key), context=context(identity, key))


def test_witness_rejects_wrong_type_or_signature() -> None:
    key = Ed25519PrivateKey.generate()
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    candidate = payload(identity)
    wrong_type = sign(candidate, key, typ="stoin-signed-release+jws")
    with pytest.raises(RecoveryWitnessSignatureRejected):
        verify_recovery_witness(wrong_type, context=context(identity, key))

    exact = sign(candidate, key)
    protected, body, signature = exact.split(b".")
    signature = (b"A" if signature[:1] != b"A" else b"B") + signature[1:]
    with pytest.raises(RecoveryWitnessSignatureRejected):
        verify_recovery_witness(
            b".".join((protected, body, signature)), context=context(identity, key)
        )


def test_record_decoder_verifies_witness_then_root_signed_anchor() -> None:
    witness_key = Ed25519PrivateKey.generate()
    root_key = Ed25519PrivateKey.generate()
    identity = RecoveryAnchorIdentity("staging", uuid4(), uuid4())
    witness_jws = sign(payload(identity), witness_key)
    verified_witness = verify_recovery_witness(
        witness_jws, context=context(identity, witness_key)
    )
    anchor_payload: dict[str, object] = {
        "format_version": "1",
        "transition_version": 1,
        "previous_transition_sha256": None,
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "storage_epoch": str(identity.storage_epoch),
        "recovery_generation": 7,
        "witness_revision": 2,
        "witness_jws_sha256": verified_witness.exact_sha256,
        "continuity": "continuity_established",
        "beacon": {
            "system_identifier": "pg-system-1",
            "timeline_id": 1,
            "flushed_wal_lsn": "0/100",
            "checkpoint_digest": "d" * 64,
        },
    }
    anchor_jws = sign(
        anchor_payload,
        root_key,
        typ=ANCHOR_TRANSITION_TYP,
        kid="anchor-root-1",
    )
    decoder = RecoveryAnchorRecordDecoder(
        context(identity, witness_key),
        "anchor-root-1",
        root_key.public_key(),
    )

    transition = decoder(anchor_jws, witness_jws)

    assert transition.witness == verified_witness
    assert transition.beacon is not None
    assert transition.beacon.checkpoint_digest == "d" * 64
