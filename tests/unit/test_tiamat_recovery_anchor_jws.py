from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.recovery_anchor import RecoveryAnchorIdentity, VerifiedRecoveryWitness
from lucy.shared_execution.recovery_anchor_jws import (
    ANCHOR_TRANSITION_TYP,
    RecoveryAnchorSignatureRejected,
    anchor_transition_sha256,
    verify_anchor_transition,
)

NOW = datetime(2026, 9, 18, 12, tzinfo=UTC)


def _b64url(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _sign(
    payload: dict[str, object],
    private_key: Ed25519PrivateKey,
    *,
    typ: str = ANCHOR_TRANSITION_TYP,
) -> bytes:
    header = {"alg": "EdDSA", "kid": "recovery-root-1", "typ": typ}
    signing_input = _b64url(json.dumps(header, separators=(",", ":")).encode()) + b"." + _b64url(
        json.dumps(payload, separators=(",", ":")).encode()
    )
    return signing_input + b"." + _b64url(private_key.sign(signing_input))


def _witness() -> VerifiedRecoveryWitness:
    return VerifiedRecoveryWitness(
        identity=RecoveryAnchorIdentity("staging", uuid4(), uuid4()),
        recovery_generation=5,
        witness_revision=1,
        status="reconciled",
        checkpoint_digest="a" * 64,
        witness_inventory_digest="b" * 64,
        exact_jws=b"verified-witness",
        not_before=NOW - timedelta(minutes=1),
        not_after=NOW + timedelta(hours=1),
    )


def _payload(witness: VerifiedRecoveryWitness) -> dict[str, object]:
    return {
        "format_version": "1",
        "transition_version": 1,
        "previous_transition_sha256": None,
        "environment": witness.identity.environment,
        "ledger_id": str(witness.identity.ledger_id),
        "storage_epoch": str(witness.identity.storage_epoch),
        "recovery_generation": witness.recovery_generation,
        "witness_revision": witness.witness_revision,
        "witness_jws_sha256": witness.exact_sha256,
        "continuity": "continuity_established",
        "beacon": {
            "system_identifier": "pg-system-1",
            "timeline_id": 1,
            "flushed_wal_lsn": "0/100",
            "checkpoint_digest": witness.checkpoint_digest,
        },
    }


def test_anchor_transition_binds_all_signed_fields_to_verified_witness() -> None:
    private_key = Ed25519PrivateKey.generate()
    witness = _witness()
    exact = _sign(_payload(witness), private_key)

    verified = verify_anchor_transition(
        exact,
        root_key_id="recovery-root-1",
        root_public_key=private_key.public_key(),
        witness=witness,
    )

    assert verified.witness == witness
    assert verified.beacon is not None
    assert verified.exact_sha256 == anchor_transition_sha256(exact)


@pytest.mark.parametrize(
    "field", ["environment", "ledger_id", "storage_epoch", "witness_jws_sha256"]
)
def test_anchor_transition_rejects_signed_payload_not_bound_to_its_witness(field: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    witness = _witness()
    payload = _payload(witness)
    payload[field] = "other" if field == "environment" else "0" * 64
    if field in {"ledger_id", "storage_epoch"}:
        payload[field] = str(uuid4())
    exact = _sign(payload, private_key)

    with pytest.raises(RecoveryAnchorSignatureRejected, match="binding|invalid"):
        verify_anchor_transition(
            exact,
            root_key_id="recovery-root-1",
            root_public_key=private_key.public_key(),
            witness=witness,
        )


def test_anchor_transition_rejects_signature_and_type_substitution() -> None:
    private_key = Ed25519PrivateKey.generate()
    witness = _witness()
    exact = _sign(_payload(witness), private_key)
    protected, payload, signature = exact.split(b".")
    # Mutate meaningful signature bits; the final base64url character can contain unused pad bits.
    signature = (b"A" if signature[:1] != b"A" else b"B") + signature[1:]
    tampered = b".".join((protected, payload, signature))
    with pytest.raises(RecoveryAnchorSignatureRejected):
        verify_anchor_transition(
            tampered,
            root_key_id="recovery-root-1",
            root_public_key=private_key.public_key(),
            witness=witness,
        )
    wrong_type = _sign(_payload(witness), private_key, typ="stoin-signed-release+jws")
    with pytest.raises(RecoveryAnchorSignatureRejected):
        verify_anchor_transition(
            wrong_type,
            root_key_id="recovery-root-1",
            root_public_key=private_key.public_key(),
            witness=witness,
        )
