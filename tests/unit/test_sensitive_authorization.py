from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.authorization import (
    SensitiveAction,
    SensitiveActionPermitSigner,
    SensitiveActionPermitV1,
    SensitiveActionPermitVerifier,
)


def _permit() -> tuple[SensitiveActionPermitV1, SensitiveActionPermitVerifier]:
    private = Ed25519PrivateKey.generate()
    signer = SensitiveActionPermitSigner(private)
    now = datetime.now(UTC)
    evidence_id = uuid4()
    unsigned = SensitiveActionPermitV1(
        permit_id=uuid4(),
        action=SensitiveAction.EVIDENCE_RETRIEVE,
        owner_subject="owner:forti",
        owner_interaction_id="telegram:turn-123",
        evidence_ids=(evidence_id,),
        reason="resolve_ambiguity",
        max_records=1,
        max_bytes=4096,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        nonce="n" * 32,
        signature="",
    )
    return signer.sign(unsigned), SensitiveActionPermitVerifier(private.public_key())


def test_permit_signature_binds_every_authorization_field() -> None:
    permit, verifier = _permit()
    verifier.verify_signature(permit)

    tampered = permit.model_copy(update={"reason": "verify_exact_wording"})
    with pytest.raises(PermissionError, match="signature"):
        verifier.verify_signature(tampered)


def test_permit_rejects_more_than_five_minutes() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="lifetime"):
        SensitiveActionPermitV1(
            permit_id=uuid4(),
            action=SensitiveAction.EVIDENCE_DELETE,
            owner_subject="owner:forti",
            owner_interaction_id="telegram:turn-123",
            evidence_ids=(uuid4(),),
            reason="owner_request",
            max_records=1,
            max_bytes=1,
            issued_at=now,
            expires_at=now + timedelta(minutes=6),
            nonce="n" * 32,
            signature="unused",
        )
