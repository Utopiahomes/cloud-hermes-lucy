from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy import cloud_acceptance
from lucy.cloud_acceptance import CloudAcceptanceError
from lucy.contracts import ContractTrustStore, Ed25519ContractSigner, VerificationKeyV1
from lucy.contracts.security_v1_2 import (
    DeploymentEnvironment,
    SensitiveActionV2,
    SignatureAlgorithm,
    SigningKeyPurpose,
    VerificationKeyStatus,
)


def _acceptance_environment(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    values = {
        "LUCY_CLOUD_ACCEPTANCE_AUTHORIZED": "synthetic-only-v1.2",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_SECURITY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_SERVICE_MODE": mode,
        "LUCY_STORAGE_EPOCH": str(uuid4()),
        "LUCY_SECURITY_STORAGE_EPOCH": "1",
        "LUCY_SECURITY_REGISTRY_EPOCH": "2",
        "LUCY_SECURITY_KEY_EPOCH": "3",
        "LUCY_OWNER_SUBJECT": "owner:synthetic",
        "LUCY_ACCEPTANCE_OWNER_KEY_ID": "owner-broker.synthetic-acceptance.test",
        "LUCY_ACCEPTANCE_OWNER_ISSUER": "owner-broker.synthetic-acceptance",
        "LUCY_ACCEPTANCE_OWNER_SIGNING_PRIVATE_KEY_B64": base64.b64encode(
            bytes(range(32))
        ).decode("ascii"),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(cloud_acceptance, "_ready_sessions", lambda: object())


def test_cloud_acceptance_preflight_requires_disabled_capture_and_exact_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _acceptance_environment(monkeypatch, "evidence")
    cloud_acceptance._preflight("evidence")

    monkeypatch.setenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true")
    with pytest.raises(CloudAcceptanceError, match="must remain disabled"):
        cloud_acceptance._preflight("evidence")

    monkeypatch.setenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "false")
    with pytest.raises(CloudAcceptanceError, match="wrong service identity"):
        cloud_acceptance._preflight("deletion")


def test_synthetic_owner_assertion_matches_a_bounded_production_trust_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _acceptance_environment(monkeypatch, "evidence")
    run_id, evidence_id = uuid4(), uuid4()
    assertion = cloud_acceptance._assertion(
        run_id,
        evidence_id,
        SensitiveActionV2.EVIDENCE_RETRIEVE,
    )
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signer = Ed25519ContractSigner(
        private,
        key_id="owner-broker.synthetic-acceptance.test",
    )
    now = datetime.now(UTC)
    trust = ContractTrustStore(
        (
            VerificationKeyV1(
                key_id=signer.key_id,
                issuer="owner-broker.synthetic-acceptance",
                purpose=SigningKeyPurpose.OWNER_BROKER,
                algorithm=SignatureAlgorithm.ED25519,
                environment=DeploymentEnvironment.PRODUCTION,
                public_key_b64=signer.public_key_b64,
                valid_from=now - timedelta(minutes=1),
                issuance_not_after=now + timedelta(minutes=5),
                verify_not_after=now + timedelta(minutes=10),
                status=VerificationKeyStatus.ACTIVE,
            ),
        )
    )
    trust.verify(
        assertion,
        purpose=SigningKeyPurpose.OWNER_BROKER,
        environment=DeploymentEnvironment.PRODUCTION,
        now=now,
    )
    assert assertion.evidence_id == evidence_id
    assert assertion.storage_epoch == 1
    assert assertion.registry_epoch == 2
    assert assertion.key_epoch == 3


def test_acceptance_report_never_contains_the_synthetic_plaintext_or_seed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_id = uuid4()
    cloud_acceptance._report(
        {
            "phase": "archive",
            "run_id": str(run_id),
            "capture_flag_remained_false": True,
        }
    )
    output = capsys.readouterr().out.strip()
    assert output.startswith("LUCY_CLOUD_ACCEPTANCE_RESULT=")
    payload = json.loads(output.split("=", 1)[1])
    assert payload["run_id"] == str(run_id)
    assert cloud_acceptance._synthetic_content(run_id, "user") not in output
    assert base64.b64encode(bytes(range(32))).decode("ascii") not in output
