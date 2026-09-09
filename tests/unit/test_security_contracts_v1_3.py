from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import ValidationError

from lucy.contracts.security_v1_2 import DeploymentEnvironment, SensitiveActionV2
from lucy.contracts.security_v1_3 import (
    AuthenticationStrength,
    Ed25519V13Signer,
    ExactObjectSelectorV1,
    ExecutionBindingV1,
    KmsEncryptionContextV2,
    OriginScopeV1,
    SensitiveActionPermitV3,
    SensitiveExecutionGrantV2,
    V13ContractVerifier,
    V13SigningKeyPurpose,
    V13VerificationKeyStatus,
    V13VerificationKeyV1,
    security_v1_3_json_schemas,
)

ZERO = UUID("00000000-0000-4000-8000-000000000000")
ONE = UUID("00000000-0000-4000-8000-000000000001")
TWO = UUID("00000000-0000-4000-8000-000000000002")
THREE = UUID("00000000-0000-4000-8000-000000000003")
FOUR = UUID("00000000-0000-4000-8000-000000000004")
NOW = datetime(2026, 9, 9, 12, 0, tzinfo=UTC)
DIGEST = "1" * 64
NONCE = "n" * 32


def _scope(*, realm: UUID = THREE, storage_epoch: int = 7) -> OriginScopeV1:
    return OriginScopeV1(
        tenant_account_id=ZERO,
        node_id=ONE,
        node_tenure_id=TWO,
        tenure_epoch=1,
        security_realm_id=realm,
        storage_epoch=storage_epoch,
    )


def _binding(*, realm: UUID = THREE, storage_epoch: int = 7) -> ExecutionBindingV1:
    return ExecutionBindingV1(
        deployment_id=FOUR,
        active_realm_id=realm,
        active_storage_epoch=storage_epoch,
        realm_binding_generation=2,
        node_authz_epoch=3,
    )


def _permit(**changes: object) -> SensitiveActionPermitV3:
    values: dict[str, object] = {
        "signing_key_purpose": V13SigningKeyPurpose.POLICY_NOTARY,
        "key_id": "policy-v13-test",
        "issuer": "lucy-policy-v13-test",
        "environment": DeploymentEnvironment.TEST,
        "issued_at": NOW,
        "permit_id": ZERO,
        "action": SensitiveActionV2.EVIDENCE_RETRIEVE,
        "reason": "owner_review",
        "principal_id": ONE,
        "service_principal_id": TWO,
        "service_binding_id": THREE,
        "operation_id": FOUR,
        "target_scope": _scope(),
        "workspace_id": FOUR,
        "resource_selector": ExactObjectSelectorV1(object_id=ZERO, object_version=1),
        "execution_binding": _binding(),
        "owner_assertion_id": ONE,
        "owner_assertion_digest": DIGEST,
        "approval_digest": DIGEST,
        "policy_version": 1,
        "membership_generation": 1,
        "channel_generation": 1,
        "permit_claim_deadline": NOW + timedelta(seconds=60),
        "execution_completion_deadline": NOW + timedelta(seconds=120),
        "max_records": 1,
        "max_bytes": 65_536,
        "nonce": NONCE,
    }
    values.update(changes)
    return SensitiveActionPermitV3.model_validate(values)


def _grant(**changes: object) -> SensitiveExecutionGrantV2:
    values: dict[str, object] = {
        "signing_key_purpose": V13SigningKeyPurpose.POLICY_NOTARY,
        "key_id": "policy-v13-test",
        "issuer": "lucy-policy-v13-test",
        "environment": DeploymentEnvironment.TEST,
        "issued_at": NOW + timedelta(seconds=2),
        "grant_id": ONE,
        "action": SensitiveActionV2.EVIDENCE_RETRIEVE,
        "permit_id": ZERO,
        "permit_digest": DIGEST,
        "operation_id": FOUR,
        "caller_identity": "arn:aws:iam::123456789012:role/utopia-evidence-workflow",
        "target_scope": _scope(),
        "workspace_id": FOUR,
        "resource_selector": ExactObjectSelectorV1(object_id=ZERO, object_version=1),
        "execution_binding": _binding(),
        "encrypted_package_digest": DIGEST,
        "package_size_bytes": 32_768,
        "idempotency_key": "utopia-retrieve-one",
        "executor_identity": "lucy-utopia-evidence-executor-v13",
        "executor_alias_arn": (
            "arn:aws:lambda:us-east-1:123456789012:"
            "function:lucy-utopia-evidence-executor-v13:production"
        ),
        "executor_version": 1,
        "permit_claimed_at": NOW + timedelta(seconds=1),
        "permit_claim_deadline": NOW + timedelta(seconds=60),
        "execution_completion_deadline": NOW + timedelta(seconds=120),
        "max_records": 1,
        "max_bytes": 65_536,
        "nonce": NONCE,
    }
    values.update(changes)
    return SensitiveExecutionGrantV2.model_validate(values)


def test_permit_v3_binds_scope_deadlines_and_key_purpose() -> None:
    permit = _permit()
    assert permit.contract_version == "3"
    assert permit.object_type == "lucy.sensitive-action-permit.v3"
    assert permit.signing_key_purpose == V13SigningKeyPurpose.POLICY_NOTARY
    assert permit.unsigned_digest_hex() == (
        "cbc7438e71f5f8d709759765f87d12e9031698fc17474338451a22cd8c248be6"
    )

    with pytest.raises(ValidationError, match="60 seconds"):
        _permit(permit_claim_deadline=NOW + timedelta(seconds=61))
    with pytest.raises(ValidationError, match="single-record"):
        _permit(max_records=2)
    with pytest.raises(ValidationError, match="literal_error"):
        _permit(signing_key_purpose=V13SigningKeyPurpose.OWNER_BROKER)


def test_historical_scope_mismatch_requires_exact_restore_mapping() -> None:
    foreign_binding = _binding(realm=FOUR, storage_epoch=8)
    with pytest.raises(ValidationError, match="restore mapping"):
        _permit(execution_binding=foreign_binding)
    assert (
        _permit(execution_binding=foreign_binding, restore_mapping_id=ONE).restore_mapping_id == ONE
    )


def test_execution_grant_v2_binds_claim_scope_and_exact_executor() -> None:
    grant = _grant()
    assert grant.object_type == "lucy.sensitive-execution-grant.v2"
    assert grant.operation_id == _permit().operation_id
    assert grant.max_records == 1

    with pytest.raises(ValidationError, match="qualified Lambda"):
        _grant(executor_alias_arn="arn:aws:lambda:us-east-1:123456789012:function:executor")
    with pytest.raises(ValidationError, match="byte ceiling"):
        _grant(package_size_bytes=65_537)
    with pytest.raises(ValidationError, match="admission closed"):
        _grant(issued_at=NOW + timedelta(seconds=70))
    with pytest.raises(ValidationError, match="deletion manifest"):
        _grant(deletion_manifest_id=ONE, deletion_manifest_digest=DIGEST)


def test_deletion_execution_grant_requires_exact_manifest() -> None:
    with pytest.raises(ValidationError, match="deletion manifest"):
        _grant(action=SensitiveActionV2.EVIDENCE_DELETE, max_records=10, max_bytes=131_072)
    deletion = _grant(
        action=SensitiveActionV2.EVIDENCE_DELETE,
        deletion_manifest_id=TWO,
        deletion_manifest_digest=DIGEST,
        max_records=10,
        max_bytes=131_072,
    )
    assert deletion.deletion_manifest_id == TWO


def test_kms_context_has_only_fixed_nonsecret_keys() -> None:
    context = KmsEncryptionContextV2(
        tenant_account_id=ZERO,
        node_id=ONE,
        node_tenure_id=TWO,
        tenure_epoch=1,
        security_realm_id=THREE,
        storage_epoch=7,
        evidence_id=FOUR,
    ).as_aws_context()
    assert set(context) == {
        "contract_version",
        "tenant_account_id",
        "node_id",
        "node_tenure_id",
        "tenure_epoch",
        "security_realm_id",
        "storage_epoch",
        "evidence_id",
        "purpose",
    }
    assert all(isinstance(value, str) for value in context.values())


def test_v13_schemas_and_models_reject_unknown_fields() -> None:
    schemas = security_v1_3_json_schemas()
    assert schemas["SensitiveActionPermitV3"]["additionalProperties"] is False
    assert schemas["SensitiveExecutionGrantV2"]["additionalProperties"] is False
    with pytest.raises(ValidationError, match="extra_forbidden"):
        OriginScopeV1.model_validate({**_scope().model_dump(), "tenant_name": "secret"})


def test_authentication_strength_is_not_inferred_from_identity_name() -> None:
    assert AuthenticationStrength.MFA.value == "mfa"


def test_v13_signature_verification_pins_purpose_and_live_window() -> None:
    private = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519V13Signer(
        private, key_id="policy-v13-test", purpose=V13SigningKeyPurpose.POLICY_NOTARY
    )
    signed = signer.sign(_permit())
    key = V13VerificationKeyV1(
        key_id="policy-v13-test",
        issuer="lucy-policy-v13-test",
        environment=DeploymentEnvironment.TEST,
        purpose=V13SigningKeyPurpose.POLICY_NOTARY,
        public_key_b64=signer.public_key_b64,
        status=V13VerificationKeyStatus.ACTIVE,
        valid_from=NOW - timedelta(days=1),
        issuance_not_after=NOW + timedelta(days=1),
        verify_not_after=NOW + timedelta(days=2),
    )
    verifier = V13ContractVerifier((key,))
    verifier.verify(
        signed,
        expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
        checked_at=NOW + timedelta(seconds=30),
    )
    with pytest.raises(PermissionError, match="purpose"):
        verifier.verify(
            signed,
            expected_purpose=V13SigningKeyPurpose.OWNER_BROKER,
            checked_at=NOW + timedelta(seconds=30),
        )
    with pytest.raises(PermissionError, match="expired"):
        verifier.verify(
            signed,
            expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
            checked_at=NOW + timedelta(seconds=66),
        )

    signed_grant = signer.sign(_grant())
    verifier.verify(
        signed_grant,
        expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
        checked_at=NOW + timedelta(seconds=30),
    )
    with pytest.raises(PermissionError, match="expired"):
        verifier.verify(
            signed_grant,
            expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
            checked_at=NOW + timedelta(seconds=126),
        )
