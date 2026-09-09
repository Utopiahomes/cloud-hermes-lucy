from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from pydantic import ValidationError

from lucy.authorized_deletion_recovery import (
    AuthorizedDeletionRecoveryError,
    verify_authorized_deletion_recovery_v2,
)
from lucy.contracts.security_v1_2 import (
    DeploymentEnvironment,
    ExecutorResult,
    SensitiveActionV2,
)
from lucy.contracts.security_v1_3 import (
    AuthenticationStrength,
    DeletionArtifactClass,
    DeletionDisposition,
    DeletionTargetManifestV2,
    DeletionTargetReferenceV2,
    Ed25519V13Signer,
    EncryptedEvidencePackageV2,
    EvidencePayloadBindingV2,
    EvidenceWrapperBindingV2,
    ExactObjectSelectorV1,
    ExecutionBindingV1,
    ExecutorReceiptV2,
    KmsEncryptionContextV2,
    OriginScopeV1,
    SensitiveActionPermitV3,
    SensitiveExecutionGrantV2,
    V13ContractVerifier,
    V13SigningKeyPurpose,
    V13VerificationKeyStatus,
    V13VerificationKeyV1,
    deletion_targets_digest_v2,
    security_v1_3_json_schemas,
)
from lucy.scoped_deletion import (
    ScopedDeletionManifestResult,
    VerifiedScopedDeletionService,
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
        "service_binding_generation": 1,
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
        "channel_binding_id": TWO,
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


def _receipt(**changes: object) -> ExecutorReceiptV2:
    values: dict[str, object] = {
        "signing_key_purpose": V13SigningKeyPurpose.RETRIEVAL_RECEIPT,
        "key_id": "utopia-retrieval-receipt-v13-test",
        "issuer": "lucy-utopia-retrieval-executor-v13-test",
        "environment": DeploymentEnvironment.TEST,
        "issued_at": NOW + timedelta(seconds=30),
        "receipt_id": TWO,
        "action": SensitiveActionV2.EVIDENCE_RETRIEVE,
        "executor_identity": "lucy-utopia-evidence-executor-v13",
        "executor_alias_arn": (
            "arn:aws:lambda:us-east-1:123456789012:"
            "function:lucy-utopia-evidence-executor-v13:production"
        ),
        "executor_version": 1,
        "caller_identity": "arn:aws:iam::123456789012:role/utopia-evidence-workflow",
        "target_scope": _scope(),
        "execution_binding": _binding(),
        "operation_id": FOUR,
        "permit_id": ZERO,
        "permit_digest": DIGEST,
        "execution_grant_id": ONE,
        "execution_grant_digest": DIGEST,
        "package_digest": DIGEST,
        "result": ExecutorResult.RETRIEVAL_SUCCEEDED,
        "lambda_request_id": "lambda-request-one",
        "kms_request_id": "kms-request-one",
        "execution_completion_deadline": NOW + timedelta(seconds=120),
        "completed_at": NOW + timedelta(seconds=30),
        "record_version": 1,
        "journal_ref": "utopia-retrieval-receipts/operation-four",
        "finality_state": "not_applicable",
    }
    values.update(changes)
    return ExecutorReceiptV2.model_validate(values)


def _package(
    *,
    payload_scope: OriginScopeV1 | None = None,
    wrapping_scope: OriginScopeV1 | None = None,
    migration_receipt_id: UUID | None = None,
) -> EncryptedEvidencePackageV2:
    ciphertext = b"synthetic-ciphertext-and-gcm-tag"
    payload = EvidencePayloadBindingV2(
        evidence_id=ZERO,
        original_scope=payload_scope or _scope(),
        record_version=1,
        ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
        content_nonce_b64=base64.b64encode(b"123456789012").decode("ascii"),
        authenticated_header_b64=base64.b64encode(b"opaque-header").decode("ascii"),
        payload_ciphertext_digest=hashlib.sha256(ciphertext).hexdigest(),
    )
    scope = wrapping_scope or _scope()
    wrapper = EvidenceWrapperBindingV2(
        representation_id=ONE,
        wrapping_scope=scope,
        wrapped_key_ref=TWO,
        encryption_context=KmsEncryptionContextV2(
            tenant_account_id=scope.tenant_account_id,
            node_id=scope.node_id,
            node_tenure_id=scope.node_tenure_id,
            tenure_epoch=scope.tenure_epoch,
            security_realm_id=scope.security_realm_id,
            storage_epoch=scope.storage_epoch,
            evidence_id=ZERO,
        ),
        payload_ciphertext_digest=payload.payload_ciphertext_digest,
        migration_receipt_id=migration_receipt_id,
    )
    return EncryptedEvidencePackageV2(
        operation_id=FOUR,
        permit_id=ZERO,
        payload_binding=payload,
        wrapper_binding=wrapper,
        content_classification="owner_conversation",
        lineage_refs=(THREE,),
    )


def _deletion_targets() -> tuple[DeletionTargetReferenceV2, ...]:
    return (
        DeletionTargetReferenceV2(
            artifact_class=DeletionArtifactClass.ENCRYPTED_ARCHIVE,
            artifact_id=ZERO,
            artifact_version=1,
            root_evidence_id=ZERO,
            disposition=DeletionDisposition.DESTROY_WRAPPED_KEY,
            representation_id=ONE,
            wrapped_key_ref=TWO,
        ),
        DeletionTargetReferenceV2(
            artifact_class=DeletionArtifactClass.MEMORY_CLAIM,
            artifact_id=THREE,
            artifact_version=1,
            root_evidence_id=ZERO,
            disposition=DeletionDisposition.INVALIDATE,
        ),
    )


def _deletion_manifest(**changes: object) -> DeletionTargetManifestV2:
    targets = _deletion_targets()
    values: dict[str, object] = {
        "signing_key_purpose": V13SigningKeyPurpose.POLICY_NOTARY,
        "key_id": "policy-v13-test",
        "issuer": "lucy-policy-v13-test",
        "environment": DeploymentEnvironment.TEST,
        "issued_at": NOW,
        "manifest_id": TWO,
        "permit_id": ONE,
        "permit_digest": DIGEST,
        "operation_id": FOUR,
        "target_scope": _scope(),
        "workspace_id": FOUR,
        "root_evidence_id": ZERO,
        "root_representation_id": ONE,
        "owner_assertion_id": ONE,
        "owner_assertion_digest": DIGEST,
        "idempotency_key": "delete-root-zero",
        "closure_version": 1,
        "targets": targets,
        "target_count": len(targets),
        "targets_digest": deletion_targets_digest_v2(targets),
        "tombstone_policy_version": 1,
        "finality_policy_version": 1,
        "permit_claim_deadline": NOW + timedelta(seconds=60),
        "execution_completion_deadline": NOW + timedelta(seconds=120),
        "nonce": NONCE,
    }
    values.update(changes)
    return DeletionTargetManifestV2.model_validate(values)


def test_permit_v3_binds_scope_deadlines_and_key_purpose() -> None:
    permit = _permit()
    assert permit.contract_version == "3"
    assert permit.object_type == "lucy.sensitive-action-permit.v3"
    assert permit.signing_key_purpose == V13SigningKeyPurpose.POLICY_NOTARY
    assert permit.channel_binding_id == TWO

    with pytest.raises(ValidationError, match="60 seconds"):
        _permit(permit_claim_deadline=NOW + timedelta(seconds=61))
    with pytest.raises(ValidationError, match="single-record"):
        _permit(max_records=2)
    with pytest.raises(ValidationError, match="literal_error"):
        _permit(signing_key_purpose=V13SigningKeyPurpose.OWNER_BROKER)
    with pytest.raises(ValidationError, match="deletion reason"):
        _permit(reason="owner_request")


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


def test_executor_receipt_v2_pins_scope_action_fields_and_ecdsa_key() -> None:
    receipt = _receipt()
    assert receipt.signature_algorithm.value == "ECDSA_SHA_256"
    with pytest.raises(ValidationError, match="action-specific"):
        _receipt(transaction_client_token="wrong-for-retrieval")
    with pytest.raises(ValidationError, match="wrong signing-key purpose"):
        _receipt(signing_key_purpose=V13SigningKeyPurpose.DELETION_RECEIPT)
    with pytest.raises(ValidationError, match="execution scope"):
        _receipt(execution_binding=_binding(realm=FOUR))

    private = ec.generate_private_key(ec.SECP256R1())
    signature = private.sign(
        bytes.fromhex(receipt.unsigned_digest_hex()),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    signed = receipt.model_copy(update={"signature": base64.b64encode(signature).decode("ascii")})
    public_der = private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key = V13VerificationKeyV1(
        key_id=receipt.key_id,
        issuer=receipt.issuer,
        environment=DeploymentEnvironment.TEST,
        purpose=V13SigningKeyPurpose.RETRIEVAL_RECEIPT,
        algorithm=receipt.signature_algorithm,
        public_key_b64=base64.b64encode(public_der).decode("ascii"),
        status=V13VerificationKeyStatus.ACTIVE,
        valid_from=NOW - timedelta(days=1),
        issuance_not_after=NOW + timedelta(days=1),
        verify_not_after=NOW + timedelta(days=2),
    )
    V13ContractVerifier((key,)).verify(
        signed,
        expected_purpose=V13SigningKeyPurpose.RETRIEVAL_RECEIPT,
        checked_at=NOW + timedelta(seconds=31),
    )
    V13ContractVerifier((key,)).verify(
        signed,
        expected_purpose=V13SigningKeyPurpose.RETRIEVAL_RECEIPT,
        checked_at=NOW + timedelta(seconds=130),
    )


def test_rejected_deletion_receipt_cannot_claim_operational_deletion() -> None:
    values = {
        **_receipt().model_dump(mode="python"),
        "signing_key_purpose": V13SigningKeyPurpose.DELETION_RECEIPT,
        "action": SensitiveActionV2.EVIDENCE_DELETE,
        "deletion_manifest_id": TWO,
        "deletion_manifest_digest": DIGEST,
        "kms_request_id": None,
        "transaction_client_token": "deletion-transaction-one",
        "result": ExecutorResult.REJECTED,
        "finality_state": "not_applicable",
    }
    rejected = ExecutorReceiptV2.model_validate(values)
    assert rejected.finality_state == "not_applicable"
    with pytest.raises(ValidationError, match="contradicts"):
        ExecutorReceiptV2.model_validate(
            {**values, "finality_state": "operationally_deleted"}
        )


def test_encrypted_package_v2_separates_payload_and_wrapper_scope() -> None:
    package = _package()
    assert package.payload_binding.original_scope == package.wrapper_binding.wrapping_scope
    assert len(package.package_digest_hex()) == 64

    moved_scope = _scope(realm=FOUR, storage_epoch=8)
    with pytest.raises(ValidationError, match="migration receipt"):
        _package(wrapping_scope=moved_scope)
    moved = _package(wrapping_scope=moved_scope, migration_receipt_id=FOUR)
    assert moved.payload_binding.original_scope != moved.wrapper_binding.wrapping_scope


def test_encrypted_package_v2_rejects_ciphertext_or_context_mismatch() -> None:
    package = _package()
    payload = package.payload_binding
    with pytest.raises(ValidationError, match="ciphertext digest"):
        EvidencePayloadBindingV2.model_validate(
            {**payload.model_dump(mode="python"), "payload_ciphertext_digest": "2" * 64}
        )
    wrapper = package.wrapper_binding
    with pytest.raises(ValidationError, match="wrapping scope"):
        EvidenceWrapperBindingV2.model_validate(
            {
                **wrapper.model_dump(mode="python"),
                "wrapping_scope": _scope(realm=FOUR),
            }
        )


def test_deletion_manifest_v2_freezes_exact_archive_and_derived_closure() -> None:
    manifest = _deletion_manifest()
    assert manifest.target_count == 2
    assert manifest.targets[0].wrapped_key_ref == TWO
    with pytest.raises(ValidationError, match="target digest"):
        _deletion_manifest(targets_digest="2" * 64)
    with pytest.raises(ValidationError, match="canonical order"):
        reversed_targets = tuple(reversed(_deletion_targets()))
        _deletion_manifest(
            targets=reversed_targets,
            targets_digest=deletion_targets_digest_v2(reversed_targets),
        )


def test_deletion_target_separates_archive_key_authority_from_derived_cleanup() -> None:
    with pytest.raises(ValidationError, match="archive deletion target"):
        DeletionTargetReferenceV2(
            artifact_class=DeletionArtifactClass.ENCRYPTED_ARCHIVE,
            artifact_id=ZERO,
            artifact_version=1,
            root_evidence_id=ZERO,
            disposition=DeletionDisposition.DELETE,
        )
    with pytest.raises(ValidationError, match="archive key authority"):
        DeletionTargetReferenceV2(
            artifact_class=DeletionArtifactClass.MEMORY_CLAIM,
            artifact_id=THREE,
            artifact_version=1,
            root_evidence_id=ZERO,
            disposition=DeletionDisposition.DESTROY_WRAPPED_KEY,
            representation_id=ONE,
            wrapped_key_ref=TWO,
        )


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
    assert schemas["ExecutorReceiptV2"]["additionalProperties"] is False
    assert schemas["EncryptedEvidencePackageV2"]["additionalProperties"] is False
    assert schemas["DeletionTargetManifestV2"]["additionalProperties"] is False
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


def test_v13_historical_deletion_recovery_binds_complete_scoped_chain() -> None:
    policy_private = ed25519.Ed25519PrivateKey.generate()
    policy_signer = Ed25519V13Signer(
        policy_private,
        key_id="policy-v13-test",
        purpose=V13SigningKeyPurpose.POLICY_NOTARY,
    )
    permit = policy_signer.sign(
        _permit(
            permit_id=ONE,
            action=SensitiveActionV2.EVIDENCE_DELETE,
            reason="owner_request",
            max_records=2,
        )
    )
    manifest = policy_signer.sign(
        _deletion_manifest(
            permit_id=permit.permit_id,
            permit_digest=permit.unsigned_digest_hex(),
            owner_assertion_id=permit.owner_assertion_id,
            owner_assertion_digest=permit.owner_assertion_digest,
        )
    )
    caller = "arn:aws:iam::123456789012:role/utopia-deletion-workflow"
    executor = "lucy-utopia-deletion-executor-v13"
    alias = (
        "arn:aws:lambda:us-east-1:123456789012:"
        "function:lucy-utopia-deletion-executor-v13:production"
    )
    grant = policy_signer.sign(
        _grant(
            action=SensitiveActionV2.EVIDENCE_DELETE,
            permit_id=permit.permit_id,
            permit_digest=permit.unsigned_digest_hex(),
            caller_identity=caller,
            deletion_manifest_id=manifest.manifest_id,
            deletion_manifest_digest=manifest.unsigned_digest_hex(),
            encrypted_package_digest=manifest.unsigned_digest_hex(),
            package_size_bytes=len(manifest.canonical_unsigned_bytes()),
            idempotency_key=manifest.idempotency_key,
            executor_identity=executor,
            executor_alias_arn=alias,
            max_records=permit.max_records,
        )
    )
    receipt_private = ec.generate_private_key(ec.SECP256R1())
    unsigned_receipt = _receipt(
        signing_key_purpose=V13SigningKeyPurpose.DELETION_RECEIPT,
        key_id="utopia-deletion-receipt-v13-test",
        issuer="lucy-utopia-deletion-executor-v13-test",
        action=SensitiveActionV2.EVIDENCE_DELETE,
        caller_identity=caller,
        executor_identity=executor,
        executor_alias_arn=alias,
        permit_id=permit.permit_id,
        permit_digest=permit.unsigned_digest_hex(),
        execution_grant_id=grant.grant_id,
        execution_grant_digest=grant.unsigned_digest_hex(),
        deletion_manifest_id=manifest.manifest_id,
        deletion_manifest_digest=manifest.unsigned_digest_hex(),
        package_digest=manifest.unsigned_digest_hex(),
        result=ExecutorResult.DELETION_SUCCEEDED,
        kms_request_id=None,
        transaction_client_token="delete-operation-four",
        journal_ref="utopia-deletion-receipts/operation-four",
        finality_state="operationally_deleted",
    )
    receipt_signature = receipt_private.sign(
        bytes.fromhex(unsigned_receipt.unsigned_digest_hex()),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    receipt = unsigned_receipt.model_copy(
        update={"signature": base64.b64encode(receipt_signature).decode("ascii")}
    )
    policy_key = V13VerificationKeyV1(
        key_id=permit.key_id,
        issuer=permit.issuer,
        environment=DeploymentEnvironment.TEST,
        purpose=V13SigningKeyPurpose.POLICY_NOTARY,
        public_key_b64=policy_signer.public_key_b64,
        status=V13VerificationKeyStatus.RETIRED,
        valid_from=NOW - timedelta(days=1),
        issuance_not_after=NOW + timedelta(days=1),
        verify_not_after=NOW + timedelta(days=2),
    )
    receipt_public_der = receipt_private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    receipt_key = V13VerificationKeyV1(
        key_id=receipt.key_id,
        issuer=receipt.issuer,
        environment=DeploymentEnvironment.TEST,
        purpose=V13SigningKeyPurpose.DELETION_RECEIPT,
        algorithm=receipt.signature_algorithm,
        public_key_b64=base64.b64encode(receipt_public_der).decode("ascii"),
        status=V13VerificationKeyStatus.RETIRED,
        valid_from=NOW - timedelta(days=1),
        issuance_not_after=NOW + timedelta(days=1),
        verify_not_after=NOW + timedelta(days=2),
    )
    proof = verify_authorized_deletion_recovery_v2(
        permit=permit,
        manifest=manifest,
        grant=grant,
        receipt=receipt,
        policy_verifier=V13ContractVerifier((policy_key,)),
        receipt_verifier=V13ContractVerifier((receipt_key,)),
        environment=DeploymentEnvironment.TEST,
        caller_identity=caller,
        executor_identity=executor,
        executor_alias_arn=alias,
        executor_version=1,
        receipt_key_id=receipt.key_id,
        checked_at=NOW + timedelta(days=90),
    )
    assert proof.operation_id == str(permit.operation_id)
    assert proof.target_count == 2
    assert len(proof.scope_digest) == len(proof.recovery_digest) == 64

    wrong_grant = policy_signer.sign(
        grant.model_copy(update={"caller_identity": f"{caller}-wrong", "signature": ""})
    )
    with pytest.raises(AuthorizedDeletionRecoveryError, match="receipt binding"):
        verify_authorized_deletion_recovery_v2(
            permit=permit,
            manifest=manifest,
            grant=wrong_grant,
            receipt=receipt,
            policy_verifier=V13ContractVerifier((policy_key,)),
            receipt_verifier=V13ContractVerifier((receipt_key,)),
            environment=DeploymentEnvironment.TEST,
            caller_identity=caller,
            executor_identity=executor,
            executor_alias_arn=alias,
            executor_version=1,
            receipt_key_id=receipt.key_id,
            checked_at=NOW + timedelta(days=90),
        )
    with pytest.raises(AuthorizedDeletionRecoveryError, match="historical v1.3"):
        verify_authorized_deletion_recovery_v2(
            permit=permit,
            manifest=manifest,
            grant=grant,
            receipt=receipt,
            policy_verifier=V13ContractVerifier(
                (policy_key.model_copy(update={"status": V13VerificationKeyStatus.REVOKED}),)
            ),
            receipt_verifier=V13ContractVerifier((receipt_key,)),
            environment=DeploymentEnvironment.TEST,
            caller_identity=caller,
            executor_identity=executor,
            executor_alias_arn=alias,
            executor_version=1,
            receipt_key_id=receipt.key_id,
            checked_at=NOW + timedelta(days=90),
        )


def test_scoped_deletion_verifies_signature_before_database_effect() -> None:
    private = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519V13Signer(
        private, key_id="policy-v13-test", purpose=V13SigningKeyPurpose.POLICY_NOTARY
    )
    manifest = signer.sign(_deletion_manifest())
    verifier = V13ContractVerifier(
        (
            V13VerificationKeyV1(
                key_id="policy-v13-test",
                issuer="lucy-policy-v13-test",
                environment=DeploymentEnvironment.TEST,
                purpose=V13SigningKeyPurpose.POLICY_NOTARY,
                public_key_b64=signer.public_key_b64,
                status=V13VerificationKeyStatus.ACTIVE,
                valid_from=NOW - timedelta(days=1),
                issuance_not_after=NOW + timedelta(days=1),
                verify_not_after=NOW + timedelta(days=2),
            ),
        )
    )
    stored: list[DeletionTargetManifestV2] = []

    class Store:
        def store(
            self, candidate: DeletionTargetManifestV2
        ) -> ScopedDeletionManifestResult:
            stored.append(candidate)
            return ScopedDeletionManifestResult(
                manifest_id=candidate.manifest_id,
                manifest_digest=candidate.unsigned_digest_hex(),
                targets_digest=candidate.targets_digest,
                target_count=candidate.target_count,
                replayed=False,
            )

    service = VerifiedScopedDeletionService(
        Store(), policy_verifier=verifier, clock=lambda: NOW + timedelta(seconds=30)
    )
    assert service.freeze(manifest).manifest_id == manifest.manifest_id
    assert stored == [manifest]
    tampered = manifest.model_copy(update={"signature": base64.b64encode(b"bad").decode()})
    with pytest.raises(PermissionError, match="signature"):
        service.freeze(tampered)
    assert stored == [manifest]
