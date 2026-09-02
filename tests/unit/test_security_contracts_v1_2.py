from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from pydantic import ValidationError

from lucy.authorization import SensitiveAction, SensitiveActionPermitV1
from lucy.contracts.security_v1_2 import (
    ContractTrustStore,
    DeletionFinalityRecordV1,
    DeletionOperationState,
    DeletionTargetManifestV1,
    DeletionTargetReferenceV1,
    DeploymentEnvironment,
    Ed25519ContractSigner,
    EncryptedEvidencePackageV1,
    ExecutorQuotaV1,
    ExecutorReceiptV1,
    ExecutorResult,
    FinalityStatus,
    KmsEncryptionContextV1,
    OwnerAuthenticationMethod,
    OwnerInteractionAssertionV1,
    OwnerInteractionChannel,
    RetrievalOperationState,
    SensitiveActionPermitV2,
    SensitiveActionV2,
    SensitiveExecutionGrantV1,
    SensitiveReasonCode,
    SignatureAlgorithm,
    SigningKeyPurpose,
    VerificationKeyStatus,
    VerificationKeyV1,
    VerificationMode,
    deletion_targets_digest,
    ecdsa_public_key_der_b64,
    require_deletion_transition,
    require_retrieval_transition,
)

NOW = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
ROOT_EVIDENCE_ID = UUID("11111111-1111-4111-8111-111111111111")
DERIVED_EVIDENCE_ID = UUID("22222222-2222-4222-8222-222222222222")
ASSERTION_ID = UUID("33333333-3333-4333-8333-333333333333")
PERMIT_ID = UUID("44444444-4444-4444-8444-444444444444")
MANIFEST_ID = UUID("55555555-5555-4555-8555-555555555555")
OPERATION_ID = UUID("66666666-6666-4666-8666-666666666666")
GRANT_ID = UUID("77777777-7777-4777-8777-777777777777")
RECEIPT_ID = UUID("88888888-8888-4888-8888-888888888888")
POLICY_KEY_ID = "policy-notary.test.2026-09"
RECEIPT_KEY_ID = "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
POLICY_ALIAS_ARN = (
    "arn:aws:lambda:us-east-1:123456789012:function:lucy-evidence-executor:production"
)
DELETION_ALIAS_ARN = (
    "arn:aws:lambda:us-east-1:123456789012:function:lucy-deletion-executor:production"
)
VECTOR_PATH = Path(__file__).parents[1] / "fixtures" / "security-contract-v1.2-vectors.json"


def _policy_signer() -> Ed25519ContractSigner:
    return Ed25519ContractSigner(
        ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
        key_id=POLICY_KEY_ID,
    )


def _verification_key(
    signer: Ed25519ContractSigner,
    *,
    status: VerificationKeyStatus = VerificationKeyStatus.ACTIVE,
    environment: DeploymentEnvironment = DeploymentEnvironment.TEST,
) -> VerificationKeyV1:
    return VerificationKeyV1(
        key_id=POLICY_KEY_ID,
        issuer="lucy-policy.test",
        purpose=SigningKeyPurpose.POLICY_NOTARY,
        algorithm=SignatureAlgorithm.ED25519,
        environment=environment,
        public_key_b64=signer.public_key_b64,
        valid_from=NOW - timedelta(hours=1),
        issuance_not_after=NOW + timedelta(hours=1),
        verify_not_after=NOW + timedelta(hours=2),
        status=status,
    )


def _unsigned_permit(**changes: object) -> SensitiveActionPermitV2:
    values: dict[str, object] = {
        "key_id": POLICY_KEY_ID,
        "issuer": "lucy-policy.test",
        "environment": DeploymentEnvironment.TEST,
        "issued_at": NOW,
        "storage_epoch": 1,
        "registry_epoch": 1,
        "key_epoch": 1,
        "permit_id": PERMIT_ID,
        "action": SensitiveActionV2.EVIDENCE_RETRIEVE,
        "owner_subject": "owner:forti",
        "owner_assertion_id": ASSERTION_ID,
        "owner_assertion_digest": "a" * 64,
        "evidence_id": ROOT_EVIDENCE_ID,
        "reason": SensitiveReasonCode.RESOLVE_AMBIGUITY,
        "max_records": 1,
        "max_bytes": 4096,
        "record_version": 3,
        "permit_claim_deadline": NOW + timedelta(minutes=5),
        "nonce": "permit-nonce-0000000000000000000000000001",
        "signature": "",
    }
    values.update(changes)
    return SensitiveActionPermitV2.model_validate(values)


def _targets() -> tuple[DeletionTargetReferenceV1, ...]:
    return (
        DeletionTargetReferenceV1(
            evidence_id=ROOT_EVIDENCE_ID,
            key_ref=UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            record_version=3,
            key_epoch=1,
        ),
        DeletionTargetReferenceV1(
            evidence_id=DERIVED_EVIDENCE_ID,
            key_ref=UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            record_version=1,
            key_epoch=1,
        ),
    )


def _unsigned_manifest(**changes: object) -> DeletionTargetManifestV1:
    targets = _targets()
    values: dict[str, object] = {
        "key_id": POLICY_KEY_ID,
        "issuer": "lucy-policy.test",
        "environment": DeploymentEnvironment.TEST,
        "issued_at": NOW,
        "storage_epoch": 1,
        "registry_epoch": 1,
        "key_epoch": 1,
        "manifest_id": MANIFEST_ID,
        "permit_id": PERMIT_ID,
        "permit_nonce": "permit-nonce-0000000000000000000000000001",
        "root_evidence_id": ROOT_EVIDENCE_ID,
        "owner_assertion_id": ASSERTION_ID,
        "owner_assertion_digest": "a" * 64,
        "idempotency_key": "delete-operation-1",
        "scope_version": 7,
        "root_record_version": 3,
        "targets": targets,
        "target_count": len(targets),
        "targets_digest": deletion_targets_digest(targets),
        "permit_claim_deadline": NOW + timedelta(minutes=5),
        "execution_deadline": NOW + timedelta(minutes=10),
        "signature": "",
    }
    values.update(changes)
    return DeletionTargetManifestV1.model_validate(values)


def _unsigned_grant(
    action: SensitiveActionV2 = SensitiveActionV2.EVIDENCE_RETRIEVE,
    **changes: object,
) -> SensitiveExecutionGrantV1:
    values: dict[str, object] = {
        "key_id": POLICY_KEY_ID,
        "issuer": "lucy-policy.test",
        "environment": DeploymentEnvironment.TEST,
        "issued_at": NOW + timedelta(minutes=1),
        "storage_epoch": 1,
        "registry_epoch": 1,
        "key_epoch": 1,
        "grant_id": GRANT_ID,
        "action": action,
        "permit_id": PERMIT_ID,
        "permit_nonce": "permit-nonce-0000000000000000000000000001",
        "operation_id": OPERATION_ID,
        "database_session_user": "lucy_evidence_workflow",
        "evidence_id": ROOT_EVIDENCE_ID,
        "deletion_manifest_id": None,
        "deletion_manifest_digest": None,
        "encrypted_package_digest": "b" * 64,
        "package_size_bytes": 4096,
        "idempotency_key": "retrieve-operation-1",
        "record_version": 3,
        "executor_identity": "lucy-evidence-executor",
        "executor_alias_arn": POLICY_ALIAS_ARN,
        "executor_version": 12,
        "permit_claim_deadline": NOW + timedelta(minutes=5),
        "execution_deadline": NOW + timedelta(minutes=10),
        "signature": "",
    }
    if action == SensitiveActionV2.EVIDENCE_DELETE:
        values.update(
            {
                "database_session_user": "lucy_deletion_workflow",
                "deletion_manifest_id": MANIFEST_ID,
                "deletion_manifest_digest": "c" * 64,
                "idempotency_key": "delete-operation-1",
                "executor_identity": "lucy-deletion-executor",
                "executor_alias_arn": DELETION_ALIAS_ARN,
            }
        )
    values.update(changes)
    return SensitiveExecutionGrantV1.model_validate(values)


def test_policy_signature_binds_domain_and_every_permit_field() -> None:
    signer = _policy_signer()
    permit = signer.sign(_unsigned_permit())
    trust = ContractTrustStore((_verification_key(signer),))
    trust.verify(
        permit,
        purpose=SigningKeyPurpose.POLICY_NOTARY,
        environment=DeploymentEnvironment.TEST,
        now=NOW + timedelta(minutes=1),
    )

    tampered = permit.model_copy(update={"max_bytes": permit.max_bytes + 1})
    with pytest.raises(PermissionError, match="signature"):
        trust.verify(
            tampered,
            purpose=SigningKeyPurpose.POLICY_NOTARY,
            environment=DeploymentEnvironment.TEST,
            now=NOW + timedelta(minutes=1),
        )


def test_cross_language_ed25519_contract_vector_is_stable() -> None:
    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    contract = SensitiveActionPermitV2.model_validate(vector["contract"])
    assert base64.b64encode(contract.canonical_unsigned_bytes()).decode() == vector[
        "canonical_unsigned_b64"
    ]
    assert contract.unsigned_digest_hex() == vector["unsigned_sha256"]
    assert contract.signature == vector["signature_b64"]

    seed = base64.b64decode(vector["private_key_seed_b64"], validate=True)
    signer = Ed25519ContractSigner(
        ed25519.Ed25519PrivateKey.from_private_bytes(seed), key_id=contract.key_id
    )
    assert signer.public_key_b64 == vector["public_key_b64"]
    recreated = signer.sign(contract.model_copy(update={"signature": ""}))
    assert recreated.signature == vector["signature_b64"]


def test_v1_permit_cannot_be_parsed_as_v2() -> None:
    old = SensitiveActionPermitV1(
        permit_id=PERMIT_ID,
        action=SensitiveAction.EVIDENCE_RETRIEVE,
        owner_subject="owner:forti",
        owner_interaction_id="telegram:one",
        evidence_ids=(ROOT_EVIDENCE_ID,),
        reason="resolve_ambiguity",
        max_records=1,
        max_bytes=4096,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce="n" * 32,
        signature="unused",
    )
    with pytest.raises(ValidationError):
        SensitiveActionPermitV2.model_validate(old.model_dump(mode="json"))


def test_owner_assertion_rejects_stale_interaction_and_unknown_fields() -> None:
    values = {
        "key_id": "owner-broker.test.1",
        "issuer": "owner-broker.test",
        "environment": DeploymentEnvironment.TEST,
        "issued_at": NOW,
        "storage_epoch": 1,
        "registry_epoch": 1,
        "key_epoch": 1,
        "assertion_id": ASSERTION_ID,
        "broker_identity": "owner-broker.test",
        "channel": OwnerInteractionChannel.SYNTHETIC_ACCEPTANCE,
        "owner_subject": "owner:forti",
        "source_interaction_id": "interaction-1",
        "source_message_id": "message-1",
        "requested_action": SensitiveActionV2.EVIDENCE_RETRIEVE,
        "evidence_id": ROOT_EVIDENCE_ID,
        "authentication_method": OwnerAuthenticationMethod.SYNTHETIC_ACCEPTANCE,
        "interaction_created_at": NOW - timedelta(minutes=6),
        "max_age_seconds": 300,
        "expires_at": NOW + timedelta(seconds=1),
        "nonce": "assertion-nonce-00000000000000001",
        "anti_replay_id": "owner-event-1",
        "signature": "",
        "unexpected": True,
    }
    with pytest.raises(ValidationError):
        OwnerInteractionAssertionV1.model_validate(values)
    values.pop("unexpected")
    with pytest.raises(ValidationError, match="too old"):
        OwnerInteractionAssertionV1.model_validate(values)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"permit_claim_deadline": NOW + timedelta(seconds=301)}, "maximum"),
        ({"reason": SensitiveReasonCode.OWNER_REQUEST}, "deletion reason"),
        ({"max_records": 2}, "single-record"),
        ({"max_bytes": 65_537}, "single-record"),
    ],
)
def test_retrieval_permit_fails_closed_on_invalid_scope(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        _unsigned_permit(**changes)


def test_deletion_manifest_binds_canonical_unique_scope() -> None:
    manifest = _unsigned_manifest()
    assert manifest.target_count == 2
    assert manifest.targets_digest == deletion_targets_digest(manifest.targets)

    with pytest.raises(ValidationError, match="canonical"):
        _unsigned_manifest(targets=tuple(reversed(_targets())))
    duplicate = (_targets()[0], _targets()[0])
    with pytest.raises(ValidationError, match="duplicate"):
        _unsigned_manifest(
            targets=duplicate,
            target_count=2,
            targets_digest=deletion_targets_digest(duplicate),
        )


def test_encrypted_package_binds_exact_kms_context_and_size() -> None:
    context = KmsEncryptionContextV1(
        environment=DeploymentEnvironment.TEST,
        evidence_id=ROOT_EVIDENCE_ID,
        storage_epoch=1,
        registry_epoch=1,
        key_epoch=1,
        record_version=3,
    )
    package = EncryptedEvidencePackageV1(
        operation_id=OPERATION_ID,
        permit_id=PERMIT_ID,
        evidence_id=ROOT_EVIDENCE_ID,
        key_ref=UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        ciphertext_b64=base64.b64encode(b"ciphertext-with-gcm-tag").decode(),
        content_nonce_b64=base64.b64encode(b"n" * 12).decode(),
        aad_b64=base64.b64encode(b'{"source":"synthetic"}').decode(),
        encryption_context=context,
        record_version=3,
        storage_epoch=1,
        registry_epoch=1,
        key_epoch=1,
    )
    assert package.package_digest_hex() == package.package_digest_hex()
    assert set(context.as_aws_context()) == {
        "application",
        "environment",
        "evidence-id",
        "storage-epoch",
        "registry-epoch",
        "key-epoch",
        "record-version",
    }
    with pytest.raises(ValidationError, match="context"):
        EncryptedEvidencePackageV1.model_validate(
            {**package.model_dump(mode="python"), "record_version": 4}
        )


def test_execution_grant_requires_exact_alias_and_action_bindings() -> None:
    _unsigned_grant()
    _unsigned_grant(SensitiveActionV2.EVIDENCE_DELETE)
    with pytest.raises(ValidationError, match="qualified"):
        _unsigned_grant(executor_alias_arn=POLICY_ALIAS_ARN.rsplit(":", 1)[0])
    with pytest.raises(ValidationError, match="deletion manifest"):
        _unsigned_grant(SensitiveActionV2.EVIDENCE_DELETE, deletion_manifest_digest=None)


def test_kms_style_ecdsa_receipt_signature_and_action_fields() -> None:
    private_key = ec.derive_private_key(1, ec.SECP256R1())
    receipt = ExecutorReceiptV1(
        key_id=RECEIPT_KEY_ID,
        issuer="lucy-evidence-executor",
        environment=DeploymentEnvironment.TEST,
        issued_at=NOW + timedelta(minutes=2),
        storage_epoch=1,
        registry_epoch=1,
        key_epoch=1,
        receipt_id=RECEIPT_ID,
        action=SensitiveActionV2.EVIDENCE_RETRIEVE,
        executor_identity="lucy-evidence-executor",
        executor_alias_arn=POLICY_ALIAS_ARN,
        executor_version=12,
        operation_id=OPERATION_ID,
        permit_id=PERMIT_ID,
        execution_grant_id=GRANT_ID,
        package_digest="b" * 64,
        result=ExecutorResult.RETRIEVAL_SUCCEEDED,
        lambda_request_id="lambda-request-1",
        kms_request_id="kms-request-1",
        execution_deadline=NOW + timedelta(minutes=10),
        completed_at=NOW + timedelta(minutes=2),
        record_version=3,
        signature="",
    )
    digest = bytes.fromhex(receipt.unsigned_digest_hex())
    signature = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    signed = receipt.model_copy(update={"signature": base64.b64encode(signature).decode()})
    key = VerificationKeyV1(
        key_id=RECEIPT_KEY_ID,
        issuer="lucy-evidence-executor",
        purpose=SigningKeyPurpose.RETRIEVAL_RECEIPT,
        algorithm=SignatureAlgorithm.ECDSA_SHA_256,
        environment=DeploymentEnvironment.TEST,
        public_key_b64=ecdsa_public_key_der_b64(private_key.public_key()),
        valid_from=NOW - timedelta(hours=1),
        issuance_not_after=NOW + timedelta(hours=1),
        verify_not_after=NOW + timedelta(hours=2),
        status=VerificationKeyStatus.ACTIVE,
    )
    ContractTrustStore((key,)).verify(
        signed,
        purpose=SigningKeyPurpose.RETRIEVAL_RECEIPT,
        environment=DeploymentEnvironment.TEST,
        now=NOW + timedelta(minutes=3),
    )

    with pytest.raises(ValidationError, match="deletion-only"):
        ExecutorReceiptV1.model_validate(
            {**receipt.model_dump(mode="python"), "transaction_client_token": "not-allowed"}
        )


def test_key_rotation_revocation_and_environment_separation() -> None:
    signer = _policy_signer()
    permit = signer.sign(_unsigned_permit())
    retired = ContractTrustStore(
        (_verification_key(signer, status=VerificationKeyStatus.RETIRED),)
    )
    with pytest.raises(PermissionError, match="retired"):
        retired.verify(
            permit,
            purpose=SigningKeyPurpose.POLICY_NOTARY,
            environment=DeploymentEnvironment.TEST,
            now=NOW + timedelta(minutes=1),
        )
    retired.verify(
        permit,
        purpose=SigningKeyPurpose.POLICY_NOTARY,
        environment=DeploymentEnvironment.TEST,
        now=NOW + timedelta(days=30),
        mode=VerificationMode.HISTORICAL_AUDIT,
    )

    revoked = ContractTrustStore(
        (_verification_key(signer, status=VerificationKeyStatus.REVOKED),)
    )
    with pytest.raises(PermissionError, match="revoked"):
        revoked.verify(
            permit,
            purpose=SigningKeyPurpose.POLICY_NOTARY,
            environment=DeploymentEnvironment.TEST,
            mode=VerificationMode.HISTORICAL_AUDIT,
        )
    production = ContractTrustStore(
        (_verification_key(signer, environment=DeploymentEnvironment.PRODUCTION),)
    )
    with pytest.raises(PermissionError, match="environment"):
        production.verify(
            permit,
            purpose=SigningKeyPurpose.POLICY_NOTARY,
            environment=DeploymentEnvironment.TEST,
        )


def test_live_verification_rejects_expired_contract() -> None:
    signer = _policy_signer()
    permit = signer.sign(_unsigned_permit())
    with pytest.raises(PermissionError, match="deadline"):
        ContractTrustStore((_verification_key(signer),)).verify(
            permit,
            purpose=SigningKeyPurpose.POLICY_NOTARY,
            environment=DeploymentEnvironment.TEST,
            now=NOW + timedelta(minutes=6),
        )


def test_state_transitions_are_monotonic_and_retry_is_explicit() -> None:
    require_retrieval_transition(
        RetrievalOperationState.EXECUTING, RetrievalOperationState.EXECUTOR_RECEIPTED
    )
    require_retrieval_transition(
        RetrievalOperationState.FAILED_RETRYABLE, RetrievalOperationState.EXECUTING
    )
    require_deletion_transition(
        DeletionOperationState.EXECUTOR_RECEIPTED, DeletionOperationState.EFFECTIVE
    )
    with pytest.raises(ValueError, match="invalid retrieval"):
        require_retrieval_transition(
            RetrievalOperationState.DELIVERY_UNKNOWN, RetrievalOperationState.EXECUTING
        )
    with pytest.raises(ValueError, match="invalid deletion"):
        require_deletion_transition(
            DeletionOperationState.FINALITY_VERIFIED, DeletionOperationState.EFFECTIVE
        )


def test_finality_requires_actual_absence_after_lower_bound() -> None:
    base = {
        "operation_id": OPERATION_ID,
        "deletion_effective_at": NOW,
        "finality_not_before": NOW + timedelta(days=30),
        "finality_verified_at": NOW + timedelta(days=31),
        "finality_status": FinalityStatus.VERIFIED,
        "metadata_observed_at": NOW + timedelta(days=31),
        "recoverable_copy_count": 0,
        "metadata_inventory_digest": "d" * 64,
    }
    DeletionFinalityRecordV1.model_validate(base)
    with pytest.raises(ValidationError, match="recoverable copy"):
        DeletionFinalityRecordV1.model_validate({**base, "recoverable_copy_count": 1})
    with pytest.raises(ValidationError, match="before"):
        DeletionFinalityRecordV1.model_validate(
            {**base, "finality_verified_at": NOW + timedelta(days=29)}
        )


def test_phase1_quota_contract_matches_approved_hard_limits() -> None:
    retrieval = ExecutorQuotaV1.phase1(SensitiveActionV2.EVIDENCE_RETRIEVE)
    deletion = ExecutorQuotaV1.phase1(SensitiveActionV2.EVIDENCE_DELETE)
    assert (retrieval.max_plaintext_bytes, retrieval.configured_timeout_seconds) == (65_536, 60)
    assert (deletion.max_targets, deletion.max_chunks, deletion.configured_timeout_seconds) == (
        90,
        1,
        120,
    )
    assert deletion.aws_transaction_action_limit == 100
    assert deletion.aws_transaction_bytes_limit == 4_000_000
    assert deletion.aws_lambda_sync_payload_limit == 6_000_000
