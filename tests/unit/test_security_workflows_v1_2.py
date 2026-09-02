from __future__ import annotations

import base64
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from lucy.contracts.canonical import canonical_json_bytes
from lucy.contracts.security_v1_2 import (
    ContractTrustStore,
    DeletionOperationState,
    DeletionTargetManifestV1,
    DeletionTargetReferenceV1,
    DeploymentEnvironment,
    Ed25519ContractSigner,
    EncryptedEvidencePackageV1,
    ExecutorReceiptV1,
    ExecutorResult,
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
    ecdsa_public_key_der_b64,
)
from lucy.executors.models import (
    DeletionExecutorInvocationV1,
    ExecutorInvocationResultV1,
    RetrievalExecutorInvocationV1,
)
from lucy.security_workflows import (
    BotoLambdaExecutorInvoker,
    ClaimDigestV1,
    DeletionClaimV1,
    DeletionCoordinator,
    DeletionScopeDraftV1,
    ExecutorBindingV1,
    PolicyNotaryService,
    RetrievalClaimV1,
    RetrievalCoordinator,
    WorkflowRejected,
)

NOW = datetime(2026, 9, 2, 18, 0, tzinfo=UTC)
EVIDENCE_ID = UUID("11111111-1111-4111-8111-111111111111")
KEY_REF = UUID("22222222-2222-4222-8222-222222222222")
OPERATION_ID = UUID("33333333-3333-4333-8333-333333333333")
RETRIEVAL_ALIAS = (
    "arn:aws:lambda:us-east-1:123456789012:function:lucy-evidence-executor:production"
)
DELETION_ALIAS = (
    "arn:aws:lambda:us-east-1:123456789012:function:lucy-deletion-executor:production"
)
RETRIEVAL_RECEIPT_KEY = "receipt-key.retrieval.1"
DELETION_RECEIPT_KEY = "receipt-key.deletion.1"


def _ed25519_material(
    seed: int,
    *,
    key_id: str,
    issuer: str,
    purpose: SigningKeyPurpose,
) -> tuple[Ed25519ContractSigner, VerificationKeyV1]:
    signer = Ed25519ContractSigner(
        ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32),
        key_id=key_id,
    )
    key = VerificationKeyV1(
        key_id=key_id,
        issuer=issuer,
        purpose=purpose,
        algorithm=SignatureAlgorithm.ED25519,
        environment=DeploymentEnvironment.TEST,
        public_key_b64=signer.public_key_b64,
        valid_from=NOW - timedelta(hours=1),
        issuance_not_after=NOW + timedelta(hours=1),
        verify_not_after=NOW + timedelta(hours=2),
        status=VerificationKeyStatus.ACTIVE,
    )
    return signer, key


def _receipt_material() -> tuple[ec.EllipticCurvePrivateKey, tuple[VerificationKeyV1, ...]]:
    retrieval = ec.derive_private_key(17, ec.SECP256R1())
    deletion = ec.derive_private_key(19, ec.SECP256R1())
    keys = (
        VerificationKeyV1(
            key_id=RETRIEVAL_RECEIPT_KEY,
            issuer="lucy-evidence-executor",
            purpose=SigningKeyPurpose.RETRIEVAL_RECEIPT,
            algorithm=SignatureAlgorithm.ECDSA_SHA_256,
            environment=DeploymentEnvironment.TEST,
            public_key_b64=ecdsa_public_key_der_b64(retrieval.public_key()),
            valid_from=NOW - timedelta(hours=1),
            issuance_not_after=NOW + timedelta(hours=1),
            verify_not_after=NOW + timedelta(hours=2),
            status=VerificationKeyStatus.ACTIVE,
        ),
        VerificationKeyV1(
            key_id=DELETION_RECEIPT_KEY,
            issuer="lucy-deletion-executor",
            purpose=SigningKeyPurpose.DELETION_RECEIPT,
            algorithm=SignatureAlgorithm.ECDSA_SHA_256,
            environment=DeploymentEnvironment.TEST,
            public_key_b64=ecdsa_public_key_der_b64(deletion.public_key()),
            valid_from=NOW - timedelta(hours=1),
            issuance_not_after=NOW + timedelta(hours=1),
            verify_not_after=NOW + timedelta(hours=2),
            status=VerificationKeyStatus.ACTIVE,
        ),
    )
    return retrieval, keys


def _owner_assertion(
    signer: Ed25519ContractSigner,
    action: SensitiveActionV2,
) -> OwnerInteractionAssertionV1:
    return signer.sign(
        OwnerInteractionAssertionV1(
            key_id=signer.key_id,
            issuer="owner-broker.test",
            environment=DeploymentEnvironment.TEST,
            issued_at=NOW,
            storage_epoch=1,
            registry_epoch=1,
            key_epoch=1,
            assertion_id=UUID("44444444-4444-4444-8444-444444444444"),
            broker_identity="owner-broker.test",
            channel=OwnerInteractionChannel.SYNTHETIC_ACCEPTANCE,
            owner_subject="owner:synthetic",
            source_interaction_id="interaction-synthetic-1",
            source_message_id="message-synthetic-1",
            requested_action=action,
            evidence_id=EVIDENCE_ID,
            authentication_method=OwnerAuthenticationMethod.SYNTHETIC_ACCEPTANCE,
            interaction_created_at=NOW,
            max_age_seconds=300,
            expires_at=NOW + timedelta(minutes=4),
            nonce="owner-nonce-0000000000000000000000000001",
            anti_replay_id="owner-replay-synthetic-1",
            signature="",
        )
    )


def _package(permit_id: UUID) -> EncryptedEvidencePackageV1:
    return EncryptedEvidencePackageV1(
        operation_id=OPERATION_ID,
        permit_id=permit_id,
        evidence_id=EVIDENCE_ID,
        key_ref=KEY_REF,
        ciphertext_b64=base64.b64encode(b"synthetic-ciphertext").decode(),
        content_nonce_b64=base64.b64encode(b"n" * 12).decode(),
        aad_b64=base64.b64encode(b"{}").decode(),
        encryption_context=KmsEncryptionContextV1(
            environment=DeploymentEnvironment.TEST,
            evidence_id=EVIDENCE_ID,
            storage_epoch=1,
            registry_epoch=1,
            key_epoch=1,
            record_version=1,
        ),
        record_version=1,
        storage_epoch=1,
        registry_epoch=1,
        key_epoch=1,
    )


class FakeStore:
    def __init__(self) -> None:
        self.permit: SensitiveActionPermitV2 | None = None
        self.manifest: DeletionTargetManifestV1 | None = None
        self.grants: list[SensitiveExecutionGrantV1] = []
        self.receipts: list[ExecutorReceiptV1] = []
        self.calls: list[str] = []
        self.action = SensitiveActionV2.EVIDENCE_RETRIEVE
        self.retrieval_state = RetrievalOperationState.CLAIMED
        self.deletion_state = DeletionOperationState.CLAIMED
        self.receipt_digest: str | None = None

    def issue_permit(
        self,
        assertion: OwnerInteractionAssertionV1,
        permit: SensitiveActionPermitV2,
        idempotency_key: str,
    ) -> UUID:
        assert assertion.assertion_id == permit.owner_assertion_id
        assert idempotency_key
        self.calls.append("issue_permit")
        self.permit = permit
        return permit.permit_id

    def prepare_deletion_scope(
        self, manifest_id: UUID, permit_id: UUID, idempotency_key: str
    ) -> DeletionScopeDraftV1:
        assert self.permit is not None
        self.calls.append("prepare_scope")
        return DeletionScopeDraftV1(
            manifest_id=manifest_id,
            permit_id=permit_id,
            root_evidence_id=EVIDENCE_ID,
            idempotency_key=idempotency_key,
            scope_version=1,
            root_record_version=1,
            target_count=1,
            targets=(
                DeletionTargetReferenceV1(
                    evidence_id=EVIDENCE_ID,
                    key_ref=KEY_REF,
                    record_version=1,
                    key_epoch=1,
                ),
            ),
            permit_claim_deadline=self.permit.permit_claim_deadline,
            execution_deadline=NOW + timedelta(minutes=10),
            state="PREPARED",
            storage_epoch=1,
            registry_epoch=1,
            key_epoch=1,
            owner_assertion_id=self.permit.owner_assertion_id,
            owner_assertion_digest=self.permit.owner_assertion_digest,
            permit_nonce=self.permit.nonce,
        )

    def finalize_deletion_scope(
        self, unsigned: DeletionTargetManifestV1, signed: DeletionTargetManifestV1
    ) -> str:
        assert not unsigned.signature and signed.signature
        self.calls.append("finalize_scope")
        self.manifest = signed
        return signed.unsigned_digest_hex()

    def claim_retrieval(
        self, permit: SensitiveActionPermitV2, idempotency_key: str
    ) -> RetrievalClaimV1:
        self.calls.append("claim_retrieval")
        package = _package(permit.permit_id)
        return RetrievalClaimV1(
            operation_id=OPERATION_ID,
            package=package,
            package_digest=package.package_digest_hex(),
            execution_deadline=NOW + timedelta(minutes=10),
            state=self.retrieval_state,
            receipt_digest=self.receipt_digest,
            replayed=self.retrieval_state != RetrievalOperationState.CLAIMED,
        )

    def claim_deletion(
        self,
        permit: SensitiveActionPermitV2,
        manifest: DeletionTargetManifestV1,
        idempotency_key: str,
    ) -> DeletionClaimV1:
        self.calls.append("claim_deletion")
        return DeletionClaimV1(
            operation_id=OPERATION_ID,
            manifest=manifest,
            package_digest=manifest.unsigned_digest_hex(),
            execution_deadline=manifest.execution_deadline,
            state=self.deletion_state,
            receipt_digest=self.receipt_digest,
            replayed=self.deletion_state != DeletionOperationState.CLAIMED,
        )

    def read_claim_digest(self, operation_id: UUID) -> ClaimDigestV1:
        assert operation_id == OPERATION_ID and self.permit is not None
        self.calls.append("read_claim")
        package_digest: str
        manifest_id: UUID | None
        if self.action == SensitiveActionV2.EVIDENCE_RETRIEVE:
            package_digest = _package(self.permit.permit_id).package_digest_hex()
            manifest_id = None
        else:
            assert self.manifest is not None
            package_digest = self.manifest.unsigned_digest_hex()
            manifest_id = self.manifest.manifest_id
        return ClaimDigestV1(
            operation_id=operation_id,
            action=self.action,
            permit_id=self.permit.permit_id,
            permit_nonce=self.permit.nonce,
            evidence_id=EVIDENCE_ID,
            manifest_id=manifest_id,
            manifest_digest=package_digest if manifest_id else None,
            package_digest=package_digest,
            package_size_bytes=(
                len(canonical_json_bytes(self.manifest))
                if self.manifest is not None
                else len(canonical_json_bytes(_package(self.permit.permit_id)))
            ),
            database_session_user=(
                "lucy_deletion_workflow"
                if self.action == SensitiveActionV2.EVIDENCE_DELETE
                else "lucy_evidence_workflow"
            ),
            idempotency_key="sensitive-operation-1",
            record_version=1,
            storage_epoch=1,
            registry_epoch=1,
            key_epoch=1,
            environment=DeploymentEnvironment.TEST,
            permit_claim_deadline=self.permit.permit_claim_deadline,
            execution_deadline=NOW + timedelta(minutes=10),
        )

    def store_execution_grant(
        self, operation_id: UUID, grant: SensitiveExecutionGrantV1
    ) -> str:
        assert operation_id == OPERATION_ID
        self.calls.append("store_grant")
        self.grants.append(grant)
        return grant.unsigned_digest_hex()

    def attest_executor_receipt(self, operation_id: UUID, receipt: ExecutorReceiptV1) -> str:
        assert operation_id == OPERATION_ID
        self.calls.append("attest_receipt")
        self.receipts.append(receipt)
        self.receipt_digest = receipt.unsigned_digest_hex()
        return self.receipt_digest

    def reconcile_retrieval(self, operation_id: UUID) -> RetrievalOperationState:
        assert operation_id == OPERATION_ID
        self.calls.append("reconcile_retrieval")
        self.retrieval_state = RetrievalOperationState.EXECUTOR_RECEIPTED
        return self.retrieval_state

    def record_delivery(self, operation_id: UUID, outcome: str) -> RetrievalOperationState:
        assert operation_id == OPERATION_ID
        self.calls.append(f"delivery_{outcome}")
        self.retrieval_state = (
            RetrievalOperationState.DELIVERY_CONFIRMED
            if outcome == "accepted"
            else RetrievalOperationState.DELIVERY_UNKNOWN
        )
        return self.retrieval_state

    def reconcile_deletion(self, operation_id: UUID) -> dict[str, Any]:
        assert operation_id == OPERATION_ID
        self.calls.append("reconcile_deletion")
        self.deletion_state = DeletionOperationState.FINALITY_PENDING
        return {
            "state": self.deletion_state.value,
            "derived_summary": {"evidence_records_deleted": 1},
            "replayed": False,
        }


def _policy(store: FakeStore) -> tuple[PolicyNotaryService, Ed25519ContractSigner]:
    owner_signer, owner_key = _ed25519_material(
        3,
        key_id="owner-broker.test.1",
        issuer="owner-broker.test",
        purpose=SigningKeyPurpose.OWNER_BROKER,
    )
    policy_signer, _ = _ed25519_material(
        5,
        key_id="policy-notary.test.1",
        issuer="lucy-policy.test",
        purpose=SigningKeyPurpose.POLICY_NOTARY,
    )
    _, receipt_keys = _receipt_material()
    service = PolicyNotaryService(
        store,
        owner_trust_store=ContractTrustStore((owner_key,)),
        receipt_trust_store=ContractTrustStore(receipt_keys),
        signer=policy_signer,
        issuer="lucy-policy.test",
        environment=DeploymentEnvironment.TEST,
        bindings=(
            ExecutorBindingV1(
                action=SensitiveActionV2.EVIDENCE_RETRIEVE,
                environment=DeploymentEnvironment.TEST,
                executor_identity="lucy-evidence-executor",
                executor_alias_arn=RETRIEVAL_ALIAS,
                executor_version=12,
            ),
            ExecutorBindingV1(
                action=SensitiveActionV2.EVIDENCE_DELETE,
                environment=DeploymentEnvironment.TEST,
                executor_identity="lucy-deletion-executor",
                executor_alias_arn=DELETION_ALIAS,
                executor_version=13,
            ),
        ),
        clock=lambda: NOW + timedelta(minutes=1),
    )
    return service, owner_signer


class FakeExecutor:
    def __init__(self, receipt_key: ec.EllipticCurvePrivateKey) -> None:
        self._receipt_key = receipt_key
        self.calls: list[SensitiveActionV2] = []
        self.replay = False

    def invoke_retrieval(
        self, invocation: RetrievalExecutorInvocationV1
    ) -> ExecutorInvocationResultV1:
        self.calls.append(SensitiveActionV2.EVIDENCE_RETRIEVE)
        receipt = self._receipt(invocation.execution_grant, RETRIEVAL_RECEIPT_KEY)
        return ExecutorInvocationResultV1(
            action=SensitiveActionV2.EVIDENCE_RETRIEVE,
            receipt=receipt,
            receipt_digest=receipt.unsigned_digest_hex(),
            replayed=self.replay,
            plaintext_b64=None if self.replay else base64.b64encode(b"synthetic").decode(),
        )

    def invoke_deletion(
        self, invocation: DeletionExecutorInvocationV1
    ) -> ExecutorInvocationResultV1:
        self.calls.append(SensitiveActionV2.EVIDENCE_DELETE)
        receipt = self._receipt(invocation.execution_grant, DELETION_RECEIPT_KEY)
        return ExecutorInvocationResultV1(
            action=SensitiveActionV2.EVIDENCE_DELETE,
            receipt=receipt,
            receipt_digest=receipt.unsigned_digest_hex(),
            replayed=self.replay,
        )

    def _receipt(
        self, grant: SensitiveExecutionGrantV1, key_id: str
    ) -> ExecutorReceiptV1:
        completed = NOW + timedelta(minutes=1)
        unsigned = ExecutorReceiptV1(
            key_id=key_id,
            issuer=grant.executor_identity,
            environment=DeploymentEnvironment.TEST,
            issued_at=completed,
            storage_epoch=1,
            registry_epoch=1,
            key_epoch=1,
            receipt_id=UUID("55555555-5555-4555-8555-555555555555"),
            action=grant.action,
            executor_identity=grant.executor_identity,
            executor_alias_arn=grant.executor_alias_arn,
            executor_version=grant.executor_version,
            operation_id=grant.operation_id,
            permit_id=grant.permit_id,
            execution_grant_id=grant.grant_id,
            deletion_manifest_id=grant.deletion_manifest_id,
            package_digest=grant.encrypted_package_digest,
            result=(
                ExecutorResult.RETRIEVAL_SUCCEEDED
                if grant.action == SensitiveActionV2.EVIDENCE_RETRIEVE
                else ExecutorResult.DELETION_SUCCEEDED
            ),
            lambda_request_id="lambda-request-workflow-1",
            kms_request_id=(
                "kms-request-workflow-1"
                if grant.action == SensitiveActionV2.EVIDENCE_RETRIEVE
                else None
            ),
            transaction_client_token=(
                str(grant.operation_id)
                if grant.action == SensitiveActionV2.EVIDENCE_DELETE
                else None
            ),
            execution_deadline=grant.execution_deadline,
            completed_at=completed,
            record_version=1,
            signature="",
        )
        signature = self._receipt_key.sign(
            bytes.fromhex(unsigned.unsigned_digest_hex()),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        return unsigned.model_copy(
            update={"signature": base64.b64encode(signature).decode()}
        )


def test_policy_permit_manifest_and_grant_are_deterministic_across_retries() -> None:
    store = FakeStore()
    policy, owner_signer = _policy(store)
    assertion = _owner_assertion(owner_signer, SensitiveActionV2.EVIDENCE_DELETE)
    first = policy.issue_permit(
        assertion,
        reason=SensitiveReasonCode.OWNER_REQUEST,
        record_version=1,
        idempotency_key="issue-delete-1",
    )
    second = policy.issue_permit(
        assertion,
        reason=SensitiveReasonCode.OWNER_REQUEST,
        record_version=1,
        idempotency_key="issue-delete-1",
    )
    assert first == second

    manifest_one = policy.prepare_deletion_manifest(first, idempotency_key="delete-1")
    manifest_two = policy.prepare_deletion_manifest(first, idempotency_key="delete-1")
    assert manifest_one == manifest_two
    store.action = SensitiveActionV2.EVIDENCE_DELETE
    grant_one = policy.notarize_operation(OPERATION_ID)
    grant_two = policy.notarize_operation(OPERATION_ID)
    assert grant_one == grant_two
    assert grant_one.database_session_user == "lucy_deletion_workflow"
    assert grant_one.executor_alias_arn == DELETION_ALIAS


def test_retrieval_workflow_releases_plaintext_then_records_transport_separately() -> None:
    store = FakeStore()
    policy, owner_signer = _policy(store)
    permit = policy.issue_permit(
        _owner_assertion(owner_signer, SensitiveActionV2.EVIDENCE_RETRIEVE),
        reason=SensitiveReasonCode.OWNER_REVIEW,
        record_version=1,
        idempotency_key="issue-retrieve-1",
    )
    receipt_private, _ = _receipt_material()
    executor = FakeExecutor(receipt_private)
    result = RetrievalCoordinator(store, policy, executor).execute(
        permit,
        idempotency_key="sensitive-operation-1",
    )
    assert base64.b64decode(result.plaintext_b64 or "") == b"synthetic"
    assert result.state == RetrievalOperationState.EXECUTOR_RECEIPTED
    assert store.calls[-4:] == [
        "read_claim",
        "store_grant",
        "attest_receipt",
        "reconcile_retrieval",
    ]
    assert RetrievalCoordinator(store, policy, executor).record_delivery(
        OPERATION_ID,
        accepted=True,
    ) == RetrievalOperationState.DELIVERY_CONFIRMED


def test_retrieval_executor_replay_never_releases_plaintext_and_becomes_unknown() -> None:
    store = FakeStore()
    policy, owner_signer = _policy(store)
    permit = policy.issue_permit(
        _owner_assertion(owner_signer, SensitiveActionV2.EVIDENCE_RETRIEVE),
        reason=SensitiveReasonCode.OWNER_REVIEW,
        record_version=1,
        idempotency_key="issue-retrieve-2",
    )
    receipt_private, _ = _receipt_material()
    executor = FakeExecutor(receipt_private)
    executor.replay = True
    result = RetrievalCoordinator(store, policy, executor).execute(
        permit,
        idempotency_key="sensitive-operation-1",
    )
    assert result.plaintext_b64 is None
    assert result.state == RetrievalOperationState.DELIVERY_UNKNOWN
    assert store.calls[-1] == "delivery_unknown"


def test_deletion_workflow_uses_exact_manifest_and_reconciles_to_finality_pending() -> None:
    store = FakeStore()
    policy, owner_signer = _policy(store)
    permit = policy.issue_permit(
        _owner_assertion(owner_signer, SensitiveActionV2.EVIDENCE_DELETE),
        reason=SensitiveReasonCode.OWNER_REQUEST,
        record_version=1,
        idempotency_key="issue-delete-2",
    )
    manifest = policy.prepare_deletion_manifest(permit, idempotency_key="delete-2")
    store.action = SensitiveActionV2.EVIDENCE_DELETE
    receipt_private = ec.derive_private_key(19, ec.SECP256R1())
    result = DeletionCoordinator(store, policy, FakeExecutor(receipt_private)).execute(
        permit,
        manifest,
        idempotency_key="sensitive-operation-1",
    )
    assert result.state == DeletionOperationState.FINALITY_PENDING
    assert result.derived_summary == {"evidence_records_deleted": 1}
    assert store.calls[-1] == "reconcile_deletion"


class FakeLambdaClient:
    def __init__(self, result: ExecutorInvocationResultV1) -> None:
        self.result = result
        self.calls: list[dict[str, Any]] = []

    def invoke(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        body = json.dumps(
            {"ok": True, "result": self.result.model_dump(mode="json")},
            separators=(",", ":"),
        ).encode()
        return {
            "StatusCode": 200,
            "ExecutedVersion": str(self.result.receipt.executor_version),
            "Payload": io.BytesIO(body),
        }


def test_boto_invoker_calls_only_configured_qualified_alias() -> None:
    store = FakeStore()
    policy, owner_signer = _policy(store)
    permit = policy.issue_permit(
        _owner_assertion(owner_signer, SensitiveActionV2.EVIDENCE_RETRIEVE),
        reason=SensitiveReasonCode.OWNER_REVIEW,
        record_version=1,
        idempotency_key="issue-retrieve-3",
    )
    grant = policy.notarize_operation(OPERATION_ID)
    receipt_private, _ = _receipt_material()
    expected = FakeExecutor(receipt_private).invoke_retrieval(
        RetrievalExecutorInvocationV1(
            permit=permit,
            execution_grant=grant,
            package=_package(permit.permit_id),
        )
    )
    client = FakeLambdaClient(expected)
    invoker = BotoLambdaExecutorInvoker(client, retrieval_alias_arn=RETRIEVAL_ALIAS)
    observed = invoker.invoke_retrieval(
        RetrievalExecutorInvocationV1(
            permit=permit,
            execution_grant=grant,
            package=_package(permit.permit_id),
        )
    )
    assert observed == expected
    assert client.calls[0]["FunctionName"] == RETRIEVAL_ALIAS
    assert client.calls[0]["InvocationType"] == "RequestResponse"
    assert "$LATEST" not in client.calls[0]["FunctionName"]


def test_boto_invoker_rejects_alias_that_executed_an_unexpected_version() -> None:
    store = FakeStore()
    policy, owner_signer = _policy(store)
    permit = policy.issue_permit(
        _owner_assertion(owner_signer, SensitiveActionV2.EVIDENCE_RETRIEVE),
        reason=SensitiveReasonCode.OWNER_REVIEW,
        record_version=1,
        idempotency_key="issue-retrieve-version-mismatch",
    )
    grant = policy.notarize_operation(OPERATION_ID)
    receipt_private, _ = _receipt_material()
    result = FakeExecutor(receipt_private).invoke_retrieval(
        RetrievalExecutorInvocationV1(
            permit=permit,
            execution_grant=grant,
            package=_package(permit.permit_id),
        )
    )
    client = FakeLambdaClient(result)
    client.result = result.model_copy(
        update={
            "receipt": result.receipt.model_copy(update={"executor_version": 99})
        }
    )
    with pytest.raises(WorkflowRejected, match="executor_version_mismatch"):
        BotoLambdaExecutorInvoker(
            client,
            retrieval_alias_arn=RETRIEVAL_ALIAS,
        ).invoke_retrieval(
            RetrievalExecutorInvocationV1(
                permit=permit,
                execution_grant=grant,
                package=_package(permit.permit_id),
            )
        )
