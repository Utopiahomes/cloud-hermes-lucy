from __future__ import annotations

import base64
import json
import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lucy.contracts.canonical import canonical_json_bytes
from lucy.contracts.security_v1_2 import (
    ContractTrustStore,
    DeletionTargetManifestV1,
    DeletionTargetReferenceV1,
    DeploymentEnvironment,
    Ed25519ContractSigner,
    EncryptedEvidencePackageV1,
    ExecutorQuotaV1,
    ExecutorReceiptV1,
    KmsEncryptionContextV1,
    SensitiveActionPermitV2,
    SensitiveActionV2,
    SensitiveExecutionGrantV1,
    SensitiveReasonCode,
    SignatureAlgorithm,
    SigningKeyPurpose,
    VerificationKeyStatus,
    VerificationKeyV1,
    deletion_targets_digest,
)
from lucy.executors import handlers
from lucy.executors.aws import AwsExecutorBackend, AwsExecutorTables
from lucy.executors.core import (
    DeletionExecutor,
    ExecutorIdentity,
    ExecutorRejected,
    RetrievalExecutor,
)
from lucy.executors.models import (
    DeletionExecutorInvocationV1,
    RetrievalExecutorInvocationV1,
    WrappedKeyMaterial,
)

NOW = datetime(2026, 9, 2, 16, 0, tzinfo=UTC)
EVIDENCE_ID = UUID("11111111-1111-4111-8111-111111111111")
DERIVED_ID = UUID("22222222-2222-4222-8222-222222222222")
PERMIT_ID = UUID("33333333-3333-4333-8333-333333333333")
ASSERTION_ID = UUID("44444444-4444-4444-8444-444444444444")
OPERATION_ID = UUID("55555555-5555-4555-8555-555555555555")
GRANT_ID = UUID("66666666-6666-4666-8666-666666666666")
MANIFEST_ID = UUID("77777777-7777-4777-8777-777777777777")
KEY_REF = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
DERIVED_KEY_REF = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
POLICY_KEY_ID = "policy-notary.test.1"
EVIDENCE_KEY = "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
RECEIPT_KEY = "arn:aws:kms:us-east-1:123456789012:key/bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
RETRIEVAL_ALIAS = (
    "arn:aws:lambda:us-east-1:123456789012:function:lucy-evidence-executor:production"
)
DELETION_ALIAS = (
    "arn:aws:lambda:us-east-1:123456789012:function:lucy-deletion-executor:production"
)
DEK = b"d" * 32
PLAINTEXT = b"Synthetic exact evidence."
AAD = b'{"contract_version":"3","encrypted":true}'
NONCE = b"n" * 12


class FakeBackend:
    def __init__(self) -> None:
        self.receipts: dict[UUID, ExecutorReceiptV1] = {}
        self.keys = {
            KEY_REF: WrappedKeyMaterial(
                ciphertext_b64=base64.b64encode(b"wrapped-root").decode(),
                nonce_b64=base64.b64encode(b"kms").decode(),
                kek_version=EVIDENCE_KEY,
            ),
            DERIVED_KEY_REF: WrappedKeyMaterial(
                ciphertext_b64=base64.b64encode(b"wrapped-derived").decode(),
                nonce_b64=base64.b64encode(b"kms").decode(),
                kek_version=EVIDENCE_KEY,
            ),
        }
        self.contexts: list[dict[str, str]] = []
        self.quota_reservations = 0
        self.fail_signing = False
        self.lose_receipt_race = False
        self.fail_deletion_without_receipt = False
        self.deleted: list[UUID] = []
        self.receipt_private_key = ec.derive_private_key(7, ec.SECP256R1())

    def load_receipt(self, operation_id: UUID) -> ExecutorReceiptV1 | None:
        return self.receipts.get(operation_id)

    def load_wrapped_key(self, key_ref: UUID) -> WrappedKeyMaterial | None:
        return self.keys.get(key_ref)

    def decrypt_data_key(
        self,
        wrapped_key: WrappedKeyMaterial,
        encryption_context: dict[str, str],
    ) -> tuple[bytes, str]:
        assert wrapped_key.kek_version == EVIDENCE_KEY
        self.contexts.append(encryption_context)
        return DEK, "kms-request-synthetic"

    def sign_receipt(self, receipt: ExecutorReceiptV1) -> ExecutorReceiptV1:
        if self.fail_signing:
            raise RuntimeError("synthetic signing failure with forbidden plaintext")
        signature = self.receipt_private_key.sign(
            bytes.fromhex(receipt.unsigned_digest_hex()),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        return receipt.model_copy(
            update={"signature": base64.b64encode(signature).decode("ascii")}
        )

    def reserve_retrieval_quota(self, *, now: datetime, quota: ExecutorQuotaV1) -> None:
        assert now == NOW + timedelta(minutes=2)
        assert quota.action == SensitiveActionV2.EVIDENCE_RETRIEVE
        self.quota_reservations += 1

    def commit_retrieval_receipt(self, receipt: ExecutorReceiptV1) -> bool:
        if self.lose_receipt_race:
            self.receipts[receipt.operation_id] = receipt
            return False
        if receipt.operation_id in self.receipts:
            return False
        self.receipts[receipt.operation_id] = receipt
        return True

    def commit_deletion(
        self,
        *,
        manifest: DeletionTargetManifestV1,
        receipt: ExecutorReceiptV1,
        transaction_token: str,
        now: datetime,
        quota: ExecutorQuotaV1,
    ) -> bool:
        assert transaction_token == str(OPERATION_ID)
        assert now == NOW + timedelta(minutes=2)
        assert quota.action == SensitiveActionV2.EVIDENCE_DELETE
        if self.fail_deletion_without_receipt:
            return False
        if any(target.key_ref not in self.keys for target in manifest.targets):
            return False
        for target in manifest.targets:
            del self.keys[target.key_ref]
            self.deleted.append(target.key_ref)
        self.receipts[receipt.operation_id] = receipt
        return True


class FakeDynamoClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.get_response: dict[str, Any] = {}
        self.put_error: ClientError | None = None
        self.transact_error: ClientError | None = None

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_item", kwargs))
        return self.get_response

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("put_item", kwargs))
        if self.put_error is not None:
            raise self.put_error
        return {}

    def transact_write_items(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("transact_write_items", kwargs))
        if self.transact_error is not None:
            raise self.transact_error
        return {}


class FakeKmsClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def decrypt(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("decrypt", kwargs))
        return {
            "Plaintext": DEK,
            "KeyId": EVIDENCE_KEY,
            "ResponseMetadata": {"RequestId": "kms-request-adapter"},
        }

    def sign(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("sign", kwargs))
        return {
            "Signature": b"synthetic-ecdsa-signature",
            "KeyId": RECEIPT_KEY,
            "SigningAlgorithm": "ECDSA_SHA_256",
        }


def _policy() -> tuple[Ed25519ContractSigner, ContractTrustStore]:
    signer = Ed25519ContractSigner(
        ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
        key_id=POLICY_KEY_ID,
    )
    key = VerificationKeyV1(
        key_id=POLICY_KEY_ID,
        issuer="lucy-policy.test",
        purpose=SigningKeyPurpose.POLICY_NOTARY,
        algorithm=SignatureAlgorithm.ED25519,
        environment=DeploymentEnvironment.TEST,
        public_key_b64=signer.public_key_b64,
        valid_from=NOW - timedelta(hours=1),
        issuance_not_after=NOW + timedelta(hours=1),
        verify_not_after=NOW + timedelta(hours=2),
        status=VerificationKeyStatus.ACTIVE,
    )
    return signer, ContractTrustStore((key,))


def _permit(
    signer: Ed25519ContractSigner,
    action: SensitiveActionV2,
) -> SensitiveActionPermitV2:
    return signer.sign(
        SensitiveActionPermitV2(
            key_id=POLICY_KEY_ID,
            issuer="lucy-policy.test",
            environment=DeploymentEnvironment.TEST,
            issued_at=NOW,
            storage_epoch=1,
            registry_epoch=1,
            key_epoch=1,
            permit_id=PERMIT_ID,
            action=action,
            owner_subject="owner:synthetic",
            owner_assertion_id=ASSERTION_ID,
            owner_assertion_digest="a" * 64,
            evidence_id=EVIDENCE_ID,
            reason=(
                SensitiveReasonCode.OWNER_REVIEW
                if action == SensitiveActionV2.EVIDENCE_RETRIEVE
                else SensitiveReasonCode.OWNER_REQUEST
            ),
            max_records=1 if action == SensitiveActionV2.EVIDENCE_RETRIEVE else 2,
            max_bytes=4096,
            record_version=1,
            permit_claim_deadline=NOW + timedelta(minutes=5),
            nonce="permit-nonce-0000000000000000000000000001",
            signature="",
        )
    )


def _retrieval(
    signer: Ed25519ContractSigner,
) -> tuple[SensitiveActionPermitV2, EncryptedEvidencePackageV1, SensitiveExecutionGrantV1]:
    permit = _permit(signer, SensitiveActionV2.EVIDENCE_RETRIEVE)
    context = KmsEncryptionContextV1(
        environment=DeploymentEnvironment.TEST,
        evidence_id=EVIDENCE_ID,
        storage_epoch=1,
        registry_epoch=1,
        key_epoch=1,
        record_version=1,
    )
    ciphertext = AESGCM(DEK).encrypt(NONCE, PLAINTEXT, AAD)
    package = EncryptedEvidencePackageV1(
        operation_id=OPERATION_ID,
        permit_id=PERMIT_ID,
        evidence_id=EVIDENCE_ID,
        key_ref=KEY_REF,
        ciphertext_b64=base64.b64encode(ciphertext).decode(),
        content_nonce_b64=base64.b64encode(NONCE).decode(),
        aad_b64=base64.b64encode(AAD).decode(),
        encryption_context=context,
        record_version=1,
        storage_epoch=1,
        registry_epoch=1,
        key_epoch=1,
    )
    grant = signer.sign(
        SensitiveExecutionGrantV1(
            key_id=POLICY_KEY_ID,
            issuer="lucy-policy.test",
            environment=DeploymentEnvironment.TEST,
            issued_at=NOW + timedelta(minutes=1),
            storage_epoch=1,
            registry_epoch=1,
            key_epoch=1,
            grant_id=GRANT_ID,
            action=SensitiveActionV2.EVIDENCE_RETRIEVE,
            permit_id=PERMIT_ID,
            permit_nonce=permit.nonce,
            operation_id=OPERATION_ID,
            database_session_user="lucy_evidence_workflow",
            evidence_id=EVIDENCE_ID,
            encrypted_package_digest=package.package_digest_hex(),
            package_size_bytes=len(canonical_json_bytes(package)),
            idempotency_key="retrieve-synthetic-1",
            record_version=1,
            executor_identity="lucy-evidence-executor",
            executor_alias_arn=RETRIEVAL_ALIAS,
            executor_version=12,
            permit_claim_deadline=permit.permit_claim_deadline,
            execution_deadline=NOW + timedelta(minutes=10),
            signature="",
        )
    )
    return permit, package, grant


def _manifest(
    signer: Ed25519ContractSigner,
) -> tuple[SensitiveActionPermitV2, DeletionTargetManifestV1, SensitiveExecutionGrantV1]:
    permit = _permit(signer, SensitiveActionV2.EVIDENCE_DELETE)
    targets = (
        DeletionTargetReferenceV1(
            evidence_id=EVIDENCE_ID,
            key_ref=KEY_REF,
            record_version=1,
            key_epoch=1,
        ),
        DeletionTargetReferenceV1(
            evidence_id=DERIVED_ID,
            key_ref=DERIVED_KEY_REF,
            record_version=1,
            key_epoch=1,
        ),
    )
    manifest = signer.sign(
        DeletionTargetManifestV1(
            key_id=POLICY_KEY_ID,
            issuer="lucy-policy.test",
            environment=DeploymentEnvironment.TEST,
            issued_at=NOW,
            storage_epoch=1,
            registry_epoch=1,
            key_epoch=1,
            manifest_id=MANIFEST_ID,
            permit_id=PERMIT_ID,
            permit_nonce=permit.nonce,
            root_evidence_id=EVIDENCE_ID,
            owner_assertion_id=ASSERTION_ID,
            owner_assertion_digest="a" * 64,
            idempotency_key="delete-synthetic-1",
            scope_version=1,
            root_record_version=1,
            targets=targets,
            target_count=2,
            targets_digest=deletion_targets_digest(targets),
            permit_claim_deadline=permit.permit_claim_deadline,
            execution_deadline=NOW + timedelta(minutes=10),
            signature="",
        )
    )
    digest = manifest.unsigned_digest_hex()
    grant = signer.sign(
        SensitiveExecutionGrantV1(
            key_id=POLICY_KEY_ID,
            issuer="lucy-policy.test",
            environment=DeploymentEnvironment.TEST,
            issued_at=NOW + timedelta(minutes=1),
            storage_epoch=1,
            registry_epoch=1,
            key_epoch=1,
            grant_id=GRANT_ID,
            action=SensitiveActionV2.EVIDENCE_DELETE,
            permit_id=PERMIT_ID,
            permit_nonce=permit.nonce,
            operation_id=OPERATION_ID,
            database_session_user="lucy_deletion_workflow",
            evidence_id=EVIDENCE_ID,
            deletion_manifest_id=MANIFEST_ID,
            deletion_manifest_digest=digest,
            encrypted_package_digest=digest,
            package_size_bytes=len(canonical_json_bytes(manifest)),
            idempotency_key="delete-synthetic-1",
            record_version=1,
            executor_identity="lucy-deletion-executor",
            executor_alias_arn=DELETION_ALIAS,
            executor_version=13,
            permit_claim_deadline=permit.permit_claim_deadline,
            execution_deadline=manifest.execution_deadline,
            signature="",
        )
    )
    return permit, manifest, grant


def _identity(action: SensitiveActionV2) -> ExecutorIdentity:
    retrieval = action == SensitiveActionV2.EVIDENCE_RETRIEVE
    return ExecutorIdentity(
        action=action,
        environment=DeploymentEnvironment.TEST,
        storage_epoch=1,
        registry_epoch=1,
        key_epoch=1,
        record_version=1,
        executor_identity="lucy-evidence-executor" if retrieval else "lucy-deletion-executor",
        executor_alias_arn=RETRIEVAL_ALIAS if retrieval else DELETION_ALIAS,
        executor_version=12 if retrieval else 13,
        database_session_user=(
            "lucy_evidence_workflow" if retrieval else "lucy_deletion_workflow"
        ),
        receipt_key_id=RECEIPT_KEY,
        evidence_key_arn=EVIDENCE_KEY if retrieval else None,
    )


def test_retrieval_releases_plaintext_only_after_durable_receipt_then_replays_status() -> None:
    signer, trust = _policy()
    permit, package, grant = _retrieval(signer)
    backend = FakeBackend()
    executor = RetrievalExecutor(
        backend,
        trust,
        _identity(SensitiveActionV2.EVIDENCE_RETRIEVE),
        clock=lambda: NOW + timedelta(minutes=2),
    )
    invocation = RetrievalExecutorInvocationV1(
        permit=permit,
        execution_grant=grant,
        package=package,
    )

    result = executor.execute(invocation, lambda_request_id="lambda-request-1")
    assert base64.b64decode(result.plaintext_b64 or "", validate=True) == PLAINTEXT
    assert result.receipt.operation_id in backend.receipts
    assert backend.quota_reservations == 1
    assert backend.contexts == [package.encryption_context.as_aws_context()]

    replay = executor.execute(invocation, lambda_request_id="lambda-request-2")
    assert replay.replayed is True and replay.plaintext_b64 is None
    assert replay.receipt == result.receipt
    assert backend.quota_reservations == 1


def test_retrieval_receipt_race_loser_returns_no_plaintext() -> None:
    signer, trust = _policy()
    permit, package, grant = _retrieval(signer)
    backend = FakeBackend()
    backend.lose_receipt_race = True
    executor = RetrievalExecutor(
        backend,
        trust,
        _identity(SensitiveActionV2.EVIDENCE_RETRIEVE),
        clock=lambda: NOW + timedelta(minutes=2),
    )
    result = executor.execute(
        RetrievalExecutorInvocationV1(
            permit=permit,
            execution_grant=grant,
            package=package,
        ),
        lambda_request_id="lambda-request-race",
    )
    assert result.replayed is True and result.plaintext_b64 is None


def test_retrieval_signing_failure_never_persists_or_returns_plaintext() -> None:
    signer, trust = _policy()
    permit, package, grant = _retrieval(signer)
    backend = FakeBackend()
    backend.fail_signing = True
    executor = RetrievalExecutor(
        backend,
        trust,
        _identity(SensitiveActionV2.EVIDENCE_RETRIEVE),
        clock=lambda: NOW + timedelta(minutes=2),
    )
    with pytest.raises(ExecutorRejected, match="receipt_signing_failed"):
        executor.execute(
            RetrievalExecutorInvocationV1(
                permit=permit,
                execution_grant=grant,
                package=package,
            ),
            lambda_request_id="lambda-request-fail",
        )
    assert backend.receipts == {}


def test_tampered_retrieval_package_fails_before_kms_or_quota() -> None:
    signer, trust = _policy()
    permit, package, grant = _retrieval(signer)
    backend = FakeBackend()
    executor = RetrievalExecutor(
        backend,
        trust,
        _identity(SensitiveActionV2.EVIDENCE_RETRIEVE),
        clock=lambda: NOW + timedelta(minutes=2),
    )
    tampered = package.model_copy(update={"key_ref": DERIVED_KEY_REF})
    with pytest.raises(ExecutorRejected, match="digest_mismatch"):
        executor.execute(
            RetrievalExecutorInvocationV1(
                permit=permit,
                execution_grant=grant,
                package=tampered,
            ),
            lambda_request_id="lambda-request-tampered",
        )
    assert backend.contexts == [] and backend.quota_reservations == 0


def test_executor_rejects_valid_contracts_from_a_different_deployment_epoch() -> None:
    signer, trust = _policy()
    permit, package, grant = _retrieval(signer)
    backend = FakeBackend()
    identity = replace(
        _identity(SensitiveActionV2.EVIDENCE_RETRIEVE),
        storage_epoch=2,
    )
    executor = RetrievalExecutor(
        backend,
        trust,
        identity,
        clock=lambda: NOW + timedelta(minutes=2),
    )
    with pytest.raises(ExecutorRejected, match="deployment_epoch_or_record_mismatch"):
        executor.execute(
            RetrievalExecutorInvocationV1(
                permit=permit,
                execution_grant=grant,
                package=package,
            ),
            lambda_request_id="lambda-request-wrong-epoch",
        )
    assert backend.contexts == [] and backend.quota_reservations == 0


def test_deletion_commits_only_the_signed_exact_manifest_and_replays_receipt() -> None:
    signer, trust = _policy()
    permit, manifest, grant = _manifest(signer)
    backend = FakeBackend()
    executor = DeletionExecutor(
        backend,
        trust,
        _identity(SensitiveActionV2.EVIDENCE_DELETE),
        clock=lambda: NOW + timedelta(minutes=2),
    )
    invocation = DeletionExecutorInvocationV1(
        permit=permit,
        execution_grant=grant,
        manifest=manifest,
    )
    result = executor.execute(invocation, lambda_request_id="lambda-request-delete")
    assert result.plaintext_b64 is None
    assert backend.deleted == [KEY_REF, DERIVED_KEY_REF]
    assert backend.keys == {}
    replay = executor.execute(invocation, lambda_request_id="lambda-request-delete-retry")
    assert replay.replayed is True and replay.receipt == result.receipt


def test_deletion_missing_key_without_matching_receipt_fails_closed() -> None:
    signer, trust = _policy()
    permit, manifest, grant = _manifest(signer)
    backend = FakeBackend()
    backend.fail_deletion_without_receipt = True
    executor = DeletionExecutor(
        backend,
        trust,
        _identity(SensitiveActionV2.EVIDENCE_DELETE),
        clock=lambda: NOW + timedelta(minutes=2),
    )
    with pytest.raises(ExecutorRejected, match="deletion_state_ambiguous"):
        executor.execute(
            DeletionExecutorInvocationV1(
                permit=permit,
                execution_grant=grant,
                manifest=manifest,
            ),
            lambda_request_id="lambda-request-delete-missing",
        )
    assert backend.deleted == [] and backend.receipts == {}


def test_deletion_manifest_substitution_fails_before_transaction() -> None:
    signer, trust = _policy()
    permit, manifest, grant = _manifest(signer)
    backend = FakeBackend()
    executor = DeletionExecutor(
        backend,
        trust,
        _identity(SensitiveActionV2.EVIDENCE_DELETE),
        clock=lambda: NOW + timedelta(minutes=2),
    )
    changed_target = manifest.targets[1].model_copy(
        update={"key_ref": UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")}
    )
    changed_targets = (manifest.targets[0], changed_target)
    changed = manifest.model_copy(
        update={
            "targets": changed_targets,
            "targets_digest": deletion_targets_digest(changed_targets),
        }
    )
    with pytest.raises(ExecutorRejected, match="manifest_signature_invalid"):
        executor.execute(
            DeletionExecutorInvocationV1(
                permit=permit,
                execution_grant=grant,
                manifest=changed,
            ),
            lambda_request_id="lambda-request-delete-tampered",
        )
    assert backend.deleted == []


def test_executor_identity_never_configures_deletion_with_evidence_kms_key() -> None:
    with pytest.raises(ValueError, match="must not"):
        ExecutorIdentity(
            action=SensitiveActionV2.EVIDENCE_DELETE,
            environment=DeploymentEnvironment.TEST,
            storage_epoch=1,
            registry_epoch=1,
            key_epoch=1,
            record_version=1,
            executor_identity="lucy-deletion-executor",
            executor_alias_arn=DELETION_ALIAS,
            executor_version=1,
            database_session_user="lucy_deletion_workflow",
            receipt_key_id=RECEIPT_KEY,
            evidence_key_arn=EVIDENCE_KEY,
        )


def test_invocation_contracts_forbid_unknown_fields() -> None:
    signer, _ = _policy()
    permit, package, grant = _retrieval(signer)
    values: dict[str, Any] = {
        "permit": permit,
        "execution_grant": grant,
        "package": package,
        "plaintext": "must-not-be-accepted",
    }
    with pytest.raises(ValueError):
        RetrievalExecutorInvocationV1.model_validate(values)


def test_aws_adapter_uses_exact_item_kms_and_conditional_receipt_calls() -> None:
    signer, trust = _policy()
    permit, package, grant = _retrieval(signer)
    core_backend = FakeBackend()
    result = RetrievalExecutor(
        core_backend,
        trust,
        _identity(SensitiveActionV2.EVIDENCE_RETRIEVE),
        clock=lambda: NOW + timedelta(minutes=2),
    ).execute(
        RetrievalExecutorInvocationV1(
            permit=permit,
            execution_grant=grant,
            package=package,
        ),
        lambda_request_id="lambda-request-adapter",
    )

    dynamo = FakeDynamoClient()
    kms = FakeKmsClient()
    adapter = AwsExecutorBackend(
        dynamo,
        kms,
        tables=AwsExecutorTables(
            wrapped_keys="lucy-wrapped-keys-test",
            receipts="lucy-retrieval-receipts-test",
            quotas="lucy-retrieval-quotas-test",
        ),
        evidence_key_arn=EVIDENCE_KEY,
        receipt_key_arn=RECEIPT_KEY,
        minute_limit=5,
        day_limit=20,
    )
    dynamo.get_response = {
        "Item": {
            "key_ref": {"S": str(KEY_REF)},
            "ciphertext": {"B": b"wrapped-root"},
            "nonce": {"B": b"kms"},
            "kek_version": {"S": EVIDENCE_KEY},
        }
    }
    wrapped = adapter.load_wrapped_key(KEY_REF)
    assert wrapped is not None
    assert dynamo.calls[-1][1] == {
        "TableName": "lucy-wrapped-keys-test",
        "Key": {"key_ref": {"S": str(KEY_REF)}},
        "ProjectionExpression": "key_ref, ciphertext, nonce, kek_version",
        "ConsistentRead": True,
    }
    assert adapter.decrypt_data_key(wrapped, package.encryption_context.as_aws_context()) == (
        DEK,
        "kms-request-adapter",
    )
    assert kms.calls[-1] == (
        "decrypt",
        {
            "CiphertextBlob": b"wrapped-root",
            "KeyId": EVIDENCE_KEY,
            "EncryptionContext": package.encryption_context.as_aws_context(),
        },
    )

    unsigned = result.receipt.model_copy(update={"signature": ""})
    signed = adapter.sign_receipt(unsigned)
    assert signed.signature == base64.b64encode(b"synthetic-ecdsa-signature").decode()
    assert kms.calls[-1][1]["MessageType"] == "DIGEST"
    assert kms.calls[-1][1]["SigningAlgorithm"] == "ECDSA_SHA_256"
    assert adapter.commit_retrieval_receipt(result.receipt) is True
    method, put = dynamo.calls[-1]
    assert method == "put_item"
    assert put["ConditionExpression"] == "attribute_not_exists(operation_id)"
    assert put["Item"]["receipt_json"]["S"].find(PLAINTEXT.decode()) == -1
    assert not any(name in {"scan", "query", "batch_get_item"} for name, _ in dynamo.calls)


def test_aws_deletion_adapter_commits_intent_receipt_quotas_and_exact_keys_atomically() -> None:
    signer, trust = _policy()
    permit, manifest, grant = _manifest(signer)
    core_backend = FakeBackend()
    result = DeletionExecutor(
        core_backend,
        trust,
        _identity(SensitiveActionV2.EVIDENCE_DELETE),
        clock=lambda: NOW + timedelta(minutes=2),
    ).execute(
        DeletionExecutorInvocationV1(
            permit=permit,
            execution_grant=grant,
            manifest=manifest,
        ),
        lambda_request_id="lambda-request-delete-adapter",
    )
    dynamo = FakeDynamoClient()
    kms = FakeKmsClient()
    adapter = AwsExecutorBackend(
        dynamo,
        kms,
        tables=AwsExecutorTables(
            wrapped_keys="lucy-wrapped-keys-test",
            receipts="lucy-deletion-receipts-test",
            quotas="lucy-deletion-quotas-test",
            intents="lucy-deletion-intents-v12-test",
        ),
        evidence_key_arn=None,
        receipt_key_arn=RECEIPT_KEY,
        minute_limit=3,
        day_limit=10,
    )
    assert adapter.commit_deletion(
        manifest=manifest,
        receipt=result.receipt,
        transaction_token=str(OPERATION_ID),
        now=NOW + timedelta(minutes=2),
        quota=ExecutorQuotaV1.phase1(SensitiveActionV2.EVIDENCE_DELETE),
    )
    method, call = dynamo.calls[-1]
    assert method == "transact_write_items"
    assert call["ClientRequestToken"] == str(OPERATION_ID)
    actions = call["TransactItems"]
    assert len(actions) == 6
    assert [action["Put"]["TableName"] for action in actions[:2]] == [
        "lucy-deletion-intents-v12-test",
        "lucy-deletion-receipts-test",
    ]
    assert all("Update" in action for action in actions[2:4])
    deleted = {
        UUID(action["Delete"]["Key"]["key_ref"]["S"])
        for action in actions[4:]
    }
    assert deleted == {KEY_REF, DERIVED_KEY_REF}
    assert all(
        action["Delete"]["ConditionExpression"] == "attribute_exists(key_ref)"
        for action in actions[4:]
    )
    assert kms.calls == []


@pytest.mark.parametrize(
    ("operation", "code"),
    [
        ("PutItem", "ConditionalCheckFailedException"),
        ("TransactWriteItems", "TransactionCanceledException"),
    ],
)
def test_aws_adapter_surfaces_idempotent_conditional_conflicts_as_false(
    operation: str,
    code: str,
) -> None:
    signer, trust = _policy()
    permit, manifest, grant = _manifest(signer)
    result = DeletionExecutor(
        FakeBackend(),
        trust,
        _identity(SensitiveActionV2.EVIDENCE_DELETE),
        clock=lambda: NOW + timedelta(minutes=2),
    ).execute(
        DeletionExecutorInvocationV1(
            permit=permit,
            execution_grant=grant,
            manifest=manifest,
        ),
        lambda_request_id="lambda-request-conflict",
    )
    dynamo = FakeDynamoClient()
    error = ClientError({"Error": {"Code": code, "Message": "synthetic"}}, operation)
    if operation == "PutItem":
        dynamo.put_error = error
    else:
        dynamo.transact_error = error
    adapter = AwsExecutorBackend(
        dynamo,
        FakeKmsClient(),
        tables=AwsExecutorTables(
            wrapped_keys="lucy-wrapped-keys-test",
            receipts="lucy-receipts-test",
            quotas="lucy-quotas-test",
            intents="lucy-intents-test",
        ),
        evidence_key_arn=None,
        receipt_key_arn=RECEIPT_KEY,
        minute_limit=2,
        day_limit=10,
    )
    if operation == "PutItem":
        assert adapter.commit_retrieval_receipt(result.receipt) is False
    else:
        assert (
            adapter.commit_deletion(
                manifest=manifest,
                receipt=result.receipt,
                transaction_token=str(OPERATION_ID),
                now=NOW + timedelta(minutes=2),
                quota=ExecutorQuotaV1.phase1(SensitiveActionV2.EVIDENCE_DELETE),
            )
            is False
        )


def test_lambda_runtime_rejects_unqualified_alias_and_wrong_published_version() -> None:
    identity = _identity(SensitiveActionV2.EVIDENCE_RETRIEVE)
    runtime = handlers._ExecutorRuntime(object(), identity)  # type: ignore[arg-type]
    good = SimpleNamespace(
        invoked_function_arn=RETRIEVAL_ALIAS,
        function_version="12",
        aws_request_id="lambda-request-context",
    )
    runtime.verify_context(good)

    for changed, code in (
        (
            {"invoked_function_arn": RETRIEVAL_ALIAS.removesuffix(":production")},
            "invoked_alias_mismatch",
        ),
        ({"function_version": "$LATEST"}, "published_version_mismatch"),
        ({"function_version": "11"}, "published_version_mismatch"),
        ({"aws_request_id": ""}, "lambda_request_id_missing"),
    ):
        context = SimpleNamespace(**(vars(good) | changed))
        with pytest.raises(ExecutorRejected, match=code):
            runtime.verify_context(context)


def test_lambda_handler_sanitizes_unexpected_failures_without_request_material(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    signer, _ = _policy()
    permit, package, grant = _retrieval(signer)
    invocation = RetrievalExecutorInvocationV1(
        permit=permit,
        execution_grant=grant,
        package=package,
    )

    class FailingExecutor:
        def execute(self, *_: object, **__: object) -> None:
            raise RuntimeError(PLAINTEXT.decode())

    class Runtime:
        executor = FailingExecutor()

        @staticmethod
        def verify_context(_: object) -> None:
            return None

    monkeypatch.setattr(handlers, "_runtime", lambda *_: Runtime())
    context = SimpleNamespace(
        invoked_function_arn=RETRIEVAL_ALIAS,
        function_version="12",
        aws_request_id="lambda-request-failure",
    )
    with caplog.at_level(logging.ERROR, logger="lucy.executor"):
        response = handlers.retrieval_lambda_handler(
            invocation.model_dump(mode="json"),
            context,
        )
    assert response == {
        "ok": False,
        "error": "executor_unavailable",
        "code": "internal_failure",
    }
    metric = json.loads(capsys.readouterr().out)
    assert metric["Action"] == "evidence.retrieve"
    assert metric["Failed"] == 1
    assert metric["_aws"]["CloudWatchMetrics"][0]["Namespace"] == (
        "CloudLucy/SecurityV1_2"
    )
    rendered = caplog.text + json.dumps(response) + json.dumps(metric)
    assert PLAINTEXT.decode() not in rendered
    assert package.ciphertext_b64 not in rendered
    assert "RuntimeError" in caplog.text


def test_lambda_handler_returns_content_free_alias_denial(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    signer, _ = _policy()
    permit, package, grant = _retrieval(signer)
    invocation = RetrievalExecutorInvocationV1(
        permit=permit,
        execution_grant=grant,
        package=package,
    )

    class Runtime:
        executor = object()

        @staticmethod
        def verify_context(_: object) -> None:
            raise ExecutorRejected("invoked_alias_mismatch")

    monkeypatch.setattr(handlers, "_runtime", lambda *_: Runtime())
    context = SimpleNamespace(
        invoked_function_arn=RETRIEVAL_ALIAS.removesuffix(":production"),
        function_version="12",
        aws_request_id="lambda-request-denied",
    )
    with caplog.at_level(logging.WARNING, logger="lucy.executor"):
        response = handlers.retrieval_lambda_handler(
            invocation.model_dump(mode="json"),
            context,
        )
    assert response == {
        "ok": False,
        "error": "request_rejected",
        "code": "invoked_alias_mismatch",
    }
    metric = json.loads(capsys.readouterr().out)
    assert metric["Denied"] == metric["IntegrityDenied"] == 1
    assert "Failed" not in metric
    rendered = caplog.text + json.dumps(metric)
    assert package.ciphertext_b64 not in rendered
    assert PLAINTEXT.decode() not in rendered


def test_embedded_metrics_record_acceptance_and_replay_without_identifiers(
    capsys: pytest.CaptureFixture[str],
) -> None:
    handlers._emit_metrics(SensitiveActionV2.EVIDENCE_DELETE, ["Accepted", "Replayed"])
    metric = json.loads(capsys.readouterr().out)
    assert metric["Action"] == "evidence.delete"
    assert metric["Accepted"] == metric["Replayed"] == 1
    assert set(metric) == {"_aws", "Action", "Accepted", "Replayed"}
