"""Locally testable executor cores with no boto3 dependency."""

from __future__ import annotations

import base64
import binascii
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lucy.contracts.canonical import canonical_json_bytes
from lucy.contracts.security_v1_2 import (
    CLOCK_SKEW_SECONDS,
    ContractTrustStore,
    DeletionTargetManifestV1,
    DeploymentEnvironment,
    EncryptedEvidencePackageV1,
    ExecutorQuotaV1,
    ExecutorReceiptV1,
    ExecutorResult,
    SensitiveActionPermitV2,
    SensitiveActionV2,
    SensitiveExecutionGrantV1,
    SignatureAlgorithm,
    SigningKeyPurpose,
)
from lucy.executors.models import (
    DeletionExecutorInvocationV1,
    ExecutorInvocationResultV1,
    RetrievalExecutorInvocationV1,
    WrappedKeyMaterial,
)


class ExecutorRejected(PermissionError):
    """A content-free, safe-to-return executor denial."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ExecutorBackend(Protocol):
    def load_receipt(self, operation_id: UUID) -> ExecutorReceiptV1 | None: ...

    def load_wrapped_key(self, key_ref: UUID) -> WrappedKeyMaterial | None: ...

    def decrypt_data_key(
        self,
        wrapped_key: WrappedKeyMaterial,
        encryption_context: dict[str, str],
    ) -> tuple[bytes, str]: ...

    def sign_receipt(self, receipt: ExecutorReceiptV1) -> ExecutorReceiptV1: ...

    def reserve_retrieval_quota(self, *, now: datetime, quota: ExecutorQuotaV1) -> None: ...

    def commit_retrieval_receipt(self, receipt: ExecutorReceiptV1) -> bool: ...

    def commit_deletion(
        self,
        *,
        manifest: DeletionTargetManifestV1,
        receipt: ExecutorReceiptV1,
        transaction_token: str,
        now: datetime,
        quota: ExecutorQuotaV1,
    ) -> bool: ...


@dataclass(frozen=True)
class ExecutorIdentity:
    action: SensitiveActionV2
    environment: DeploymentEnvironment
    storage_epoch: int
    registry_epoch: int
    key_epoch: int
    record_version: int
    executor_identity: str
    executor_alias_arn: str
    executor_version: int
    database_session_user: str
    receipt_key_id: str
    evidence_key_arn: str | None = None

    def __post_init__(self) -> None:
        if min(
            self.storage_epoch,
            self.registry_epoch,
            self.key_epoch,
            self.record_version,
            self.executor_version,
        ) < 1:
            raise ValueError("executor epochs, record, and published version must be positive")
        if not all(
            value.strip()
            for value in (
                self.executor_identity,
                self.executor_alias_arn,
                self.database_session_user,
                self.receipt_key_id,
            )
        ):
            raise ValueError("executor identity configuration must be complete")
        if self.action == SensitiveActionV2.EVIDENCE_RETRIEVE and not self.evidence_key_arn:
            raise ValueError("retrieval executor requires the exact evidence KMS key ARN")
        if self.action == SensitiveActionV2.EVIDENCE_DELETE and self.evidence_key_arn is not None:
            raise ValueError("deletion executor must not be configured with an evidence KMS key")


class _ExecutorBase:
    def __init__(
        self,
        backend: ExecutorBackend,
        trust_store: ContractTrustStore,
        identity: ExecutorIdentity,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._backend = backend
        self._trust_store = trust_store
        self._identity = identity
        self._clock = clock or (lambda: datetime.now(UTC))

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise RuntimeError("executor clock returned a naive timestamp")
        return value

    def _verify_common(
        self,
        permit: SensitiveActionPermitV2,
        grant: SensitiveExecutionGrantV1,
        *,
        now: datetime,
    ) -> None:
        try:
            for contract in (permit, grant):
                self._trust_store.verify(
                    contract,
                    purpose=SigningKeyPurpose.POLICY_NOTARY,
                    environment=self._identity.environment,
                    now=now,
                )
        except PermissionError as exc:
            raise ExecutorRejected("authorization_signature_invalid") from exc

        if permit.action != self._identity.action or grant.action != self._identity.action:
            raise ExecutorRejected("action_mismatch")
        if (
            permit.environment != self._identity.environment
            or grant.environment != self._identity.environment
        ):
            raise ExecutorRejected("environment_mismatch")
        if grant.permit_id != permit.permit_id or grant.permit_nonce != permit.nonce:
            raise ExecutorRejected("permit_binding_mismatch")
        if grant.evidence_id != permit.evidence_id:
            raise ExecutorRejected("evidence_binding_mismatch")
        if grant.permit_claim_deadline != permit.permit_claim_deadline:
            raise ExecutorRejected("claim_deadline_mismatch")
        if (
            grant.record_version != permit.record_version
            or grant.storage_epoch != permit.storage_epoch
            or grant.registry_epoch != permit.registry_epoch
            or grant.key_epoch != permit.key_epoch
        ):
            raise ExecutorRejected("epoch_or_record_mismatch")
        if (
            permit.record_version != self._identity.record_version
            or permit.storage_epoch != self._identity.storage_epoch
            or permit.registry_epoch != self._identity.registry_epoch
            or permit.key_epoch != self._identity.key_epoch
        ):
            raise ExecutorRejected("deployment_epoch_or_record_mismatch")
        if grant.database_session_user != self._identity.database_session_user:
            raise ExecutorRejected("database_caller_mismatch")
        if (
            grant.executor_identity != self._identity.executor_identity
            or grant.executor_alias_arn != self._identity.executor_alias_arn
            or grant.executor_version != self._identity.executor_version
        ):
            raise ExecutorRejected("executor_binding_mismatch")
        if now > grant.execution_deadline + timedelta(seconds=CLOCK_SKEW_SECONDS):
            raise ExecutorRejected("execution_deadline_expired")

    def _receipt_replay(
        self,
        receipt: ExecutorReceiptV1,
        *,
        grant: SensitiveExecutionGrantV1,
    ) -> ExecutorInvocationResultV1:
        expected = (
            self._identity.action,
            self._identity.executor_identity,
            self._identity.executor_alias_arn,
            self._identity.executor_version,
            grant.operation_id,
            grant.permit_id,
            grant.grant_id,
            grant.encrypted_package_digest,
            grant.record_version,
            self._identity.receipt_key_id,
            grant.deletion_manifest_id,
            self._identity.environment,
            grant.storage_epoch,
            grant.registry_epoch,
            grant.key_epoch,
            grant.execution_deadline,
        )
        observed = (
            receipt.action,
            receipt.executor_identity,
            receipt.executor_alias_arn,
            receipt.executor_version,
            receipt.operation_id,
            receipt.permit_id,
            receipt.execution_grant_id,
            receipt.package_digest,
            receipt.record_version,
            receipt.key_id,
            receipt.deletion_manifest_id,
            receipt.environment,
            receipt.storage_epoch,
            receipt.registry_epoch,
            receipt.key_epoch,
            receipt.execution_deadline,
        )
        successful_result = (
            ExecutorResult.RETRIEVAL_SUCCEEDED
            if self._identity.action == SensitiveActionV2.EVIDENCE_RETRIEVE
            else ExecutorResult.DELETION_SUCCEEDED
        )
        if (
            observed != expected
            or receipt.issuer != self._identity.executor_identity
            or receipt.result != successful_result
            or not receipt.signature
        ):
            raise ExecutorRejected("durable_receipt_binding_mismatch")
        return ExecutorInvocationResultV1(
            action=self._identity.action,
            receipt=receipt,
            receipt_digest=receipt.unsigned_digest_hex(),
            replayed=True,
        )

    def _unsigned_receipt(
        self,
        *,
        grant: SensitiveExecutionGrantV1,
        result: ExecutorResult,
        lambda_request_id: str,
        completed_at: datetime,
        kms_request_id: str | None = None,
        manifest_id: UUID | None = None,
        transaction_token: str | None = None,
    ) -> ExecutorReceiptV1:
        return ExecutorReceiptV1(
            signature_algorithm=SignatureAlgorithm.ECDSA_SHA_256,
            key_id=self._identity.receipt_key_id,
            issuer=self._identity.executor_identity,
            environment=self._identity.environment,
            issued_at=completed_at,
            storage_epoch=grant.storage_epoch,
            registry_epoch=grant.registry_epoch,
            key_epoch=grant.key_epoch,
            receipt_id=uuid4(),
            action=self._identity.action,
            executor_identity=self._identity.executor_identity,
            executor_alias_arn=self._identity.executor_alias_arn,
            executor_version=self._identity.executor_version,
            operation_id=grant.operation_id,
            permit_id=grant.permit_id,
            execution_grant_id=grant.grant_id,
            deletion_manifest_id=manifest_id,
            package_digest=grant.encrypted_package_digest,
            result=result,
            lambda_request_id=lambda_request_id,
            kms_request_id=kms_request_id,
            transaction_client_token=transaction_token,
            execution_deadline=grant.execution_deadline,
            completed_at=completed_at,
            record_version=grant.record_version,
            signature="",
        )

    @staticmethod
    def _require_exact_signed_receipt(
        unsigned: ExecutorReceiptV1,
        signed: ExecutorReceiptV1,
    ) -> None:
        if not signed.signature or signed.model_copy(update={"signature": ""}) != unsigned:
            raise ExecutorRejected("receipt_signer_changed_contract")


class RetrievalExecutor(_ExecutorBase):
    def execute(
        self,
        invocation: RetrievalExecutorInvocationV1,
        *,
        lambda_request_id: str,
    ) -> ExecutorInvocationResultV1:
        now = self._now()
        permit = invocation.permit
        grant = invocation.execution_grant
        self._verify_common(permit, grant, now=now)
        if self._identity.action != SensitiveActionV2.EVIDENCE_RETRIEVE:
            raise ExecutorRejected("executor_action_misconfigured")
        try:
            package = EncryptedEvidencePackageV1.model_validate(invocation.package)
        except (TypeError, ValueError) as exc:
            raise ExecutorRejected("encrypted_package_invalid") from exc
        self._verify_package(permit, grant, package)

        existing = self._backend.load_receipt(grant.operation_id)
        if existing is not None:
            return self._receipt_replay(existing, grant=grant)

        quota = ExecutorQuotaV1.phase1(SensitiveActionV2.EVIDENCE_RETRIEVE)
        try:
            self._backend.reserve_retrieval_quota(now=now, quota=quota)
        except Exception as exc:
            raise ExecutorRejected("quota_denied") from exc
        wrapped = self._backend.load_wrapped_key(package.key_ref)
        if wrapped is None:
            raise ExecutorRejected("wrapped_key_missing")
        if wrapped.kek_version != self._identity.evidence_key_arn:
            raise ExecutorRejected("wrapped_key_version_mismatch")
        if _decode_b64(wrapped.nonce_b64) != b"kms":
            raise ExecutorRejected("wrapped_key_format_invalid")

        try:
            dek, kms_request_id = self._backend.decrypt_data_key(
                wrapped,
                package.encryption_context.as_aws_context(),
            )
            if len(dek) != 32:
                raise ExecutorRejected("kms_plaintext_key_invalid")
            plaintext = AESGCM(dek).decrypt(
                _decode_b64(package.content_nonce_b64),
                _decode_b64(package.ciphertext_b64),
                _decode_b64(package.aad_b64),
            )
        except ExecutorRejected:
            raise
        except (InvalidTag, ValueError, TypeError) as exc:
            raise ExecutorRejected("ciphertext_authentication_failed") from exc
        if len(plaintext) > permit.max_bytes or len(plaintext) > quota.max_plaintext_bytes:
            raise ExecutorRejected("plaintext_limit_exceeded")

        completed_at = self._now()
        unsigned = self._unsigned_receipt(
            grant=grant,
            result=ExecutorResult.RETRIEVAL_SUCCEEDED,
            lambda_request_id=lambda_request_id,
            completed_at=completed_at,
            kms_request_id=kms_request_id,
        )
        try:
            signed = self._backend.sign_receipt(unsigned)
        except Exception as exc:
            raise ExecutorRejected("receipt_signing_failed") from exc
        self._require_exact_signed_receipt(unsigned, signed)
        try:
            stored = self._backend.commit_retrieval_receipt(signed)
        except Exception as exc:
            raise ExecutorRejected("receipt_persistence_failed") from exc
        if not stored:
            winner = self._backend.load_receipt(grant.operation_id)
            if winner is None:
                raise ExecutorRejected("receipt_persistence_ambiguous")
            return self._receipt_replay(winner, grant=grant)
        return ExecutorInvocationResultV1(
            action=SensitiveActionV2.EVIDENCE_RETRIEVE,
            receipt=signed,
            receipt_digest=signed.unsigned_digest_hex(),
            replayed=False,
            plaintext_b64=base64.b64encode(plaintext).decode("ascii"),
        )

    @staticmethod
    def _verify_package(
        permit: SensitiveActionPermitV2,
        grant: SensitiveExecutionGrantV1,
        package: EncryptedEvidencePackageV1,
    ) -> None:
        package_bytes = canonical_json_bytes(package)
        if (
            package.operation_id != grant.operation_id
            or package.permit_id != permit.permit_id
            or package.evidence_id != permit.evidence_id
            or package.record_version != permit.record_version
            or package.storage_epoch != permit.storage_epoch
            or package.registry_epoch != permit.registry_epoch
            or package.key_epoch != permit.key_epoch
            or package.encryption_context.environment != permit.environment
        ):
            raise ExecutorRejected("encrypted_package_binding_mismatch")
        if not hmac.compare_digest(package.package_digest_hex(), grant.encrypted_package_digest):
            raise ExecutorRejected("encrypted_package_digest_mismatch")
        if len(package_bytes) != grant.package_size_bytes:
            raise ExecutorRejected("encrypted_package_size_mismatch")


class DeletionExecutor(_ExecutorBase):
    def execute(
        self,
        invocation: DeletionExecutorInvocationV1,
        *,
        lambda_request_id: str,
    ) -> ExecutorInvocationResultV1:
        now = self._now()
        permit = invocation.permit
        grant = invocation.execution_grant
        manifest = invocation.manifest
        self._verify_common(permit, grant, now=now)
        if self._identity.action != SensitiveActionV2.EVIDENCE_DELETE:
            raise ExecutorRejected("executor_action_misconfigured")
        self._verify_manifest(permit, grant, manifest)

        existing = self._backend.load_receipt(grant.operation_id)
        if existing is not None:
            return self._receipt_replay(existing, grant=grant)

        quota = ExecutorQuotaV1.phase1(SensitiveActionV2.EVIDENCE_DELETE)
        if manifest.target_count > quota.max_targets:
            raise ExecutorRejected("deletion_target_limit_exceeded")
        transaction_token = str(grant.operation_id)
        completed_at = self._now()
        unsigned = self._unsigned_receipt(
            grant=grant,
            result=ExecutorResult.DELETION_SUCCEEDED,
            lambda_request_id=lambda_request_id,
            completed_at=completed_at,
            manifest_id=manifest.manifest_id,
            transaction_token=transaction_token,
        )
        try:
            signed = self._backend.sign_receipt(unsigned)
        except Exception as exc:
            raise ExecutorRejected("receipt_signing_failed") from exc
        self._require_exact_signed_receipt(unsigned, signed)
        try:
            committed = self._backend.commit_deletion(
                manifest=manifest,
                receipt=signed,
                transaction_token=transaction_token,
                now=now,
                quota=quota,
            )
        except Exception as exc:
            raise ExecutorRejected("deletion_transaction_failed") from exc
        if not committed:
            winner = self._backend.load_receipt(grant.operation_id)
            if winner is None:
                raise ExecutorRejected("deletion_state_ambiguous")
            return self._receipt_replay(winner, grant=grant)
        return ExecutorInvocationResultV1(
            action=SensitiveActionV2.EVIDENCE_DELETE,
            receipt=signed,
            receipt_digest=signed.unsigned_digest_hex(),
            replayed=False,
        )

    def _verify_manifest(
        self,
        permit: SensitiveActionPermitV2,
        grant: SensitiveExecutionGrantV1,
        manifest: DeletionTargetManifestV1,
    ) -> None:
        try:
            self._trust_store.verify(
                manifest,
                purpose=SigningKeyPurpose.POLICY_NOTARY,
                environment=self._identity.environment,
                now=self._now(),
            )
        except PermissionError as exc:
            raise ExecutorRejected("manifest_signature_invalid") from exc
        manifest_digest = manifest.unsigned_digest_hex()
        if (
            manifest.permit_id != permit.permit_id
            or manifest.permit_nonce != permit.nonce
            or manifest.root_evidence_id != permit.evidence_id
            or manifest.owner_assertion_id != permit.owner_assertion_id
            or manifest.owner_assertion_digest != permit.owner_assertion_digest
            or manifest.idempotency_key != grant.idempotency_key
            or manifest.root_record_version != permit.record_version
            or manifest.storage_epoch != permit.storage_epoch
            or manifest.registry_epoch != permit.registry_epoch
            or manifest.key_epoch != permit.key_epoch
            or manifest.execution_deadline != grant.execution_deadline
            or manifest.permit_claim_deadline != permit.permit_claim_deadline
        ):
            raise ExecutorRejected("manifest_binding_mismatch")
        if (
            grant.deletion_manifest_id != manifest.manifest_id
            or grant.deletion_manifest_digest is None
            or not hmac.compare_digest(grant.deletion_manifest_digest, manifest_digest)
            or not hmac.compare_digest(grant.encrypted_package_digest, manifest_digest)
        ):
            raise ExecutorRejected("manifest_digest_mismatch")
        if len(canonical_json_bytes(manifest)) != grant.package_size_bytes:
            raise ExecutorRejected("manifest_size_mismatch")


def _decode_b64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ExecutorRejected("base64_invalid") from exc
