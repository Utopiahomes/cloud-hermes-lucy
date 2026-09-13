"""Realm-scoped V1.3 executor effects, additive to the frozen V1.2 core."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lucy.contracts.security_v1_2 import (
    ExecutorQuotaV1,
    ExecutorResult,
    SensitiveActionV2,
    SignatureAlgorithm,
)
from lucy.contracts.security_v1_3 import (
    DeletionTargetManifestV2,
    DeletionTargetManifestV3,
    ExecutorReceiptV2,
    SensitiveActionPermitV3,
    SensitiveExecutionGrantV2,
    V13ContractVerifier,
    V13SigningKeyPurpose,
)
from lucy.executors.admission_v1_3 import (
    RealmExecutorIdentityV1,
    verify_deletion_invocation_v2,
    verify_deletion_invocation_v3,
    verify_retrieval_invocation_v2,
)
from lucy.executors.core import ExecutorRejected
from lucy.executors.models import (
    DeletionExecutorInvocationV2,
    DeletionExecutorInvocationV3,
    ExecutorInvocationResultV2,
    RetrievalExecutorInvocationV2,
    WrappedKeyMaterial,
)


class RealmExecutorBackend(Protocol):
    def load_receipt_v2(self, operation_id: UUID) -> ExecutorReceiptV2 | None: ...

    def load_wrapped_key(self, key_ref: UUID) -> WrappedKeyMaterial | None: ...

    def decrypt_data_key(
        self, wrapped_key: WrappedKeyMaterial, encryption_context: dict[str, str]
    ) -> tuple[bytes, str]: ...

    def sign_receipt_v2(self, receipt: ExecutorReceiptV2) -> ExecutorReceiptV2: ...

    def reserve_retrieval_quota(self, *, now: datetime, quota: ExecutorQuotaV1) -> None: ...

    def commit_retrieval_receipt_v2(self, receipt: ExecutorReceiptV2) -> bool: ...

    def commit_deletion_v2(
        self,
        *,
        permit: SensitiveActionPermitV3,
        grant: SensitiveExecutionGrantV2,
        manifest: DeletionTargetManifestV2,
        receipt: ExecutorReceiptV2,
        transaction_token: str,
        now: datetime,
        quota: ExecutorQuotaV1,
    ) -> bool: ...

    def commit_deletion_v3(
        self,
        *,
        permit: SensitiveActionPermitV3,
        grant: SensitiveExecutionGrantV2,
        manifest: DeletionTargetManifestV3,
        receipt: ExecutorReceiptV2,
        transaction_token: str,
        now: datetime,
        quota: ExecutorQuotaV1,
    ) -> bool: ...


class _RealmExecutorBase:
    def __init__(
        self,
        backend: RealmExecutorBackend,
        verifier: V13ContractVerifier,
        identity: RealmExecutorIdentityV1,
        *,
        receipt_key_id: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not receipt_key_id.strip():
            raise ValueError("realm receipt key ID is required")
        self._backend = backend
        self._verifier = verifier
        self._identity = identity
        self._receipt_key_id = receipt_key_id
        self._clock = clock or (lambda: datetime.now(UTC))

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise RuntimeError("executor clock returned a naive timestamp")
        return value

    def _unsigned_receipt(
        self,
        *,
        permit: SensitiveActionPermitV3,
        grant: SensitiveExecutionGrantV2,
        result: ExecutorResult,
        lambda_request_id: str,
        completed_at: datetime,
        kms_request_id: str | None,
        manifest: DeletionTargetManifestV2 | DeletionTargetManifestV3 | None,
        transaction_token: str | None,
    ) -> ExecutorReceiptV2:
        retrieval = self._identity.action == SensitiveActionV2.EVIDENCE_RETRIEVE
        return ExecutorReceiptV2(
            signing_key_purpose=(
                V13SigningKeyPurpose.RETRIEVAL_RECEIPT
                if retrieval
                else V13SigningKeyPurpose.DELETION_RECEIPT
            ),
            signature_algorithm=SignatureAlgorithm.ECDSA_SHA_256,
            key_id=self._receipt_key_id,
            issuer=self._identity.executor_identity,
            environment=self._identity.environment,
            issued_at=completed_at,
            receipt_id=uuid4(),
            action=self._identity.action,
            executor_identity=self._identity.executor_identity,
            executor_alias_arn=self._identity.executor_alias_arn,
            executor_version=self._identity.executor_version,
            caller_identity=self._identity.caller_identity,
            target_scope=self._identity.target_scope,
            execution_binding=self._identity.execution_binding,
            operation_id=grant.operation_id,
            permit_id=permit.permit_id,
            permit_digest=permit.unsigned_digest_hex(),
            execution_grant_id=grant.grant_id,
            execution_grant_digest=grant.unsigned_digest_hex(),
            deletion_manifest_id=manifest.manifest_id if manifest else None,
            deletion_manifest_digest=manifest.unsigned_digest_hex() if manifest else None,
            package_digest=grant.encrypted_package_digest,
            result=result,
            lambda_request_id=lambda_request_id,
            kms_request_id=kms_request_id,
            transaction_client_token=transaction_token,
            execution_completion_deadline=grant.execution_completion_deadline,
            completed_at=completed_at,
            record_version=self._identity.record_version,
            journal_ref=(
                f"realm-retrieval-receipts/{grant.operation_id}"
                if retrieval
                else f"realm-deletion-receipts/{grant.operation_id}"
            ),
            finality_state="not_applicable" if retrieval else "operationally_deleted",
            signature="",
        )

    @staticmethod
    def _require_exact_signed_receipt(
        unsigned: ExecutorReceiptV2, signed: ExecutorReceiptV2
    ) -> None:
        if not signed.signature or signed.model_copy(update={"signature": ""}) != unsigned:
            raise ExecutorRejected("receipt_signer_changed_contract")

    def _receipt_replay(
        self,
        receipt: ExecutorReceiptV2,
        *,
        permit: SensitiveActionPermitV3,
        grant: SensitiveExecutionGrantV2,
        manifest: DeletionTargetManifestV2 | DeletionTargetManifestV3 | None,
    ) -> ExecutorInvocationResultV2:
        successful = (
            ExecutorResult.RETRIEVAL_SUCCEEDED
            if self._identity.action == SensitiveActionV2.EVIDENCE_RETRIEVE
            else ExecutorResult.DELETION_SUCCEEDED
        )
        expected = self._unsigned_receipt(
            permit=permit,
            grant=grant,
            result=successful,
            lambda_request_id=receipt.lambda_request_id,
            completed_at=receipt.completed_at,
            kms_request_id=receipt.kms_request_id,
            manifest=manifest,
            transaction_token=receipt.transaction_client_token,
        ).model_copy(update={"receipt_id": receipt.receipt_id})
        if (
            receipt.model_copy(update={"signature": ""}) != expected
            or receipt.key_id != self._receipt_key_id
            or not receipt.signature
        ):
            raise ExecutorRejected("durable_receipt_binding_mismatch")
        return ExecutorInvocationResultV2(
            action=self._identity.action,
            receipt=receipt,
            receipt_digest=receipt.unsigned_digest_hex(),
            replayed=True,
        )


class RealmRetrievalExecutor(_RealmExecutorBase):
    def __init__(
        self,
        backend: RealmExecutorBackend,
        verifier: V13ContractVerifier,
        identity: RealmExecutorIdentityV1,
        *,
        receipt_key_id: str,
        evidence_key_arn: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if identity.action != SensitiveActionV2.EVIDENCE_RETRIEVE:
            raise ValueError("retrieval executor identity has the wrong action")
        if not evidence_key_arn.strip():
            raise ValueError("retrieval executor requires an evidence key ARN")
        super().__init__(backend, verifier, identity, receipt_key_id=receipt_key_id, clock=clock)
        self._evidence_key_arn = evidence_key_arn

    def execute(
        self, invocation: RetrievalExecutorInvocationV2, *, lambda_request_id: str
    ) -> ExecutorInvocationResultV2:
        now = self._now()
        verify_retrieval_invocation_v2(
            invocation,
            verifier=self._verifier,
            identity=self._identity,
            checked_at=now,
        )
        permit, grant, package = (
            invocation.permit,
            invocation.execution_grant,
            invocation.package,
        )
        existing = self._backend.load_receipt_v2(grant.operation_id)
        if existing is not None:
            return self._receipt_replay(existing, permit=permit, grant=grant, manifest=None)
        quota = ExecutorQuotaV1.phase1(SensitiveActionV2.EVIDENCE_RETRIEVE)
        try:
            self._backend.reserve_retrieval_quota(now=now, quota=quota)
        except Exception as exc:
            raise ExecutorRejected("quota_denied") from exc
        wrapper = package.wrapper_binding
        wrapped = self._backend.load_wrapped_key(wrapper.wrapped_key_ref)
        if wrapped is None:
            raise ExecutorRejected("wrapped_key_missing")
        if wrapped.kek_version != self._evidence_key_arn:
            raise ExecutorRejected("wrapped_key_version_mismatch")
        if _decode_b64(wrapped.nonce_b64) != b"kms":
            raise ExecutorRejected("wrapped_key_format_invalid")
        try:
            dek, kms_request_id = self._backend.decrypt_data_key(
                wrapped, wrapper.encryption_context.as_aws_context()
            )
            if len(dek) != 32:
                raise ExecutorRejected("kms_plaintext_key_invalid")
            payload = package.payload_binding
            plaintext = AESGCM(dek).decrypt(
                _decode_b64(payload.content_nonce_b64),
                _decode_b64(payload.ciphertext_b64),
                _decode_b64(payload.authenticated_header_b64),
            )
        except ExecutorRejected:
            raise
        except (InvalidTag, ValueError, TypeError) as exc:
            raise ExecutorRejected("ciphertext_authentication_failed") from exc
        if len(plaintext) > min(permit.max_bytes, grant.max_bytes, quota.max_plaintext_bytes):
            raise ExecutorRejected("plaintext_limit_exceeded")
        completed_at = self._now()
        unsigned = self._unsigned_receipt(
            permit=permit,
            grant=grant,
            result=ExecutorResult.RETRIEVAL_SUCCEEDED,
            lambda_request_id=lambda_request_id,
            completed_at=completed_at,
            kms_request_id=kms_request_id,
            manifest=None,
            transaction_token=None,
        )
        try:
            signed = self._backend.sign_receipt_v2(unsigned)
        except Exception as exc:
            raise ExecutorRejected("receipt_signing_failed") from exc
        self._require_exact_signed_receipt(unsigned, signed)
        try:
            stored = self._backend.commit_retrieval_receipt_v2(signed)
        except Exception as exc:
            raise ExecutorRejected("receipt_persistence_failed") from exc
        if not stored:
            winner = self._backend.load_receipt_v2(grant.operation_id)
            if winner is None:
                raise ExecutorRejected("receipt_persistence_ambiguous")
            return self._receipt_replay(winner, permit=permit, grant=grant, manifest=None)
        return ExecutorInvocationResultV2(
            action=self._identity.action,
            receipt=signed,
            receipt_digest=signed.unsigned_digest_hex(),
            replayed=False,
            plaintext_b64=base64.b64encode(plaintext).decode("ascii"),
        )


class RealmDeletionExecutor(_RealmExecutorBase):
    def __init__(
        self,
        backend: RealmExecutorBackend,
        verifier: V13ContractVerifier,
        identity: RealmExecutorIdentityV1,
        *,
        receipt_key_id: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if identity.action != SensitiveActionV2.EVIDENCE_DELETE:
            raise ValueError("deletion executor identity has the wrong action")
        super().__init__(backend, verifier, identity, receipt_key_id=receipt_key_id, clock=clock)

    def execute(
        self, invocation: DeletionExecutorInvocationV2, *, lambda_request_id: str
    ) -> ExecutorInvocationResultV2:
        now = self._now()
        verify_deletion_invocation_v2(
            invocation,
            verifier=self._verifier,
            identity=self._identity,
            checked_at=now,
        )
        permit, grant, manifest = (
            invocation.permit,
            invocation.execution_grant,
            invocation.manifest,
        )
        existing = self._backend.load_receipt_v2(grant.operation_id)
        if existing is not None:
            return self._receipt_replay(
                existing, permit=permit, grant=grant, manifest=manifest
            )
        quota = ExecutorQuotaV1.phase1(SensitiveActionV2.EVIDENCE_DELETE)
        if manifest.target_count > quota.max_targets:
            raise ExecutorRejected("deletion_target_limit_exceeded")
        transaction_token = str(grant.operation_id)
        completed_at = self._now()
        unsigned = self._unsigned_receipt(
            permit=permit,
            grant=grant,
            result=ExecutorResult.DELETION_SUCCEEDED,
            lambda_request_id=lambda_request_id,
            completed_at=completed_at,
            kms_request_id=None,
            manifest=manifest,
            transaction_token=transaction_token,
        )
        try:
            signed = self._backend.sign_receipt_v2(unsigned)
        except Exception as exc:
            raise ExecutorRejected("receipt_signing_failed") from exc
        self._require_exact_signed_receipt(unsigned, signed)
        try:
            committed = self._backend.commit_deletion_v2(
                permit=permit,
                grant=grant,
                manifest=manifest,
                receipt=signed,
                transaction_token=transaction_token,
                now=now,
                quota=quota,
            )
        except Exception as exc:
            raise ExecutorRejected("deletion_transaction_failed") from exc
        if not committed:
            winner = self._backend.load_receipt_v2(grant.operation_id)
            if winner is None:
                raise ExecutorRejected("deletion_state_ambiguous")
            return self._receipt_replay(
                winner, permit=permit, grant=grant, manifest=manifest
            )
        return ExecutorInvocationResultV2(
            action=self._identity.action,
            receipt=signed,
            receipt_digest=signed.unsigned_digest_hex(),
            replayed=False,
        )

    def execute_v3(
        self, invocation: DeletionExecutorInvocationV3, *, lambda_request_id: str
    ) -> ExecutorInvocationResultV2:
        """Execute the additive V3 imported-memory deletion closure."""

        now = self._now()
        verify_deletion_invocation_v3(
            invocation,
            verifier=self._verifier,
            identity=self._identity,
            checked_at=now,
        )
        permit, grant, manifest = (
            invocation.permit,
            invocation.execution_grant,
            invocation.manifest,
        )
        existing = self._backend.load_receipt_v2(grant.operation_id)
        if existing is not None:
            return self._receipt_replay(
                existing, permit=permit, grant=grant, manifest=manifest
            )
        quota = ExecutorQuotaV1.phase1(SensitiveActionV2.EVIDENCE_DELETE)
        if manifest.target_count > quota.max_targets:
            raise ExecutorRejected("deletion_target_limit_exceeded")
        transaction_token = str(grant.operation_id)
        completed_at = self._now()
        unsigned = self._unsigned_receipt(
            permit=permit,
            grant=grant,
            result=ExecutorResult.DELETION_SUCCEEDED,
            lambda_request_id=lambda_request_id,
            completed_at=completed_at,
            kms_request_id=None,
            manifest=manifest,
            transaction_token=transaction_token,
        )
        try:
            signed = self._backend.sign_receipt_v2(unsigned)
        except Exception as exc:
            raise ExecutorRejected("receipt_signing_failed") from exc
        self._require_exact_signed_receipt(unsigned, signed)
        try:
            committed = self._backend.commit_deletion_v3(
                permit=permit,
                grant=grant,
                manifest=manifest,
                receipt=signed,
                transaction_token=transaction_token,
                now=now,
                quota=quota,
            )
        except Exception as exc:
            raise ExecutorRejected("deletion_transaction_failed") from exc
        if not committed:
            winner = self._backend.load_receipt_v2(grant.operation_id)
            if winner is None:
                raise ExecutorRejected("deletion_state_ambiguous")
            return self._receipt_replay(
                winner, permit=permit, grant=grant, manifest=manifest
            )
        return ExecutorInvocationResultV2(
            action=self._identity.action,
            receipt=signed,
            receipt_digest=signed.unsigned_digest_hex(),
            replayed=False,
        )


def _decode_b64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ExecutorRejected("base64_invalid") from exc
