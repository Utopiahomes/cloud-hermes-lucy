"""Wire and adapter models for the two v1.2 AWS executors."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from lucy.contracts.security_v1_2 import (
    DeletionTargetManifestV1,
    EncryptedEvidencePackageV1,
    ExecutorReceiptV1,
    SensitiveActionPermitV2,
    SensitiveActionV2,
    SensitiveExecutionGrantV1,
    StrictSecurityContract,
)


class RetrievalExecutorInvocationV1(StrictSecurityContract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.retrieval-executor-invocation.v1"] = (
        "lucy.retrieval-executor-invocation.v1"
    )
    permit: SensitiveActionPermitV2
    execution_grant: SensitiveExecutionGrantV1
    package: EncryptedEvidencePackageV1

    @model_validator(mode="after")
    def validate_action(self) -> RetrievalExecutorInvocationV1:
        if self.permit.action != SensitiveActionV2.EVIDENCE_RETRIEVE:
            raise ValueError("retrieval invocation contains a non-retrieval permit")
        if self.execution_grant.action != SensitiveActionV2.EVIDENCE_RETRIEVE:
            raise ValueError("retrieval invocation contains a non-retrieval grant")
        return self


class DeletionExecutorInvocationV1(StrictSecurityContract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.deletion-executor-invocation.v1"] = (
        "lucy.deletion-executor-invocation.v1"
    )
    permit: SensitiveActionPermitV2
    execution_grant: SensitiveExecutionGrantV1
    manifest: DeletionTargetManifestV1

    @model_validator(mode="after")
    def validate_action(self) -> DeletionExecutorInvocationV1:
        if self.permit.action != SensitiveActionV2.EVIDENCE_DELETE:
            raise ValueError("deletion invocation contains a non-deletion permit")
        if self.execution_grant.action != SensitiveActionV2.EVIDENCE_DELETE:
            raise ValueError("deletion invocation contains a non-deletion grant")
        return self


class ExecutorInvocationResultV1(StrictSecurityContract):
    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.executor-invocation-result.v1"] = (
        "lucy.executor-invocation-result.v1"
    )
    action: SensitiveActionV2
    receipt: ExecutorReceiptV1
    receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    replayed: bool
    plaintext_b64: str | None = Field(default=None, max_length=90_000)

    @model_validator(mode="after")
    def validate_result(self) -> ExecutorInvocationResultV1:
        if self.receipt.action != self.action:
            raise ValueError("executor result and receipt actions differ")
        if self.receipt.unsigned_digest_hex() != self.receipt_digest:
            raise ValueError("executor receipt digest does not match")
        if self.action == SensitiveActionV2.EVIDENCE_DELETE and self.plaintext_b64 is not None:
            raise ValueError("deletion result must not contain plaintext")
        if self.replayed and self.plaintext_b64 is not None:
            raise ValueError("an idempotent replay must never return plaintext")
        return self


class WrappedKeyMaterial(StrictSecurityContract):
    ciphertext_b64: str = Field(min_length=1, max_length=32_768)
    nonce_b64: str = Field(min_length=1, max_length=64)
    kek_version: str = Field(min_length=1, max_length=300)
