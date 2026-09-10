"""Typed execute-only adapters for Security Baseline V1.3 workflows."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from lucy.contracts.security_v1_2 import SensitiveActionV2
from lucy.contracts.security_v1_3 import (
    Ed25519V13Signer,
    EncryptedEvidencePackageV2,
    ExecutorReceiptV2,
    SensitiveActionPermitV3,
    SensitiveExecutionGrantV2,
    V13ContractVerifier,
    V13SigningKeyPurpose,
)


class RealmWorkflowUnavailable(PermissionError):
    """A V1.3 workflow operation failed closed at its database boundary."""


class RealmOperationClaimResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: UUID
    replayed: bool


class RealmFrozenPackageResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    package: EncryptedEvidencePackageV2
    package_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    replayed: bool


class RealmReconciliationResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: UUID
    state: str = Field(min_length=1, max_length=40)
    result: str = Field(min_length=1, max_length=80)
    receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    finality_not_before: datetime | None = None
    replayed: bool


class RealmGrantAuthorityV1(BaseModel):
    """Content-free, realm-derived material required to construct one grant."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: UUID
    action: SensitiveActionV2
    claimed_at: datetime
    claim_idempotency_key: str = Field(min_length=1, max_length=512)
    permit: SensitiveActionPermitV3
    package_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    package_size_bytes: int = Field(ge=1, le=131_072)
    executor_binding_id: UUID
    caller_identity: str = Field(min_length=1, max_length=512)
    executor_identity: str = Field(min_length=1, max_length=512)
    executor_alias_arn: str = Field(min_length=1, max_length=300)
    executor_version: int = Field(ge=1)
    receipt_key_id: str = Field(min_length=1, max_length=512)
    deletion_manifest_id: UUID | None = None
    deletion_manifest_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    existing_grant: SensitiveExecutionGrantV2 | None = None

    @model_validator(mode="after")
    def validate_binding(self) -> RealmGrantAuthorityV1:
        if self.permit.operation_id != self.operation_id or self.permit.action != self.action:
            raise ValueError("grant authority permit binding differs")
        if self.package_size_bytes > self.permit.max_bytes:
            raise ValueError("grant authority package exceeds permit")
        deletion = self.action == SensitiveActionV2.EVIDENCE_DELETE
        if deletion != (self.deletion_manifest_id is not None) or deletion != (
            self.deletion_manifest_digest is not None
        ):
            raise ValueError("grant authority manifest binding differs")
        if deletion and self.deletion_manifest_digest != self.package_digest:
            raise ValueError("deletion authority package digest differs")
        if self.existing_grant is not None and (
            self.existing_grant.operation_id != self.operation_id
            or self.existing_grant.permit_id != self.permit.permit_id
            or self.existing_grant.action != self.action
            or self.existing_grant.encrypted_package_digest != self.package_digest
        ):
            raise ValueError("existing grant differs from authority")
        return self


class RealmPolicyStore(Protocol):
    def store_permit(self, permit: SensitiveActionPermitV3, idempotency_key: str) -> UUID: ...

    def store_grant(self, grant: SensitiveExecutionGrantV2) -> str: ...

    def grant_authority(self, operation_id: UUID) -> RealmGrantAuthorityV1: ...

    def attest_receipt(self, receipt: ExecutorReceiptV2) -> str: ...


class PostgresRealmPolicyStore:
    """Policy-login adapter exposing only exact security-definer functions."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def store_permit(self, permit: SensitiveActionPermitV3, idempotency_key: str) -> UUID:
        result = self._execute(
            "SELECT lucy.issue_sensitive_action_permit_v3(:contract,:key)",
            {"contract": permit.model_dump_json(), "key": idempotency_key},
        )
        try:
            return UUID(str(result))
        except ValueError as exc:
            raise RealmWorkflowUnavailable("policy permit result is invalid") from exc

    def store_grant(self, grant: SensitiveExecutionGrantV2) -> str:
        function = (
            "store_sensitive_execution_grant_v2"
            if grant.action == SensitiveActionV2.EVIDENCE_RETRIEVE
            else "store_deletion_execution_grant_v2"
        )
        return str(
            self._execute(
                f"SELECT lucy.{function}(:operation,:contract)",
                {"operation": grant.operation_id, "contract": grant.model_dump_json()},
            )
        )

    def grant_authority(self, operation_id: UUID) -> RealmGrantAuthorityV1:
        result = self._execute(
            "SELECT lucy.read_claimed_sensitive_authority_v1(:operation)",
            {"operation": operation_id},
        )
        authority = RealmGrantAuthorityV1.model_validate(result)
        if authority.operation_id != operation_id:
            raise RealmWorkflowUnavailable("grant authority operation differs")
        return authority

    def attest_receipt(self, receipt: ExecutorReceiptV2) -> str:
        function = (
            "attest_executor_receipt_v2"
            if receipt.action == SensitiveActionV2.EVIDENCE_RETRIEVE
            else "attest_deletion_executor_receipt_v2"
        )
        return str(
            self._execute(
                f"SELECT lucy.{function}(:operation,:contract)",
                {"operation": receipt.operation_id, "contract": receipt.model_dump_json()},
            )
        )

    def _execute(self, statement: str, parameters: dict[str, object]) -> object:
        try:
            with self._sessions.begin() as session:
                return session.execute(text(statement), parameters).scalar_one()
        except DBAPIError as exc:
            raise RealmWorkflowUnavailable("realm policy operation is unavailable") from exc


class VerifiedRealmPolicyAdapter:
    """Cryptographically verify every signed object before policy storage."""

    def __init__(
        self,
        store: RealmPolicyStore,
        *,
        verifier: V13ContractVerifier,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._verifier = verifier
        self._clock = clock or (lambda: datetime.now(UTC))

    def admit_permit(self, permit: SensitiveActionPermitV3, idempotency_key: str) -> UUID:
        self._verify(permit, V13SigningKeyPurpose.POLICY_NOTARY)
        stored = self._store.store_permit(permit, idempotency_key)
        if stored != permit.permit_id:
            raise RealmWorkflowUnavailable("stored permit differs from verified authority")
        return stored

    def admit_grant(self, grant: SensitiveExecutionGrantV2) -> str:
        self._verify(grant, V13SigningKeyPurpose.POLICY_NOTARY)
        digest = self._store.store_grant(grant)
        if digest != grant.unsigned_digest_hex():
            raise RealmWorkflowUnavailable("stored grant differs from verified authority")
        return digest

    def attest_receipt(self, receipt: ExecutorReceiptV2) -> str:
        purpose = (
            V13SigningKeyPurpose.RETRIEVAL_RECEIPT
            if receipt.action == SensitiveActionV2.EVIDENCE_RETRIEVE
            else V13SigningKeyPurpose.DELETION_RECEIPT
        )
        self._verify(receipt, purpose)
        digest = self._store.attest_receipt(receipt)
        if digest != receipt.unsigned_digest_hex():
            raise RealmWorkflowUnavailable("stored receipt differs from verified authority")
        return digest

    def _verify(
        self,
        contract: SensitiveActionPermitV3 | SensitiveExecutionGrantV2 | ExecutorReceiptV2,
        purpose: V13SigningKeyPurpose,
    ) -> None:
        self._verifier.verify(contract, expected_purpose=purpose, checked_at=self._clock())


class RealmPolicyGrantService:
    """Construct and persist an exact replay-safe post-claim execution grant."""

    def __init__(
        self,
        store: RealmPolicyStore,
        *,
        signer: Ed25519V13Signer,
        verifier: V13ContractVerifier,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._signer = signer
        self._verifier = verifier
        self._clock = clock or (lambda: datetime.now(UTC))

    def issue(self, operation_id: UUID) -> SensitiveExecutionGrantV2:
        authority = self._store.grant_authority(operation_id)
        now = self._clock()
        self._verifier.verify(
            authority.permit,
            expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
            checked_at=now,
        )
        if authority.existing_grant is not None:
            grant = authority.existing_grant
            self._verifier.verify(
                grant,
                expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
                checked_at=now,
            )
        else:
            if authority.permit.restore_mapping_id is not None:
                raise RealmWorkflowUnavailable("restore-mapped grant requires a later feature gate")
            unsigned = SensitiveExecutionGrantV2(
                key_id=authority.permit.key_id,
                issuer=authority.permit.issuer,
                environment=authority.permit.environment,
                issued_at=now,
                grant_id=uuid4(),
                action=authority.action,
                permit_id=authority.permit.permit_id,
                permit_digest=authority.permit.unsigned_digest_hex(),
                operation_id=authority.operation_id,
                caller_identity=authority.caller_identity,
                target_scope=authority.permit.target_scope,
                workspace_id=authority.permit.workspace_id,
                resource_selector=authority.permit.resource_selector,
                execution_binding=authority.permit.execution_binding,
                deletion_manifest_id=authority.deletion_manifest_id,
                deletion_manifest_digest=authority.deletion_manifest_digest,
                encrypted_package_digest=authority.package_digest,
                package_size_bytes=authority.package_size_bytes,
                idempotency_key=authority.claim_idempotency_key,
                executor_identity=authority.executor_identity,
                executor_alias_arn=authority.executor_alias_arn,
                executor_version=authority.executor_version,
                permit_claimed_at=authority.claimed_at,
                permit_claim_deadline=authority.permit.permit_claim_deadline,
                execution_completion_deadline=authority.permit.execution_completion_deadline,
                max_records=authority.permit.max_records,
                max_bytes=authority.permit.max_bytes,
                nonce=secrets.token_hex(16),
            )
            grant = self._signer.sign(unsigned)
        digest = self._store.store_grant(grant)
        if digest != grant.unsigned_digest_hex():
            raise RealmWorkflowUnavailable("stored grant differs from signed authority")
        return grant


class PostgresRealmWorkflowStore:
    """Workflow-login adapter; callers cannot select a realm or database role."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def claim(self, permit_id: UUID, idempotency_key: str) -> RealmOperationClaimResultV1:
        result = self._execute(
            "SELECT lucy.claim_sensitive_operation_v2(:permit,:key)",
            {"permit": permit_id, "key": idempotency_key},
        )
        return RealmOperationClaimResultV1.model_validate(result)

    def freeze_retrieval(self, operation_id: UUID) -> RealmFrozenPackageResultV1:
        result = self._execute(
            "SELECT lucy.freeze_claimed_evidence_package_v2(:operation)",
            {"operation": operation_id},
        )
        frozen = RealmFrozenPackageResultV1.model_validate(result)
        if frozen.package.operation_id != operation_id:
            raise RealmWorkflowUnavailable("frozen package operation differs")
        if frozen.package.package_digest_hex() != frozen.package_digest:
            raise RealmWorkflowUnavailable("frozen package digest differs")
        return frozen

    def reconcile(
        self, operation_id: UUID, action: SensitiveActionV2
    ) -> RealmReconciliationResultV1:
        function = (
            "reconcile_sensitive_operation_v2"
            if action == SensitiveActionV2.EVIDENCE_RETRIEVE
            else "reconcile_scoped_deletion_v2"
        )
        result = self._execute(
            f"SELECT lucy.{function}(:operation)", {"operation": operation_id}
        )
        reconciled = RealmReconciliationResultV1.model_validate(result)
        if reconciled.operation_id != operation_id:
            raise RealmWorkflowUnavailable("reconciled operation differs")
        return reconciled

    def _execute(self, statement: str, parameters: dict[str, object]) -> object:
        try:
            with self._sessions.begin() as session:
                return session.execute(text(statement), parameters).scalar_one()
        except DBAPIError as exc:
            raise RealmWorkflowUnavailable("realm workflow operation is unavailable") from exc
