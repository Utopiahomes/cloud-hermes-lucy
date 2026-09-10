"""Typed execute-only adapters for Security Baseline V1.3 workflows."""

from __future__ import annotations

import http.client
import json
import re
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from lucy.contracts.canonical import canonical_json_bytes
from lucy.contracts.security_v1_2 import SensitiveActionV2
from lucy.contracts.security_v1_3 import (
    DeletionTargetManifestV2,
    DeletionTargetReferenceV2,
    Ed25519V13Signer,
    EncryptedEvidencePackageV2,
    ExecutorReceiptV2,
    SensitiveActionPermitV3,
    SensitiveExecutionGrantV2,
    V13ContractVerifier,
    V13SigningKeyPurpose,
    deletion_targets_digest_v2,
)
from lucy.executors.models import (
    DeletionExecutorInvocationV2,
    ExecutorInvocationResultV2,
    RetrievalExecutorInvocationV2,
)
from lucy.scoped_deletion import ScopedDeletionManifestResult

_QUALIFIED_LAMBDA_ALIAS_ARN = re.compile(
    r"arn:(?:aws|aws-us-gov|aws-cn):lambda:[a-z0-9-]+:\d{12}:"
    r"function:[A-Za-z0-9-_]{1,64}:(?!\$LATEST\Z|[0-9]+\Z)[A-Za-z0-9-_]{1,128}\Z"
)


class RealmWorkflowUnavailable(PermissionError):
    """A V1.3 workflow operation failed closed at its database boundary."""


class RealmOperationClaimResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: UUID
    replayed: bool


class RealmOperationStatusV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: UUID
    action: SensitiveActionV2
    state: str = Field(min_length=1, max_length=40)
    result: str | None = Field(default=None, max_length=80)
    receipt_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    finality_not_before: datetime | None = None


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


class RealmDeletionAuthorityV1(BaseModel):
    """Exact content-free closure material for one claimed deletion operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: UUID
    action: SensitiveActionV2
    claimed_at: datetime
    claim_idempotency_key: str = Field(min_length=1, max_length=512)
    permit: SensitiveActionPermitV3
    root_evidence_id: UUID
    record_version: int = Field(ge=1)
    root_representation_id: UUID | None = None
    targets: tuple[DeletionTargetReferenceV2, ...] = ()
    target_count: int | None = Field(default=None, ge=1, le=90)
    targets_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    closure_version: int | None = Field(default=None, ge=1)
    tombstone_policy_version: int | None = Field(default=None, ge=1)
    finality_policy_version: int | None = Field(default=None, ge=1)
    existing_manifest: DeletionTargetManifestV2 | None = None

    @model_validator(mode="after")
    def validate_authority(self) -> RealmDeletionAuthorityV1:
        selector = self.permit.resource_selector
        if (
            self.action != SensitiveActionV2.EVIDENCE_DELETE
            or self.permit.action != self.action
            or self.permit.operation_id != self.operation_id
            or selector.object_id != self.root_evidence_id
            or selector.object_version != self.record_version
        ):
            raise ValueError("deletion authority binding differs")
        if self.existing_manifest is not None:
            manifest = self.existing_manifest
            if (
                manifest.operation_id != self.operation_id
                or manifest.permit_id != self.permit.permit_id
                or manifest.root_evidence_id != self.root_evidence_id
            ):
                raise ValueError("existing deletion manifest differs from authority")
            return self
        if (
            self.root_representation_id is None
            or self.target_count != len(self.targets)
            or self.targets_digest is None
            or self.targets_digest != deletion_targets_digest_v2(self.targets)
            or self.closure_version != 1
            or self.tombstone_policy_version != 1
            or self.finality_policy_version != 1
        ):
            raise ValueError("deletion authority closure differs")
        return self


class RealmPolicyStore(Protocol):
    def store_permit(self, permit: SensitiveActionPermitV3, idempotency_key: str) -> UUID: ...

    def store_grant(self, grant: SensitiveExecutionGrantV2) -> str: ...

    def grant_authority(self, operation_id: UUID) -> RealmGrantAuthorityV1: ...

    def deletion_authority(self, operation_id: UUID) -> RealmDeletionAuthorityV1: ...

    def store_manifest(
        self, manifest: DeletionTargetManifestV2
    ) -> ScopedDeletionManifestResult: ...

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

    def deletion_authority(self, operation_id: UUID) -> RealmDeletionAuthorityV1:
        result = self._execute(
            "SELECT lucy.read_claimed_deletion_authority_v1(:operation)",
            {"operation": operation_id},
        )
        authority = RealmDeletionAuthorityV1.model_validate(result)
        if authority.operation_id != operation_id:
            raise RealmWorkflowUnavailable("deletion authority operation differs")
        return authority

    def store_manifest(
        self, manifest: DeletionTargetManifestV2
    ) -> ScopedDeletionManifestResult:
        result = self._execute(
            "SELECT lucy.store_scoped_deletion_manifest_v3(:operation,:manifest)",
            {
                "operation": manifest.operation_id,
                "manifest": manifest.model_dump_json(),
            },
        )
        return ScopedDeletionManifestResult.model_validate(result)

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

    def issue_grant(self, operation_id: UUID) -> SensitiveExecutionGrantV2:
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


class RealmPolicyDeletionService:
    """Construct, sign, and freeze one exact replay-safe deletion manifest."""

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

    def prepare_manifest(self, operation_id: UUID) -> DeletionTargetManifestV2:
        authority = self._store.deletion_authority(operation_id)
        now = self._clock()
        self._verifier.verify(
            authority.permit,
            expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
            checked_at=now,
        )
        if authority.existing_manifest is not None:
            manifest = authority.existing_manifest
            self._verifier.verify(
                manifest,
                expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
                checked_at=now,
            )
            return manifest
        assert authority.root_representation_id is not None
        assert authority.target_count is not None
        assert authority.targets_digest is not None
        assert authority.closure_version is not None
        assert authority.tombstone_policy_version is not None
        assert authority.finality_policy_version is not None
        permit = authority.permit
        unsigned = DeletionTargetManifestV2(
            key_id=permit.key_id,
            issuer=permit.issuer,
            environment=permit.environment,
            issued_at=now,
            manifest_id=uuid4(),
            permit_id=permit.permit_id,
            permit_digest=permit.unsigned_digest_hex(),
            operation_id=authority.operation_id,
            target_scope=permit.target_scope,
            workspace_id=permit.workspace_id,
            root_evidence_id=authority.root_evidence_id,
            root_representation_id=authority.root_representation_id,
            owner_assertion_id=permit.owner_assertion_id,
            owner_assertion_digest=permit.owner_assertion_digest,
            idempotency_key=authority.claim_idempotency_key,
            closure_version=authority.closure_version,
            targets=authority.targets,
            target_count=authority.target_count,
            targets_digest=authority.targets_digest,
            tombstone_policy_version=authority.tombstone_policy_version,
            finality_policy_version=authority.finality_policy_version,
            permit_claim_deadline=permit.permit_claim_deadline,
            execution_completion_deadline=permit.execution_completion_deadline,
            nonce=secrets.token_hex(16),
        )
        manifest = self._signer.sign(unsigned)
        frozen = self._store.store_manifest(manifest)
        if (
            frozen.manifest_id != manifest.manifest_id
            or frozen.manifest_digest != manifest.unsigned_digest_hex()
            or frozen.targets_digest != manifest.targets_digest
            or frozen.target_count != manifest.target_count
        ):
            raise RealmWorkflowUnavailable(
                "stored deletion manifest differs from signed authority"
            )
        return manifest


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

    def status(self, operation_id: UUID) -> RealmOperationStatusV1:
        result = self._execute(
            "SELECT lucy.read_sensitive_operation_status_v1(:operation)",
            {"operation": operation_id},
        )
        status = RealmOperationStatusV1.model_validate(result)
        if status.operation_id != operation_id:
            raise RealmWorkflowUnavailable("operation status differs")
        return status

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


class RealmLambdaExecutorInvoker:
    """Invoke one exact realm executor alias and validate its bounded response."""

    def __init__(
        self,
        client: Any,
        *,
        retrieval_alias_arn: str | None = None,
        deletion_alias_arn: str | None = None,
    ) -> None:
        if (retrieval_alias_arn is None) == (deletion_alias_arn is None):
            raise ValueError("one realm executor alias must be configured")
        configured_alias = retrieval_alias_arn or deletion_alias_arn
        if (
            configured_alias is None
            or _QUALIFIED_LAMBDA_ALIAS_ARN.fullmatch(configured_alias) is None
        ):
            raise ValueError("realm executor requires an exact non-version Lambda alias ARN")
        self._client = client
        self._retrieval_alias = retrieval_alias_arn
        self._deletion_alias = deletion_alias_arn

    def invoke_retrieval(
        self, invocation: RetrievalExecutorInvocationV2
    ) -> ExecutorInvocationResultV2:
        if self._retrieval_alias is None:
            raise RealmWorkflowUnavailable("realm retrieval executor is not configured")
        return self._invoke(
            self._retrieval_alias, invocation, SensitiveActionV2.EVIDENCE_RETRIEVE
        )

    def invoke_deletion(
        self, invocation: DeletionExecutorInvocationV2
    ) -> ExecutorInvocationResultV2:
        if self._deletion_alias is None:
            raise RealmWorkflowUnavailable("realm deletion executor is not configured")
        return self._invoke(
            self._deletion_alias, invocation, SensitiveActionV2.EVIDENCE_DELETE
        )

    def _invoke(
        self,
        alias: str,
        invocation: RetrievalExecutorInvocationV2 | DeletionExecutorInvocationV2,
        action: SensitiveActionV2,
    ) -> ExecutorInvocationResultV2:
        if invocation.execution_grant.executor_alias_arn != alias:
            raise RealmWorkflowUnavailable("realm executor alias differs from grant")
        try:
            response = self._client.invoke(
                FunctionName=alias,
                InvocationType="RequestResponse",
                Payload=canonical_json_bytes(invocation),
            )
        except Exception as exc:
            raise RealmWorkflowUnavailable("realm executor invocation failed") from exc
        if response.get("StatusCode") != 200 or response.get("FunctionError"):
            raise RealmWorkflowUnavailable("realm executor invocation failed")
        if response.get("ExecutedVersion") != str(invocation.execution_grant.executor_version):
            raise RealmWorkflowUnavailable("realm executor version differs")
        stream = response.get("Payload")
        raw = stream.read() if hasattr(stream, "read") else stream
        if not isinstance(raw, bytes) or len(raw) > 6_000_000:
            raise RealmWorkflowUnavailable("realm executor response is invalid")
        try:
            envelope = json.loads(raw)
            if not isinstance(envelope, dict) or envelope.get("ok") is not True:
                raise RealmWorkflowUnavailable("realm executor rejected the invocation")
            result = ExecutorInvocationResultV2.model_validate(envelope.get("result"))
        except RealmWorkflowUnavailable:
            raise
        except (ValueError, TypeError) as exc:
            raise RealmWorkflowUnavailable("realm executor response is invalid") from exc
        if result.action != action:
            raise RealmWorkflowUnavailable("realm executor action differs")
        return result


class RealmRetrievalWorkflowResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: UUID
    state: str = Field(min_length=1, max_length=40)
    receipt_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    plaintext_b64: str | None = Field(default=None, max_length=90_000)
    executor_replayed: bool


class RealmDeletionWorkflowResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: UUID
    state: str = Field(min_length=1, max_length=40)
    receipt_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    finality_not_before: datetime | None = None
    executor_replayed: bool


class RealmPolicyClient(Protocol):
    def prepare_deletion_manifest(
        self, operation_id: UUID
    ) -> DeletionTargetManifestV2: ...

    def issue_grant(self, operation_id: UUID) -> SensitiveExecutionGrantV2: ...

    def attest_receipt(self, receipt: ExecutorReceiptV2) -> str: ...


class HttpRealmPolicyClient:
    """Bounded private-network V1.3 policy client with no caller-selected URL."""

    def __init__(self, hostport: str, token: str, *, timeout_seconds: int = 15) -> None:
        match = re.fullmatch(
            r"([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?):([0-9]{2,5})", hostport
        )
        if match is None or not token or timeout_seconds not in range(1, 31):
            raise ValueError("private realm policy client configuration is invalid")
        port = int(match.group(2))
        if port > 65_535:
            raise ValueError("private realm policy client port is invalid")
        self._host = match.group(1)
        self._port = port
        self._token = token
        self._timeout = timeout_seconds

    def issue_grant(self, operation_id: UUID) -> SensitiveExecutionGrantV2:
        payload = self._post(
            f"/internal/v3/security/operations/{operation_id}/grant", {}
        )
        return SensitiveExecutionGrantV2.model_validate(payload)

    def prepare_deletion_manifest(
        self, operation_id: UUID
    ) -> DeletionTargetManifestV2:
        payload = self._post(
            f"/internal/v3/security/operations/{operation_id}/deletion-manifest", {}
        )
        return DeletionTargetManifestV2.model_validate(payload)

    def attest_receipt(self, receipt: ExecutorReceiptV2) -> str:
        payload = self._post(
            f"/internal/v3/security/operations/{receipt.operation_id}/receipt-attestation",
            receipt.model_dump(mode="json"),
        )
        digest = payload.get("receipt_digest") if isinstance(payload, dict) else None
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise RealmWorkflowUnavailable("realm policy response is invalid")
        return digest

    def _post(self, path: str, payload: dict[str, Any]) -> Any:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(body) > 262_144:
            raise RealmWorkflowUnavailable("realm policy request is too large")
        connection = http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)
        try:
            connection.request(
                "POST",
                path,
                body=body,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                },
            )
            response = connection.getresponse()
            raw = response.read(262_145)
        except (OSError, http.client.HTTPException) as exc:
            raise RealmWorkflowUnavailable("realm policy is unavailable") from exc
        finally:
            connection.close()
        if response.status != 200:
            raise RealmWorkflowUnavailable("realm policy rejected the operation")
        if len(raw) > 262_144:
            raise RealmWorkflowUnavailable("realm policy response is too large")
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise RealmWorkflowUnavailable("realm policy response is invalid") from exc


class RealmRetrievalCoordinator:
    """Choreograph one exact scoped retrieval across DB, policy, and Lambda."""

    def __init__(
        self,
        workflow: PostgresRealmWorkflowStore,
        policy: RealmPolicyClient,
        executor: RealmLambdaExecutorInvoker,
    ) -> None:
        self._workflow = workflow
        self._policy = policy
        self._executor = executor

    def execute(
        self, permit: SensitiveActionPermitV3, *, idempotency_key: str
    ) -> RealmRetrievalWorkflowResultV1:
        if permit.action != SensitiveActionV2.EVIDENCE_RETRIEVE:
            raise RealmWorkflowUnavailable("retrieval permit required")
        claim = self._workflow.claim(permit.permit_id, idempotency_key)
        if claim.operation_id != permit.operation_id:
            raise RealmWorkflowUnavailable("claimed operation differs from permit")
        status = self._workflow.status(claim.operation_id)
        if status.action != permit.action:
            raise RealmWorkflowUnavailable("operation action differs from permit")
        if status.state in {"RECONCILED", "REJECTED"}:
            return RealmRetrievalWorkflowResultV1(
                operation_id=status.operation_id,
                state=status.state,
                receipt_digest=status.receipt_digest,
                plaintext_b64=None,
                executor_replayed=True,
            )
        if status.state != "CLAIMED":
            raise RealmWorkflowUnavailable("retrieval operation state is unavailable")
        frozen = self._workflow.freeze_retrieval(claim.operation_id)
        grant = self._policy.issue_grant(claim.operation_id)
        result = self._executor.invoke_retrieval(
            RetrievalExecutorInvocationV2(
                permit=permit,
                execution_grant=grant,
                package=frozen.package,
            )
        )
        self._policy.attest_receipt(result.receipt)
        reconciled = self._workflow.reconcile(
            claim.operation_id, SensitiveActionV2.EVIDENCE_RETRIEVE
        )
        return RealmRetrievalWorkflowResultV1(
            operation_id=reconciled.operation_id,
            state=reconciled.state,
            receipt_digest=reconciled.receipt_digest,
            plaintext_b64=result.plaintext_b64,
            executor_replayed=result.replayed,
        )


class RealmDeletionCoordinator:
    """Choreograph one exact scoped deletion across DB, policy, and Lambda."""

    _TERMINAL_STATES = {
        "REJECTED",
        "FINALITY_PENDING",
        "FINALITY_EXTENDED",
        "FINALITY_VERIFIED",
    }

    def __init__(
        self,
        workflow: PostgresRealmWorkflowStore,
        policy: RealmPolicyClient,
        executor: RealmLambdaExecutorInvoker,
    ) -> None:
        self._workflow = workflow
        self._policy = policy
        self._executor = executor

    def execute(
        self, permit: SensitiveActionPermitV3, *, idempotency_key: str
    ) -> RealmDeletionWorkflowResultV1:
        if permit.action != SensitiveActionV2.EVIDENCE_DELETE:
            raise RealmWorkflowUnavailable("deletion permit required")
        claim = self._workflow.claim(permit.permit_id, idempotency_key)
        if claim.operation_id != permit.operation_id:
            raise RealmWorkflowUnavailable("claimed operation differs from permit")
        status = self._workflow.status(claim.operation_id)
        if status.action != permit.action:
            raise RealmWorkflowUnavailable("operation action differs from permit")
        if status.state in self._TERMINAL_STATES:
            return RealmDeletionWorkflowResultV1(
                operation_id=status.operation_id,
                state=status.state,
                receipt_digest=status.receipt_digest,
                finality_not_before=status.finality_not_before,
                executor_replayed=True,
            )
        if status.state != "CLAIMED":
            raise RealmWorkflowUnavailable("deletion operation state is unavailable")
        manifest = self._policy.prepare_deletion_manifest(claim.operation_id)
        if (
            manifest.operation_id != claim.operation_id
            or manifest.permit_id != permit.permit_id
            or manifest.root_evidence_id != permit.resource_selector.object_id
        ):
            raise RealmWorkflowUnavailable("deletion manifest differs from permit")
        grant = self._policy.issue_grant(claim.operation_id)
        result = self._executor.invoke_deletion(
            DeletionExecutorInvocationV2(
                permit=permit,
                execution_grant=grant,
                manifest=manifest,
            )
        )
        self._policy.attest_receipt(result.receipt)
        reconciled = self._workflow.reconcile(
            claim.operation_id, SensitiveActionV2.EVIDENCE_DELETE
        )
        return RealmDeletionWorkflowResultV1(
            operation_id=reconciled.operation_id,
            state=reconciled.state,
            receipt_digest=reconciled.receipt_digest,
            finality_not_before=reconciled.finality_not_before,
            executor_replayed=result.replayed,
        )
