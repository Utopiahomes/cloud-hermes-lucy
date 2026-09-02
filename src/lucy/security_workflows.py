"""Security Baseline v1.2 policy and untrusted workflow choreography.

The evidence/deletion coordinators deliberately know how to call only named
PostgreSQL functions, the content-free policy notary, and one exact Lambda
alias. They never receive KMS or DynamoDB clients.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

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
    OwnerInteractionAssertionV1,
    RetrievalOperationState,
    SensitiveActionPermitV2,
    SensitiveActionV2,
    SensitiveExecutionGrantV1,
    SensitiveReasonCode,
    SigningKeyPurpose,
    deletion_targets_digest,
)
from lucy.executors.models import (
    DeletionExecutorInvocationV1,
    ExecutorInvocationResultV1,
    RetrievalExecutorInvocationV1,
)

_ID_NAMESPACE = UUID("0d2bc15d-ec95-5fe6-a87c-f444b4b80a76")
_EXECUTION_WINDOW = timedelta(minutes=10)
_QUALIFIED_LAMBDA_ALIAS_ARN = re.compile(
    r"arn:(?:aws|aws-us-gov|aws-cn):lambda:[a-z0-9-]+:\d{12}:"
    r"function:[A-Za-z0-9-_]{1,64}:[A-Za-z0-9-_]{1,128}"
)


class WorkflowRejected(RuntimeError):
    """Content-free workflow denial suitable for an internal API response."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _WorkflowModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RetrievalClaimV1(_WorkflowModel):
    operation_id: UUID
    package: EncryptedEvidencePackageV1
    package_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_deadline: datetime
    state: RetrievalOperationState = RetrievalOperationState.CLAIMED
    receipt_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    replayed: bool

    @model_validator(mode="after")
    def validate_package(self) -> RetrievalClaimV1:
        if self.package.operation_id != self.operation_id:
            raise ValueError("retrieval claim operation binding differs")
        if self.package.package_digest_hex() != self.package_digest:
            raise ValueError("retrieval claim package digest differs")
        return self


class DeletionClaimV1(_WorkflowModel):
    operation_id: UUID
    manifest: DeletionTargetManifestV1
    package_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_deadline: datetime
    state: DeletionOperationState = DeletionOperationState.CLAIMED
    receipt_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    replayed: bool

    @model_validator(mode="after")
    def validate_manifest(self) -> DeletionClaimV1:
        if self.manifest.unsigned_digest_hex() != self.package_digest:
            raise ValueError("deletion claim manifest digest differs")
        return self


class ClaimDigestV1(_WorkflowModel):
    operation_id: UUID
    action: SensitiveActionV2
    permit_id: UUID
    permit_nonce: str
    evidence_id: UUID
    manifest_id: UUID | None
    manifest_digest: str | None
    package_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    package_size_bytes: int = Field(ge=1, le=131_072)
    database_session_user: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=512)
    record_version: int = Field(ge=1)
    storage_epoch: int = Field(ge=1)
    registry_epoch: int = Field(ge=1)
    key_epoch: int = Field(ge=1)
    environment: DeploymentEnvironment
    permit_claim_deadline: datetime
    execution_deadline: datetime


class DeletionScopeDraftV1(_WorkflowModel):
    manifest_id: UUID
    permit_id: UUID
    root_evidence_id: UUID
    idempotency_key: str
    scope_version: int = Field(ge=1)
    root_record_version: int = Field(ge=1)
    target_count: int = Field(ge=1)
    targets: tuple[DeletionTargetReferenceV1, ...]
    permit_claim_deadline: datetime
    execution_deadline: datetime
    state: str
    storage_epoch: int = Field(ge=1)
    registry_epoch: int = Field(ge=1)
    key_epoch: int = Field(ge=1)
    owner_assertion_id: UUID
    owner_assertion_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    permit_nonce: str


class RetrievalWorkflowResultV1(_WorkflowModel):
    operation_id: UUID
    state: RetrievalOperationState
    receipt_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    plaintext_b64: str | None = None
    executor_replayed: bool


class DeletionWorkflowResultV1(_WorkflowModel):
    operation_id: UUID
    state: DeletionOperationState
    derived_summary: dict[str, int] | None = None
    executor_replayed: bool


@dataclass(frozen=True)
class ExecutorBindingV1:
    action: SensitiveActionV2
    environment: DeploymentEnvironment
    executor_identity: str
    executor_alias_arn: str
    executor_version: int

    def __post_init__(self) -> None:
        if self.executor_version < 1 or not all(
            value.strip() for value in (self.executor_identity, self.executor_alias_arn)
        ):
            raise ValueError("executor binding is incomplete")
        if _QUALIFIED_LAMBDA_ALIAS_ARN.fullmatch(self.executor_alias_arn) is None:
            raise ValueError("executor binding requires an exact qualified Lambda alias ARN")


class SecurityWorkflowStore(Protocol):
    def issue_permit(
        self,
        assertion: OwnerInteractionAssertionV1,
        permit: SensitiveActionPermitV2,
        idempotency_key: str,
    ) -> UUID: ...

    def prepare_deletion_scope(
        self, manifest_id: UUID, permit_id: UUID, idempotency_key: str
    ) -> DeletionScopeDraftV1: ...

    def finalize_deletion_scope(
        self, unsigned: DeletionTargetManifestV1, signed: DeletionTargetManifestV1
    ) -> str: ...

    def claim_retrieval(
        self, permit: SensitiveActionPermitV2, idempotency_key: str
    ) -> RetrievalClaimV1: ...

    def claim_deletion(
        self,
        permit: SensitiveActionPermitV2,
        manifest: DeletionTargetManifestV1,
        idempotency_key: str,
    ) -> DeletionClaimV1: ...

    def read_claim_digest(self, operation_id: UUID) -> ClaimDigestV1: ...

    def store_execution_grant(
        self, operation_id: UUID, grant: SensitiveExecutionGrantV1
    ) -> str: ...

    def attest_executor_receipt(self, operation_id: UUID, receipt: ExecutorReceiptV1) -> str: ...

    def reconcile_retrieval(self, operation_id: UUID) -> RetrievalOperationState: ...

    def record_delivery(
        self, operation_id: UUID, outcome: str
    ) -> RetrievalOperationState: ...

    def reconcile_deletion(self, operation_id: UUID) -> dict[str, Any]: ...


class SqlSecurityWorkflowStore:
    """Named-function-only adapter usable by each exact PostgreSQL login."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def issue_permit(
        self,
        assertion: OwnerInteractionAssertionV1,
        permit: SensitiveActionPermitV2,
        idempotency_key: str,
    ) -> UUID:
        value = self._scalar(
            "SELECT lucy.issue_sensitive_action_permit_v2("
            "CAST(:assertion AS jsonb),CAST(:permit AS jsonb),:idempotency_key)",
            assertion=_json_contract(assertion),
            permit=_json_contract(permit),
            idempotency_key=idempotency_key,
        )
        return UUID(str(value))

    def prepare_deletion_scope(
        self, manifest_id: UUID, permit_id: UUID, idempotency_key: str
    ) -> DeletionScopeDraftV1:
        value = self._scalar(
            "SELECT lucy.prepare_deletion_scope_v1("
            ":manifest_id,:permit_id,:idempotency_key)",
            manifest_id=manifest_id,
            permit_id=permit_id,
            idempotency_key=idempotency_key,
        )
        return DeletionScopeDraftV1.model_validate(value)

    def finalize_deletion_scope(
        self, unsigned: DeletionTargetManifestV1, signed: DeletionTargetManifestV1
    ) -> str:
        return str(
            self._scalar(
                "SELECT lucy.finalize_deletion_scope_v1("
                ":manifest_id,CAST(:unsigned AS jsonb),CAST(:signed AS jsonb))",
                manifest_id=signed.manifest_id,
                unsigned=_json_contract(unsigned),
                signed=_json_contract(signed),
            )
        )

    def claim_retrieval(
        self, permit: SensitiveActionPermitV2, idempotency_key: str
    ) -> RetrievalClaimV1:
        value = self._scalar(
            "SELECT lucy.claim_evidence_retrieval_v1("
            "CAST(:permit AS jsonb),:idempotency_key)",
            permit=_json_contract(permit),
            idempotency_key=idempotency_key,
        )
        return RetrievalClaimV1.model_validate(value)

    def claim_deletion(
        self,
        permit: SensitiveActionPermitV2,
        manifest: DeletionTargetManifestV1,
        idempotency_key: str,
    ) -> DeletionClaimV1:
        value = self._scalar(
            "SELECT lucy.claim_evidence_deletion_v1("
            "CAST(:permit AS jsonb),CAST(:manifest AS jsonb),:idempotency_key)",
            permit=_json_contract(permit),
            manifest=_json_contract(manifest),
            idempotency_key=idempotency_key,
        )
        return DeletionClaimV1.model_validate(value)

    def read_claim_digest(self, operation_id: UUID) -> ClaimDigestV1:
        value = self._scalar(
            "SELECT lucy.read_claim_digest_for_notary_v1(:operation_id)",
            operation_id=operation_id,
        )
        return ClaimDigestV1.model_validate(value)

    def store_execution_grant(
        self, operation_id: UUID, grant: SensitiveExecutionGrantV1
    ) -> str:
        return str(
            self._scalar(
                "SELECT lucy.store_sensitive_execution_grant_v1("
                ":operation_id,CAST(:grant AS jsonb))",
                operation_id=operation_id,
                grant=_json_contract(grant),
            )
        )

    def attest_executor_receipt(self, operation_id: UUID, receipt: ExecutorReceiptV1) -> str:
        return str(
            self._scalar(
                "SELECT lucy.attest_executor_receipt_v1("
                ":operation_id,CAST(:receipt AS jsonb))",
                operation_id=operation_id,
                receipt=_json_contract(receipt),
            )
        )

    def reconcile_retrieval(self, operation_id: UUID) -> RetrievalOperationState:
        value = self._scalar(
            "SELECT lucy.reconcile_evidence_retrieval_v1(:operation_id)",
            operation_id=operation_id,
        )
        return RetrievalOperationState(str(value))

    def record_delivery(self, operation_id: UUID, outcome: str) -> RetrievalOperationState:
        value = self._scalar(
            "SELECT lucy.record_evidence_delivery_v1(:operation_id,:outcome)",
            operation_id=operation_id,
            outcome=outcome,
        )
        return RetrievalOperationState(str(value))

    def reconcile_deletion(self, operation_id: UUID) -> dict[str, Any]:
        value = self._scalar(
            "SELECT lucy.reconcile_evidence_deletion_v1(:operation_id)",
            operation_id=operation_id,
        )
        if not isinstance(value, dict):
            raise ValueError("deletion reconciliation did not return an object")
        return cast(dict[str, Any], value)

    def _scalar(self, statement: str, **parameters: object) -> object:
        with self._sessions.begin() as session:
            value = session.scalar(text(statement), parameters)
        if value is None:
            raise ValueError("security workflow function returned no result")
        return value


class PolicyNotaryClient(Protocol):
    def notarize_operation(self, operation_id: UUID) -> SensitiveExecutionGrantV1: ...

    def attest_receipt(self, operation_id: UUID, receipt: ExecutorReceiptV1) -> str: ...


class HttpPolicyNotaryClient:
    """Bounded private-network client with no redirects or external URL input."""

    def __init__(self, hostport: str, token: str, *, timeout_seconds: int = 15) -> None:
        match = re.fullmatch(r"([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?):([0-9]{2,5})", hostport)
        if match is None or not token or timeout_seconds not in range(1, 31):
            raise ValueError("private policy client configuration is invalid")
        port = int(match.group(2))
        if port > 65_535:
            raise ValueError("private policy client port is invalid")
        self._host = match.group(1)
        self._port = port
        self._token = token
        self._timeout = timeout_seconds

    def notarize_operation(self, operation_id: UUID) -> SensitiveExecutionGrantV1:
        payload = self._post(
            f"/internal/v2/security/operations/{operation_id}/grant",
            {},
        )
        return SensitiveExecutionGrantV1.model_validate(payload)

    def attest_receipt(self, operation_id: UUID, receipt: ExecutorReceiptV1) -> str:
        payload = self._post(
            f"/internal/v2/security/operations/{operation_id}/receipt-attestation",
            receipt.model_dump(mode="json"),
        )
        digest = payload.get("receipt_digest") if isinstance(payload, dict) else None
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise WorkflowRejected("policy_response_invalid")
        return digest

    def prepare_deletion_manifest(
        self,
        permit: SensitiveActionPermitV2,
        *,
        idempotency_key: str,
    ) -> DeletionTargetManifestV1:
        payload = self._post(
            "/internal/v2/security/deletion-manifests",
            {
                "permit": permit.model_dump(mode="json"),
                "idempotency_key": idempotency_key,
            },
        )
        return DeletionTargetManifestV1.model_validate(payload)

    def _post(self, path: str, payload: dict[str, Any]) -> Any:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(body) > 262_144:
            raise WorkflowRejected("policy_request_too_large")
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
            raise WorkflowRejected("policy_unavailable") from exc
        finally:
            connection.close()
        if response.status != 200:
            raise WorkflowRejected("policy_rejected")
        if len(raw) > 262_144:
            raise WorkflowRejected("policy_response_too_large")
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise WorkflowRejected("policy_response_invalid") from exc


class ExecutorInvoker(Protocol):
    def invoke_retrieval(
        self, invocation: RetrievalExecutorInvocationV1
    ) -> ExecutorInvocationResultV1: ...

    def invoke_deletion(
        self, invocation: DeletionExecutorInvocationV1
    ) -> ExecutorInvocationResultV1: ...


class PolicyNotaryService:
    def __init__(
        self,
        store: SecurityWorkflowStore,
        *,
        owner_trust_store: ContractTrustStore,
        receipt_trust_store: ContractTrustStore,
        signer: Ed25519ContractSigner,
        issuer: str,
        environment: DeploymentEnvironment,
        bindings: tuple[ExecutorBindingV1, ...],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._owner_trust = owner_trust_store
        self._receipt_trust = receipt_trust_store
        self._signer = signer
        self._issuer = issuer
        self._environment = environment
        self._bindings = {binding.action: binding for binding in bindings}
        if set(self._bindings) != {
            SensitiveActionV2.EVIDENCE_RETRIEVE,
            SensitiveActionV2.EVIDENCE_DELETE,
        }:
            raise ValueError("policy requires one exact binding for each sensitive action")
        if any(binding.environment != environment for binding in bindings):
            raise ValueError("policy executor binding environment differs")
        self._clock = clock or (lambda: datetime.now(UTC))

    def issue_permit(
        self,
        assertion: OwnerInteractionAssertionV1,
        *,
        reason: SensitiveReasonCode,
        record_version: int,
        idempotency_key: str,
    ) -> SensitiveActionPermitV2:
        now = self._clock()
        self._owner_trust.verify(
            assertion,
            purpose=SigningKeyPurpose.OWNER_BROKER,
            environment=self._environment,
            now=now,
        )
        if assertion.evidence_id is None:
            raise WorkflowRejected("evidence_id_required")
        permit_id = uuid5(
            _ID_NAMESPACE,
            f"permit:{assertion.assertion_id}:{idempotency_key}",
        )
        nonce = hashlib.sha256(
            b"lucy-sensitive-permit-v2\0"
            + assertion.canonical_unsigned_bytes()
            + b"\0"
            + idempotency_key.encode("utf-8")
        ).hexdigest()
        max_records = 1 if assertion.requested_action == SensitiveActionV2.EVIDENCE_RETRIEVE else 90
        max_bytes = 65_536 if max_records == 1 else 131_072
        unsigned = SensitiveActionPermitV2(
            key_id=self._signer.key_id,
            issuer=self._issuer,
            environment=self._environment,
            issued_at=assertion.issued_at,
            storage_epoch=assertion.storage_epoch,
            registry_epoch=assertion.registry_epoch,
            key_epoch=assertion.key_epoch,
            permit_id=permit_id,
            action=assertion.requested_action,
            owner_subject=assertion.owner_subject,
            owner_assertion_id=assertion.assertion_id,
            owner_assertion_digest=assertion.unsigned_digest_hex(),
            evidence_id=assertion.evidence_id,
            reason=reason,
            max_records=max_records,
            max_bytes=max_bytes,
            record_version=record_version,
            permit_claim_deadline=assertion.expires_at,
            nonce=nonce,
            signature="",
        )
        permit = self._signer.sign(unsigned)
        if self._store.issue_permit(assertion, permit, idempotency_key) != permit.permit_id:
            raise WorkflowRejected("permit_storage_binding_mismatch")
        return permit

    def prepare_deletion_manifest(
        self,
        permit: SensitiveActionPermitV2,
        *,
        idempotency_key: str,
    ) -> DeletionTargetManifestV1:
        if permit.action != SensitiveActionV2.EVIDENCE_DELETE:
            raise WorkflowRejected("deletion_permit_required")
        manifest_id = uuid5(
            _ID_NAMESPACE,
            f"manifest:{permit.permit_id}:{idempotency_key}",
        )
        scope = self._store.prepare_deletion_scope(
            manifest_id,
            permit.permit_id,
            idempotency_key,
        )
        if scope.state == "BULK_REQUIRED" or scope.target_count > 90:
            raise WorkflowRejected("bulk_required")
        if (
            scope.permit_id != permit.permit_id
            or scope.permit_nonce != permit.nonce
            or scope.root_evidence_id != permit.evidence_id
        ):
            raise WorkflowRejected("deletion_scope_binding_mismatch")
        issued_at = scope.execution_deadline - _EXECUTION_WINDOW
        unsigned = DeletionTargetManifestV1(
            key_id=self._signer.key_id,
            issuer=self._issuer,
            environment=self._environment,
            issued_at=issued_at,
            storage_epoch=scope.storage_epoch,
            registry_epoch=scope.registry_epoch,
            key_epoch=scope.key_epoch,
            manifest_id=scope.manifest_id,
            permit_id=scope.permit_id,
            permit_nonce=scope.permit_nonce,
            root_evidence_id=scope.root_evidence_id,
            owner_assertion_id=scope.owner_assertion_id,
            owner_assertion_digest=scope.owner_assertion_digest,
            idempotency_key=scope.idempotency_key,
            scope_version=scope.scope_version,
            root_record_version=scope.root_record_version,
            targets=scope.targets,
            target_count=scope.target_count,
            targets_digest=deletion_targets_digest(scope.targets),
            permit_claim_deadline=scope.permit_claim_deadline,
            execution_deadline=scope.execution_deadline,
            signature="",
        )
        signed = self._signer.sign(unsigned)
        digest = self._store.finalize_deletion_scope(unsigned, signed)
        if digest != signed.unsigned_digest_hex():
            raise WorkflowRejected("manifest_storage_binding_mismatch")
        return signed

    def notarize_operation(self, operation_id: UUID) -> SensitiveExecutionGrantV1:
        claim = self._store.read_claim_digest(operation_id)
        binding = self._bindings[claim.action]
        issued_at = claim.execution_deadline - _EXECUTION_WINDOW
        unsigned = SensitiveExecutionGrantV1(
            key_id=self._signer.key_id,
            issuer=self._issuer,
            environment=claim.environment,
            issued_at=issued_at,
            storage_epoch=claim.storage_epoch,
            registry_epoch=claim.registry_epoch,
            key_epoch=claim.key_epoch,
            grant_id=uuid5(_ID_NAMESPACE, f"grant:{claim.operation_id}"),
            action=claim.action,
            permit_id=claim.permit_id,
            permit_nonce=claim.permit_nonce,
            operation_id=claim.operation_id,
            database_session_user=claim.database_session_user,
            evidence_id=claim.evidence_id,
            deletion_manifest_id=claim.manifest_id,
            deletion_manifest_digest=claim.manifest_digest,
            encrypted_package_digest=claim.package_digest,
            package_size_bytes=claim.package_size_bytes,
            idempotency_key=claim.idempotency_key,
            record_version=claim.record_version,
            executor_identity=binding.executor_identity,
            executor_alias_arn=binding.executor_alias_arn,
            executor_version=binding.executor_version,
            permit_claim_deadline=claim.permit_claim_deadline,
            execution_deadline=claim.execution_deadline,
            signature="",
        )
        grant = self._signer.sign(unsigned)
        if self._store.store_execution_grant(operation_id, grant) != grant.unsigned_digest_hex():
            raise WorkflowRejected("grant_storage_binding_mismatch")
        return grant

    def attest_receipt(self, operation_id: UUID, receipt: ExecutorReceiptV1) -> str:
        purpose = (
            SigningKeyPurpose.RETRIEVAL_RECEIPT
            if receipt.action == SensitiveActionV2.EVIDENCE_RETRIEVE
            else SigningKeyPurpose.DELETION_RECEIPT
        )
        self._receipt_trust.verify(
            receipt,
            purpose=purpose,
            environment=self._environment,
            now=self._clock(),
        )
        digest = receipt.unsigned_digest_hex()
        if self._store.attest_executor_receipt(operation_id, receipt) != digest:
            raise WorkflowRejected("receipt_storage_binding_mismatch")
        return digest


class BotoLambdaExecutorInvoker:
    """Invoke only the aliases supplied by the caller role's exact IAM policy."""

    def __init__(
        self,
        client: Any,
        *,
        retrieval_alias_arn: str | None = None,
        deletion_alias_arn: str | None = None,
    ) -> None:
        if (retrieval_alias_arn is None) == (deletion_alias_arn is None):
            raise ValueError("one executor alias must be configured per Render caller")
        configured_alias = retrieval_alias_arn or deletion_alias_arn
        if (
            configured_alias is None
            or _QUALIFIED_LAMBDA_ALIAS_ARN.fullmatch(configured_alias) is None
        ):
            raise ValueError("executor caller requires an exact qualified Lambda alias ARN")
        self._client = client
        self._retrieval_alias = retrieval_alias_arn
        self._deletion_alias = deletion_alias_arn

    def invoke_retrieval(
        self, invocation: RetrievalExecutorInvocationV1
    ) -> ExecutorInvocationResultV1:
        if self._retrieval_alias is None:
            raise WorkflowRejected("retrieval_executor_not_configured")
        return self._invoke(self._retrieval_alias, invocation, SensitiveActionV2.EVIDENCE_RETRIEVE)

    def invoke_deletion(
        self, invocation: DeletionExecutorInvocationV1
    ) -> ExecutorInvocationResultV1:
        if self._deletion_alias is None:
            raise WorkflowRejected("deletion_executor_not_configured")
        return self._invoke(self._deletion_alias, invocation, SensitiveActionV2.EVIDENCE_DELETE)

    def _invoke(
        self,
        alias_arn: str,
        invocation: RetrievalExecutorInvocationV1 | DeletionExecutorInvocationV1,
        action: SensitiveActionV2,
    ) -> ExecutorInvocationResultV1:
        payload = canonical_json_bytes(invocation)
        response = self._client.invoke(
            FunctionName=alias_arn,
            InvocationType="RequestResponse",
            Payload=payload,
        )
        if response.get("StatusCode") != 200 or response.get("FunctionError"):
            raise WorkflowRejected("executor_unavailable")
        expected_version = invocation.execution_grant.executor_version
        if response.get("ExecutedVersion") != str(expected_version):
            raise WorkflowRejected("executor_version_mismatch")
        stream = response.get("Payload")
        raw = stream.read() if hasattr(stream, "read") else stream
        if not isinstance(raw, bytes) or len(raw) > 6_000_000:
            raise WorkflowRejected("executor_response_invalid")
        try:
            envelope = json.loads(raw)
            if not isinstance(envelope, dict) or envelope.get("ok") is not True:
                code = envelope.get("code") if isinstance(envelope, dict) else None
                raise WorkflowRejected(
                    code if isinstance(code, str) and len(code) <= 100 else "executor_rejected"
                )
            result = ExecutorInvocationResultV1.model_validate(envelope.get("result"))
        except WorkflowRejected:
            raise
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise WorkflowRejected("executor_response_invalid") from exc
        if result.action != action:
            raise WorkflowRejected("executor_action_mismatch")
        return result


class RetrievalCoordinator:
    def __init__(
        self,
        store: SecurityWorkflowStore,
        policy: PolicyNotaryClient,
        executor: ExecutorInvoker,
    ) -> None:
        self._store = store
        self._policy = policy
        self._executor = executor

    def execute(
        self, permit: SensitiveActionPermitV2, *, idempotency_key: str
    ) -> RetrievalWorkflowResultV1:
        if permit.action != SensitiveActionV2.EVIDENCE_RETRIEVE:
            raise WorkflowRejected("retrieval_permit_required")
        claim = self._store.claim_retrieval(permit, idempotency_key)
        if claim.state in {
            RetrievalOperationState.DELIVERY_CONFIRMED,
            RetrievalOperationState.DELIVERY_UNKNOWN,
        }:
            return RetrievalWorkflowResultV1(
                operation_id=claim.operation_id,
                state=claim.state,
                receipt_digest=claim.receipt_digest,
                plaintext_b64=None,
                executor_replayed=True,
            )
        grant = self._policy.notarize_operation(claim.operation_id)
        result = self._executor.invoke_retrieval(
            RetrievalExecutorInvocationV1(
                permit=permit,
                execution_grant=grant,
                package=claim.package,
            )
        )
        self._policy.attest_receipt(claim.operation_id, result.receipt)
        state = self._store.reconcile_retrieval(claim.operation_id)
        if result.plaintext_b64 is None:
            state = self._store.record_delivery(claim.operation_id, "unknown")
        return RetrievalWorkflowResultV1(
            operation_id=claim.operation_id,
            state=state,
            receipt_digest=result.receipt_digest,
            plaintext_b64=result.plaintext_b64,
            executor_replayed=result.replayed,
        )

    def record_delivery(
        self, operation_id: UUID, *, accepted: bool
    ) -> RetrievalOperationState:
        return self._store.record_delivery(
            operation_id,
            "accepted" if accepted else "unknown",
        )


class DeletionCoordinator:
    def __init__(
        self,
        store: SecurityWorkflowStore,
        policy: PolicyNotaryClient,
        executor: ExecutorInvoker,
    ) -> None:
        self._store = store
        self._policy = policy
        self._executor = executor

    def execute(
        self,
        permit: SensitiveActionPermitV2,
        manifest: DeletionTargetManifestV1,
        *,
        idempotency_key: str,
    ) -> DeletionWorkflowResultV1:
        if permit.action != SensitiveActionV2.EVIDENCE_DELETE:
            raise WorkflowRejected("deletion_permit_required")
        claim = self._store.claim_deletion(permit, manifest, idempotency_key)
        if claim.state in {
            DeletionOperationState.EFFECTIVE,
            DeletionOperationState.FINALITY_PENDING,
            DeletionOperationState.FINALITY_EXTENDED,
            DeletionOperationState.FINALITY_VERIFIED,
        }:
            reconciled = self._store.reconcile_deletion(claim.operation_id)
            return _deletion_result(claim.operation_id, reconciled, executor_replayed=True)
        grant = self._policy.notarize_operation(claim.operation_id)
        result = self._executor.invoke_deletion(
            DeletionExecutorInvocationV1(
                permit=permit,
                execution_grant=grant,
                manifest=claim.manifest,
            )
        )
        self._policy.attest_receipt(claim.operation_id, result.receipt)
        reconciled = self._store.reconcile_deletion(claim.operation_id)
        return _deletion_result(
            claim.operation_id,
            reconciled,
            executor_replayed=result.replayed,
        )


def _json_contract(contract: BaseModel) -> str:
    return json.dumps(contract.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)


def _deletion_result(
    operation_id: UUID,
    reconciled: dict[str, Any],
    *,
    executor_replayed: bool,
) -> DeletionWorkflowResultV1:
    try:
        state = DeletionOperationState(str(reconciled["state"]))
    except (KeyError, ValueError) as exc:
        raise WorkflowRejected("deletion_reconciliation_invalid") from exc
    summary = reconciled.get("derived_summary")
    if summary is not None and not isinstance(summary, dict):
        raise WorkflowRejected("deletion_reconciliation_invalid")
    return DeletionWorkflowResultV1(
        operation_id=operation_id,
        state=state,
        derived_summary=cast(dict[str, int] | None, summary),
        executor_replayed=executor_replayed,
    )
