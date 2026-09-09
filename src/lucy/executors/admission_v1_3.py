"""Pure, effect-free admission boundary for realm-scoped V1.3 executors."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from lucy.contracts.canonical import canonical_json_bytes
from lucy.contracts.security_v1_2 import DeploymentEnvironment, SensitiveActionV2
from lucy.contracts.security_v1_3 import (
    ExecutionBindingV1,
    OriginScopeV1,
    SensitiveActionPermitV3,
    SensitiveExecutionGrantV2,
    V13ContractVerifier,
    V13SigningKeyPurpose,
)
from lucy.executors.core import ExecutorRejected
from lucy.executors.models import (
    DeletionExecutorInvocationV2,
    RetrievalExecutorInvocationV2,
)


@dataclass(frozen=True)
class RealmExecutorIdentityV1:
    """Deployment-owned identity; request data can never select these values."""

    action: SensitiveActionV2
    environment: DeploymentEnvironment
    target_scope: OriginScopeV1
    workspace_id: UUID
    execution_binding: ExecutionBindingV1
    caller_identity: str
    executor_identity: str
    executor_alias_arn: str
    executor_version: int
    record_version: int

    def __post_init__(self) -> None:
        if self.executor_version < 1 or self.record_version < 1:
            raise ValueError("executor and record versions must be positive")
        if not all(
            value.strip()
            for value in (
                self.caller_identity,
                self.executor_identity,
                self.executor_alias_arn,
            )
        ):
            raise ValueError("realm executor identity is incomplete")
        if (
            self.execution_binding.active_realm_id != self.target_scope.security_realm_id
            or self.execution_binding.active_storage_epoch != self.target_scope.storage_epoch
        ):
            raise ValueError("realm executor scope and active binding differ")


@dataclass(frozen=True)
class VerifiedRealmInvocationV1:
    action: SensitiveActionV2
    operation_id: UUID
    permit_id: UUID
    grant_id: UUID
    package_digest: str
    record_version: int
    deletion_manifest_id: UUID | None = None


def verify_retrieval_invocation_v2(
    invocation: RetrievalExecutorInvocationV2,
    *,
    verifier: V13ContractVerifier,
    identity: RealmExecutorIdentityV1,
    checked_at: datetime,
) -> VerifiedRealmInvocationV1:
    permit, grant, package = (
        invocation.permit,
        invocation.execution_grant,
        invocation.package,
    )
    _verify_common(permit, grant, verifier=verifier, identity=identity, checked_at=checked_at)
    if identity.action != SensitiveActionV2.EVIDENCE_RETRIEVE:
        raise ExecutorRejected("executor_action_misconfigured")
    payload, wrapper = package.payload_binding, package.wrapper_binding
    digest = package.package_digest_hex()
    if (
        package.operation_id != grant.operation_id
        or package.permit_id != permit.permit_id
        or payload.evidence_id != permit.resource_selector.object_id
        or payload.record_version != permit.resource_selector.object_version
        or payload.record_version != identity.record_version
        or wrapper.wrapping_scope != identity.target_scope
        or wrapper.encryption_context.evidence_id != payload.evidence_id
    ):
        raise ExecutorRejected("encrypted_package_binding_mismatch")
    if not hmac.compare_digest(digest, grant.encrypted_package_digest):
        raise ExecutorRejected("encrypted_package_digest_mismatch")
    if len(canonical_json_bytes(package)) != grant.package_size_bytes:
        raise ExecutorRejected("encrypted_package_size_mismatch")
    return VerifiedRealmInvocationV1(
        action=identity.action,
        operation_id=grant.operation_id,
        permit_id=permit.permit_id,
        grant_id=grant.grant_id,
        package_digest=digest,
        record_version=payload.record_version,
    )


def verify_deletion_invocation_v2(
    invocation: DeletionExecutorInvocationV2,
    *,
    verifier: V13ContractVerifier,
    identity: RealmExecutorIdentityV1,
    checked_at: datetime,
) -> VerifiedRealmInvocationV1:
    permit, grant, manifest = (
        invocation.permit,
        invocation.execution_grant,
        invocation.manifest,
    )
    _verify_common(permit, grant, verifier=verifier, identity=identity, checked_at=checked_at)
    if identity.action != SensitiveActionV2.EVIDENCE_DELETE:
        raise ExecutorRejected("executor_action_misconfigured")
    try:
        verifier.verify(
            manifest,
            expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
            checked_at=checked_at,
        )
    except PermissionError as exc:
        raise ExecutorRejected("manifest_signature_invalid") from exc
    digest = manifest.unsigned_digest_hex()
    if (
        manifest.permit_id != permit.permit_id
        or not hmac.compare_digest(manifest.permit_digest, permit.unsigned_digest_hex())
        or manifest.operation_id != permit.operation_id
        or manifest.target_scope != identity.target_scope
        or manifest.workspace_id != identity.workspace_id
        or manifest.root_evidence_id != permit.resource_selector.object_id
        or manifest.owner_assertion_id != permit.owner_assertion_id
        or manifest.owner_assertion_digest != permit.owner_assertion_digest
        or manifest.idempotency_key != grant.idempotency_key
        or manifest.permit_claim_deadline != permit.permit_claim_deadline
        or manifest.execution_completion_deadline != permit.execution_completion_deadline
    ):
        raise ExecutorRejected("manifest_binding_mismatch")
    if (
        grant.deletion_manifest_id != manifest.manifest_id
        or grant.deletion_manifest_digest is None
        or not hmac.compare_digest(grant.deletion_manifest_digest, digest)
        or not hmac.compare_digest(grant.encrypted_package_digest, digest)
    ):
        raise ExecutorRejected("manifest_digest_mismatch")
    if len(manifest.targets) > grant.max_records:
        raise ExecutorRejected("deletion_target_limit_exceeded")
    if len(canonical_json_bytes(manifest)) != grant.package_size_bytes:
        raise ExecutorRejected("manifest_size_mismatch")
    return VerifiedRealmInvocationV1(
        action=identity.action,
        operation_id=grant.operation_id,
        permit_id=permit.permit_id,
        grant_id=grant.grant_id,
        package_digest=digest,
        record_version=permit.resource_selector.object_version,
        deletion_manifest_id=manifest.manifest_id,
    )


def _verify_common(
    permit: SensitiveActionPermitV3,
    grant: SensitiveExecutionGrantV2,
    *,
    verifier: V13ContractVerifier,
    identity: RealmExecutorIdentityV1,
    checked_at: datetime,
) -> None:
    # The permit's admission deadline has served its purpose once PostgreSQL has
    # claimed it. The live post-claim grant is the executor authorization.
    try:
        verifier.verify_historical(
            permit,
            expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
            checked_at=checked_at,
        )
        verifier.verify(
            grant,
            expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
            checked_at=checked_at,
        )
    except PermissionError as exc:
        raise ExecutorRejected("authorization_signature_invalid") from exc
    if permit.action != identity.action or grant.action != identity.action:
        raise ExecutorRejected("action_mismatch")
    if permit.environment != identity.environment or grant.environment != identity.environment:
        raise ExecutorRejected("environment_mismatch")
    if (
        grant.permit_id != permit.permit_id
        or grant.operation_id != permit.operation_id
        or not hmac.compare_digest(grant.permit_digest, permit.unsigned_digest_hex())
    ):
        raise ExecutorRejected("permit_binding_mismatch")
    if (
        permit.target_scope != identity.target_scope
        or grant.target_scope != identity.target_scope
        or permit.workspace_id != identity.workspace_id
        or grant.workspace_id != identity.workspace_id
        or permit.execution_binding != identity.execution_binding
        or grant.execution_binding != identity.execution_binding
        or permit.resource_selector != grant.resource_selector
        or permit.restore_mapping_id != grant.restore_mapping_id
    ):
        raise ExecutorRejected("realm_scope_binding_mismatch")
    if (
        grant.caller_identity != identity.caller_identity
        or grant.executor_identity != identity.executor_identity
        or grant.executor_alias_arn != identity.executor_alias_arn
        or grant.executor_version != identity.executor_version
    ):
        raise ExecutorRejected("executor_binding_mismatch")
    if (
        grant.permit_claim_deadline != permit.permit_claim_deadline
        or grant.execution_completion_deadline != permit.execution_completion_deadline
    ):
        raise ExecutorRejected("deadline_binding_mismatch")
    if grant.max_records > permit.max_records or grant.max_bytes > permit.max_bytes:
        raise ExecutorRejected("authority_ceiling_exceeded")
