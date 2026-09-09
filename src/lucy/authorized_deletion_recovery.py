"""Verify durable v1.2 deletion authority before PostgreSQL recovery replay.

This module is deliberately content-free.  It accepts only the signed permit,
manifest, execution grant, and executor receipt that were committed by the AWS
deletion transaction.  It performs historical signature and cross-contract
binding checks; applying the resulting target set remains an offline,
quarantined database operation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from lucy.contracts.canonical import canonical_sha256
from lucy.contracts.security_v1_2 import (
    ContractTrustStore,
    DeletionTargetManifestV1,
    DeploymentEnvironment,
    ExecutorReceiptV1,
    ExecutorResult,
    SensitiveActionPermitV2,
    SensitiveActionV2,
    SensitiveExecutionGrantV1,
    SigningKeyPurpose,
    VerificationMode,
)
from lucy.contracts.security_v1_3 import (
    DeletionTargetManifestV2,
    ExecutorReceiptV2,
    SensitiveActionPermitV3,
    SensitiveExecutionGrantV2,
    V13ContractVerifier,
    V13SigningKeyPurpose,
)

_RECOVERY_PREFIX = b"lucy:authorized-deletion-recovery:v1\0"
_RECOVERY_V2_PREFIX = b"lucy:authorized-deletion-recovery:v2\0"
_SCOPE_PREFIX = b"lucy:authorized-deletion-recovery-scope:v2\0"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class AuthorizedDeletionRecoveryError(PermissionError):
    """The supplied durable contracts do not prove one authorized deletion."""


@dataclass(frozen=True)
class AuthorizedDeletionRecoveryProof:
    operation_id: str
    permit_id: str
    manifest_id: str
    permit_digest: str
    manifest_digest: str
    grant_digest: str
    receipt_digest: str
    targets_digest: str
    target_count: int
    storage_epoch: int
    registry_epoch: int
    key_epoch: int
    completed_at: str
    recovery_digest: str


@dataclass(frozen=True)
class AuthorizedDeletionRecoveryProofV2:
    operation_id: str
    permit_id: str
    manifest_id: str
    permit_digest: str
    manifest_digest: str
    grant_digest: str
    receipt_digest: str
    targets_digest: str
    target_count: int
    scope_digest: str
    completed_at: str
    recovery_digest: str


def verify_authorized_deletion_recovery_v2(
    *,
    permit: SensitiveActionPermitV3,
    manifest: DeletionTargetManifestV2,
    grant: SensitiveExecutionGrantV2,
    receipt: ExecutorReceiptV2,
    policy_verifier: V13ContractVerifier,
    receipt_verifier: V13ContractVerifier,
    environment: DeploymentEnvironment,
    caller_identity: str,
    executor_identity: str,
    executor_alias_arn: str,
    executor_version: int,
    receipt_key_id: str,
    checked_at: datetime,
) -> AuthorizedDeletionRecoveryProofV2:
    """Verify one historical, realm-scoped deletion chain for recovery replay."""

    try:
        for contract in (permit, manifest, grant):
            policy_verifier.verify_historical(
                contract,
                expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
                checked_at=checked_at,
            )
        receipt_verifier.verify_historical(
            receipt,
            expected_purpose=V13SigningKeyPurpose.DELETION_RECEIPT,
            checked_at=checked_at,
        )
    except PermissionError as exc:
        raise AuthorizedDeletionRecoveryError("historical v1.3 contract trust failed") from exc

    contracts = (permit, manifest, grant, receipt)
    if any(contract.environment != environment for contract in contracts):
        raise AuthorizedDeletionRecoveryError("deployment environment binding mismatch")
    if any(contract.action != SensitiveActionV2.EVIDENCE_DELETE for contract in contracts) or (
        receipt.result
        not in {ExecutorResult.DELETION_SUCCEEDED, ExecutorResult.IDEMPOTENT_REPLAY}
        or receipt.finality_state != "operationally_deleted"
    ):
        raise AuthorizedDeletionRecoveryError("contracts do not prove operational deletion")

    permit_digest = permit.unsigned_digest_hex()
    manifest_digest = manifest.unsigned_digest_hex()
    grant_digest = grant.unsigned_digest_hex()
    receipt_digest = receipt.unsigned_digest_hex()
    if (
        manifest.permit_id != permit.permit_id
        or manifest.permit_digest != permit_digest
        or manifest.operation_id != permit.operation_id
        or manifest.target_scope != permit.target_scope
        or manifest.workspace_id != permit.workspace_id
        or manifest.root_evidence_id != permit.resource_selector.object_id
        or manifest.owner_assertion_id != permit.owner_assertion_id
        or manifest.owner_assertion_digest != permit.owner_assertion_digest
        or manifest.permit_claim_deadline != permit.permit_claim_deadline
        or manifest.execution_completion_deadline != permit.execution_completion_deadline
        or manifest.target_count > permit.max_records
    ):
        raise AuthorizedDeletionRecoveryError("permit and scoped manifest binding mismatch")
    if (
        grant.permit_id != permit.permit_id
        or grant.permit_digest != permit_digest
        or grant.operation_id != permit.operation_id
        or grant.target_scope != permit.target_scope
        or grant.workspace_id != permit.workspace_id
        or grant.resource_selector != permit.resource_selector
        or grant.execution_binding != permit.execution_binding
        or grant.restore_mapping_id != permit.restore_mapping_id
        or grant.deletion_manifest_id != manifest.manifest_id
        or grant.deletion_manifest_digest != manifest_digest
        or grant.encrypted_package_digest != manifest_digest
        or grant.package_size_bytes != len(manifest.canonical_unsigned_bytes())
        or grant.idempotency_key != manifest.idempotency_key
        or grant.permit_claim_deadline != permit.permit_claim_deadline
        or grant.execution_completion_deadline != permit.execution_completion_deadline
        or grant.max_records != permit.max_records
        or grant.max_bytes != permit.max_bytes
    ):
        raise AuthorizedDeletionRecoveryError("manifest and execution-grant binding mismatch")
    if (
        receipt.caller_identity != grant.caller_identity
        or receipt.target_scope != grant.target_scope
        or receipt.execution_binding != grant.execution_binding
        or receipt.operation_id != grant.operation_id
        or receipt.permit_id != permit.permit_id
        or receipt.permit_digest != permit_digest
        or receipt.execution_grant_id != grant.grant_id
        or receipt.execution_grant_digest != grant_digest
        or receipt.deletion_manifest_id != manifest.manifest_id
        or receipt.deletion_manifest_digest != manifest_digest
        or receipt.package_digest != manifest_digest
        or receipt.execution_completion_deadline != grant.execution_completion_deadline
        or receipt.record_version != permit.resource_selector.object_version
    ):
        raise AuthorizedDeletionRecoveryError("execution grant and receipt binding mismatch")
    expected_executor = (
        caller_identity,
        executor_identity,
        executor_alias_arn,
        executor_version,
    )
    if (
        (
            grant.caller_identity,
            grant.executor_identity,
            grant.executor_alias_arn,
            grant.executor_version,
        )
        != expected_executor
        or (
            receipt.caller_identity,
            receipt.executor_identity,
            receipt.executor_alias_arn,
            receipt.executor_version,
        )
        != expected_executor
        or receipt.key_id != receipt_key_id
    ):
        raise AuthorizedDeletionRecoveryError("reviewed scoped executor binding mismatch")

    scope_digest = canonical_sha256(permit.target_scope, prefix=_SCOPE_PREFIX)
    bindings = {
        "operation_id": str(permit.operation_id),
        "permit_digest": permit_digest,
        "manifest_digest": manifest_digest,
        "grant_digest": grant_digest,
        "receipt_digest": receipt_digest,
        "targets_digest": manifest.targets_digest,
        "scope_digest": scope_digest,
    }
    return AuthorizedDeletionRecoveryProofV2(
        operation_id=str(permit.operation_id),
        permit_id=str(permit.permit_id),
        manifest_id=str(manifest.manifest_id),
        permit_digest=permit_digest,
        manifest_digest=manifest_digest,
        grant_digest=grant_digest,
        receipt_digest=receipt_digest,
        targets_digest=manifest.targets_digest,
        target_count=manifest.target_count,
        scope_digest=scope_digest,
        completed_at=receipt.completed_at.isoformat(),
        recovery_digest=canonical_sha256(bindings, prefix=_RECOVERY_V2_PREFIX),
    )


def build_authorized_deletion_recovery_contract_v2(
    *,
    proof: AuthorizedDeletionRecoveryProofV2,
    permit: SensitiveActionPermitV3,
    manifest: DeletionTargetManifestV2,
    grant: SensitiveExecutionGrantV2,
    receipt: ExecutorReceiptV2,
    authority_evidence_digest: str,
) -> dict[str, Any]:
    """Build the strict content-free V1.3 contract for quarantined replay."""

    if _DIGEST.fullmatch(authority_evidence_digest) is None:
        raise ValueError("authority evidence digest must be lowercase SHA-256")
    if (
        proof.operation_id != str(permit.operation_id)
        or proof.permit_id != str(permit.permit_id)
        or proof.manifest_id != str(manifest.manifest_id)
        or proof.grant_digest != grant.unsigned_digest_hex()
        or proof.receipt_digest != receipt.unsigned_digest_hex()
    ):
        raise ValueError("scoped recovery proof does not bind the supplied contracts")
    return {
        "contract_version": "2",
        "object_type": "lucy.authorized-deletion-recovery.v2",
        "operation_id": proof.operation_id,
        "permit_id": proof.permit_id,
        "manifest_id": proof.manifest_id,
        "grant_id": str(grant.grant_id),
        "receipt_id": str(receipt.receipt_id),
        "permit_digest": proof.permit_digest,
        "manifest_digest": proof.manifest_digest,
        "grant_digest": proof.grant_digest,
        "receipt_digest": proof.receipt_digest,
        "targets_digest": proof.targets_digest,
        "target_count": proof.target_count,
        "scope_digest": proof.scope_digest,
        "target_scope": permit.target_scope.model_dump(mode="json"),
        "workspace_id": str(permit.workspace_id),
        "root_evidence_id": str(manifest.root_evidence_id),
        "root_representation_id": str(manifest.root_representation_id),
        "restore_mapping_id": (
            str(permit.restore_mapping_id) if permit.restore_mapping_id is not None else None
        ),
        "caller_identity": receipt.caller_identity,
        "executor_identity": receipt.executor_identity,
        "executor_alias_arn": receipt.executor_alias_arn,
        "executor_version": receipt.executor_version,
        "receipt_key_id": receipt.key_id,
        "completed_at": proof.completed_at,
        "reason_category": permit.reason.value,
        "recovery_digest": proof.recovery_digest,
        "authority_evidence_digest": authority_evidence_digest,
        "targets": [target.model_dump(mode="json") for target in manifest.targets],
    }


def verify_authorized_deletion_recovery(
    *,
    permit: SensitiveActionPermitV2,
    manifest: DeletionTargetManifestV1,
    grant: SensitiveExecutionGrantV1,
    receipt: ExecutorReceiptV1,
    policy_trust_store: ContractTrustStore,
    receipt_trust_store: ContractTrustStore,
    environment: DeploymentEnvironment,
    executor_identity: str,
    executor_alias_arn: str,
    executor_version: int,
    receipt_key_id: str,
) -> AuthorizedDeletionRecoveryProof:
    """Return a content-free proof only when all four durable contracts bind."""

    try:
        for contract in (permit, manifest, grant):
            policy_trust_store.verify(
                contract,
                purpose=SigningKeyPurpose.POLICY_NOTARY,
                environment=environment,
                mode=VerificationMode.HISTORICAL_AUDIT,
            )
        receipt_trust_store.verify(
            receipt,
            purpose=SigningKeyPurpose.DELETION_RECEIPT,
            environment=environment,
            mode=VerificationMode.HISTORICAL_AUDIT,
        )
    except PermissionError as exc:
        raise AuthorizedDeletionRecoveryError("historical contract trust failed") from exc

    common_epochs = (permit.storage_epoch, permit.registry_epoch, permit.key_epoch)
    if any(
        (contract.storage_epoch, contract.registry_epoch, contract.key_epoch) != common_epochs
        for contract in (manifest, grant, receipt)
    ):
        raise AuthorizedDeletionRecoveryError("security epoch binding mismatch")
    if any(contract.environment != environment for contract in (permit, manifest, grant, receipt)):
        raise AuthorizedDeletionRecoveryError("deployment environment binding mismatch")

    manifest_digest = manifest.unsigned_digest_hex()
    if (
        permit.action != SensitiveActionV2.EVIDENCE_DELETE
        or manifest.action != SensitiveActionV2.EVIDENCE_DELETE
        or grant.action != SensitiveActionV2.EVIDENCE_DELETE
        or receipt.action != SensitiveActionV2.EVIDENCE_DELETE
        or receipt.result
        not in {ExecutorResult.DELETION_SUCCEEDED, ExecutorResult.IDEMPOTENT_REPLAY}
    ):
        raise AuthorizedDeletionRecoveryError("contracts do not prove a successful deletion")
    if (
        manifest.permit_id != permit.permit_id
        or manifest.permit_nonce != permit.nonce
        or manifest.root_evidence_id != permit.evidence_id
        or manifest.owner_assertion_id != permit.owner_assertion_id
        or manifest.owner_assertion_digest != permit.owner_assertion_digest
        or manifest.root_record_version != permit.record_version
        or manifest.permit_claim_deadline != permit.permit_claim_deadline
    ):
        raise AuthorizedDeletionRecoveryError("permit and manifest binding mismatch")
    if (
        grant.permit_id != permit.permit_id
        or grant.action != permit.action
        or grant.evidence_id != permit.evidence_id
        or grant.record_version != permit.record_version
        or grant.deletion_manifest_id != manifest.manifest_id
        or grant.deletion_manifest_digest != manifest_digest
        or grant.encrypted_package_digest != manifest_digest
        or grant.idempotency_key != manifest.idempotency_key
        or grant.permit_claim_deadline != manifest.permit_claim_deadline
        or grant.execution_deadline != manifest.execution_deadline
    ):
        raise AuthorizedDeletionRecoveryError("manifest and execution-grant binding mismatch")
    if (
        receipt.operation_id != grant.operation_id
        or receipt.permit_id != grant.permit_id
        or receipt.execution_grant_id != grant.grant_id
        or receipt.deletion_manifest_id != manifest.manifest_id
        or receipt.package_digest != manifest_digest
        or receipt.record_version != manifest.root_record_version
        or receipt.execution_deadline != grant.execution_deadline
        or receipt.completed_at > grant.execution_deadline
    ):
        raise AuthorizedDeletionRecoveryError("execution grant and receipt binding mismatch")
    expected_executor = (executor_identity, executor_alias_arn, executor_version)
    if (
        (grant.executor_identity, grant.executor_alias_arn, grant.executor_version)
        != expected_executor
        or (receipt.executor_identity, receipt.executor_alias_arn, receipt.executor_version)
        != expected_executor
        or receipt.key_id != receipt_key_id
    ):
        raise AuthorizedDeletionRecoveryError("reviewed executor binding mismatch")

    digests = {
        "operation_id": str(receipt.operation_id),
        "permit_digest": permit.unsigned_digest_hex(),
        "manifest_digest": manifest_digest,
        "grant_digest": grant.unsigned_digest_hex(),
        "receipt_digest": receipt.unsigned_digest_hex(),
        "targets_digest": manifest.targets_digest,
    }
    return AuthorizedDeletionRecoveryProof(
        operation_id=str(receipt.operation_id),
        permit_id=str(permit.permit_id),
        manifest_id=str(manifest.manifest_id),
        permit_digest=digests["permit_digest"],
        manifest_digest=manifest_digest,
        grant_digest=digests["grant_digest"],
        receipt_digest=digests["receipt_digest"],
        targets_digest=manifest.targets_digest,
        target_count=manifest.target_count,
        storage_epoch=permit.storage_epoch,
        registry_epoch=permit.registry_epoch,
        key_epoch=permit.key_epoch,
        completed_at=receipt.completed_at.isoformat(),
        recovery_digest=canonical_sha256(digests, prefix=_RECOVERY_PREFIX),
    )


def build_authorized_deletion_recovery_contract(
    *,
    proof: AuthorizedDeletionRecoveryProof,
    permit: SensitiveActionPermitV2,
    manifest: DeletionTargetManifestV1,
    receipt: ExecutorReceiptV1,
    recovered_storage_epoch: int,
    authority_evidence_digest: str,
) -> dict[str, Any]:
    """Build the strict content-free contract consumed by the offline DB gate."""

    if recovered_storage_epoch < 1:
        raise ValueError("recovered storage epoch must be positive")
    if _DIGEST.fullmatch(authority_evidence_digest) is None:
        raise ValueError("authority evidence digest must be lowercase SHA-256")
    if (
        proof.operation_id != str(receipt.operation_id)
        or proof.permit_id != str(permit.permit_id)
        or proof.manifest_id != str(manifest.manifest_id)
    ):
        raise ValueError("recovery proof does not bind the supplied contracts")
    return {
        "contract_version": "1",
        "object_type": "lucy.authorized-deletion-recovery.v1",
        "operation_id": proof.operation_id,
        "permit_id": proof.permit_id,
        "manifest_id": proof.manifest_id,
        "receipt_id": str(receipt.receipt_id),
        "permit_digest": proof.permit_digest,
        "manifest_digest": proof.manifest_digest,
        "grant_digest": proof.grant_digest,
        "receipt_digest": proof.receipt_digest,
        "targets_digest": proof.targets_digest,
        "target_count": proof.target_count,
        "storage_epoch": proof.storage_epoch,
        "registry_epoch": proof.registry_epoch,
        "key_epoch": proof.key_epoch,
        "executor_identity": receipt.executor_identity,
        "executor_alias_arn": receipt.executor_alias_arn,
        "executor_version": receipt.executor_version,
        "receipt_key_id": receipt.key_id,
        "completed_at": proof.completed_at,
        "reason_category": permit.reason.value,
        "recovery_digest": proof.recovery_digest,
        "authority_evidence_digest": authority_evidence_digest,
        "recovered_storage_epoch": recovered_storage_epoch,
        "targets": [target.model_dump(mode="json") for target in manifest.targets],
    }
