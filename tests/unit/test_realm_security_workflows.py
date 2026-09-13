from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from lucy.contracts.security_v1_2 import DeploymentEnvironment, SensitiveActionV2
from lucy.contracts.security_v1_3 import (
    AuthenticationStrength,
    DeletionArtifactClass,
    DeletionArtifactClassV3,
    DeletionDisposition,
    DeletionTargetReferenceV2,
    DeletionTargetReferenceV3,
    Ed25519V13Signer,
    ExactObjectSelectorV1,
    ExecutionBindingV1,
    OriginScopeV1,
    OwnerInteractionAssertionV2,
    SensitiveActionPermitV3,
    SensitiveExecutionGrantV2,
    SensitiveReasonCode,
    V13ContractVerifier,
    V13SigningKeyPurpose,
    V13VerificationKeyStatus,
    V13VerificationKeyV1,
    deletion_targets_digest_v2,
    deletion_targets_digest_v3,
)
from lucy.realm_security_workflows import (
    HttpRealmPolicyClient,
    PostgresRealmPolicyStore,
    PostgresRealmWorkflowStore,
    RealmDeletionAuthorityV1,
    RealmDeletionAuthorityV2,
    RealmDeletionCoordinator,
    RealmGrantAuthorityV1,
    RealmLambdaExecutorInvoker,
    RealmOperationClaimResultV1,
    RealmOperationStatusV1,
    RealmPermitAuthorityV1,
    RealmPolicyDeletionService,
    RealmPolicyDeletionServiceV3,
    RealmPolicyGrantService,
    RealmPolicyGrantServiceV3,
    RealmPolicyPermitService,
    RealmRetrievalCoordinator,
    RealmWorkflowUnavailable,
    VerifiedRealmPolicyAdapter,
)
from lucy.scoped_deletion import ScopedDeletionManifestResult


def _permit(
    action: SensitiveActionV2 = SensitiveActionV2.EVIDENCE_RETRIEVE,
) -> tuple[
    SensitiveActionPermitV3, V13ContractVerifier, Ed25519V13Signer
]:
    now = datetime.now(UTC)
    private = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519V13Signer(
        private, key_id="policy-v13", purpose=V13SigningKeyPurpose.POLICY_NOTARY
    )
    scope = OriginScopeV1(
        tenant_account_id=uuid4(),
        node_id=uuid4(),
        node_tenure_id=uuid4(),
        tenure_epoch=1,
        security_realm_id=uuid4(),
        storage_epoch=1,
    )
    permit = signer.sign(
        SensitiveActionPermitV3(
            key_id="policy-v13",
            issuer="lucy-policy",
            environment=DeploymentEnvironment.PRODUCTION,
            issued_at=now,
            permit_id=uuid4(),
            action=action,
            reason=(
                SensitiveReasonCode.OWNER_REVIEW
                if action == SensitiveActionV2.EVIDENCE_RETRIEVE
                else SensitiveReasonCode.OWNER_REQUEST
            ),
            principal_id=uuid4(),
            service_principal_id=uuid4(),
            service_binding_id=uuid4(),
            service_binding_generation=1,
            operation_id=uuid4(),
            target_scope=scope,
            workspace_id=uuid4(),
            resource_selector=ExactObjectSelectorV1(object_id=uuid4(), object_version=1),
            execution_binding=ExecutionBindingV1(
                deployment_id=uuid4(),
                active_realm_id=scope.security_realm_id,
                active_storage_epoch=scope.storage_epoch,
                realm_binding_generation=1,
                node_authz_epoch=1,
            ),
            owner_assertion_id=uuid4(),
            owner_assertion_digest="a" * 64,
            approval_digest="b" * 64,
            policy_version=1,
            membership_generation=1,
            channel_binding_id=uuid4(),
            channel_generation=1,
            permit_claim_deadline=now + timedelta(seconds=30),
            execution_completion_deadline=now + timedelta(minutes=5),
            max_records=1 if action == SensitiveActionV2.EVIDENCE_RETRIEVE else 2,
            max_bytes=(
                65_536 if action == SensitiveActionV2.EVIDENCE_RETRIEVE else 131_072
            ),
            nonce=uuid4().hex,
        )
    )
    key = V13VerificationKeyV1(
        key_id="policy-v13",
        issuer="lucy-policy",
        environment=DeploymentEnvironment.PRODUCTION,
        purpose=V13SigningKeyPurpose.POLICY_NOTARY,
        public_key_b64=signer.public_key_b64,
        status=V13VerificationKeyStatus.ACTIVE,
        valid_from=now - timedelta(minutes=1),
        issuance_not_after=now + timedelta(hours=1),
        verify_not_after=now + timedelta(hours=2),
    )
    return permit, V13ContractVerifier((key,)), signer


class _PolicyStore:
    def __init__(
        self,
        stored_id: UUID | None = None,
        authority: RealmPermitAuthorityV1 | None = None,
    ) -> None:
        self.stored_id = stored_id
        self.authority = authority
        self.calls: list[tuple[SensitiveActionPermitV3, str]] = []

    def permit_authority(self, *_args: Any) -> RealmPermitAuthorityV1:
        if self.authority is None:
            raise AssertionError("not used")
        return self.authority

    def store_permit(self, permit: SensitiveActionPermitV3, idempotency_key: str) -> UUID:
        self.calls.append((permit, idempotency_key))
        return self.stored_id or permit.permit_id

    def store_grant(self, _grant: Any) -> str:
        raise AssertionError("not used")

    def attest_receipt(self, _receipt: Any) -> str:
        raise AssertionError("not used")


def test_verified_policy_adapter_checks_signature_and_storage_binding() -> None:
    permit, verifier, _signer = _permit()
    store = _PolicyStore()
    adapter = VerifiedRealmPolicyAdapter(store, verifier=verifier)
    assert adapter.admit_permit(permit, "permit-once") == permit.permit_id
    assert store.calls == [(permit, "permit-once")]

    tampered = permit.model_copy(update={"signature": "invalid"})
    with pytest.raises(PermissionError):
        adapter.admit_permit(tampered, "never-stored")
    assert len(store.calls) == 1

    wrong_store = _PolicyStore(uuid4())
    with pytest.raises(RealmWorkflowUnavailable, match="stored permit differs"):
        VerifiedRealmPolicyAdapter(wrong_store, verifier=verifier).admit_permit(
            permit, "permit-once"
        )


def _owner_assertion_and_authority(
    *, now: datetime
) -> tuple[
    OwnerInteractionAssertionV2,
    V13ContractVerifier,
    RealmPermitAuthorityV1,
]:
    private = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519V13Signer(
        private, key_id="owner-v13", purpose=V13SigningKeyPurpose.OWNER_BROKER
    )
    scope = OriginScopeV1(
        tenant_account_id=uuid4(),
        node_id=uuid4(),
        node_tenure_id=uuid4(),
        tenure_epoch=1,
        security_realm_id=uuid4(),
        storage_epoch=1,
    )
    principal_id = uuid4()
    workspace_id = uuid4()
    channel_id = uuid4()
    selector = ExactObjectSelectorV1(object_id=uuid4(), object_version=1)
    execution = ExecutionBindingV1(
        deployment_id=uuid4(),
        active_realm_id=scope.security_realm_id,
        active_storage_epoch=scope.storage_epoch,
        realm_binding_generation=1,
        node_authz_epoch=1,
    )
    assertion = signer.sign(
        OwnerInteractionAssertionV2(
            key_id="owner-v13",
            issuer="lucy-owner-broker",
            environment=DeploymentEnvironment.PRODUCTION,
            issued_at=now,
            assertion_id=uuid4(),
            principal_id=principal_id,
            identity_issuer="synthetic-commissioning",
            identity_subject="synthetic-owner",
            authn_strength=AuthenticationStrength.PHISHING_RESISTANT,
            auth_time=now,
            target_scope=scope,
            workspace_id=workspace_id,
            requested_action=SensitiveActionV2.EVIDENCE_RETRIEVE,
            resource_selector=selector,
            displayed_action_digest="d" * 64,
            channel_binding_id=channel_id,
            challenge_id=uuid4(),
            node_authz_epoch=1,
            expires_at=now + timedelta(seconds=60),
            nonce=uuid4().hex,
        )
    )
    key = V13VerificationKeyV1(
        key_id="owner-v13",
        issuer="lucy-owner-broker",
        environment=DeploymentEnvironment.PRODUCTION,
        purpose=V13SigningKeyPurpose.OWNER_BROKER,
        public_key_b64=signer.public_key_b64,
        status=V13VerificationKeyStatus.ACTIVE,
        valid_from=now - timedelta(minutes=1),
        issuance_not_after=now + timedelta(hours=1),
        verify_not_after=now + timedelta(hours=2),
    )
    authority = RealmPermitAuthorityV1(
        principal_id=principal_id,
        identity_issuer="synthetic-commissioning",
        identity_subject="synthetic-owner",
        target_scope=scope,
        workspace_id=workspace_id,
        service_principal_id=uuid4(),
        service_binding_id=uuid4(),
        service_binding_generation=1,
        execution_binding=execution,
        membership_generation=1,
        channel_binding_id=channel_id,
        channel_generation=1,
        policy_version=1,
        resource_selector=selector,
    )
    return assertion, V13ContractVerifier((key,)), authority


def test_policy_permit_service_verifies_owner_and_its_own_signed_permit() -> None:
    now = datetime.now(UTC)
    assertion, owner_verifier, authority = _owner_assertion_and_authority(now=now)
    _unused, policy_verifier, policy_signer = _permit()
    store = _PolicyStore(authority=authority)
    permit = RealmPolicyPermitService(
        store,  # type: ignore[arg-type]
        owner_verifier=owner_verifier,
        policy_verifier=policy_verifier,
        signer=policy_signer,
        issuer="lucy-policy",
        environment=DeploymentEnvironment.PRODUCTION,
        clock=lambda: now + timedelta(seconds=1),
    ).issue_permit(
        assertion,
        reason=SensitiveReasonCode.OWNER_REVIEW,
        idempotency_key="synthetic-permit-once",
    )
    assert permit.owner_assertion_id == assertion.assertion_id
    assert permit.resource_selector == authority.resource_selector
    assert store.calls == [(permit, "synthetic-permit-once")]


def test_policy_permit_service_rejects_assertion_authority_drift() -> None:
    now = datetime.now(UTC)
    assertion, owner_verifier, authority = _owner_assertion_and_authority(now=now)
    _unused, policy_verifier, policy_signer = _permit()
    store = _PolicyStore(
        authority=authority.model_copy(update={"identity_subject": "different-owner"})
    )
    with pytest.raises(RealmWorkflowUnavailable, match="authority differs"):
        RealmPolicyPermitService(
            store,  # type: ignore[arg-type]
            owner_verifier=owner_verifier,
            policy_verifier=policy_verifier,
            signer=policy_signer,
            issuer="lucy-policy",
            environment=DeploymentEnvironment.PRODUCTION,
            clock=lambda: now + timedelta(seconds=1),
        ).issue_permit(
            assertion,
            reason=SensitiveReasonCode.OWNER_REVIEW,
            idempotency_key="authority-drift",
        )
    assert store.calls == []


class _Result:
    def __init__(self, value: object) -> None:
        self.value = value

    def scalar_one(self) -> object:
        return self.value


class _Session:
    def __init__(self, values: list[object]) -> None:
        self.values = values
        self.statements: list[str] = []

    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: object, _parameters: object) -> _Result:
        self.statements.append(str(statement))
        return _Result(self.values.pop(0))


class _Sessions:
    def __init__(self, values: list[object]) -> None:
        self.session = _Session(values)

    def begin(self) -> _Session:
        return self.session


def test_policy_store_reads_exact_permit_authority() -> None:
    now = datetime.now(UTC)
    assertion, _verifier, authority = _owner_assertion_and_authority(now=now)
    sessions = _Sessions([authority.model_dump(mode="json")])
    result = PostgresRealmPolicyStore(sessions).permit_authority(
        assertion.principal_id,
        assertion.channel_binding_id,
        assertion.requested_action,
        assertion.resource_selector.object_id,
        assertion.resource_selector.object_version,
    )
    assert result == authority
    assert "read_sensitive_permit_authority_v1" in sessions.session.statements[0]


def test_workflow_store_loads_only_exact_permit_and_action() -> None:
    permit, _verifier, _signer = _permit()
    sessions = _Sessions([permit.model_dump(mode="json")])
    result = PostgresRealmWorkflowStore(sessions).load_permit(
        permit.permit_id, permit.action
    )
    assert result == permit
    assert "read_sensitive_action_permit_v3" in sessions.session.statements[0]


def test_policy_store_reads_only_exact_post_claim_authority() -> None:
    permit, _verifier, _signer = _permit()
    authority = {
        "operation_id": str(permit.operation_id),
        "action": permit.action,
        "claimed_at": datetime.now(UTC).isoformat(),
        "claim_idempotency_key": "claim-once",
        "permit": permit.model_dump(mode="json"),
        "package_digest": "c" * 64,
        "package_size_bytes": 100,
        "executor_binding_id": str(uuid4()),
        "caller_identity": "arn:aws:iam::123456789012:role/lucy-utopia-retrieval",
        "executor_identity": "lucy-utopia-retrieval",
        "executor_alias_arn": (
            "arn:aws:lambda:us-east-1:123456789012:"
            "function:lucy-utopia-retrieval:realm-v13"
        ),
        "executor_version": 1,
        "receipt_key_id": (
            "arn:aws:kms:us-east-1:123456789012:"
            "key/00000000-0000-4000-8000-000000000001"
        ),
        "deletion_manifest_id": None,
        "deletion_manifest_digest": None,
    }
    sessions = _Sessions([authority])
    result = PostgresRealmPolicyStore(sessions).grant_authority(permit.operation_id)  # type: ignore[arg-type]
    assert result.permit == permit
    assert result.package_digest == "c" * 64
    assert "read_claimed_sensitive_authority_v1" in sessions.session.statements[0]


class _GrantStore:
    def __init__(self, authority: RealmGrantAuthorityV1) -> None:
        self.authority = authority
        self.grants: list[Any] = []

    def grant_authority(self, _operation_id: UUID) -> RealmGrantAuthorityV1:
        return self.authority

    def store_grant(self, grant: Any) -> str:
        self.grants.append(grant)
        return grant.unsigned_digest_hex()

    def store_permit(self, _permit: Any, _idempotency_key: str) -> UUID:
        raise AssertionError("not used")

    def attest_receipt(self, _receipt: Any) -> str:
        raise AssertionError("not used")

    def deletion_authority(self, _operation_id: UUID) -> Any:
        raise AssertionError("not used")

    def store_manifest(self, _manifest: Any) -> Any:
        raise AssertionError("not used")


def test_policy_grant_service_builds_and_replays_exact_signed_grant() -> None:
    permit, verifier, signer = _permit()
    now = permit.issued_at + timedelta(seconds=1)
    authority = RealmGrantAuthorityV1(
        operation_id=permit.operation_id,
        action=permit.action,
        claimed_at=permit.issued_at,
        claim_idempotency_key="claim-once",
        permit=permit,
        package_digest="c" * 64,
        package_size_bytes=100,
        executor_binding_id=uuid4(),
        caller_identity="arn:aws:iam::123456789012:role/lucy-utopia-retrieval",
        executor_identity="lucy-utopia-retrieval",
        executor_alias_arn=(
            "arn:aws:lambda:us-east-1:123456789012:"
            "function:lucy-utopia-retrieval:realm-v13"
        ),
        executor_version=1,
        receipt_key_id=(
            "arn:aws:kms:us-east-1:123456789012:"
            "key/00000000-0000-4000-8000-000000000001"
        ),
    )
    store = _GrantStore(authority)
    service = RealmPolicyGrantService(
        store, signer=signer, verifier=verifier, clock=lambda: now
    )
    grant = service.issue_grant(permit.operation_id)
    assert grant.permit_claimed_at == authority.claimed_at
    assert grant.executor_alias_arn == authority.executor_alias_arn
    assert grant.encrypted_package_digest == authority.package_digest
    assert grant.signature

    store.authority = authority.model_copy(update={"existing_grant": grant})
    assert service.issue_grant(permit.operation_id) == grant
    assert store.grants == [grant, grant]


class _DeletionStore:
    def __init__(self, authority: RealmDeletionAuthorityV1) -> None:
        self.authority = authority
        self.manifests: list[Any] = []

    def deletion_authority(self, _operation_id: UUID) -> RealmDeletionAuthorityV1:
        return self.authority

    def store_manifest(self, manifest: Any) -> ScopedDeletionManifestResult:
        self.manifests.append(manifest)
        return ScopedDeletionManifestResult(
            manifest_id=manifest.manifest_id,
            manifest_digest=manifest.unsigned_digest_hex(),
            targets_digest=manifest.targets_digest,
            target_count=manifest.target_count,
            replayed=False,
        )


def test_policy_deletion_service_builds_and_replays_exact_manifest() -> None:
    permit, verifier, signer = _permit(SensitiveActionV2.EVIDENCE_DELETE)
    evidence_id = permit.resource_selector.object_id
    representation_id = uuid4()
    targets = (
        DeletionTargetReferenceV2(
            artifact_class=DeletionArtifactClass.ENCRYPTED_ARCHIVE,
            artifact_id=evidence_id,
            artifact_version=permit.resource_selector.object_version,
            root_evidence_id=evidence_id,
            disposition=DeletionDisposition.DESTROY_WRAPPED_KEY,
            representation_id=representation_id,
            wrapped_key_ref=uuid4(),
        ),
    )
    authority = RealmDeletionAuthorityV1(
        operation_id=permit.operation_id,
        action=permit.action,
        claimed_at=permit.issued_at,
        claim_idempotency_key="claim-delete-once",
        permit=permit,
        root_evidence_id=evidence_id,
        record_version=permit.resource_selector.object_version,
        root_representation_id=representation_id,
        targets=targets,
        target_count=1,
        targets_digest=deletion_targets_digest_v2(targets),
        closure_version=1,
        tombstone_policy_version=1,
        finality_policy_version=1,
    )
    store = _DeletionStore(authority)
    service = RealmPolicyDeletionService(
        store,  # type: ignore[arg-type]
        signer=signer,
        verifier=verifier,
        clock=lambda: permit.issued_at + timedelta(seconds=1),
    )
    manifest = service.prepare_manifest(permit.operation_id)
    assert manifest.targets == targets
    assert manifest.idempotency_key == "claim-delete-once"
    assert store.manifests == [manifest]

    store.authority = RealmDeletionAuthorityV1(
        operation_id=permit.operation_id,
        action=permit.action,
        claimed_at=permit.issued_at,
        claim_idempotency_key="claim-delete-once",
        permit=permit,
        root_evidence_id=evidence_id,
        record_version=permit.resource_selector.object_version,
        existing_manifest=manifest,
    )
    assert service.prepare_manifest(permit.operation_id) == manifest
    assert store.manifests == [manifest]


class _DeletionStoreV3:
    def __init__(self, authority: RealmDeletionAuthorityV2) -> None:
        self.authority = authority
        self.manifests: list[Any] = []
        self.grant_authority: RealmGrantAuthorityV1 | None = None
        self.grants: list[SensitiveExecutionGrantV2] = []

    def deletion_authority_v3(self, _operation_id: UUID) -> RealmDeletionAuthorityV2:
        return self.authority

    def store_manifest_v3(self, manifest: Any) -> ScopedDeletionManifestResult:
        self.manifests.append(manifest)
        return ScopedDeletionManifestResult(
            manifest_id=manifest.manifest_id,
            manifest_digest=manifest.unsigned_digest_hex(),
            targets_digest=manifest.targets_digest,
            target_count=manifest.target_count,
            replayed=False,
        )

    def grant_authority_v3(self, _operation_id: UUID) -> RealmGrantAuthorityV1:
        assert self.grant_authority is not None
        return self.grant_authority

    def store_grant_v3(self, grant: SensitiveExecutionGrantV2) -> str:
        self.grants.append(grant)
        return grant.unsigned_digest_hex()


def test_policy_deletion_service_v3_signs_versioned_import_closure() -> None:
    permit, verifier, signer = _permit(SensitiveActionV2.EVIDENCE_DELETE)
    evidence_id = permit.resource_selector.object_id
    representation_id = uuid4()
    candidate_id = uuid4()
    outcome_id = uuid4()
    outcome_encryption_id = uuid4()
    targets = (
        DeletionTargetReferenceV3(
            artifact_class=DeletionArtifactClassV3.ENCRYPTED_ARCHIVE,
            artifact_id=evidence_id,
            artifact_version=permit.resource_selector.object_version,
            root_evidence_id=evidence_id,
            disposition=DeletionDisposition.DESTROY_WRAPPED_KEY,
            representation_id=representation_id,
            wrapped_key_ref=uuid4(),
        ),
        DeletionTargetReferenceV3(
            artifact_class=DeletionArtifactClassV3.MEMORY_CANDIDATE,
            artifact_id=candidate_id,
            artifact_version=2,
            root_evidence_id=evidence_id,
            disposition=DeletionDisposition.INVALIDATE,
        ),
        DeletionTargetReferenceV3(
            artifact_class=DeletionArtifactClassV3.MEMORY_IMPORT_PROVIDER_OUTCOME,
            artifact_id=outcome_id,
            artifact_version=1,
            root_evidence_id=evidence_id,
            disposition=DeletionDisposition.DESTROY_WRAPPED_KEY,
            representation_id=outcome_encryption_id,
            wrapped_key_ref=outcome_encryption_id,
            key_registry_id=uuid4(),
        ),
    )
    authority = RealmDeletionAuthorityV2(
        operation_id=permit.operation_id,
        action=permit.action,
        claimed_at=permit.issued_at,
        claim_idempotency_key="claim-delete-v3-once",
        permit=permit,
        root_evidence_id=evidence_id,
        record_version=permit.resource_selector.object_version,
        root_representation_id=representation_id,
        targets=targets,
        target_count=len(targets),
        targets_digest=deletion_targets_digest_v3(targets),
        closure_version=3,
        tombstone_policy_version=3,
        finality_policy_version=3,
    )
    store = _DeletionStoreV3(authority)
    service = RealmPolicyDeletionServiceV3(
        store,
        signer=signer,
        verifier=verifier,
        clock=lambda: permit.issued_at + timedelta(seconds=1),
    )
    manifest = service.prepare_manifest(permit.operation_id)
    assert manifest.contract_version == "3"
    assert manifest.targets == targets
    assert manifest.signature
    assert store.manifests == [manifest]

    store.grant_authority = RealmGrantAuthorityV1(
        operation_id=permit.operation_id,
        action=permit.action,
        claimed_at=permit.issued_at,
        claim_idempotency_key="claim-delete-v3-once",
        permit=permit,
        package_digest=manifest.unsigned_digest_hex(),
        package_size_bytes=len(manifest.canonical_unsigned_bytes()),
        executor_binding_id=uuid4(),
        caller_identity="arn:aws:iam::123456789012:role/lucy-utopia-deletion",
        executor_identity="lucy-utopia-deletion",
        executor_alias_arn=(
            "arn:aws:lambda:us-east-1:123456789012:"
            "function:lucy-utopia-deletion:realm-v13"
        ),
        executor_version=1,
        receipt_key_id=(
            "arn:aws:kms:us-east-1:123456789012:"
            "key/00000000-0000-4000-8000-000000000001"
        ),
        deletion_manifest_id=manifest.manifest_id,
        deletion_manifest_digest=manifest.unsigned_digest_hex(),
    )
    grant = RealmPolicyGrantServiceV3(
        store,
        signer=signer,
        verifier=verifier,
        clock=lambda: permit.issued_at + timedelta(seconds=1),
    ).issue_grant(permit.operation_id)
    assert grant.deletion_manifest_id == manifest.manifest_id
    assert grant.encrypted_package_digest == manifest.unsigned_digest_hex()
    assert store.grants == [grant]

    store.authority = RealmDeletionAuthorityV2(
        operation_id=permit.operation_id,
        action=permit.action,
        claimed_at=permit.issued_at,
        claim_idempotency_key="claim-delete-v3-once",
        permit=permit,
        root_evidence_id=evidence_id,
        record_version=permit.resource_selector.object_version,
        existing_manifest=manifest,
    )
    assert service.prepare_manifest(permit.operation_id) == manifest
    assert store.manifests == [manifest]

def test_grant_authority_migration_is_policy_only_and_content_free() -> None:
    source = (
        Path(__file__).parents[2]
        / "migrations"
        / "versions"
        / "0040_r1_grant_authority_snapshot.py"
    ).read_text(encoding="utf-8")
    assert "session_login=session_user AND actor_role='policy_notary'" in source
    assert "serialized_package" in source and "'package_digest'" in source
    assert "'package',v_package.serialized_package" not in source
    assert "REVOKE ALL ON FUNCTION lucy.read_claimed_sensitive_authority_v1" in source
    assert "session_login=session_user AND actor_role='sensitive_workflow'" in source
    assert "REVOKE ALL ON FUNCTION lucy.read_sensitive_operation_status_v1" in source


def test_deletion_authority_snapshot_is_exact_content_free_and_rechecks_after_lock() -> None:
    source = (
        Path(__file__).parents[2]
        / "migrations"
        / "versions"
        / "0041_r1_deletion_authority_snapshot.py"
    ).read_text(encoding="utf-8")
    assert "session_login=session_user AND actor_role='policy_notary'" in source
    assert "target_service_binding_id=v_actor.target_service_binding_id" in source
    assert "serialized_payload" not in source
    assert "serialized_wrapper" not in source
    assert "read_claimed_deletion_authority_v1(p_operation_id uuid)" in source
    assert "store_scoped_deletion_manifest_v3" in source
    lock = source.index("PERFORM pg_advisory_xact_lock")
    current_time = source.index("clock_timestamp()>v_deadline")
    delegated_store = source.index(
        "RETURN lucy.store_scoped_deletion_manifest_v2", current_time
    )
    assert lock < current_time < delegated_store
    assert "REVOKE ALL ON FUNCTION lucy.read_claimed_deletion_authority_v1" in source


def test_v3_deletion_execution_migration_is_additive_and_tombstones_derivations() -> None:
    source = (
        Path(__file__).parents[2]
        / "migrations"
        / "versions"
        / "0065_memory_deletion_execution_v3.py"
    ).read_text(encoding="utf-8")
    assert "scoped_deletion_execution_grants_v3" in source
    assert "scoped_memory_candidate_tombstones_v3" in source
    assert "memory_import_outcome_tombstones_v3" in source
    assert "scoped_deletion_effects_v3" in source
    assert "read_claimed_sensitive_authority_v2" in source
    assert "store_deletion_execution_grant_v3" in source
    assert "attest_deletion_executor_receipt_v3" in source
    assert "reconcile_scoped_deletion_v3" in source
    assert "memory_import_outcome_v3_deletion_gate" in source
    assert "DROP FUNCTION lucy.reconcile_scoped_deletion_v2" not in source


def test_permit_authority_migration_is_exact_fenced_and_role_scoped() -> None:
    source = (
        Path(__file__).parents[2]
        / "migrations"
        / "versions"
        / "0042_r1_permit_authority.py"
    ).read_text(encoding="utf-8")
    assert "session_login=session_user AND actor_role='policy_notary'" in source
    assert "p_action NOT IN ('evidence.retrieve','evidence.delete')" in source
    assert "e.id=p_resource_object_id" in source
    assert "ep.record_version=p_resource_object_version" in source
    assert "scoped_evidence_deletion_fences_v2" in source
    assert "scoped_recovery_deletion_fences_v2" in source
    assert "read_sensitive_action_permit_v3(uuid,text)" in source
    assert "p.id=p_permit_id AND p.action=p_expected_action" in source
    assert "REVOKE ALL ON FUNCTION" in source


class _TerminalWorkflow:
    def __init__(self, permit: SensitiveActionPermitV3) -> None:
        self.permit = permit

    def claim(self, _permit_id: UUID, _key: str) -> RealmOperationClaimResultV1:
        return RealmOperationClaimResultV1(
            operation_id=self.permit.operation_id, replayed=True
        )

    def status(self, _operation_id: UUID) -> RealmOperationStatusV1:
        deletion = self.permit.action == SensitiveActionV2.EVIDENCE_DELETE
        return RealmOperationStatusV1(
            operation_id=self.permit.operation_id,
            action=self.permit.action,
            state="FINALITY_PENDING" if deletion else "RECONCILED",
            result="deletion_succeeded" if deletion else "retrieval_succeeded",
            receipt_digest="d" * 64,
            finality_not_before=(
                datetime.now(UTC) + timedelta(days=30) if deletion else None
            ),
        )


class _NeverPolicy:
    def prepare_deletion_manifest(self, _operation_id: UUID) -> Any:
        raise AssertionError("terminal replay must not prepare a deletion manifest")

    def issue_grant(self, _operation_id: UUID) -> Any:
        raise AssertionError("terminal replay must not issue a grant")

    def attest_receipt(self, _receipt: Any) -> str:
        raise AssertionError("terminal replay must not attest a receipt")


class _NeverExecutor:
    def invoke_retrieval(self, _invocation: Any) -> Any:
        raise AssertionError("terminal replay must not reinvoke Lambda")

    def invoke_deletion(self, _invocation: Any) -> Any:
        raise AssertionError("terminal replay must not reinvoke Lambda")


def test_retrieval_coordinator_returns_terminal_replay_without_lambda() -> None:
    permit, _verifier, _signer = _permit()
    coordinator = RealmRetrievalCoordinator(
        _TerminalWorkflow(permit),  # type: ignore[arg-type]
        _NeverPolicy(),  # type: ignore[arg-type]
        _NeverExecutor(),  # type: ignore[arg-type]
    )
    result = coordinator.execute(permit, idempotency_key="claim-once")
    assert result.state == "RECONCILED"
    assert result.plaintext_b64 is None
    assert result.executor_replayed is True


def test_deletion_coordinator_returns_terminal_replay_without_lambda() -> None:
    permit, _verifier, _signer = _permit(SensitiveActionV2.EVIDENCE_DELETE)
    coordinator = RealmDeletionCoordinator(
        _TerminalWorkflow(permit),  # type: ignore[arg-type]
        _NeverPolicy(),  # type: ignore[arg-type]
        _NeverExecutor(),  # type: ignore[arg-type]
    )
    result = coordinator.execute(permit, idempotency_key="claim-delete-once")
    assert result.state == "FINALITY_PENDING"
    assert result.receipt_digest == "d" * 64
    assert result.executor_replayed is True


def test_deletion_coordinator_executes_manifest_grant_receipt_then_reconciles() -> None:
    permit, _verifier, _signer = _permit(SensitiveActionV2.EVIDENCE_DELETE)
    events: list[str] = []

    class Workflow:
        def claim(self, permit_id: UUID, key: str) -> RealmOperationClaimResultV1:
            assert permit_id == permit.permit_id and key == "delete-once"
            events.append("claim")
            return RealmOperationClaimResultV1(
                operation_id=permit.operation_id, replayed=False
            )

        def status(self, operation_id: UUID) -> RealmOperationStatusV1:
            assert operation_id == permit.operation_id
            events.append("status")
            return RealmOperationStatusV1(
                operation_id=operation_id,
                action=SensitiveActionV2.EVIDENCE_DELETE,
                state="CLAIMED",
            )

        def reconcile(self, operation_id: UUID, action: SensitiveActionV2) -> Any:
            assert operation_id == permit.operation_id
            assert action == SensitiveActionV2.EVIDENCE_DELETE
            events.append("reconcile")
            return SimpleNamespace(
                operation_id=operation_id,
                state="FINALITY_PENDING",
                receipt_digest="e" * 64,
                finality_not_before=datetime.now(UTC) + timedelta(days=30),
            )

    evidence_id = permit.resource_selector.object_id
    representation_id = uuid4()
    targets = (
        DeletionTargetReferenceV2(
            artifact_class=DeletionArtifactClass.ENCRYPTED_ARCHIVE,
            artifact_id=evidence_id,
            artifact_version=permit.resource_selector.object_version,
            root_evidence_id=evidence_id,
            disposition=DeletionDisposition.DESTROY_WRAPPED_KEY,
            representation_id=representation_id,
            wrapped_key_ref=uuid4(),
        ),
    )
    authority = RealmDeletionAuthorityV1(
        operation_id=permit.operation_id,
        action=permit.action,
        claimed_at=permit.issued_at,
        claim_idempotency_key="delete-once",
        permit=permit,
        root_evidence_id=evidence_id,
        record_version=permit.resource_selector.object_version,
        root_representation_id=representation_id,
        targets=targets,
        target_count=1,
        targets_digest=deletion_targets_digest_v2(targets),
        closure_version=1,
        tombstone_policy_version=1,
        finality_policy_version=1,
    )
    manifest = RealmPolicyDeletionService(
        _DeletionStore(authority),  # type: ignore[arg-type]
        signer=_signer,
        verifier=_verifier,
        clock=lambda: permit.issued_at + timedelta(seconds=1),
    ).prepare_manifest(permit.operation_id)
    alias = (
        "arn:aws:lambda:us-east-1:123456789012:"
        "function:lucy-utopia-deletion:realm-v13"
    )
    grant = _signer.sign(
        SensitiveExecutionGrantV2(
            key_id=permit.key_id,
            issuer=permit.issuer,
            environment=permit.environment,
            issued_at=permit.issued_at + timedelta(seconds=1),
            grant_id=uuid4(),
            action=permit.action,
            permit_id=permit.permit_id,
            permit_digest=permit.unsigned_digest_hex(),
            operation_id=permit.operation_id,
            caller_identity="arn:aws:iam::123456789012:role/lucy-utopia-deletion",
            target_scope=permit.target_scope,
            workspace_id=permit.workspace_id,
            resource_selector=permit.resource_selector,
            execution_binding=permit.execution_binding,
            deletion_manifest_id=manifest.manifest_id,
            deletion_manifest_digest=manifest.unsigned_digest_hex(),
            encrypted_package_digest=manifest.unsigned_digest_hex(),
            package_size_bytes=len(manifest.canonical_unsigned_bytes()),
            idempotency_key="delete-once",
            executor_identity="lucy-utopia-deletion-executor",
            executor_alias_arn=alias,
            executor_version=1,
            permit_claimed_at=permit.issued_at,
            permit_claim_deadline=permit.permit_claim_deadline,
            execution_completion_deadline=permit.execution_completion_deadline,
            max_records=permit.max_records,
            max_bytes=permit.max_bytes,
            nonce=uuid4().hex,
        )
    )
    receipt = object()

    class Policy:
        def prepare_deletion_manifest(self, operation_id: UUID) -> Any:
            assert operation_id == permit.operation_id
            events.append("manifest")
            return manifest

        def issue_grant(self, operation_id: UUID) -> Any:
            assert operation_id == permit.operation_id
            events.append("grant")
            return grant

        def attest_receipt(self, candidate: object) -> str:
            assert candidate is receipt
            events.append("attest")
            return "e" * 64

    class Executor:
        def invoke_deletion(self, invocation: Any) -> Any:
            assert invocation.permit == permit
            assert invocation.execution_grant == grant
            assert invocation.manifest == manifest
            events.append("invoke")
            return SimpleNamespace(receipt=receipt, replayed=False)

    result = RealmDeletionCoordinator(
        Workflow(),  # type: ignore[arg-type]
        Policy(),  # type: ignore[arg-type]
        Executor(),  # type: ignore[arg-type]
    ).execute(permit, idempotency_key="delete-once")
    assert result.state == "FINALITY_PENDING"
    assert result.executor_replayed is False
    assert events == [
        "claim",
        "status",
        "manifest",
        "grant",
        "invoke",
        "attest",
        "reconcile",
    ]


@pytest.mark.parametrize(
    "alias",
    [
        "",
        "arn:aws:lambda:us-east-1:123456789012:function:executor:$LATEST",
        "arn:aws:lambda:us-east-1:123456789012:function:executor:1",
        "https://example.com/executor",
    ],
)
def test_realm_lambda_invoker_requires_exact_alias(alias: str) -> None:
    with pytest.raises(ValueError, match="exact non-version"):
        RealmLambdaExecutorInvoker(object(), retrieval_alias_arn=alias)


def test_realm_lambda_invoker_requires_one_execution_identity() -> None:
    alias = (
        "arn:aws:lambda:us-east-1:123456789012:"
        "function:lucy-utopia-executor:realm-v13"
    )
    with pytest.raises(ValueError, match="one realm executor alias"):
        RealmLambdaExecutorInvoker(object())
    with pytest.raises(ValueError, match="one realm executor alias"):
        RealmLambdaExecutorInvoker(
            object(), retrieval_alias_arn=alias, deletion_alias_arn=alias
        )


@pytest.mark.parametrize(
    "hostport,token",
    [
        ("https://lucy-policy:8080", "token"),
        ("lucy-policy", "token"),
        ("lucy-policy:70000", "token"),
        ("lucy-policy:8080", ""),
    ],
)
def test_realm_policy_client_rejects_unbounded_configuration(
    hostport: str, token: str
) -> None:
    with pytest.raises(ValueError, match="private realm policy client"):
        HttpRealmPolicyClient(hostport, token)


def test_workflow_store_selects_action_specific_reconciliation() -> None:
    operation_id = uuid4()
    sessions = _Sessions(
        [
            {"operation_id": str(operation_id), "replayed": False},
            {
                "operation_id": str(operation_id),
                "action": SensitiveActionV2.EVIDENCE_RETRIEVE,
                "state": "CLAIMED",
                "result": None,
                "receipt_digest": None,
                "finality_not_before": None,
            },
            {
                "operation_id": str(operation_id),
                "state": "RECONCILED",
                "result": "retrieval_succeeded",
                "receipt_digest": "a" * 64,
                "replayed": False,
            },
            {
                "operation_id": str(operation_id),
                "state": "FINALITY_PENDING",
                "result": "deletion_succeeded",
                "receipt_digest": "b" * 64,
                "finality_not_before": datetime.now(UTC).isoformat(),
                "replayed": False,
            },
            {
                "operation_id": str(operation_id),
                "state": "FINALITY_PENDING",
                "result": "deletion_succeeded",
                "receipt_digest": "c" * 64,
                "finality_not_before": datetime.now(UTC).isoformat(),
                "replayed": False,
            },
        ]
    )
    store = PostgresRealmWorkflowStore(sessions)  # type: ignore[arg-type]
    assert store.claim(uuid4(), "claim-once").operation_id == operation_id
    assert store.status(operation_id).state == "CLAIMED"
    assert store.reconcile(operation_id, SensitiveActionV2.EVIDENCE_RETRIEVE).state == (
        "RECONCILED"
    )
    assert store.reconcile(operation_id, SensitiveActionV2.EVIDENCE_DELETE).state == (
        "FINALITY_PENDING"
    )
    assert store.reconcile_deletion_v3(operation_id).state == "FINALITY_PENDING"
    statements = sessions.session.statements
    assert "claim_sensitive_operation_v2" in statements[0]
    assert "read_sensitive_operation_status_v1" in statements[1]
    assert "reconcile_sensitive_operation_v2" in statements[2]
    assert "reconcile_scoped_deletion_v2" in statements[3]
    assert "reconcile_scoped_deletion_v3" in statements[4]
