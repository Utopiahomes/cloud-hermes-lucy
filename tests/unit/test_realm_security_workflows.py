from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from lucy.contracts.security_v1_2 import DeploymentEnvironment, SensitiveActionV2
from lucy.contracts.security_v1_3 import (
    Ed25519V13Signer,
    ExactObjectSelectorV1,
    ExecutionBindingV1,
    OriginScopeV1,
    SensitiveActionPermitV3,
    SensitiveReasonCode,
    V13ContractVerifier,
    V13SigningKeyPurpose,
    V13VerificationKeyStatus,
    V13VerificationKeyV1,
)
from lucy.realm_security_workflows import (
    HttpRealmPolicyClient,
    PostgresRealmPolicyStore,
    PostgresRealmWorkflowStore,
    RealmGrantAuthorityV1,
    RealmLambdaExecutorInvoker,
    RealmOperationClaimResultV1,
    RealmOperationStatusV1,
    RealmPolicyGrantService,
    RealmRetrievalCoordinator,
    RealmWorkflowUnavailable,
    VerifiedRealmPolicyAdapter,
)


def _permit() -> tuple[
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
            action=SensitiveActionV2.EVIDENCE_RETRIEVE,
            reason=SensitiveReasonCode.OWNER_REVIEW,
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
            max_records=1,
            max_bytes=65_536,
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
    def __init__(self, stored_id: UUID | None = None) -> None:
        self.stored_id = stored_id
        self.calls: list[tuple[SensitiveActionPermitV3, str]] = []

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


class _TerminalWorkflow:
    def __init__(self, permit: SensitiveActionPermitV3) -> None:
        self.permit = permit

    def claim(self, _permit_id: UUID, _key: str) -> RealmOperationClaimResultV1:
        return RealmOperationClaimResultV1(
            operation_id=self.permit.operation_id, replayed=True
        )

    def status(self, _operation_id: UUID) -> RealmOperationStatusV1:
        return RealmOperationStatusV1(
            operation_id=self.permit.operation_id,
            action=self.permit.action,
            state="RECONCILED",
            result="retrieval_succeeded",
            receipt_digest="d" * 64,
        )


class _NeverPolicy:
    def issue_grant(self, _operation_id: UUID) -> Any:
        raise AssertionError("terminal replay must not issue a grant")

    def attest_receipt(self, _receipt: Any) -> str:
        raise AssertionError("terminal replay must not attest a receipt")


class _NeverExecutor:
    def invoke_retrieval(self, _invocation: Any) -> Any:
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
    statements = sessions.session.statements
    assert "claim_sensitive_operation_v2" in statements[0]
    assert "read_sensitive_operation_status_v1" in statements[1]
    assert "reconcile_sensitive_operation_v2" in statements[2]
    assert "reconcile_scoped_deletion_v2" in statements[3]
