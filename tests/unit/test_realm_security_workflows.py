from __future__ import annotations

from datetime import UTC, datetime, timedelta
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
    PostgresRealmWorkflowStore,
    RealmWorkflowUnavailable,
    VerifiedRealmPolicyAdapter,
)


def _permit() -> tuple[SensitiveActionPermitV3, V13ContractVerifier]:
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
    return permit, V13ContractVerifier((key,))


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
    permit, verifier = _permit()
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


def test_workflow_store_selects_action_specific_reconciliation() -> None:
    operation_id = uuid4()
    sessions = _Sessions(
        [
            {"operation_id": str(operation_id), "replayed": False},
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
    assert store.reconcile(operation_id, SensitiveActionV2.EVIDENCE_RETRIEVE).state == (
        "RECONCILED"
    )
    assert store.reconcile(operation_id, SensitiveActionV2.EVIDENCE_DELETE).state == (
        "FINALITY_PENDING"
    )
    statements = sessions.session.statements
    assert "claim_sensitive_operation_v2" in statements[0]
    assert "reconcile_sensitive_operation_v2" in statements[1]
    assert "reconcile_scoped_deletion_v2" in statements[2]
