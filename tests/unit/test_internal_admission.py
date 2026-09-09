from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from pydantic import SecretStr, ValidationError

from lucy.contracts.security_v1_3 import (
    AuthenticationStrength,
    ExactObjectSelectorV1,
    OriginScopeV1,
    PrincipalType,
    ResolvedExecutionContextV1,
)
from lucy.internal_admission import (
    DirectoryAdmissionDecisionV1,
    DirectoryAdmissionRequestV1,
    InternalAdmissionDenied,
    RealmInternalAdmissionService,
    VerifiedCustomerIdentityV1,
)
from lucy.realm_sessions import RealmRuntimeBindingV1, RealmSessionRegistry

ZERO = UUID("00000000-0000-4000-8000-000000000000")
ONE = UUID("00000000-0000-4000-8000-000000000001")
TWO = UUID("00000000-0000-4000-8000-000000000002")
THREE = UUID("00000000-0000-4000-8000-000000000003")
FOUR = UUID("00000000-0000-4000-8000-000000000004")
FIVE = UUID("00000000-0000-4000-8000-000000000005")
NOW = datetime(2026, 9, 9, 14, 0, tzinfo=UTC)


def _scope(*, realm_id: UUID = THREE) -> OriginScopeV1:
    return OriginScopeV1(
        tenant_account_id=ZERO,
        node_id=ONE,
        node_tenure_id=TWO,
        tenure_epoch=1,
        security_realm_id=realm_id,
        storage_epoch=1,
    )


def _binding() -> RealmRuntimeBindingV1:
    return RealmRuntimeBindingV1(
        workload_subject="render:utopia:routine",
        service_principal_id=FOUR,
        service_binding_id=FIVE,
        target_scope=_scope(),
        workspace_id=FOUR,
        deployment_id=FIVE,
        channel_binding_id=THREE,
        identity_issuer="https://identity.test",
        identity_audience="lucy:utopia:internal",
        context_issuer="lucy:utopia:admission",
        database_url="postgresql://utopia:secret@utopia.private/db",
        allowed_actions=frozenset({"memory.read"}),
        allowed_authentication_strengths=frozenset({AuthenticationStrength.MFA}),
        binding_generation=2,
        policy_version=3,
    )


class SyntheticVerifier:
    def __init__(self, identity: VerifiedCustomerIdentityV1) -> None:
        self.identity = identity

    def verify(
        self,
        credential: SecretStr,
        *,
        expected_issuer: str,
        expected_audience: str,
        checked_at: datetime,
    ) -> VerifiedCustomerIdentityV1:
        assert credential.get_secret_value() == "synthetic-token"
        assert expected_issuer == "https://identity.test"
        assert expected_audience == "lucy:utopia:internal"
        assert checked_at == NOW
        return self.identity


class SyntheticDirectory:
    def __init__(self, decision: DirectoryAdmissionDecisionV1) -> None:
        self.decision = decision
        self.request: DirectoryAdmissionRequestV1 | None = None

    def authorize(
        self, request: DirectoryAdmissionRequestV1, *, checked_at: datetime
    ) -> DirectoryAdmissionDecisionV1:
        assert checked_at == NOW
        self.request = request
        return self.decision


def _identity(**changes: object) -> VerifiedCustomerIdentityV1:
    values: dict[str, object] = {
        "issuer": "https://identity.test",
        "subject": "ray-subject",
        "audience": "lucy:utopia:internal",
        "principal_type": PrincipalType.HUMAN,
        "authentication_strength": AuthenticationStrength.MFA,
        "auth_time": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=10),
        "session_id": TWO,
    }
    values.update(changes)
    return VerifiedCustomerIdentityV1.model_validate(values)


def _decision(**changes: object) -> DirectoryAdmissionDecisionV1:
    values: dict[str, object] = {
        "principal_id": ONE,
        "identity_issuer": "https://identity.test",
        "identity_subject": "ray-subject",
        "principal_type": PrincipalType.HUMAN,
        "target_scope": _scope(),
        "workspace_id": FOUR,
        "service_principal_id": FOUR,
        "service_binding_id": FIVE,
        "service_binding_generation": 2,
        "channel_binding_id": THREE,
        "channel_generation": 4,
        "membership_generations": (7,),
        "realm_binding_generation": 5,
        "node_authz_epoch": 6,
        "policy_version": 3,
        "authorized_action": "memory.read",
        "resource_selector": ExactObjectSelectorV1(object_id=FOUR, object_version=1),
    }
    values.update(changes)
    return DirectoryAdmissionDecisionV1.model_validate(values)


def _service(
    *, identity: VerifiedCustomerIdentityV1 | None = None,
    decision: DirectoryAdmissionDecisionV1 | None = None,
) -> RealmInternalAdmissionService:
    return RealmInternalAdmissionService(
        sessions=RealmSessionRegistry((_binding(),)),
        verified_workload_subject="render:utopia:routine",
        identity_verifier=SyntheticVerifier(identity or _identity()),
        directory=SyntheticDirectory(decision or _decision()),
    )


def test_realm_local_admission_builds_complete_digest_bound_context() -> None:
    selector = ExactObjectSelectorV1(object_id=FOUR, object_version=1)
    context = _service().admit(
        credential=SecretStr("synthetic-token"),
        request_id=ZERO,
        action="memory.read",
        resource_selector=selector,
        checked_at=NOW,
    )
    assert context.target_scope.security_realm_id == THREE
    assert context.workspace_id == FOUR
    assert context.channel_generation == 4
    assert context.membership_generations == (7,)
    assert context.expires_at == NOW + timedelta(minutes=5)
    with pytest.raises(ValidationError, match="digest"):
        ResolvedExecutionContextV1.model_validate(
            {**context.model_dump(mode="python"), "workspace_id": FIVE}
        )


@pytest.mark.parametrize(
    ("identity", "decision"),
    (
        (_identity(audience="lucy:raymond:internal"), _decision()),
        (_identity(authentication_strength=AuthenticationStrength.SINGLE_FACTOR), _decision()),
        (_identity(expires_at=NOW), _decision()),
        (_identity(), _decision(target_scope=_scope(realm_id=FOUR))),
        (_identity(), _decision(identity_subject="forged-subject")),
    ),
)
def test_untrusted_or_foreign_identity_and_directory_results_fail_closed(
    identity: VerifiedCustomerIdentityV1,
    decision: DirectoryAdmissionDecisionV1,
) -> None:
    with pytest.raises(InternalAdmissionDenied, match="not authorized"):
        _service(identity=identity, decision=decision).admit(
            credential=SecretStr("synthetic-token"),
            request_id=ZERO,
            action="memory.read",
            resource_selector=ExactObjectSelectorV1(object_id=FOUR, object_version=1),
            checked_at=NOW,
        )


def test_directory_contracts_cannot_carry_content_or_credentials() -> None:
    request_fields = set(DirectoryAdmissionRequestV1.model_json_schema()["properties"])
    decision_fields = set(DirectoryAdmissionDecisionV1.model_json_schema()["properties"])
    prohibited = {"credential", "database_url", "prompt", "query", "response", "content"}
    assert request_fields.isdisjoint(prohibited)
    assert decision_fields.isdisjoint(prohibited)
