from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from pydantic import SecretStr, ValidationError

from lucy.contracts.security_v1_3 import (
    AudienceClass,
    AuthenticationStrength,
    ExactObjectSelectorV1,
    ExecutionBindingV1,
    OriginScopeV1,
    PrincipalType,
    build_resolved_execution_context_v1,
)
from lucy.internal_admission import InternalAdmissionDenied
from lucy.workspaces_admission import (
    WorkspacesExperienceGateway,
    WorkspacesRoomAdmissionRequestV1,
)

ZERO = UUID("00000000-0000-4000-8000-000000000000")
ONE = UUID("00000000-0000-4000-8000-000000000001")
TWO = UUID("00000000-0000-4000-8000-000000000002")
THREE = UUID("00000000-0000-4000-8000-000000000003")
FOUR = UUID("00000000-0000-4000-8000-000000000004")
FIVE = UUID("00000000-0000-4000-8000-000000000005")
NOW = datetime(2026, 9, 12, 18, 0, tzinfo=UTC)


def _context(*, action: str, principal_id: UUID = ONE):
    return build_resolved_execution_context_v1(
        {
            "context_id": FIVE,
            "request_id": ZERO,
            "issued_at": NOW,
            "expires_at": NOW + timedelta(minutes=5),
            "principal_id": principal_id,
            "principal_type": PrincipalType.HUMAN,
            "identity_issuer": "https://identity.test",
            "identity_subject": "ray-subject",
            "authn_strength": AuthenticationStrength.MFA,
            "auth_time": NOW - timedelta(minutes=1),
            "target_scope": OriginScopeV1(
                tenant_account_id=ZERO,
                node_id=ONE,
                node_tenure_id=TWO,
                tenure_epoch=1,
                security_realm_id=THREE,
                storage_epoch=1,
            ),
            "workspace_id": FOUR,
            "service_principal_id": FOUR,
            "service_binding_id": FIVE,
            "execution_binding": ExecutionBindingV1(
                deployment_id=FIVE,
                active_realm_id=THREE,
                active_storage_epoch=1,
                realm_binding_generation=1,
                node_authz_epoch=1,
            ),
            "channel_binding_id": THREE,
            "channel_generation": 1,
            "audience_class": AudienceClass.AUTHENTICATED_INTERNAL,
            "session_id": TWO,
            "action": action,
            "resource_selector": ExactObjectSelectorV1(
                object_id=FOUR, object_version=1
            ),
            "policy_version": 1,
            "membership_generations": (1,),
            "context_issuer": "lucy:utopia:admission",
        }
    )


class SyntheticAdmission:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ExactObjectSelectorV1]] = []
        self.principal_by_action: dict[str, UUID] = {}

    def admit(self, **values: object):
        credential = values["credential"]
        assert isinstance(credential, SecretStr)
        assert credential.get_secret_value() == "identity-token"
        action = values["action"]
        selector = values["resource_selector"]
        assert isinstance(action, str)
        assert isinstance(selector, ExactObjectSelectorV1)
        self.calls.append((action, selector))
        return _context(action=action, principal_id=self.principal_by_action.get(action, ONE))


def _gateway(admission: SyntheticAdmission) -> WorkspacesExperienceGateway:
    return WorkspacesExperienceGateway(
        admission=admission,  # type: ignore[arg-type]
        workspace_id=FOUR,
        room_capabilities=frozenset({"memory.read", "task.delegate"}),
    )


def _request(*capabilities: str) -> WorkspacesRoomAdmissionRequestV1:
    return WorkspacesRoomAdmissionRequestV1(
        request_id=ZERO,
        room_id=TWO,
        requested_capabilities=capabilities,
    )


def test_preflight_intersects_fixed_room_policy_and_returns_non_bearer_receipt() -> None:
    admission = SyntheticAdmission()
    receipt = _gateway(admission).preflight(
        credential=SecretStr("identity-token"),
        request=_request("memory.read", "task.delegate"),
        checked_at=NOW,
    )

    assert [call[0] for call in admission.calls] == ["memory.read", "task.delegate"]
    assert all(call[1].object_id == FOUR for call in admission.calls)
    assert receipt.admitted_capabilities == ("memory.read", "task.delegate")
    assert receipt.usable_as_bearer is False
    assert receipt.expires_at == NOW + timedelta(minutes=5)


def test_request_contract_cannot_select_authority_or_carry_content_or_credentials() -> None:
    fields = set(WorkspacesRoomAdmissionRequestV1.model_json_schema()["properties"])
    prohibited = {
        "credential",
        "node_id",
        "realm_id",
        "workspace_id",
        "channel_binding_id",
        "query",
        "prompt",
        "content",
    }
    assert fields.isdisjoint(prohibited)
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        WorkspacesRoomAdmissionRequestV1.model_validate(
            {
                **_request("memory.read").model_dump(),
                "node_id": str(ONE),
            }
        )


def test_unconfigured_capability_fails_before_directory_admission() -> None:
    admission = SyntheticAdmission()
    with pytest.raises(InternalAdmissionDenied, match="not authorized"):
        _gateway(admission).preflight(
            credential=SecretStr("identity-token"),
            request=_request("evidence.delete"),
            checked_at=NOW,
        )
    assert admission.calls == []


def test_mixed_authority_result_fails_closed() -> None:
    admission = SyntheticAdmission()
    admission.principal_by_action["task.delegate"] = FIVE
    with pytest.raises(InternalAdmissionDenied, match="not authorized"):
        _gateway(admission).preflight(
            credential=SecretStr("identity-token"),
            request=_request("memory.read", "task.delegate"),
            checked_at=NOW,
        )


def test_execute_readmits_current_authority_and_keeps_context_inside_effect() -> None:
    admission = SyntheticAdmission()
    observed_action = _gateway(admission).execute(
        credential=SecretStr("identity-token"),
        request_id=ZERO,
        room_id=TWO,
        capability="memory.read",
        checked_at=NOW,
        effect=lambda context: context.action,
    )
    assert observed_action == "memory.read"
    assert [call[0] for call in admission.calls] == ["memory.read"]


def test_duplicate_capabilities_are_rejected() -> None:
    with pytest.raises(ValidationError, match="must be unique"):
        _request("memory.read", "memory.read")
