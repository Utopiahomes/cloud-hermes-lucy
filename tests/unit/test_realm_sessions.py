from __future__ import annotations

from uuid import UUID

import pytest

from lucy.contracts.security_v1_3 import OriginScopeV1
from lucy.realm_sessions import (
    RealmAccessDenied,
    RealmBindingConfigurationError,
    RealmRuntimeBindingV1,
    RealmSessionRegistry,
)

ZERO = UUID("00000000-0000-4000-8000-000000000000")
ONE = UUID("00000000-0000-4000-8000-000000000001")
TWO = UUID("00000000-0000-4000-8000-000000000002")
THREE = UUID("00000000-0000-4000-8000-000000000003")
FOUR = UUID("00000000-0000-4000-8000-000000000004")


def _binding(name: str, realm: UUID, database_url: str) -> RealmRuntimeBindingV1:
    return RealmRuntimeBindingV1(
        workload_subject=f"render:{name}:routine",
        service_binding_id=ONE,
        target_scope=OriginScopeV1(
            tenant_account_id=ZERO,
            node_id=TWO,
            node_tenure_id=THREE,
            tenure_epoch=1,
            security_realm_id=realm,
            storage_epoch=1,
        ),
        workspace_id=FOUR,
        deployment_id=ONE,
        database_url=database_url,
        allowed_actions=frozenset({"memory.read", "memory.write"}),
        binding_generation=1,
    )


def test_verified_workload_selects_one_fixed_realm_connection() -> None:
    utopia = _binding("utopia", ONE, "postgresql://utopia:not-a-real-password@utopia.private/db")
    alpha = _binding("alpha", TWO, "postgresql://alpha:secret@alpha.private/db")
    registry = RealmSessionRegistry((utopia, alpha))
    bound = registry.for_verified_workload(
        "render:utopia:routine",
        action="memory.read",
        requested_realm_id=ONE,
        requested_workspace_id=FOUR,
    )
    assert bound.binding.target_scope.security_realm_id == ONE
    assert "not-a-real-password" not in repr(bound.binding)


def test_unknown_action_or_request_selected_scope_fails_uniformly() -> None:
    registry = RealmSessionRegistry(
        (_binding("utopia", ONE, "postgresql://utopia:secret@utopia.private/db"),)
    )
    for values in (
        {"workload_subject": "render:unknown:routine", "action": "memory.read"},
        {"workload_subject": "render:utopia:routine", "action": "evidence.retrieve"},
        {
            "workload_subject": "render:utopia:routine",
            "action": "memory.read",
            "requested_realm_id": TWO,
        },
    ):
        with pytest.raises(RealmAccessDenied, match="not authorized"):
            registry.for_verified_workload(**values)  # type: ignore[arg-type]


def test_private_realm_bindings_cannot_share_credentials() -> None:
    shared = "postgresql://shared:secret@shared.private/db"
    with pytest.raises(RealmBindingConfigurationError, match="must not share"):
        RealmSessionRegistry(
            (
                _binding("utopia", ONE, shared),
                _binding("alpha", TWO, shared),
            )
        )
