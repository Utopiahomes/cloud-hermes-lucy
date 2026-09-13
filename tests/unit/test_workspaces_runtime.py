import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import SecretStr

from lucy.workspaces_runtime import (
    FixedWorkspacesAuthorityVerifier,
    WorkspacesRuntimeConfiguration,
    WorkspacesRuntimeConfigurationError,
)

ONE = UUID("00000000-0000-4000-8000-000000000001")
TWO = UUID("00000000-0000-4000-8000-000000000002")


def _binding() -> dict[str, object]:
    return {
        "workload_subject": "render:workspaces-private",
        "service_principal_id": str(ONE),
        "service_binding_id": str(TWO),
        "target_scope": {
            "tenant_account_id": str(ONE),
            "node_id": str(TWO),
            "node_tenure_id": str(ONE),
            "tenure_epoch": 1,
            "security_realm_id": str(TWO),
            "storage_epoch": 1,
        },
        "workspace_id": str(ONE),
        "deployment_id": str(TWO),
        "channel_binding_id": str(ONE),
        "identity_issuer": "utopia.workspaces.internal",
        "identity_audience": "cloud-lucy",
        "context_issuer": "cloud-lucy-directory",
        "database_url": "postgresql://lucy_utopia_routine:secret@db/lucy",
        "allowed_actions": ["memory.read", "task.delegate", "task.execute"],
        "allowed_authentication_strengths": ["workload_identity"],
        "binding_generation": 1,
        "policy_version": 1,
    }


def _environment() -> dict[str, str]:
    return {
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_WORKSPACES_RUNTIME_BINDING_JSON": json.dumps(_binding()),
        "LUCY_WORKSPACES_ROOM_CAPABILITIES_JSON": json.dumps(
            ["memory.read", "task.delegate"]
        ),
        "LUCY_WORKSPACES_AUTHORITY_SESSION_ID": str(ONE),
        "LUCY_WORKSPACES_PROJECTION_STORAGE_EPOCH": str(TWO),
        "LUCY_EXPECTED_DATABASE_LOGIN": "lucy_utopia_routine",
        "LUCY_WORKSPACES_DIRECTORY_DATABASE_URL": (
            "postgresql://lucy_directory_admission:secret@db/lucy"
        ),
        "LUCY_WORKSPACES_EXPECTED_DIRECTORY_LOGIN": "lucy_directory_admission",
        "LUCY_WORKSPACES_TRANSPORT_TOKEN": "t" * 32,
        "LUCY_WORKSPACES_AUTHORITY_TOKEN": "a" * 32,
        "LUCY_WORKSPACES_AUTHORITY_SUBJECT": "utopia-workspaces-lucy",
        "LUCY_WORKSPACES_AUTHORITY_MODE": "approved_knowledge",
        "LUCY_WORKSPACES_AUTHORITY_REF": "utopia-sales-approved-v1",
        "LUCY_WORKSPACES_PROJECTION_HOSTNAME": "www.utopiahomes.com",
        "LUCY_WORKSPACES_PROJECTION_SNAPSHOT_DIGEST": "b" * 64,
    }


def test_runtime_configuration_binds_one_realm_and_bounded_capabilities() -> None:
    config = WorkspacesRuntimeConfiguration.from_environment(_environment())
    assert config.binding.service_binding_id == TWO
    assert config.room_capabilities == frozenset({"memory.read", "task.delegate"})
    assert config.projection_snapshot_digest == "b" * 64


def test_runtime_configuration_rejects_unbound_or_unexecutable_capabilities() -> None:
    environment = _environment()
    environment["LUCY_WORKSPACES_ROOM_CAPABILITIES_JSON"] = '["evidence.delete"]'
    with pytest.raises(WorkspacesRuntimeConfigurationError, match="exceed"):
        WorkspacesRuntimeConfiguration.from_environment(environment)

    environment = _environment()
    binding = _binding()
    binding["allowed_actions"] = ["memory.read", "task.delegate"]
    environment["LUCY_WORKSPACES_RUNTIME_BINDING_JSON"] = json.dumps(binding)
    with pytest.raises(WorkspacesRuntimeConfigurationError, match="executor"):
        WorkspacesRuntimeConfiguration.from_environment(environment)

    environment = _environment()
    environment["LUCY_WORKSPACES_ROOM_CAPABILITIES_JSON"] = (
        '["memory.read","memory.read"]'
    )
    with pytest.raises(WorkspacesRuntimeConfigurationError, match="configuration"):
        WorkspacesRuntimeConfiguration.from_environment(environment)


def test_runtime_configuration_rejects_capture_and_database_identity_drift() -> None:
    environment = _environment() | {"LUCY_TRANSCRIPT_CAPTURE_ENABLED": "true"}
    with pytest.raises(WorkspacesRuntimeConfigurationError, match="capture"):
        WorkspacesRuntimeConfiguration.from_environment(environment)
    environment = _environment() | {"LUCY_EXPECTED_DATABASE_LOGIN": "wrong_login"}
    with pytest.raises(WorkspacesRuntimeConfigurationError, match="database identity"):
        WorkspacesRuntimeConfiguration.from_environment(environment)


def test_fixed_authority_verifier_accepts_only_server_held_token() -> None:
    config = WorkspacesRuntimeConfiguration.from_environment(_environment())
    verifier = FixedWorkspacesAuthorityVerifier(config)
    now = datetime(2026, 9, 12, 19, 0, tzinfo=UTC)
    identity = verifier.verify(
        SecretStr("a" * 32),
        expected_issuer=config.binding.identity_issuer,
        expected_audience=config.binding.identity_audience,
        checked_at=now,
    )
    assert identity.subject == "utopia-workspaces-lucy"
    assert identity.expires_at > now
    with pytest.raises(PermissionError):
        verifier.verify(
            SecretStr("x" * 32),
            expected_issuer=config.binding.identity_issuer,
            expected_audience=config.binding.identity_audience,
            checked_at=now,
        )
