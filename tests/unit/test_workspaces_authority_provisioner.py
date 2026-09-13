from datetime import UTC, datetime
from uuid import uuid4

import pytest

from deploy.postgres.provision_realm_bindings_v1_3 import RealmProvisioningError
from deploy.postgres.provision_workspaces_authority_v1 import (
    AUTHORIZATION,
    WorkspacesAuthorityConfig,
    WorkspacesAuthorityMembershipV1,
)


def _manifest() -> WorkspacesAuthorityMembershipV1:
    return WorkspacesAuthorityMembershipV1(
        realm_slug="utopia",
        membership_id=uuid4(),
        service_principal_id=uuid4(),
        service_binding_id=uuid4(),
        workspace_id=uuid4(),
        identity_issuer="lucy://utopia/services",
        identity_subject="lucy_utopia_routine",
        granted_at=datetime(2026, 9, 12, tzinfo=UTC),
    )


def _environment(manifest: WorkspacesAuthorityMembershipV1) -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_WORKSPACES_AUTHORITY_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:x@dpg-example-a/lucy_6tns"
        ),
        "LUCY_WORKSPACES_AUTHORITY_MEMBERSHIP_JSON": manifest.model_dump_json(),
        "LUCY_WORKSPACES_AUTHORITY_MEMBERSHIP_SHA256": manifest.digest_hex(),
    }


def test_config_requires_exact_quarantined_authority_manifest() -> None:
    manifest = _manifest()
    assert WorkspacesAuthorityConfig.from_environment(_environment(manifest)).manifest == manifest
    for key, value in {
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "true",
        "LUCY_WORKSPACES_AUTHORITY_AUTHORIZATION": "wrong",
        "LUCY_WORKSPACES_AUTHORITY_MEMBERSHIP_SHA256": "0" * 64,
        "LUCY_MIGRATION_DATABASE_URL": "postgresql://lucy_migration:x@example.com/other",
    }.items():
        with pytest.raises(RealmProvisioningError):
            WorkspacesAuthorityConfig.from_environment(
                _environment(manifest) | {key: value}
            )
