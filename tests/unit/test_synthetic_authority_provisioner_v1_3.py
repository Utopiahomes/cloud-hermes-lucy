from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from deploy.postgres.provision_realm_bindings_v1_3 import RealmProvisioningError
from deploy.postgres.provision_synthetic_authority_v1_3 import (
    AUTHORIZATION,
    SyntheticOwnerConfig,
    SyntheticOwnerManifestV1,
)
from lucy.realm_provisioning import RealmSecurityStampV1
from tests.unit.test_realm_foundation_provisioner import _stamp

ROOT = Path(__file__).parents[2]


def _manifest(stamp: RealmSecurityStampV1) -> SyntheticOwnerManifestV1:
    return SyntheticOwnerManifestV1(
        realm_slug=stamp.realm_slug,
        principal_id=uuid4(),
        membership_id=uuid4(),
        channel_binding_id=uuid4(),
        identity_issuer="lucy://synthetic-commissioning/utopia",
        identity_subject="synthetic-owner-utopia",
        hostname="synthetic-utopia-r1.invalid",
        provisioned_at=datetime.now(UTC),
    )


def _environment() -> dict[str, str]:
    stamp = _stamp()
    manifest = _manifest(stamp)
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_SYNTHETIC_OWNER_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_6tns"
        ),
        "LUCY_REALM_SECURITY_STAMP_JSON": stamp.model_dump_json(),
        "LUCY_REALM_SECURITY_STAMP_SHA256": stamp.digest_hex(),
        "LUCY_SYNTHETIC_OWNER_MANIFEST_JSON": manifest.model_dump_json(),
        "LUCY_SYNTHETIC_OWNER_MANIFEST_SHA256": manifest.digest_hex(),
    }


def test_synthetic_owner_config_is_digest_bound_and_private() -> None:
    config = SyntheticOwnerConfig.from_environment(_environment())
    assert config.migration_url.username == "lucy_migration"
    assert config.manifest.hostname.endswith(".invalid")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_SYNTHETIC_OWNER_AUTHORIZATION", "wrong"),
        ("LUCY_MIGRATION_DATABASE_URL", "postgresql://lucy_migration:x@public/db"),
        ("LUCY_SYNTHETIC_OWNER_MANIFEST_SHA256", "0" * 64),
    ],
)
def test_synthetic_owner_config_rejects_boundary_drift(name: str, value: str) -> None:
    environment = _environment()
    environment[name] = value
    with pytest.raises(RealmProvisioningError):
        SyntheticOwnerConfig.from_environment(environment)


def test_synthetic_owner_source_is_quarantine_only_and_monotonic() -> None:
    source = (
        ROOT / "deploy" / "postgres" / "provision_synthetic_authority_v1_3.py"
    ).read_text(encoding="utf-8")
    assert "('quarantined',)" in source or '("quarantined",)' in source
    assert "status='revoked',generation=2" in source
    assert "active=false,generation=2" in source
    assert "status='disabled'" in source
    assert "LUCY_TRANSCRIPT_CAPTURE_ENABLED" in source
    assert "runtime_admission\": \"quarantined" in source
    assert "DELETE FROM lucy.principals" not in source
    assert json.loads(_manifest(_stamp()).model_dump_json())["hostname"].endswith(".invalid")
