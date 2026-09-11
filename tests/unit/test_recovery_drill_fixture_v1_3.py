from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from deploy.postgres.provision_realm_bindings_v1_3 import RealmProvisioningError
from deploy.postgres.provision_recovery_drill_fixture_v1_3 import (
    AUTHORIZATION,
    RecoveryDrillFixtureConfig,
    RecoveryDrillFixtureManifestV1,
    _policy,
)
from lucy.realm_provisioning import RealmSecurityStampV1
from tests.unit.test_realm_foundation_provisioner import _stamp

ROOT = Path(__file__).parents[2]


def _manifest(stamp: RealmSecurityStampV1) -> RecoveryDrillFixtureManifestV1:
    return RecoveryDrillFixtureManifestV1(
        realm_slug=stamp.realm_slug,
        owner_principal_id=uuid4(),
        owner_membership_id=uuid4(),
        member_principal_id=uuid4(),
        member_membership_id=uuid4(),
        channel_binding_id=uuid4(),
        policy_id=uuid4(),
        identity_issuer=f"lucy://synthetic-recovery/{stamp.realm_slug}",
        owner_subject="synthetic-recovery-owner-utopia",
        member_subject="synthetic-recovery-member-utopia",
        hostname="synthetic-recovery-utopia.invalid",
        provisioned_at=datetime.now(UTC),
    )


def _environment() -> dict[str, str]:
    stamp = _stamp()
    manifest = _manifest(stamp)
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_RECOVERY_DRILL_FIXTURE_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_6tns"
        ),
        "LUCY_REALM_SECURITY_STAMP_JSON": stamp.model_dump_json(),
        "LUCY_REALM_SECURITY_STAMP_SHA256": stamp.digest_hex(),
        "LUCY_RECOVERY_DRILL_FIXTURE_MANIFEST_JSON": manifest.model_dump_json(),
        "LUCY_RECOVERY_DRILL_FIXTURE_MANIFEST_SHA256": manifest.digest_hex(),
    }


def test_fixture_is_digest_bound_private_and_nonspending() -> None:
    config = RecoveryDrillFixtureConfig.from_environment(_environment())
    policy = _policy(config)

    assert config.migration_url.username == "lucy_migration"
    assert config.manifest.hostname.endswith(".invalid")
    assert policy.per_request_cap_microusd == 1
    assert policy.max_input_tokens == 1
    assert policy.max_output_tokens == 1
    assert len(policy.digest_hex()) == 64


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_RECOVERY_DRILL_FIXTURE_AUTHORIZATION", "wrong"),
        ("LUCY_MIGRATION_DATABASE_URL", "postgresql://lucy_migration:x@public/db"),
        ("LUCY_RECOVERY_DRILL_FIXTURE_MANIFEST_SHA256", "0" * 64),
    ],
)
def test_fixture_rejects_boundary_drift(name: str, value: str) -> None:
    environment = _environment() | {name: value}
    with pytest.raises(RealmProvisioningError):
        RecoveryDrillFixtureConfig.from_environment(environment)


def test_fixture_rejects_non_synthetic_or_duplicate_identifiers() -> None:
    stamp = _stamp()
    manifest = _manifest(stamp)
    with pytest.raises(ValueError):
        RecoveryDrillFixtureManifestV1.model_validate(
            manifest.model_dump() | {"hostname": "utopiahomes.com"}
        )
    with pytest.raises(ValueError):
        RecoveryDrillFixtureManifestV1.model_validate(
            manifest.model_dump()
            | {"member_principal_id": manifest.owner_principal_id}
        )


def test_fixture_source_has_no_provider_or_journal_effect() -> None:
    source = (
        ROOT / "deploy" / "postgres" / "provision_recovery_drill_fixture_v1_3.py"
    ).read_text(encoding="utf-8")
    assert "lucy.capture_boundary_safe_v1()" in source
    assert '"channel_kind": "website_public"' in source
    assert '"provider_called": False' in source
    assert "append_pending" not in source
    assert "claim_provider_submission" not in source
    assert "DELETE FROM" not in source
