from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from deploy.postgres.provision_realm_bindings_v1_3 import RealmProvisioningError
from deploy.postgres.provision_recovery_drill_fixture_v1_3 import (
    RecoveryDrillFixtureManifestV1,
)
from deploy.postgres.stage_recovery_drill_events_v1_3 import (
    AUTHORIZATION,
    RecoveryDrillEventConfig,
    RecoveryDrillEventManifestV1,
)
from lucy.realm_provisioning import RealmSecurityStampV1
from lucy.recovery_journal import RecoveryStreamBindingV1, RecoveryStreamKind
from tests.unit.test_realm_foundation_provisioner import _stamp

ROOT = Path(__file__).parents[2]
ACCOUNT = "123456789012"


def _fixture(stamp: RealmSecurityStampV1) -> RecoveryDrillFixtureManifestV1:
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


def _events(stamp: RealmSecurityStampV1, fixture: RecoveryDrillFixtureManifestV1):
    return RecoveryDrillEventManifestV1(
        realm_slug=stamp.realm_slug,
        fixture_manifest_digest=fixture.digest_hex(),
        authority_idempotency_key="synthetic:recovery:authority:utopia-1",
        source_authority_ref="operator:synthetic-recovery:utopia-1",
        attempt_id=uuid4(),
        cost_idempotency_key="synthetic:recovery:cost:utopia-1",
        request_commitment="1" * 64,
        session_commitment="2" * 64,
        ip_commitment="3" * 64,
        requested_at=datetime.now(UTC),
    )


def _binding(stamp: RealmSecurityStampV1) -> RecoveryStreamBindingV1:
    return RecoveryStreamBindingV1(
        stream_kind=RecoveryStreamKind.AUTHORITY,
        stream_id=uuid4(),
        authority_epoch=1,
        independent_store_id=(
            f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/authority-table"
        ),
        writer_identity=f"arn:aws:iam::{ACCOUNT}:role/authority-writer",
        recovery_identity=f"arn:aws:iam::{ACCOUNT}:role/recovery",
        binding_manifest_digest=stamp.digest_hex(),
    )


def _environment() -> dict[str, str]:
    stamp = _stamp()
    fixture = _fixture(stamp)
    events = _events(stamp, fixture)
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_RECOVERY_DRILL_EVENT_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_6tns"
        ),
        "LUCY_REALM_SECURITY_STAMP_JSON": stamp.model_dump_json(),
        "LUCY_REALM_SECURITY_STAMP_SHA256": stamp.digest_hex(),
        "LUCY_RECOVERY_DRILL_FIXTURE_MANIFEST_JSON": fixture.model_dump_json(),
        "LUCY_RECOVERY_DRILL_EVENT_MANIFEST_JSON": events.model_dump_json(),
        "LUCY_RECOVERY_DRILL_EVENT_MANIFEST_SHA256": events.digest_hex(),
        "LUCY_AUTHORITY_RECOVERY_STREAM_BINDING_JSON": _binding(stamp).model_dump_json(),
    }


def test_event_config_is_fixture_and_authority_stream_bound() -> None:
    config = RecoveryDrillEventConfig.from_environment(_environment())
    assert config.events.fixture_manifest_digest == config.fixture.digest_hex()
    assert config.authority_binding.stream_kind is RecoveryStreamKind.AUTHORITY
    assert config.events.cost_idempotency_key.startswith("synthetic:recovery:cost:")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_RECOVERY_DRILL_EVENT_AUTHORIZATION", "wrong"),
        ("LUCY_MIGRATION_DATABASE_URL", "postgresql://lucy_migration:x@public/db"),
        ("LUCY_RECOVERY_DRILL_EVENT_MANIFEST_SHA256", "0" * 64),
    ],
)
def test_event_config_rejects_boundary_drift(name: str, value: str) -> None:
    with pytest.raises(RealmProvisioningError):
        RecoveryDrillEventConfig.from_environment(_environment() | {name: value})


def test_event_manifest_rejects_customer_shaped_values() -> None:
    stamp = _stamp()
    fixture = _fixture(stamp)
    events = _events(stamp, fixture)
    with pytest.raises(ValueError):
        RecoveryDrillEventManifestV1.model_validate(
            events.model_dump() | {"authority_idempotency_key": "customer:revocation:1"}
        )


def test_stager_uses_owner_roles_only_for_staging_and_never_calls_provider() -> None:
    source = (
        ROOT / "deploy" / "postgres" / "stage_recovery_drill_events_v1_3.py"
    ).read_text(encoding="utf-8")
    assert "SET LOCAL ROLE lucy_authority_function_owner" in source
    assert "SET LOCAL ROLE lucy_cost_function_owner" in source
    assert "stage_membership_revocation_v1" in source
    assert "reserve_provider_attempt_v1" in source
    assert '"provider_called": False' in source
    assert "append_pending" not in source
    assert "acknowledge_" not in source
    assert "claim_provider_submission" not in source
    assert "DELETE FROM" not in source
