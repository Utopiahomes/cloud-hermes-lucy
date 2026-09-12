from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from deploy.postgres.commission_public_projection_v1 import (
    AUTHORIZATION,
    PublicProjectionCommissionConfig,
    PublicProjectionCommissionError,
    PublicProjectionCommissionManifestV1,
)
from lucy.publication import snapshot_digest

ROOT = Path(__file__).parents[2]


def _manifest() -> PublicProjectionCommissionManifestV1:
    snapshot = json.loads(
        (ROOT / "deploy/render/utopia-public-projection.v0.json").read_text(
            encoding="utf-8"
        )
    )
    return PublicProjectionCommissionManifestV1(
        source_commit="a" * 40,
        schema_revision="0054_stage2_scoped_turn_commit",
        decision_id="ray-public-lucy-v0-2026-09-11",
        realm_slug="utopia",
        node_id=uuid4(),
        tenure_id=uuid4(),
        security_realm_id=uuid4(),
        realm_binding_id=uuid4(),
        storage_epoch=uuid4(),
        workspace_id=uuid4(),
        workspace_slug="utopia-public-website",
        channel_binding_id=uuid4(),
        hostname="www.utopiahomes.com",
        publisher_principal_id=uuid4(),
        publisher_membership_id=uuid4(),
        publisher_issuer="lucy://utopia/public-projection",
        publisher_subject="publisher-v1",
        approver_principal_id=uuid4(),
        approver_membership_id=uuid4(),
        approver_issuer="lucy://utopia/public-projection",
        approver_subject="approver-v1",
        candidate_id=uuid4(),
        approval_id=uuid4(),
        version_id=uuid4(),
        staged_event_id=uuid4(),
        approved_event_id=uuid4(),
        published_event_id=uuid4(),
        snapshot_digest=snapshot_digest(snapshot),
        provisioned_at=datetime(2026, 9, 12, tzinfo=UTC),
    )


def _environment() -> dict[str, str]:
    manifest = _manifest()
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_PUBLIC_PROJECTION_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_6tns"
        ),
        "LUCY_PUBLIC_PROJECTION_MANIFEST_JSON": manifest.model_dump_json(),
        "LUCY_PUBLIC_PROJECTION_MANIFEST_SHA256": manifest.digest_hex(),
        "LUCY_PUBLIC_PROJECTION_SNAPSHOT_PATH": str(
            ROOT / "deploy/render/utopia-public-projection.v0.json"
        ),
    }


def test_config_is_exactly_manifest_and_projection_bound() -> None:
    config = PublicProjectionCommissionConfig.from_environment(_environment())
    assert config.manifest.realm_slug == "utopia"
    assert config.migration_url.username == "lucy_migration"
    assert len(config.snapshot["faqs"]) == 8


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_PUBLIC_PROJECTION_AUTHORIZATION", "wrong"),
        ("LUCY_MIGRATION_DATABASE_URL", "postgresql://lucy_migration:x@public/db"),
        ("LUCY_PUBLIC_PROJECTION_MANIFEST_SHA256", "0" * 64),
        ("LUCY_PUBLIC_PROJECTION_SNAPSHOT_PATH", "other.json"),
    ],
)
def test_config_rejects_boundary_drift(key: str, value: str) -> None:
    with pytest.raises(PublicProjectionCommissionError):
        PublicProjectionCommissionConfig.from_environment(_environment() | {key: value})


def test_manifest_rejects_ambiguous_authority_and_source_is_append_only() -> None:
    manifest = _manifest()
    environment = _environment()
    ambiguous = manifest.model_copy(
        update={"approver_principal_id": manifest.publisher_principal_id}
    )
    environment["LUCY_PUBLIC_PROJECTION_MANIFEST_JSON"] = ambiguous.model_dump_json()
    environment["LUCY_PUBLIC_PROJECTION_MANIFEST_SHA256"] = ambiguous.digest_hex()
    with pytest.raises(PublicProjectionCommissionError, match="authority"):
        PublicProjectionCommissionConfig.from_environment(environment)

    source = (
        ROOT / "deploy/postgres/commission_public_projection_v1.py"
    ).read_text(encoding="utf-8")
    assert "runtime_admission" in source and '"quarantined"' in source
    assert "lucy_utopia_public" in source
    assert "DELETE FROM" not in source
    assert "DROP " not in source

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "deploy/postgres/commission_public_projection_v1.py" in dockerfile
    assert "deploy/render/utopia-public-projection.v0.json" in dockerfile
