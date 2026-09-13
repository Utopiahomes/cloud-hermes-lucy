from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from deploy.postgres.release_public_knowledge_v1 import (
    AUTHORIZATIONS,
    SNAPSHOT_RELATIVE_PATH,
    PublicKnowledgeReleaseConfig,
    PublicKnowledgeReleaseError,
    PublicKnowledgeReleaseManifestV1,
    _require_eligible,
)
from lucy.publication import knowledge_snapshot, snapshot_digest

ROOT = Path(__file__).parents[2]


def _snapshot(*, effective_from: datetime | None = None) -> dict[str, object]:
    start = effective_from or datetime(2026, 1, 1, tzinfo=UTC)
    return knowledge_snapshot(
        [
            {
                "id": "utopia-about",
                "service_line": "general",
                "kind": "description",
                "title": "Utopia Homes",
                "approved_text": "Utopia Homes creates distinctive group stays.",
                "topics": ["about"],
                "route": "about",
                "source": {
                    "id": "utopia-about-source",
                    "label": "About Utopia Homes",
                    "href": "https://www.utopiahomes.com/about",
                },
                "effective_from": start.isoformat(),
                "direct_answer": True,
            }
        ]
    )


def _manifest(
    action: str = "stage", *, snapshot: dict[str, object] | None = None
) -> PublicKnowledgeReleaseManifestV1:
    payload = snapshot or _snapshot()
    common = {
        "action": action,
        "source_commit": "a" * 40,
        "schema_revision": (
            "0057_public_conversation" if action == "activate" else "0056_memory_import_budget"
        ),
        "decision_id": f"ray-public-knowledge-{action}-2026-09-12",
        "release_id": uuid4(),
        "realm_slug": "utopia",
        "storage_epoch": uuid4(),
        "channel_binding_id": uuid4(),
        "hostname": "www.utopiahomes.com",
        "actor_id": uuid4(),
        "candidate_id": uuid4(),
        "transition_id": uuid4(),
        "snapshot_digest": snapshot_digest(payload),
        "expected_active_version_id": uuid4(),
        "expected_active_version": 1,
        "expected_active_digest": "b" * 64,
        "authorized_at": datetime(2026, 9, 12, tzinfo=UTC),
    }
    if action in {"approve", "activate"}:
        common["approval_id"] = uuid4()
    if action == "activate":
        common["version_id"] = uuid4()
    return PublicKnowledgeReleaseManifestV1.model_validate(common)


def _environment(
    manifest: PublicKnowledgeReleaseManifestV1, snapshot_path: Path
) -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_PUBLIC_KNOWLEDGE_AUTHORIZATION": AUTHORIZATIONS[manifest.action],
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_6tns"
        ),
        "LUCY_PUBLIC_KNOWLEDGE_MANIFEST_JSON": manifest.model_dump_json(),
        "LUCY_PUBLIC_KNOWLEDGE_MANIFEST_SHA256": manifest.digest_hex(),
        "LUCY_PUBLIC_KNOWLEDGE_SNAPSHOT_PATH": str(snapshot_path),
    }


def test_each_action_has_an_exact_shape_revision_and_authorization() -> None:
    stage = _manifest("stage")
    approve = _manifest("approve")
    activate = _manifest("activate")
    assert stage.approval_id is None and stage.version_id is None
    assert approve.approval_id is not None and approve.version_id is None
    assert activate.approval_id is not None and activate.version_id is not None
    assert len(set(AUTHORIZATIONS.values())) == 3

    with pytest.raises(ValidationError, match="wrong schema revision"):
        PublicKnowledgeReleaseManifestV1.model_validate(
            stage.model_dump() | {"schema_revision": "0057_public_conversation"}
        )
    with pytest.raises(ValidationError, match="approval requires"):
        PublicKnowledgeReleaseManifestV1.model_validate(
            approve.model_dump() | {"approval_id": None}
        )


def test_config_binds_exact_canonical_snapshot_manifest_and_action(tmp_path: Path) -> None:
    snapshot = _snapshot()
    snapshot_path = tmp_path / SNAPSHOT_RELATIVE_PATH
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_text(json.dumps(snapshot, ensure_ascii=False), encoding="utf-8")
    manifest = _manifest("stage", snapshot=snapshot)
    environment = _environment(manifest, snapshot_path)

    config = PublicKnowledgeReleaseConfig.from_environment(
        environment, repository_root=tmp_path
    )
    assert config.snapshot == snapshot
    assert config.manifest.snapshot_digest == snapshot_digest(snapshot)

    for key, value in (
        ("LUCY_PUBLIC_KNOWLEDGE_AUTHORIZATION", AUTHORIZATIONS["approve"]),
        ("LUCY_PUBLIC_KNOWLEDGE_MANIFEST_SHA256", "0" * 64),
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_PUBLIC_KNOWLEDGE_SNAPSHOT_PATH", str(tmp_path / "other.json")),
    ):
        with pytest.raises(PublicKnowledgeReleaseError):
            PublicKnowledgeReleaseConfig.from_environment(
                environment | {key: value}, repository_root=tmp_path
            )


def test_activation_rejects_future_or_withdrawn_knowledge() -> None:
    now = datetime(2026, 9, 12, tzinfo=UTC)
    _require_eligible(_snapshot(), now=now)

    with pytest.raises(PublicKnowledgeReleaseError, match="ineligible"):
        _require_eligible(_snapshot(effective_from=now + timedelta(days=1)), now=now)

    withdrawn = _snapshot()
    assert isinstance(withdrawn["entries"], list)
    withdrawn["entries"][0]["effective_until"] = (now - timedelta(days=1)).isoformat()
    with pytest.raises(PublicKnowledgeReleaseError, match="ineligible"):
        _require_eligible(withdrawn, now=now)


def test_release_source_is_split_append_only_and_packaged() -> None:
    source = (ROOT / "deploy/postgres/release_public_knowledge_v1.py").read_text(
        encoding="utf-8"
    )
    assert 'Action = Literal["stage", "approve", "activate"]' in source
    assert "expected_active_version_id" in source
    assert "public_projection_knowledge_v1(text,uuid)" in source
    assert "DELETE FROM" not in source
    assert "DROP " not in source
    assert "release_public_knowledge_v1.py" in (ROOT / "Dockerfile").read_text(
        encoding="utf-8"
    )
