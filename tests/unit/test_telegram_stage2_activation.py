from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from deploy.postgres import activate_telegram_stage2_v1 as activation

ROOT = Path(__file__).resolve().parents[2]


def _manifest() -> dict[str, object]:
    value = json.loads(
        (ROOT / "deploy/render/utopia-telegram-stage2-manifest.v1.json.example").read_text()
    )
    value["activation_decision_id"] = "owner-approved:telegram-stage2-test"
    value["artifacts"]["source_commit"] = "a" * 40
    value["artifacts"]["rollback_commit"] = "b" * 40
    value["artifacts"]["gateway_dockerfile_sha256"] = "c" * 64
    value["artifacts"]["profile_sha256"] = "d" * 64
    value["realm"].update(
        {
            "node_id": str(uuid4()),
            "security_realm_id": str(uuid4()),
            "content_scope_id": str(uuid4()),
            "channel_binding_id": str(uuid4()),
            "routine_render_service_id": "srv-routine",
            "gateway_render_service_id": "srv-gateway",
        }
    )
    return value


def _environment() -> dict[str, str]:
    manifest = json.dumps(_manifest(), separators=(",", ":"), sort_keys=True)
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_STAGE2_ACTIVATION_AUTHORIZATION": activation.AUTHORIZATION,
        "LUCY_STAGE2_ACTIVATION_MANIFEST_JSON": manifest,
        "LUCY_STAGE2_ACTIVATION_MANIFEST_SHA256": hashlib.sha256(
            manifest.encode()
        ).hexdigest(),
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_utopia"
        ),
        "LUCY_REALM_SECURITY_STAMP_JSON": "{}",
        "LUCY_REALM_SECURITY_STAMP_SHA256": "0" * 64,
        "LUCY_STORAGE_EPOCH": str(uuid4()),
        "LUCY_APPROVED_SYNTHETIC_CAPTURE_RECEIPTS_JSON": "[]",
    }


def test_activation_job_requires_capture_off() -> None:
    environment = _environment()
    environment["LUCY_TRANSCRIPT_CAPTURE_ENABLED"] = "true"
    with pytest.raises(activation.Stage2ActivationError, match="must keep capture disabled"):
        activation.configuration_from_environment(environment)


def test_activation_manifest_digest_is_bound() -> None:
    environment = _environment()
    environment["LUCY_STAGE2_ACTIVATION_MANIFEST_SHA256"] = "f" * 64
    with pytest.raises(activation.Stage2ActivationError, match="digest differs"):
        activation.configuration_from_environment(environment)


def test_activation_manifest_requires_distinct_services(monkeypatch: pytest.MonkeyPatch) -> None:
    environment = _environment()
    manifest = json.loads(environment["LUCY_STAGE2_ACTIVATION_MANIFEST_JSON"])
    manifest["realm"]["gateway_render_service_id"] = manifest["realm"][
        "routine_render_service_id"
    ]
    raw = json.dumps(manifest, separators=(",", ":"), sort_keys=True)
    environment["LUCY_STAGE2_ACTIVATION_MANIFEST_JSON"] = raw
    environment["LUCY_STAGE2_ACTIVATION_MANIFEST_SHA256"] = hashlib.sha256(
        raw.encode()
    ).hexdigest()

    class Stamp:
        node_id = manifest["realm"]["node_id"]
        security_realm_id = manifest["realm"]["security_realm_id"]
        content_scope_id = manifest["realm"]["content_scope_id"]

    class Config:
        stamp = Stamp()
        runtime_epoch = uuid4()

    monkeypatch.setattr(
        activation.commission.CommissionConfig,
        "from_environment",
        lambda *_args: Config(),
    )
    with pytest.raises(activation.Stage2ActivationError, match="reviewed realm"):
        activation.configuration_from_environment(environment)


def test_production_image_contains_both_stage2_database_gates() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "deploy/postgres/migrate_telegram_stage2_v1.py" in dockerfile
    assert "deploy/postgres/activate_telegram_stage2_v1.py" in dockerfile


def test_activation_accepts_original_and_additive_workspaces_revisions() -> None:
    assert {
        "0054_stage2_scoped_turn_commit",
        "0068_workspaces_service_auth",
    } == activation.ACCEPTED_REVISIONS


@pytest.mark.parametrize("revision", sorted(activation.ACCEPTED_REVISIONS))
def test_activation_reports_the_verified_schema_revision(
    monkeypatch: pytest.MonkeyPatch, revision: str
) -> None:
    class Result:
        def __init__(self, row: tuple[object, ...] | None = None) -> None:
            self.row = row

        def fetchone(self) -> tuple[object, ...] | None:
            return self.row

    class Connection:
        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, query: object, *_args: object) -> Result:
            if "alembic_version" in str(query):
                return Result((revision,))
            return Result()

    monkeypatch.setattr(activation.psycopg, "connect", lambda *_args: Connection())
    monkeypatch.setattr(activation.commission, "_conninfo", lambda *_args: "private")
    monkeypatch.setattr(
        activation.commission, "_verify_target_boundary", lambda *_args: ("quarantined", None)
    )
    monkeypatch.setattr(activation.commission, "_capture_blockers", lambda *_args: ())
    monkeypatch.setattr(activation.commission, "_verify_open_boundary", lambda *_args: None)
    monkeypatch.setattr(activation.commission, "_work_in_flight", lambda *_args: False)
    monkeypatch.setattr(activation.commission, "_runtime_sessions", lambda *_args: 0)
    monkeypatch.setattr(activation.commission, "_finality_pending", lambda *_args: False)
    config = SimpleNamespace(migration_url="private", runtime_epoch=uuid4())

    receipt = activation.activate(config, SimpleNamespace(transcript_capture_enabled=True))  # type: ignore[arg-type]

    assert receipt["schema_revision"] == revision
    assert receipt["runtime_admission"] == "ready"
