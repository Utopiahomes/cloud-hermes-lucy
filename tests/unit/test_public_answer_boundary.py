from __future__ import annotations

import json
from pathlib import Path

import yaml

from lucy.publication import snapshot_digest

ROOT = Path(__file__).parents[2]


def test_public_answer_migration_binds_identity_lifecycle_and_storage_epoch() -> None:
    migration = (
        ROOT / "migrations" / "versions" / "0052_r1_public_answer_gate.py"
    ).read_text(encoding="utf-8")
    assert 'revision: str = "0052_r1_public_answer_gate"' in migration
    assert 'down_revision: str | None = "0051_stage1_private_telegram"' in migration
    assert "session_user='lucy_' || replace(n.slug,'-','_') || '_public'" in migration
    assert "a.state='ready'" in migration
    assert "a.storage_epoch=p_storage_epoch" in migration
    assert "l.state='ready'" in migration
    assert "c.channel_kind='website_public'" in migration
    assert "FROM PUBLIC,lucy_app,lucy_public_runtime" in migration


def test_public_knowledge_migration_binds_identity_lifecycle_epoch_and_freshness() -> None:
    migration = (
        ROOT / "migrations" / "versions" / "0057_public_conversation_retrieval.py"
    ).read_text(encoding="utf-8")
    assert 'revision: str = "0057_public_conversation"' in migration
    assert 'down_revision: str | None = "0056_memory_import_budget"' in migration
    assert "session_user='lucy_' || replace(n.slug,'-','_') || '_public'" in migration
    assert "a.state='ready'" in migration
    assert "a.storage_epoch=p_storage_epoch" in migration
    assert "l.state='ready'" in migration
    assert "c.channel_kind='website_public'" in migration
    assert "v.snapshot->>'schema'='lucy-public-knowledge-v1'" in migration
    assert "effective_from" in migration
    assert "effective_until" in migration
    assert "FROM PUBLIC,lucy_app,lucy_public_runtime" in migration


def test_reviewed_role_contract_grants_only_exact_public_function() -> None:
    roles = (
        ROOT / "deploy" / "postgres" / "production_realm_roles_v1.3.sql.example"
    ).read_text(encoding="utf-8")
    assert "public_projection_knowledge_v1(text,uuid)" in roles
    assert 'TO "__LUCY_REALM_PUBLIC_LOGIN__"' in roles
    assert 'GRANT SELECT ON lucy.public_projection_' not in roles
    assert 'GRANT INSERT ON lucy.' not in roles


def test_utopia_public_projection_payload_matches_owner_approved_digest() -> None:
    snapshot = json.loads(
        (ROOT / "deploy" / "render" / "utopia-public-projection.v0.json").read_text(
            encoding="utf-8"
        )
    )
    assert snapshot_digest(snapshot) == (
        "6232b5fa0b382346fba692f29e74d2b3fdbcd9a19ee960d2e609fd0b2ce2b99e"
    )
    assert snapshot["schema"] == "lucy-public-faq-v1"
    assert len(snapshot["faqs"]) == 8
    assert all(
        item["source"].startswith("https://www.utopiahomes.com/")
        for item in snapshot["faqs"]
    )


def test_public_render_service_is_the_only_external_identity() -> None:
    blueprint = yaml.safe_load(
        (ROOT / "deploy" / "render" / "security-baseline-v1.3.yaml.example").read_text(
            encoding="utf-8"
        )
    )
    services = blueprint["projects"][0]["environments"][0]["services"]
    assert [service["name"] for service in services if service["type"] == "web"] == [
        "lucy-public"
    ]
    public = next(service for service in services if service["name"] == "lucy-public")
    environment = {item["key"]: item for item in public["envVars"]}
    assert public["dockerCommand"] == "python -m lucy.public_runtime"
    assert public["healthCheckPath"] == "/health"
    assert environment["LUCY_EXPECTED_DATABASE_LOGIN"]["value"] == "lucy_utopia_public"
    assert environment["LUCY_TRANSCRIPT_CAPTURE_ENABLED"]["value"] == "false"
    assert environment["LUCY_PUBLIC_SITE_HOSTNAME"]["value"] == "www.utopiahomes.com"
    assert environment["LUCY_PUBLIC_SNAPSHOT_DIGEST"]["value"] == (
        "6232b5fa0b382346fba692f29e74d2b3fdbcd9a19ee960d2e609fd0b2ce2b99e"
    )
    assert not any(
        key.startswith("AWS_")
        or key.startswith("LUCY_AWS_")
        or "OPENROUTER" in key
        or key in {"LUCY_OWNER_TOKEN", "LUCY_POLICY_GATEWAY_TOKEN"}
        for key in environment
    )
