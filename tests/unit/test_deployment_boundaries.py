from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).parents[2]


def _render_services() -> dict[str, dict[str, Any]]:
    blueprint = yaml.safe_load(
        (ROOT / "deploy" / "render" / "security-baseline-v1.1.yaml.example").read_text(
            encoding="utf-8"
        )
    )
    environments = blueprint["projects"][0]["environments"]
    return {service["name"]: service for service in environments[0]["services"]}


def _env_keys(service: dict[str, Any]) -> set[str]:
    return {value["key"] for value in service["envVars"]}


def test_render_services_keep_signing_and_aws_capabilities_separate() -> None:
    services = _render_services()
    assert set(services) == {
        "lucy-routine",
        "lucy-policy",
        "lucy-evidence",
        "lucy-deletion",
    }
    policy = _env_keys(services["lucy-policy"])
    evidence = _env_keys(services["lucy-evidence"])
    deletion = _env_keys(services["lucy-deletion"])
    routine = _env_keys(services["lucy-routine"])

    assert "LUCY_PERMIT_SIGNING_PRIVATE_KEY_B64" in policy
    assert "AWS_ROLE_ARN" not in policy
    assert "LUCY_AWS_KMS_KEY_ARN" not in policy
    assert "LUCY_PERMIT_SIGNING_PRIVATE_KEY_B64" not in evidence | deletion | routine
    assert "LUCY_PERMIT_SIGNING_PUBLIC_KEY_B64" in evidence & deletion
    assert "LUCY_AWS_KMS_KEY_ARN" not in deletion
    assert "LUCY_ARCHIVE_COMMITMENT_KEY_B64" not in deletion


def test_render_private_services_use_only_supported_blueprint_fields() -> None:
    for service in _render_services().values():
        assert service["type"] == "pserv"
        assert "healthCheckPath" not in service
        assert service["region"] == "virginia"
        assert service["plan"] == "0.5c-512mb"
        assert service["autoDeployTrigger"] == "off"


def test_render_services_share_one_protected_isolated_production_environment() -> None:
    blueprint = yaml.safe_load(
        (ROOT / "deploy" / "render" / "security-baseline-v1.1.yaml.example").read_text(
            encoding="utf-8"
        )
    )
    assert "services" not in blueprint
    assert len(blueprint["projects"]) == 1
    project = blueprint["projects"][0]
    assert project["name"] == "cloud-lucy"
    assert len(project["environments"]) == 1
    environment = project["environments"][0]
    assert environment["name"] == "production"
    assert environment["networking"] == {"isolation": "enabled"}
    assert environment["permissions"] == {"protection": "enabled"}


def test_production_database_roles_have_no_ddl_or_role_administration() -> None:
    sql = (
        ROOT / "deploy" / "postgres" / "production_roles.sql.example"
    ).read_text(encoding="utf-8")
    executable = "\n".join(
        line for line in sql.splitlines() if not line.lstrip().startswith("--")
    ).upper()
    assert "DROP " not in executable
    assert "CREATE TABLE" not in executable
    assert "CREATE DATABASE" not in executable
    bootstrap = (ROOT / "deploy" / "postgres" / "production_bootstrap.sql.example").read_text()
    assert bootstrap.count("NOCREATEROLE") == 6
    assert bootstrap.count("NOINHERIT") == 6
    assert "CREATE ROLE lucy_app NOLOGIN" in bootstrap
    assert "CREATE ROLE lucy_security_function_owner NOLOGIN" in bootstrap
    blueprint = yaml.safe_load(
        (
            ROOT / "deploy" / "render" / "security-baseline-v1.2.yaml.example"
        ).read_text(encoding="utf-8")
    )
    migration_login = blueprint["projects"][0]["environments"][0]["databases"][0][
        "user"
    ]
    assert f"GRANT lucy_security_function_owner TO {migration_login}" in bootstrap
    assert "lucy.runtime_admission" in executable.lower()


def test_v12_database_grants_are_direct_execute_only_for_sensitive_logins() -> None:
    sql = (
        ROOT / "deploy" / "postgres" / "production_roles_v1.2.sql.example"
    ).read_text(encoding="utf-8")
    assert "GRANT EXECUTE ON FUNCTION" in sql
    assert "TO \"__LUCY_POLICY_LOGIN__\"" in sql
    assert "TO \"__LUCY_EVIDENCE_LOGIN__\"" in sql
    assert "TO \"__LUCY_DELETION_LOGIN__\"" in sql
    assert "TO \"__LUCY_FINALITY_LOGIN__\"" in sql
    assert "GRANT lucy_policy TO" not in sql
    assert "GRANT lucy_evidence_reader TO" not in sql
    assert "GRANT lucy_evidence_deleter TO" not in sql
    assert "pg_auth_members" in sql
    assert "NOT rolinherit" in sql
    assert "record_finality_verification_v1" in sql
    assert "record_scoped_finality_inventory_v2" in sql


def test_local_maintenance_is_explicit_and_owner_credential_never_reaches_http() -> None:
    services = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]
    maintenance = services["lucy-maintenance"]
    assert maintenance["profiles"] == ["maintenance"]
    assert maintenance["command"] == ["quarantine"]
    assert maintenance["restart"] == "no"
    assert "LUCY_MAINTENANCE_DATABASE_URL" in maintenance["environment"]
    http = services["lucy-api"]
    assert "lucy-maintenance" not in http["depends_on"]
    assert "LUCY_MAINTENANCE_DATABASE_URL" not in http["environment"]
    assert "LUCY_MIGRATION_DATABASE_URL" not in http["environment"]
    for service in _render_services().values():
        assert "LUCY_STORAGE_EPOCH" in _env_keys(service)
        assert "LUCY_ENVIRONMENT" in _env_keys(service)
        assert "LUCY_MAINTENANCE_DATABASE_URL" not in _env_keys(service)


def test_render_image_installs_only_hash_locked_runtime_dependencies() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "python:3.12.11-slim@sha256:" in dockerfile
    assert "COPY deploy/render/requirements.lock" in dockerfile
    assert "COPY contracts ./contracts" in dockerfile
    assert "COPY alembic.ini tiamat_alembic.ini hermes.lock ./" in dockerfile
    assert "COPY tiamat_migrations ./tiamat_migrations" in dockerfile
    assert "pip install --no-cache-dir --require-hashes" in dockerfile
    assert "pip install --no-cache-dir ." not in dockerfile

    lock = (ROOT / "deploy" / "render" / "requirements.lock").read_text(
        encoding="utf-8"
    )
    requirements = [
        line for line in lock.splitlines() if line and not line.startswith(("#", " "))
    ]
    assert requirements
    assert all("==" in requirement for requirement in requirements)
    assert lock.count("--hash=sha256:") >= len(requirements)
    # Compile this lock in the pinned Linux image: a Windows resolution silently
    # omits uvloop even though uvicorn[standard] requires it in Render.
    assert "\nuvloop==" in lock
    assert "\npyjwt==" in lock


def test_render_image_excludes_secrets_and_copies_only_reviewed_database_files() -> None:
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert {".env", ".env.*", "secrets", "data", "archives"} <= set(ignored)
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY deploy/postgres ./deploy/postgres" not in dockerfile
    for artifact in (
        "bootstrap_cloud_v1_2.py",
        "bootstrap_realm_cloud_v1_3.py",
        "commission_realm_runtime_v1_3.py",
        "inspect_unresolved_cloud_v1_2.py",
        "recover_expired_synthetic_retrieval_cloud_v1_2.py",
        "replay_authorized_deletion_cloud_v1_2.py",
        "replay_authorized_deletion_cloud_v1_3.py",
        "provision_realm_foundation_v1_3.py",
        "provision_realm_bindings_v1_3.py",
        "provision_synthetic_authority_v1_3.py",
        "render_security_v1_2_sql.py",
        "render_security_v1_3_sql.py",
        "initialize_tiamat_ledger_v1.py",
        "verify_tiamat_render_capabilities_v1.py",
        "render_tiamat_role_template_v1.py",
        "bootstrap_tiamat_staging_v1.py",
        "bootstrap_tiamat_staging_hold_v1.py",
        "tiamat_roles.sql.example",
        "production_bootstrap.sql.example",
        "production_roles_v1.2.sql.example",
        "production_realm_roles_v1.3.sql.example",
        "configure_security_v1.2.sql.example",
    ):
        assert f"COPY deploy/postgres/{artifact}" in dockerfile


def test_security_configuration_uses_database_owned_capture_boundary() -> None:
    script = (
        ROOT / "deploy" / "postgres" / "configure_security_v1.2.sql.example"
    ).read_text(encoding="utf-8")
    assert "IF NOT lucy.capture_boundary_safe_v1() THEN" in script
    assert "SELECT 1 FROM lucy.capture_receipts WHERE capture_enabled" not in script
    assert "existing security boundary does not match reviewed bindings" in script
    assert "executor rebinding requires an empty pre-activation operation ledger" not in script
    assert "AND storage_epoch=v_storage_epoch" in script
    assert "AND executor_alias_arn=v_retrieval_alias" in script
    assert "AND executor_alias_arn=v_deletion_alias" in script
    assert "RETURN;" in script
