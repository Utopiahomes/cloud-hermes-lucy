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
    return {service["name"]: service for service in blueprint["services"]}


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
    assert executable.count("NOCREATEROLE") == 4
    assert executable.count("NOINHERIT") == 4
