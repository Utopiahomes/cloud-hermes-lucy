from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[2]


def _module() -> ModuleType:
    directory = ROOT / "deploy" / "postgres"
    sys.path.insert(0, str(directory))
    try:
        spec = importlib.util.spec_from_file_location(
            "bootstrap_cloud_v1_2", directory / "bootstrap_cloud_v1_2.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(directory))


def _environment() -> dict[str, str]:
    host = "dpg-daca8gafngtc73clvafg-a"
    result = {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_DATABASE_BOOTSTRAP_AUTHORIZATION": "security-v1.2-private-quarantined",
        "LUCY_MIGRATION_DATABASE_URL": f"postgresql://lucy_migration:migration@{host}:5432/lucy",
        "LUCY_AWS_ACCOUNT_ID": "429870640638",
        "LUCY_RETRIEVAL_EXECUTOR_ALIAS_ARN": (
            "arn:aws:lambda:us-east-1:429870640638:function:lucy-evidence-executor-v12:production"
        ),
        "LUCY_DELETION_EXECUTOR_ALIAS_ARN": (
            "arn:aws:lambda:us-east-1:429870640638:function:lucy-deletion-executor-v12:production"
        ),
        "LUCY_RETRIEVAL_RECEIPT_KEY_ARN": (
            "arn:aws:kms:us-east-1:429870640638:key/147b517c-8b1d-449b-acf9-0d7e8c9ff14a"
        ),
        "LUCY_DELETION_RECEIPT_KEY_ARN": (
            "arn:aws:kms:us-east-1:429870640638:key/b87ef3db-edf7-411f-b6d1-35d01282312e"
        ),
        "LUCY_RETRIEVAL_EXECUTOR_VERSION": "2",
        "LUCY_DELETION_EXECUTOR_VERSION": "2",
        "LUCY_SECURITY_STORAGE_EPOCH": "1",
        "LUCY_SECURITY_REGISTRY_EPOCH": "1",
        "LUCY_SECURITY_KEY_EPOCH": "1",
    }
    for mode, login in {
        "routine": "lucy_routine_workflow",
        "policy": "lucy_policy_notary",
        "evidence": "lucy_evidence_workflow",
        "deletion": "lucy_deletion_workflow",
        "finality": "lucy_finality_verifier",
    }.items():
        result[f"LUCY_{mode.upper()}_DATABASE_URL"] = (
            f"postgresql+psycopg://{login}:{mode}-secret@{host}:5432/lucy?sslmode=require"
        )
    return result


def test_bootstrap_config_requires_private_render_and_exact_logins() -> None:
    module = _module()
    config = module.BootstrapConfig.from_environment(_environment())
    assert config.migration_url.host == "dpg-daca8gafngtc73clvafg-a"
    assert set(config.runtime_urls) == {"routine", "policy", "evidence", "deletion", "finality"}
    assert all(url.query["sslmode"] == "require" for url in config.runtime_urls.values())


@pytest.mark.parametrize(
    ("key", "value", "diagnostic"),
    [
        ("RENDER", "false", "Render private-network"),
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true", "capture must remain disabled"),
        (
            "LUCY_MIGRATION_DATABASE_URL",
            "postgresql://lucy_migration:secret@public.example.com:5432/lucy",
            "private Render database host",
        ),
        (
            "LUCY_EVIDENCE_DATABASE_URL",
            "postgresql://wrong:secret@dpg-daca8gafngtc73clvafg-a:5432/lucy",
            "exact password-bearing login",
        ),
    ],
)
def test_bootstrap_config_fails_closed(key: str, value: str, diagnostic: str) -> None:
    module = _module()
    environment = _environment()
    environment[key] = value
    with pytest.raises(module.BootstrapError, match=diagnostic):
        module.BootstrapConfig.from_environment(environment)


def test_reviewed_psql_header_filter_rejects_unexpected_commands() -> None:
    module = _module()
    assert module._strip_reviewed_psql_header("\\set ON_ERROR_STOP on\nSELECT 1;\n") == (
        "SELECT 1;\n"
    )
    with pytest.raises(module.BootstrapError, match="unexpected psql meta-command"):
        module._strip_reviewed_psql_header("\\i unreviewed.sql\nSELECT 1;\n")


def test_main_never_echoes_database_secrets(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _module()
    environment = _environment()
    secret = "do-not-print-this-database-secret"
    environment["LUCY_ROUTINE_DATABASE_URL"] = environment[
        "LUCY_ROUTINE_DATABASE_URL"
    ].replace("routine-secret", secret)
    monkeypatch.setattr(module, "run", lambda _config: (_ for _ in ()).throw(RuntimeError(secret)))
    monkeypatch.setattr(module.os, "environ", environment)
    assert module.main() == 1
    output = capsys.readouterr().out
    assert secret not in output
    assert '"error_type": "RuntimeError"' in output
