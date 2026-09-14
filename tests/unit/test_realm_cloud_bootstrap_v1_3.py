from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.exc import ProgrammingError

import deploy.postgres.bootstrap_realm_cloud_v1_3 as bootstrap
from deploy.postgres.provision_realm_foundation_v1_3 import RealmFoundationSeedV1
from lucy.realm_provisioning import RealmExecutorStampV1, RealmSecurityStampV1

ACCOUNT = "123456789012"
HOST = "dpg-example-a"
DATABASE = "lucy_example"
ROOT = Path(__file__).parents[2]


def _executor(label: str, suffix: str) -> RealmExecutorStampV1:
    return RealmExecutorStampV1(
        binding_id=uuid4(),
        caller_identity=f"arn:aws:iam::{ACCOUNT}:role/lucy-utopia-{label}",
        executor_identity=f"lucy-utopia-{label}",
        executor_alias_arn=(
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:lucy-utopia-{label}:realm-v13"
        ),
        executor_version=1,
        receipt_key_id=(
            f"arn:aws:kms:us-east-1:{ACCOUNT}:key/00000000-0000-4000-8000-00000000000{suffix}"
        ),
    )


def _stamp() -> RealmSecurityStampV1:
    return RealmSecurityStampV1(
        realm_slug="utopia",
        aws_account_id=ACCOUNT,
        content_scope_id=uuid4(),
        tenant_account_id=uuid4(),
        node_id=uuid4(),
        node_tenure_id=uuid4(),
        tenure_epoch=1,
        security_realm_id=uuid4(),
        storage_epoch=1,
        realm_binding_id=uuid4(),
        workspace_id=uuid4(),
        deployment_id=uuid4(),
        service_binding_id=uuid4(),
        routine_login="lucy_utopia_routine",
        routine_principal_id=uuid4(),
        archive_actor_binding_id=uuid4(),
        policy_login="lucy_utopia_policy",
        policy_principal_id=uuid4(),
        policy_actor_binding_id=uuid4(),
        workflow_login="lucy_utopia_sensitive_workflow",
        workflow_principal_id=uuid4(),
        workflow_actor_binding_id=uuid4(),
        finality_login="lucy_utopia_finality",
        finality_principal_id=uuid4(),
        finality_actor_binding_id=uuid4(),
        binding_generation=1,
        node_authz_epoch=1,
        policy_version=1,
        retrieval_executor=_executor("retrieval", "1"),
        deletion_executor=_executor("deletion", "2"),
    )


def _seed() -> RealmFoundationSeedV1:
    return RealmFoundationSeedV1(
        realm_slug="utopia",
        account_slug="utopia",
        account_display_name="Utopia Homes",
        node_slug="utopia",
        node_display_name="Utopia Homes",
        node_kind="organization",
        workspace_slug="private",
        service_issuer="lucy://utopia/services",
        wallet_id=uuid4(),
        provisioned_at=datetime(2026, 9, 10, tzinfo=UTC),
    )


def _environment() -> dict[str, str]:
    stamp, seed = _stamp(), _seed()
    result = {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_REALM_BOOTSTRAP_AUTHORIZATION": bootstrap.AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            f"postgresql://lucy_migration:migration-secret@{HOST}:5432/{DATABASE}"
        ),
        "LUCY_REALM_SECURITY_STAMP_JSON": stamp.model_dump_json(),
        "LUCY_REALM_SECURITY_STAMP_SHA256": stamp.digest_hex(),
        "LUCY_REALM_FOUNDATION_SEED_JSON": seed.model_dump_json(),
        "LUCY_REALM_FOUNDATION_SEED_SHA256": seed.digest_hex(),
    }
    for mode, login in {
        "routine": stamp.routine_login,
        "policy": stamp.policy_login,
        "workflow": stamp.workflow_login,
        "finality": stamp.finality_login,
        "public": "lucy_utopia_public",
    }.items():
        result[f"LUCY_{mode.upper()}_DATABASE_URL"] = (
            f"postgresql://{login}:{mode}-secret@{HOST}:5432/{DATABASE}"
        )
    for mode, login in {
        "authority_writer": "lucy_utopia_authority_writer",
        "cost_writer": "lucy_utopia_cost_writer",
        "authority_recovery": "lucy_utopia_authority_recovery",
        "cost_recovery": "lucy_utopia_cost_recovery",
    }.items():
        result[f"LUCY_{mode.upper()}_DATABASE_URL"] = (
            f"postgresql://{login}:{mode}-secret@{HOST}:5432/{DATABASE}"
        )
    return result


def test_config_requires_private_capture_off_exact_realm_urls() -> None:
    config = bootstrap.BootstrapConfig.from_environment(_environment())
    assert config.stamp.realm_slug == "utopia"
    assert set(config.runtime_urls) == {
        "routine",
        "policy",
        "workflow",
        "finality",
        "public",
    }
    assert set(config.recovery_urls) == {
        "authority_writer",
        "cost_writer",
        "authority_recovery",
        "cost_recovery",
    }
    assert all(url.query["sslmode"] == "require" for url in config.runtime_urls.values())
    assert all(url.query["sslmode"] == "require" for url in config.recovery_urls.values())


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("RENDER", "false", "production Render"),
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true", "capture must remain disabled"),
        ("LUCY_REALM_BOOTSTRAP_AUTHORIZATION", "wrong", "exact reviewed"),
        (
            "LUCY_MIGRATION_DATABASE_URL",
            "postgresql://lucy_migration:x@public.example.com/lucy_example",
            "private Render",
        ),
        (
            "LUCY_POLICY_DATABASE_URL",
            f"postgresql://wrong:x@{HOST}/{DATABASE}",
            "exact password-bearing login",
        ),
    ],
)
def test_config_fails_closed(key: str, value: str, message: str) -> None:
    environment = _environment()
    environment[key] = value
    with pytest.raises(bootstrap.BootstrapError, match=message):
        bootstrap.BootstrapConfig.from_environment(environment)


def test_run_orders_quarantine_before_all_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    config = bootstrap.BootstrapConfig.from_environment(_environment())
    calls: list[str] = []
    monkeypatch.setattr(
        bootstrap,
        "_quarantine",
        lambda _config: calls.append("quarantine") or "0021_recovery_capture_safety",
    )
    monkeypatch.setattr(bootstrap, "_bootstrap_roles", lambda _config: calls.append("roles"))
    monkeypatch.setattr(bootstrap, "_run_migrations", lambda _config: calls.append("migrations"))
    monkeypatch.setattr(
        bootstrap,
        "_apply_grants_and_provision",
        lambda _config: calls.append("provision") or ("a" * 64, True, True),
    )
    monkeypatch.setattr(
        bootstrap,
        "_verify",
        lambda _config: calls.append("verify")
        or {"migration_revision": bootstrap.EXPECTED_REVISION},
    )
    report = bootstrap.run(config)
    assert calls == ["quarantine", "roles", "migrations", "provision", "verify"]
    assert report["status"] == "passed"
    assert report["source_revision"] == "0021_recovery_capture_safety"


def test_main_never_echoes_secrets(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = _environment()
    secret = "never-print-this-password"
    environment["LUCY_ROUTINE_DATABASE_URL"] = environment[
        "LUCY_ROUTINE_DATABASE_URL"
    ].replace("routine-secret", secret)
    monkeypatch.setattr(bootstrap.os, "environ", environment)
    monkeypatch.setattr(
        bootstrap,
        "run",
        lambda _config: (_ for _ in ()).throw(RuntimeError(secret)),
    )
    assert bootstrap.main() == 1
    output = capsys.readouterr().out
    assert secret not in output
    assert '"error_type": "RuntimeError"' in output


def test_prerequisite_roles_must_be_inert() -> None:
    bootstrap._assert_inert_role(
        "lucy_public_runtime",
        (False, False, False, False, False, False, False),
    )
    with pytest.raises(bootstrap.BootstrapError, match="not inert"):
        bootstrap._assert_inert_role(
            "lucy_public_runtime",
            (True, False, False, False, False, False, False),
        )


def test_bootstrap_removes_creator_membership_from_caller_roles() -> None:
    source = (
        ROOT / "deploy/postgres/bootstrap_realm_cloud_v1_3.py"
    ).read_text(encoding="utf-8")
    assert "REVOKE lucy_public_runtime FROM lucy_migration" in source
    assert "REVOKE lucy_directory_admission FROM lucy_migration" in source
    assert "GRANT lucy_directory_function_owner TO lucy_migration" in source


def test_postgres_creator_admin_rows_do_not_grant_caller_execution() -> None:
    bootstrap._validate_prerequisite_memberships(
        [
            ("lucy_directory_function_owner", "lucy_migration", True, True, True),
            ("lucy_directory_function_owner", "lucy_migration", True, False, False),
            ("lucy_public_runtime", "lucy_migration", True, False, False),
            ("lucy_directory_admission", "lucy_migration", True, False, False),
        ]
    )


@pytest.mark.parametrize(
    "unsafe",
    [
        ("lucy_public_runtime", "lucy_migration", True, False, True),
        ("lucy_directory_admission", "unexpected_runtime", False, True, True),
    ],
)
def test_prerequisite_caller_membership_rejects_privilege_paths(
    unsafe: tuple[object, ...],
) -> None:
    with pytest.raises(bootstrap.BootstrapError, match="not isolated"):
        bootstrap._validate_prerequisite_memberships(
            [
                ("lucy_directory_function_owner", "lucy_migration", True, True, True),
                unsafe,
            ]
        )


def test_stage_sanitizes_sqlalchemy_statement_and_parameters() -> None:
    secret = "never-print-this-database-secret"

    def fail() -> None:
        raise ProgrammingError("SELECT :secret", {"secret": secret}, RuntimeError("failure"))

    with pytest.raises(bootstrap.BootstrapError) as captured:
        bootstrap._stage("migration", fail)
    assert secret not in str(captured.value)
    assert "SELECT" not in str(captured.value)


def test_migrations_use_one_supplied_transaction_for_temporary_authority() -> None:
    source = (ROOT / "deploy/postgres/bootstrap_realm_cloud_v1_3.py").read_text(
        encoding="utf-8"
    )
    environment = (ROOT / "migrations/env.py").read_text(encoding="utf-8")
    grant = source.index("GRANT USAGE, CREATE ON SCHEMA lucy")
    upgrade = source.index("command.upgrade(alembic, target_revision)")
    revoke = source.index("REVOKE CREATE ON SCHEMA lucy")
    assert grant < upgrade < revoke
    assert "lucy_security_function_owner,lucy_directory_function_owner" in source
    assert 'alembic.attributes["connection"] = connection' in source
    assert 'config.attributes.get("connection")' in environment


def test_reviewed_revisions_fit_the_deployed_alembic_version_column() -> None:
    assert all(len(revision) <= 32 for revision in bootstrap.EXPECTED_SOURCE_REVISIONS)
    assert len(bootstrap.EXPECTED_REVISION) <= 32
    assert bootstrap.EXPECTED_REVISION == "0072_memory_pilot_auth_context"


def test_directory_migration_does_not_hardcode_tenant_logins() -> None:
    migration = (
        ROOT / "migrations/versions/0024_r1_internal_directory_admission.py"
    ).read_text(encoding="utf-8")
    assert "lucy_raymond_routine" not in migration
    assert "lucy_utopia_routine" not in migration
    assert "lucy_alpha_routine" not in migration


def test_documented_module_entrypoint_loads_repository_packages() -> None:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, "-m", "deploy.postgres.bootstrap_realm_cloud_v1_3"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert '"status": "failed"' in result.stdout
    assert "ModuleNotFoundError" not in result.stderr
