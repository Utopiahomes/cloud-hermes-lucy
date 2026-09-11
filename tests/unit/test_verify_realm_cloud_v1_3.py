from __future__ import annotations

import json

import pytest

import deploy.postgres.verify_realm_cloud_v1_3 as verifier
from deploy.postgres.bootstrap_realm_cloud_v1_3 import BootstrapError


def test_report_is_content_free_and_counts_verified_logins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        verifier,
        "_verify",
        lambda _config: {
            "migration_revision": "0050_r1_recovery_ack_receiver",
            "runtime_admission": "quarantined",
            "capture_enabled": False,
            "content_scope_count": 1,
            "active_actor_bindings": 4,
            "active_executor_bindings": 2,
            "directory_admission_acl_isolated": True,
            "offline_migration_schema_owner": True,
            "function_owner_schema_create_removed": True,
            "verified_runtime_logins": ["a", "b", "c", "d"],
            "verified_recovery_logins": ["e", "f", "g", "h"],
        },
    )
    report = verifier.run(object())  # type: ignore[arg-type]
    assert report["status"] == "passed"
    assert report["runtime_login_count"] == 4
    assert report["recovery_login_count"] == 4
    assert "verified_runtime_logins" not in report


def test_main_never_echoes_unexpected_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "never-print-this-private-database-url"
    monkeypatch.setattr(
        verifier.BootstrapConfig,
        "from_environment",
        lambda: (_ for _ in ()).throw(BootstrapError(secret)),
    )
    assert verifier.main() == 1
    output = capsys.readouterr().out
    assert secret not in output
    assert json.loads(output)["error_type"] == "BootstrapError"
