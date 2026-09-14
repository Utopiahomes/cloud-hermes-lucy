from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

import deploy.postgres.provision_realm_bindings_v1_3 as provision
from deploy.postgres.provision_realm_bindings_v1_3 import (
    AUTHORIZATION,
    RealmProvisioningConfig,
    RealmProvisioningError,
)
from lucy.realm_provisioning import RealmExecutorStampV1, RealmSecurityStampV1

ACCOUNT = "123456789012"


def _executor(label: str, suffix: str) -> RealmExecutorStampV1:
    return RealmExecutorStampV1(
        binding_id=uuid4(),
        caller_identity=f"arn:aws:iam::{ACCOUNT}:role/lucy-utopia-{label}",
        executor_identity=f"lucy-utopia-{label}",
        executor_alias_arn=(
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:lucy-utopia-{label}:production"
        ),
        executor_version=1,
        receipt_key_id=(
            f"arn:aws:kms:us-east-1:{ACCOUNT}:"
            f"key/00000000-0000-4000-8000-00000000000{suffix}"
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


def _environment(stamp: RealmSecurityStampV1) -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_REALM_PROVISIONING_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_6tns"
        ),
        "LUCY_REALM_SECURITY_STAMP_JSON": stamp.model_dump_json(),
        "LUCY_REALM_SECURITY_STAMP_SHA256": stamp.digest_hex(),
    }


def test_config_requires_exact_reviewed_capture_off_stamp() -> None:
    stamp = _stamp()
    config = RealmProvisioningConfig.from_environment(_environment(stamp))
    assert config.manifest == stamp

    for key, value in {
        "RENDER": "false",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "true",
        "LUCY_REALM_PROVISIONING_AUTHORIZATION": "wrong",
        "LUCY_REALM_SECURITY_STAMP_SHA256": "f" * 64,
        "LUCY_MIGRATION_DATABASE_URL": "postgresql://lucy_migration:x@example.com/other",
    }.items():
        with pytest.raises(RealmProvisioningError):
            RealmProvisioningConfig.from_environment(_environment(stamp) | {key: value})


class _Result:
    def __init__(self, row: tuple[Any, ...] | None = None) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class _Connection:
    def __init__(self, boundary: tuple[Any, ...] = ("quarantined", True)) -> None:
        self.boundary = boundary
        self.statements: list[str] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, _parameters: object = None) -> _Result:
        normalized = " ".join(statement.split())
        self.statements.append(normalized)
        if "FROM pg_stat_ssl" in normalized:
            return _Result((True,))
        if "FROM lucy.runtime_admission" in normalized:
            return _Result(self.boundary)
        return _Result()


def test_run_locks_and_checks_boundary_before_applying(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = RealmProvisioningConfig.from_environment(_environment(_stamp()))
    connection = _Connection()
    applied: list[RealmSecurityStampV1] = []
    monkeypatch.setattr(provision.psycopg, "connect", lambda *_a, **_k: connection)
    monkeypatch.setattr(
        provision,
        "apply_manifest",
        lambda _connection, manifest: applied.append(manifest) is None,
    )
    report = provision.run(config)
    assert report["status"] == "passed" and report["replayed"] is False
    assert applied == [config.manifest]
    assert sum("pg_advisory_xact_lock" in item for item in connection.statements) == 2


def test_run_never_applies_outside_quarantine(monkeypatch: pytest.MonkeyPatch) -> None:
    config = RealmProvisioningConfig.from_environment(_environment(_stamp()))
    connection = _Connection(("ready", True))
    monkeypatch.setattr(provision.psycopg, "connect", lambda *_a, **_k: connection)
    monkeypatch.setattr(
        provision,
        "apply_manifest",
        lambda *_a: pytest.fail("must not provision outside quarantine"),
    )
    with pytest.raises(RealmProvisioningError, match="outside"):
        provision.run(config)
