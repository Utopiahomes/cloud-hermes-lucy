from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

import deploy.postgres.provision_realm_foundation_v1_3 as provision
from deploy.postgres.provision_realm_bindings_v1_3 import RealmProvisioningError
from deploy.postgres.provision_realm_foundation_v1_3 import (
    AUTHORIZATION,
    RealmFoundationConfig,
    RealmFoundationSeedV1,
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
        provisioned_at=datetime(2026, 9, 9, tzinfo=UTC),
    )


def _environment(stamp: RealmSecurityStampV1, seed: RealmFoundationSeedV1) -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_REALM_FOUNDATION_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": "postgresql://lucy_migration:x@dpg-example-a/lucy_6tns",
        "LUCY_REALM_SECURITY_STAMP_JSON": stamp.model_dump_json(),
        "LUCY_REALM_SECURITY_STAMP_SHA256": stamp.digest_hex(),
        "LUCY_REALM_FOUNDATION_SEED_JSON": seed.model_dump_json(),
        "LUCY_REALM_FOUNDATION_SEED_SHA256": seed.digest_hex(),
    }


def test_config_requires_exact_capture_off_foundation_and_stamp() -> None:
    stamp, seed = _stamp(), _seed()
    config = RealmFoundationConfig.from_environment(_environment(stamp, seed))
    assert config.stamp == stamp and config.seed == seed

    for key, value in {
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "true",
        "LUCY_REALM_FOUNDATION_AUTHORIZATION": "wrong",
        "LUCY_REALM_FOUNDATION_SEED_SHA256": "0" * 64,
        "LUCY_MIGRATION_DATABASE_URL": "postgresql://lucy_migration:x@example.com/other",
    }.items():
        with pytest.raises(RealmProvisioningError):
            RealmFoundationConfig.from_environment(_environment(stamp, seed) | {key: value})


class _Result:
    def __init__(self, row: tuple[Any, ...] | None = None) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class _Connection:
    def __init__(self, boundary: tuple[Any, ...]) -> None:
        self.boundary = boundary
        self.statements: list[str] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, _parameters: object = None) -> _Result:
        normalized = " ".join(statement.split())
        self.statements.append(normalized)
        if "FROM lucy.runtime_admission" in normalized:
            return _Result(self.boundary)
        return _Result()


def test_run_locks_and_rejects_any_open_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    stamp, seed = _stamp(), _seed()
    config = RealmFoundationConfig.from_environment(_environment(stamp, seed))
    connection = _Connection(("quarantined", True, True))
    applied: list[tuple[RealmSecurityStampV1, RealmFoundationSeedV1]] = []
    monkeypatch.setattr(provision.psycopg, "connect", lambda *_a, **_k: connection)
    monkeypatch.setattr(
        provision,
        "apply_foundation",
        lambda _connection, child_stamp, child_seed: not applied.append(
            (child_stamp, child_seed)
        ),
    )
    report = provision.run(config)
    assert report["status"] == "passed" and report["replayed"] is False
    assert applied == [(stamp, seed)]
    assert sum("pg_advisory_xact_lock" in item for item in connection.statements) == 2

    connection = _Connection(("ready", True, True))
    monkeypatch.setattr(provision.psycopg, "connect", lambda *_a, **_k: connection)
    monkeypatch.setattr(
        provision,
        "apply_foundation",
        lambda *_a: pytest.fail("must not apply outside quarantine"),
    )
    with pytest.raises(RealmProvisioningError, match="outside"):
        provision.run(config)
