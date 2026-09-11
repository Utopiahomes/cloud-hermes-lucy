from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy.exc import ProgrammingError

import deploy.postgres.run_protected_recovery_v1_3 as protected_recovery
from deploy.postgres.run_protected_recovery_v1_3 import (
    AUTHORIZATION,
    ProtectedRecoveryConfig,
    ProtectedRecoveryError,
    _database_stage,
    _verify_actual_role,
    _verify_database_identity,
    _verify_migration_identity,
)
from lucy.recovery_journal import RecoveryStreamKind

ACCOUNT = "123456789012"
MANIFEST = "a" * 64
AUTHORITY_STREAM = UUID("11111111-1111-4111-8111-111111111111")
COST_STREAM = UUID("22222222-2222-4222-8222-222222222222")
ROLE = f"arn:aws:iam::{ACCOUNT}:role/lucy-utopia-recovery-coordinator"


def _binding(kind: RecoveryStreamKind, stream_id: UUID, table: str) -> dict[str, Any]:
    return {
        "contract_version": "1",
        "stream_kind": kind.value,
        "stream_id": str(stream_id),
        "authority_epoch": 1,
        "independent_store_id": f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/{table}",
        "writer_identity": f"arn:aws:iam::{ACCOUNT}:role/lucy-utopia-{kind.value}-writer",
        "recovery_identity": ROLE,
        "binding_manifest_digest": MANIFEST,
    }


def _witness(binding: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in binding.items()
        if key
        in {
            "contract_version",
            "stream_kind",
            "stream_id",
            "authority_epoch",
            "independent_store_id",
            "binding_manifest_digest",
        }
    } | {"sequence": 0, "event_digest": "0" * 64}


def _environment() -> dict[str, str]:
    authority = _binding(RecoveryStreamKind.AUTHORITY, AUTHORITY_STREAM, "authority-table")
    cost = _binding(RecoveryStreamKind.COST, COST_STREAM, "cost-table")
    database = "dpg-example-a/lucy_6tns"
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_SECURITY_BASELINE": "v1.3",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_PROTECTED_RECOVERY_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            f"postgresql://lucy_utopia_recovery_activation:x@{database}"
        ),
        "LUCY_AUTHORITY_RECOVERY_DATABASE_URL": (
            f"postgresql://lucy_utopia_authority_recovery:x@{database}"
        ),
        "LUCY_COST_RECOVERY_DATABASE_URL": (
            f"postgresql://lucy_utopia_cost_recovery:x@{database}"
        ),
        "AWS_REGION": "us-east-1",
        "LUCY_AWS_ACCOUNT_ID": ACCOUNT,
        "AWS_ROLE_ARN": ROLE,
        "LUCY_AUTHORITY_RECOVERY_JOURNAL_TABLE": "authority-table",
        "LUCY_COST_RECOVERY_JOURNAL_TABLE": "cost-table",
        "LUCY_AUTHORITY_RECOVERY_STREAM_BINDING_JSON": json.dumps(authority),
        "LUCY_COST_RECOVERY_STREAM_BINDING_JSON": json.dumps(cost),
        "LUCY_AUTHORITY_RECOVERY_WITNESS_JSON": json.dumps(_witness(authority)),
        "LUCY_COST_RECOVERY_WITNESS_JSON": json.dumps(_witness(cost)),
        "LUCY_RECOVERY_TARGET_RUNTIME_EPOCH": "33333333-3333-4333-8333-333333333333",
        "LUCY_RECOVERY_BINDING_MANIFEST_DIGEST": MANIFEST,
    }


def test_config_binds_two_streams_to_one_oidc_role_and_private_database() -> None:
    config = ProtectedRecoveryConfig.from_environment(_environment())

    assert config.authority_binding.stream_kind is RecoveryStreamKind.AUTHORITY
    assert config.cost_binding.stream_kind is RecoveryStreamKind.COST
    assert config.role_arn == ROLE
    assert config.migration_url.host == "dpg-example-a"
    assert config.migration_url.username == "lucy_utopia_recovery_activation"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("RENDER", "false"),
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_PROTECTED_RECOVERY_AUTHORIZATION", "wrong"),
        ("AWS_ACCESS_KEY_ID", "prohibited"),
        ("AWS_REGION", "us-west-2"),
        ("AWS_ROLE_ARN", f"arn:aws:iam::{ACCOUNT}:role/wrong"),
        ("LUCY_COST_RECOVERY_JOURNAL_TABLE", "authority-table"),
        ("LUCY_RECOVERY_BINDING_MANIFEST_DIGEST", "b" * 64),
        (
            "LUCY_MIGRATION_DATABASE_URL",
            "postgresql://lucy_utopia_recovery_activation:x@public.example.com/lucy_6tns",
        ),
    ],
)
def test_config_fails_closed_on_boundary_drift(name: str, value: str) -> None:
    with pytest.raises(ProtectedRecoveryError):
        ProtectedRecoveryConfig.from_environment(_environment() | {name: value})


def test_config_rejects_a_witness_for_another_stream() -> None:
    environment = _environment()
    environment["LUCY_COST_RECOVERY_WITNESS_JSON"] = environment[
        "LUCY_AUTHORITY_RECOVERY_WITNESS_JSON"
    ]

    with pytest.raises(ProtectedRecoveryError, match="witness"):
        ProtectedRecoveryConfig.from_environment(environment)


def test_actual_aws_role_must_match_the_bound_oidc_role() -> None:
    config = ProtectedRecoveryConfig.from_environment(_environment())
    _verify_actual_role(
        config,
        {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/"
            "lucy-utopia-recovery-coordinator/render-session",
        },
    )

    with pytest.raises(ProtectedRecoveryError, match="identity differs"):
        _verify_actual_role(
            config,
            {
                "Account": ACCOUNT,
                "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/wrong/render-session",
            },
        )


class _Result:
    def __init__(self, row: tuple[object, ...]) -> None:
        self._row = row

    def one(self) -> tuple[object, ...]:
        return self._row


class _Session:
    def __init__(self, row: tuple[object, ...]) -> None:
        self._row = row

    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, _statement: object) -> _Result:
        return _Result(self._row)


def test_recovery_identity_attests_execute_only_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login = "lucy_utopia_authority_recovery"
    row = (login, True, False, False, False, False, False, False,
           "0050_r1_recovery_ack_receiver", True, True)
    monkeypatch.setattr(
        protected_recovery,
        "create_session_factory",
        lambda _url: lambda: _Session(row),
    )

    config = ProtectedRecoveryConfig.from_environment(_environment())
    _verify_database_identity(config.authority_recovery_url, login)


def _migration_row() -> tuple[object, ...]:
    return (
        "lucy_utopia_recovery_activation",
        "lucy_utopia_recovery_activation",
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        "lucy_migration",
        "0050_r1_recovery_ack_receiver",
        "quarantined",
        True,
        True,
        False,
        False,
        False,
        False,
        True,
        True,
        True,
        True,
        True,
        False,
        True,
        True,
        False,
        True,
        True,
        False,
        True,
    )


def test_migration_identity_requires_exact_offline_capture_safe_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        protected_recovery,
        "create_session_factory",
        lambda _url: lambda: _Session(_migration_row()),
    )
    _verify_migration_identity(ProtectedRecoveryConfig.from_environment(_environment()).migration_url)


@pytest.mark.parametrize(
    ("index", "value"),
    [
        (0, "wrong_login"),
        (1, "wrong_login"),
        (3, True),
        (9, "wrong_owner"),
        (10, "0049_r1_cost_recovery_finalize"),
        (11, "ready"),
        (12, False),
        (13, False),
        (14, True),
        (18, False),
        (24, False),
        (27, False),
        (30, False),
    ],
)
def test_migration_identity_rejects_boundary_drift(
    monkeypatch: pytest.MonkeyPatch, index: int, value: object
) -> None:
    row = list(_migration_row())
    row[index] = value
    monkeypatch.setattr(
        protected_recovery,
        "create_session_factory",
        lambda _url: lambda: _Session(tuple(row)),
    )

    with pytest.raises(ProtectedRecoveryError, match="activation identity"):
        _verify_migration_identity(
            ProtectedRecoveryConfig.from_environment(_environment()).migration_url
        )


def test_config_rejects_elevated_migration_login() -> None:
    environment = _environment()
    environment["LUCY_MIGRATION_DATABASE_URL"] = (
        "postgresql://lucy_migration:x@dpg-example-a/lucy_6tns"
    )

    with pytest.raises(ProtectedRecoveryError, match="exact temporary login"):
        ProtectedRecoveryConfig.from_environment(environment)


def test_database_stage_hides_statement_and_parameters() -> None:
    failure = ProgrammingError(
        "SELECT :secret", {"secret": "must-not-appear"}, RuntimeError("hidden")
    )

    with pytest.raises(
        ProtectedRecoveryError, match="coordinated replay failed at database boundary"
    ) as raised:
        _database_stage("coordinated replay", lambda: (_ for _ in ()).throw(failure))

    assert "must-not-appear" not in str(raised.value)
    assert "SELECT" not in str(raised.value)
