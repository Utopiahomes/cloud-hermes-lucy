from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
from sqlalchemy.exc import OperationalError, ProgrammingError

import lucy.runtime as runtime
from lucy.readiness import (
    ReadinessError,
    expected_database_login_from_environment,
    expected_storage_epoch,
    security_baseline_from_environment,
    service_mode_from_environment,
)
from lucy.rejoining import RejoiningService


@pytest.mark.parametrize("mode", ["routine", "policy", "evidence", "deletion", "all-local"])
def test_service_startup_only_reads_admission_and_never_runs_recovery(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    monkeypatch.setenv("LUCY_SERVICE_MODE", mode)
    monkeypatch.setenv("LUCY_DATABASE_URL", "synthetic-not-connected")
    monkeypatch.setenv("LUCY_OBSERVED_HERMES_COMMIT", "a" * 40)
    monkeypatch.setenv("LUCY_STORAGE_EPOCH", str(uuid4()))
    monkeypatch.setenv("LUCY_ENVIRONMENT", "development" if mode == "all-local" else "production")
    monkeypatch.delenv("LUCY_ARCHIVE_BACKEND", raising=False)
    monkeypatch.setattr(runtime, "_expected_commit", lambda: "a" * 40)
    monkeypatch.setattr(runtime, "create_session_factory", lambda *_: object())
    monkeypatch.setattr(runtime, "deletion_journal_from_environment", lambda: object())
    calls: list[str] = []
    monkeypatch.setattr(
        runtime,
        "ServiceReadiness",
        lambda *_a, **_k: SimpleNamespace(
            check=lambda: calls.append("read_only_check"),
        ),
    )
    monkeypatch.setattr(RejoiningService, "run", lambda *_a, **_k: pytest.fail("must not recover"))
    monkeypatch.setattr(runtime.uvicorn, "run", lambda app, **_k: calls.append(app.title))
    runtime.main()
    assert calls == ["read_only_check", "Lucy Companion API"]


@pytest.mark.parametrize("mode", [None, "all-local", "unknown"])
def test_production_cannot_fall_back_to_combined_identity(
    monkeypatch: pytest.MonkeyPatch,
    mode: str | None,
) -> None:
    monkeypatch.setenv("LUCY_ENVIRONMENT", "production")
    if mode is None:
        monkeypatch.delenv("LUCY_SERVICE_MODE", raising=False)
    else:
        monkeypatch.setenv("LUCY_SERVICE_MODE", mode)
    with pytest.raises(ReadinessError, match="isolated service identity"):
        service_mode_from_environment()


def test_aws_backend_always_requires_isolated_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LUCY_ENVIRONMENT", "development")
    monkeypatch.setenv("LUCY_ARCHIVE_BACKEND", "aws-kms-dynamodb")
    monkeypatch.delenv("LUCY_SERVICE_MODE", raising=False)
    with pytest.raises(ReadinessError):
        service_mode_from_environment()


def test_v13_requires_an_explicit_expected_database_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_SECURITY_BASELINE", "v1.3")
    monkeypatch.delenv("LUCY_EXPECTED_DATABASE_LOGIN", raising=False)
    assert security_baseline_from_environment() == "v1.3"
    with pytest.raises(ReadinessError, match="database identity"):
        expected_database_login_from_environment("v1.3")
    monkeypatch.setenv("LUCY_EXPECTED_DATABASE_LOGIN", "lucy_utopia_routine")
    assert (
        expected_database_login_from_environment("v1.3")
        == "lucy_utopia_routine"
    )


def test_unknown_security_baseline_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LUCY_SECURITY_BASELINE", "moving-main")
    with pytest.raises(ReadinessError, match="security baseline"):
        security_baseline_from_environment()


def test_policy_startup_never_requests_an_aws_journal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_SERVICE_MODE", "policy")
    monkeypatch.setenv("LUCY_ENVIRONMENT", "production")
    monkeypatch.setenv("LUCY_ARCHIVE_BACKEND", "aws-kms-dynamodb")
    monkeypatch.setenv("LUCY_DATABASE_URL", "synthetic-not-connected")
    monkeypatch.setenv("LUCY_OBSERVED_HERMES_COMMIT", "a" * 40)
    monkeypatch.setenv("LUCY_STORAGE_EPOCH", str(uuid4()))
    monkeypatch.setattr(runtime, "_expected_commit", lambda: "a" * 40)
    monkeypatch.setattr(runtime, "create_session_factory", lambda *_: object())
    monkeypatch.setattr(
        runtime,
        "deletion_journal_from_environment",
        lambda: pytest.fail("policy identity must not request an AWS journal"),
    )
    monkeypatch.setattr(
        runtime,
        "ServiceReadiness",
        lambda *_a, **kwargs: SimpleNamespace(
            check=lambda: None if kwargs["journal"] is None else pytest.fail("unexpected journal")
        ),
    )
    monkeypatch.setattr(runtime.uvicorn, "run", lambda *_a, **_k: None)
    runtime.main()


def test_runtime_uses_the_platform_assigned_listener_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PORT", "10000")
    assert runtime._listener_port() == 10000


@pytest.mark.parametrize("value", ["not-a-port", "0", "65536"])
def test_runtime_rejects_an_invalid_listener_port(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("PORT", value)
    with pytest.raises(SystemExit, match="invalid listener port"):
        runtime._listener_port()


def test_service_requires_external_storage_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LUCY_STORAGE_EPOCH", raising=False)
    with pytest.raises(ReadinessError):
        expected_storage_epoch("routine")
    assert expected_storage_epoch("all-local") is None


def test_failed_startup_check_never_starts_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LUCY_SERVICE_MODE", "routine")
    monkeypatch.setenv("LUCY_DATABASE_URL", "synthetic-not-connected")
    monkeypatch.setenv("LUCY_OBSERVED_HERMES_COMMIT", "a" * 40)
    monkeypatch.setenv("LUCY_STORAGE_EPOCH", str(uuid4()))
    monkeypatch.setattr(runtime, "_expected_commit", lambda: "a" * 40)
    monkeypatch.setattr(runtime, "create_session_factory", lambda *_: object())
    monkeypatch.setattr(runtime, "deletion_journal_from_environment", lambda: object())

    def denied() -> None:
        raise ReadinessError("storage is quarantined")

    monkeypatch.setattr(
        runtime, "ServiceReadiness", lambda *_a, **_k: SimpleNamespace(check=denied)
    )
    monkeypatch.setattr(
        runtime.uvicorn, "run", lambda *_a, **_k: pytest.fail("listener must not start")
    )
    with pytest.raises(SystemExit, match="quarantined"):
        runtime.main()


def test_startup_retries_only_transient_connection_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    delays: list[int] = []

    def check() -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise OperationalError(
                "connect", {}, psycopg.OperationalError("private DNS pending")
            )

    monkeypatch.setattr(runtime.time, "sleep", delays.append)
    runtime._check_with_connection_retries(SimpleNamespace(check=check))
    assert attempts == 3
    assert delays == [1, 2]


def test_startup_does_not_retry_permission_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    delays: list[int] = []

    def check() -> None:
        nonlocal attempts
        attempts += 1
        raise ProgrammingError("select", {}, RuntimeError("permission denied"))

    monkeypatch.setattr(runtime.time, "sleep", delays.append)
    with pytest.raises(ProgrammingError):
        runtime._check_with_connection_retries(SimpleNamespace(check=check))
    assert attempts == 1
    assert delays == []


def test_startup_does_not_retry_invalid_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    delays: list[int] = []

    def check() -> None:
        nonlocal attempts
        attempts += 1
        invalid_password = psycopg.errors.InvalidPassword("authentication failed")
        raise OperationalError("connect", {}, invalid_password)

    monkeypatch.setattr(runtime.time, "sleep", delays.append)
    with pytest.raises(OperationalError):
        runtime._check_with_connection_retries(SimpleNamespace(check=check))
    assert attempts == 1
    assert delays == []


def test_startup_exhausts_bounded_connection_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    delays: list[int] = []

    def check() -> None:
        nonlocal attempts
        attempts += 1
        raise OperationalError("connect", {}, psycopg.OperationalError("network pending"))

    monkeypatch.setattr(runtime.time, "sleep", delays.append)
    with pytest.raises(OperationalError):
        runtime._check_with_connection_retries(SimpleNamespace(check=check))
    assert attempts == 6
    assert delays == [1, 2, 4, 8, 8]
