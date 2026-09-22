from __future__ import annotations

import pytest

from deploy.postgres.verify_private_memory_head_v1_3 import (
    ALL_CHECKS,
    AUTHORIZATION,
    CHECK_NAMES,
    VerificationConfiguration,
    VerificationError,
    _check_sql,
    _requested_check,
    _selected_checks,
)


def _environment() -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_PRODUCT_INGRESS_ENABLED": "false",
        "LUCY_REALM_HEAD_VERIFICATION_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql+psycopg://lucy_migration:secret@"
            "dpg-example-a:5432/lucy_raymond?sslmode=require"
        ),
        "LUCY_CONTENT_SCOPE_ID": "11111111-1111-4111-8111-111111111111",
    }


def test_configuration_accepts_only_the_private_read_only_gate() -> None:
    configuration = VerificationConfiguration.from_environment(_environment())
    assert configuration.database_url.host == "dpg-example-a"
    assert configuration.database_url.username == "lucy_migration"


def test_configuration_accepts_render_omitted_default_postgres_port() -> None:
    environment = _environment()
    environment["LUCY_MIGRATION_DATABASE_URL"] = environment[
        "LUCY_MIGRATION_DATABASE_URL"
    ].replace(":5432", "")
    configuration = VerificationConfiguration.from_environment(environment)
    assert configuration.database_url.port is None


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_PRODUCT_INGRESS_ENABLED", "true"),
        ("LUCY_REALM_HEAD_VERIFICATION_AUTHORIZATION", "wrong"),
        (
            "LUCY_MIGRATION_DATABASE_URL",
            "postgresql+psycopg://lucy_migration:secret@public.example:5432/"
            "lucy_raymond?sslmode=require",
        ),
        (
            "LUCY_MIGRATION_DATABASE_URL",
            "postgresql+psycopg://other:secret@dpg-example-a:5432/"
            "lucy_raymond?sslmode=require",
        ),
    ),
)
def test_configuration_fails_closed(key: str, value: str) -> None:
    environment = _environment()
    environment[key] = value
    with pytest.raises(VerificationError):
        VerificationConfiguration.from_environment(environment)


def test_diagnostic_checks_are_exactly_allowlisted() -> None:
    assert _selected_checks(ALL_CHECKS) == CHECK_NAMES
    for check in CHECK_NAMES:
        assert _selected_checks(check) == (check,)
        statement, parameters = _check_sql(check)
        assert statement.startswith("SELECT ")
        assert set(parameters) <= {"expected"}


def test_unknown_diagnostic_check_fails_closed() -> None:
    with pytest.raises(VerificationError):
        _selected_checks("database_dump")
    with pytest.raises(VerificationError):
        _check_sql("database_dump")


def test_head_check_matches_the_commissioning_migration_target() -> None:
    from deploy.postgres.bootstrap_realm_cloud_v1_3 import EXPECTED_REVISION

    _, parameters = _check_sql("revision")
    assert parameters["expected"] == EXPECTED_REVISION


def test_requested_check_parses_the_module_command_line() -> None:
    assert _requested_check(()) == ALL_CHECKS
    assert _requested_check(("--check", "revision")) == "revision"
    with pytest.raises(VerificationError):
        _requested_check(("--check", "database_dump"))
    with pytest.raises(VerificationError):
        _requested_check(("revision",))
