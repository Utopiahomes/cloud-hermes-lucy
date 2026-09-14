from __future__ import annotations

import pytest

from deploy.postgres.verify_private_memory_head_v1_3 import (
    AUTHORIZATION,
    VerificationConfiguration,
    VerificationError,
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
