from __future__ import annotations

import pytest

from deploy.postgres.bootstrap_realm_cloud_v1_3 import AUTHORIZATION, BootstrapError
from deploy.postgres.migrate_realm_cloud_v1_3 import configuration_from_environment


def _environment() -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_REALM_BOOTSTRAP_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:synthetic@dpg-example-a:5432/lucy"
        ),
    }


def test_accepts_exact_quarantined_private_render_boundary() -> None:
    value = configuration_from_environment(_environment())
    assert value.drivername == "postgresql+psycopg"
    assert value.username == "lucy_migration"
    assert value.host == "dpg-example-a"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("RENDER", "false"),
        ("LUCY_ENVIRONMENT", "development"),
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_REALM_BOOTSTRAP_AUTHORIZATION", "wrong"),
        (
            "LUCY_MIGRATION_DATABASE_URL",
            "postgresql://lucy_app:synthetic@dpg-example-a:5432/lucy",
        ),
        (
            "LUCY_MIGRATION_DATABASE_URL",
            "postgresql://lucy_migration:synthetic@example.com:5432/lucy",
        ),
    ],
)
def test_rejects_changed_boundary(key: str, value: str) -> None:
    with pytest.raises(BootstrapError):
        configuration_from_environment(_environment() | {key: value})
