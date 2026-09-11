from __future__ import annotations

import pytest

from deploy.postgres.bootstrap_realm_cloud_v1_3 import BootstrapError
from deploy.postgres.migrate_telegram_stage2_v1 import (
    AUTHORIZATION,
    TARGET_REVISION,
    configuration_from_environment,
)


def _environment() -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_STAGE2_MIGRATION_AUTHORIZATION": AUTHORIZATION,
        "LUCY_STAGE2_ROUTINE_LOGIN": "lucy_utopia_routine",
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:synthetic@dpg-example-a:5432/lucy"
        ),
    }


def test_stage2_migration_accepts_only_quarantined_private_render_boundary() -> None:
    url, login = configuration_from_environment(_environment())
    assert url.username == "lucy_migration"
    assert url.host == "dpg-example-a"
    assert login == "lucy_utopia_routine"
    assert TARGET_REVISION == "0054_stage2_scoped_turn_commit"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("RENDER", "false"),
        ("LUCY_ENVIRONMENT", "development"),
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_STAGE2_MIGRATION_AUTHORIZATION", "wrong"),
        ("LUCY_STAGE2_ROUTINE_LOGIN", "lucy_routine"),
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
def test_stage2_migration_rejects_changed_boundary(key: str, value: str) -> None:
    with pytest.raises(BootstrapError):
        configuration_from_environment(_environment() | {key: value})
