from __future__ import annotations

import pytest

from deploy.postgres import inspect_public_conversation_v1 as inspection
from deploy.postgres import migrate_public_conversation_v1 as migration
from deploy.postgres import reopen_public_conversation_v1 as reopen


def _migration_environment(action: migration.Action) -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_PUBLIC_CONVERSATION_MIGRATION_ACTION": action,
        "LUCY_PUBLIC_CONVERSATION_MIGRATION_AUTHORIZATION": migration.AUTHORIZATIONS[action],
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_utopia"
        ),
    }


def test_public_migration_actions_have_distinct_authorizations() -> None:
    prepare_url, prepare = migration.configuration_from_environment(
        _migration_environment("prepare")
    )
    activate_url, activate = migration.configuration_from_environment(
        _migration_environment("activate")
    )

    assert prepare == "prepare"
    assert activate == "activate"
    assert prepare_url.username == activate_url.username == "lucy_migration"
    assert migration.AUTHORIZATIONS[prepare] != migration.AUTHORIZATIONS[activate]


def test_public_migration_rejects_wrong_authorization_and_public_database() -> None:
    environment = _migration_environment("prepare")
    environment["LUCY_PUBLIC_CONVERSATION_MIGRATION_AUTHORIZATION"] = (
        migration.AUTHORIZATIONS["activate"]
    )
    with pytest.raises(migration.PublicConversationMigrationError, match="exact"):
        migration.configuration_from_environment(environment)

    environment = _migration_environment("prepare")
    environment["LUCY_MIGRATION_DATABASE_URL"] = (
        "postgresql://lucy_migration:secret@example.com/lucy_utopia"
    )
    with pytest.raises(migration.PublicConversationMigrationError, match="boundary"):
        migration.configuration_from_environment(environment)


def test_reopen_requires_exact_digest_and_private_capture_expectation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Config:
        pass

    monkeypatch.setattr(
        reopen.commission.CommissionConfig,
        "from_environment",
        lambda *_args: Config(),
    )
    environment = {
        "LUCY_PUBLIC_CONVERSATION_REOPEN_AUTHORIZATION": reopen.AUTHORIZATION,
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_PUBLIC_SNAPSHOT_DIGEST": "a" * 64,
        "LUCY_EXPECTED_PRIVATE_CAPTURE_ENABLED": "true",
    }

    config, digest, capture = reopen.configuration_from_environment(environment)

    assert isinstance(config, Config)
    assert digest == "a" * 64
    assert capture is True

    environment["LUCY_EXPECTED_PRIVATE_CAPTURE_ENABLED"] = "maybe"
    with pytest.raises(reopen.PublicConversationReopenError, match="capture"):
        reopen.configuration_from_environment(environment)


def test_reopen_authorization_is_not_a_migration_authorization() -> None:
    assert reopen.AUTHORIZATION not in set(migration.AUTHORIZATIONS.values())


def test_inspection_requires_private_production_database() -> None:
    environment = {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_PUBLIC_CONVERSATION_INSPECT_AUTHORIZATION": inspection.AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_utopia"
        ),
    }
    assert inspection.configuration_from_environment(environment).username == "lucy_migration"

    environment["LUCY_MIGRATION_DATABASE_URL"] = (
        "postgresql://lucy_migration:secret@example.com/lucy_utopia"
    )
    with pytest.raises(inspection.PublicConversationInspectionError, match="boundary"):
        inspection.configuration_from_environment(environment)
