"""Quarantine-first schema bridge for the Public Lucy R1 release.

The prepare action advances the accepted Private Lucy Stage 2 database from 0054
to 0056 so the exact public corpus can be staged and approved.  The activate
action advances 0056 to 0057 and applies the final execute-only realm grants.
Neither action reopens admission or changes any capture setting.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any, Literal

import psycopg
from pydantic import BaseModel, ConfigDict
from sqlalchemy.engine import URL

from deploy.postgres.bootstrap_realm_cloud_v1_3 import (
    _LUCY_DATABASE,
    _PRIVATE_RENDER_HOST,
    BootstrapError,
    _conninfo,
    _database_url,
    migrate_realm_database,
)
from deploy.postgres.render_security_v1_3_sql import render_realm_roles
from lucy.readiness import ADMISSION_LOCK

Action = Literal["prepare", "activate"]

AUTHORIZATIONS: dict[Action, str] = {
    "prepare": "utopia-public-conversation-prepare-v1",
    "activate": "utopia-public-conversation-schema-v1",
}
SOURCE_REVISION = "0054_stage2_scoped_turn_commit"
PREPARED_REVISION = "0056_memory_import_budget"
TARGET_REVISION = "0057_public_conversation"
MAINTENANCE_LOCK = 0x4C5543594D53
REALM_LOGINS = {
    "realm_slug": "utopia",
    "routine_login": "lucy_utopia_routine",
    "policy_login": "lucy_utopia_policy",
    "workflow_login": "lucy_utopia_sensitive_workflow",
    "finality_login": "lucy_utopia_finality",
    "public_login": "lucy_utopia_public",
}


class PublicConversationMigrationError(RuntimeError):
    """The Public Lucy schema bridge failed closed."""


class PublicConversationMigrationReceiptV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: str = "lucy.utopia.public-conversation-migration.v1"
    status: str
    action: Action
    source_revision: str
    target_revision: str
    admission_state: str
    storage_epoch_present: bool
    private_capture_state_preserved: bool
    final_public_grant_installed: bool
    residual_schema_create: bool
    replayed: bool


def configuration_from_environment(
    environment: Mapping[str, str] | None = None,
) -> tuple[URL, Action]:
    values = os.environ if environment is None else environment
    if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
        raise PublicConversationMigrationError("migration requires production Render")
    if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
        raise PublicConversationMigrationError("the migration job must not capture transcripts")
    action = values.get("LUCY_PUBLIC_CONVERSATION_MIGRATION_ACTION", "").strip()
    if action not in AUTHORIZATIONS:
        raise PublicConversationMigrationError("the migration action is invalid")
    typed_action: Action = action  # type: ignore[assignment]
    if (
        values.get("LUCY_PUBLIC_CONVERSATION_MIGRATION_AUTHORIZATION")
        != AUTHORIZATIONS[typed_action]
    ):
        raise PublicConversationMigrationError("the exact migration authorization is required")
    raw = values.get("LUCY_MIGRATION_DATABASE_URL", "").strip()
    if not raw:
        raise PublicConversationMigrationError("LUCY_MIGRATION_DATABASE_URL is required")
    try:
        migration_url = _database_url(raw)
    except BootstrapError as exc:
        raise PublicConversationMigrationError("the migration database URL is invalid") from exc
    if (
        migration_url.username != "lucy_migration"
        or migration_url.host is None
        or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
        or migration_url.database is None
        or _LUCY_DATABASE.fullmatch(migration_url.database) is None
        or migration_url.port not in (None, 5432)
    ):
        raise PublicConversationMigrationError("the migration database boundary differs")
    return migration_url, typed_action


def _boundary(connection: psycopg.Connection[Any]) -> tuple[str, str, str, object, str, bool]:
    row = connection.execute(
        "SELECT current_user,(SELECT version_num FROM public.alembic_version),"
        "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
        "(SELECT storage_epoch FROM lucy.runtime_admission WHERE singleton),"
        "(SELECT state FROM lucy.lifecycle WHERE singleton),"
        "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())"
    ).fetchone()
    if row is None:
        raise PublicConversationMigrationError("the database boundary is unavailable")
    return row


def _residual_schema_create(connection: psycopg.Connection[Any]) -> bool:
    row = connection.execute(
        "SELECT has_schema_privilege('lucy_security_function_owner','lucy','CREATE') OR "
        "has_schema_privilege('lucy_directory_function_owner','lucy','CREATE') OR "
        "has_schema_privilege('lucy_cost_function_owner','lucy','CREATE') OR "
        "has_schema_privilege('lucy_authority_function_owner','lucy','CREATE')"
    ).fetchone()
    return row is None or row != (False,)


def migrate(migration_url: URL, action: Action) -> PublicConversationMigrationReceiptV1:
    expected_sources = (
        {SOURCE_REVISION, PREPARED_REVISION}
        if action == "prepare"
        else {PREPARED_REVISION, TARGET_REVISION}
    )
    target = PREPARED_REVISION if action == "prepare" else TARGET_REVISION
    with psycopg.connect(_conninfo(migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout='15s'")
        connection.execute("SET LOCAL statement_timeout='120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (ADMISSION_LOCK,))
        before = _boundary(connection)
        if (
            before[0] != "lucy_migration"
            or before[1] not in expected_sources
            or before[3] is None
            or before[4:] != ("ready", True)
        ):
            raise PublicConversationMigrationError("the pre-migration database boundary differs")
        if action == "activate" and before[2] != "quarantined":
            raise PublicConversationMigrationError("activation migration requires quarantine")
        if action == "prepare" and before[2] not in {"ready", "quarantined"}:
            raise PublicConversationMigrationError("prepare migration admission state differs")
        if before[2] == "ready":
            connection.execute(
                "UPDATE lucy.runtime_admission SET state='quarantined',updated_at=now() "
                "WHERE singleton"
            )
        source_revision = str(before[1])
        storage_epoch = before[3]

    migrate_realm_database(migration_url, target_revision=target)

    if action == "activate":
        grants = render_realm_roles(**REALM_LOGINS)
        with psycopg.connect(_conninfo(migration_url)) as connection:
            connection.execute("SET LOCAL lock_timeout='15s'")
            connection.execute("SET LOCAL statement_timeout='120s'")
            connection.execute("SELECT pg_advisory_xact_lock(%s)", (MAINTENANCE_LOCK,))
            connection.execute("SELECT pg_advisory_xact_lock(%s)", (ADMISSION_LOCK,))
            connection.execute(grants)

    with psycopg.connect(_conninfo(migration_url)) as connection:
        after = _boundary(connection)
        final_grant = connection.execute(
            "SELECT has_function_privilege('lucy_utopia_public',"
            "'lucy.public_projection_knowledge_v1(text,uuid)','EXECUTE')"
        ).fetchone() == (True,) if action == "activate" else False
        residual = _residual_schema_create(connection)
    if (
        after
        != ("lucy_migration", target, "quarantined", storage_epoch, "ready", True)
        or residual
        or (action == "activate" and not final_grant)
    ):
        raise PublicConversationMigrationError("the post-migration database boundary differs")
    return PublicConversationMigrationReceiptV1(
        status="passed",
        action=action,
        source_revision=source_revision,
        target_revision=target,
        admission_state="quarantined",
        storage_epoch_present=True,
        private_capture_state_preserved=True,
        final_public_grant_installed=final_grant,
        residual_schema_create=False,
        replayed=source_revision == target,
    )


def main() -> int:
    try:
        migration_url, action = configuration_from_environment()
        report = migrate(migration_url, action)
    except PublicConversationMigrationError as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.utopia.public-conversation-migration.v1",
                    "status": "failed",
                    "error": str(exc),
                },
                sort_keys=True,
            )
        )
        return 1
    except Exception as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.utopia.public-conversation-migration.v1",
                    "status": "failed",
                    "error_type": type(exc).__name__,
                },
                sort_keys=True,
            )
        )
        return 1
    print(report.model_dump_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
