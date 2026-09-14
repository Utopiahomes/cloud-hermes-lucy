"""Quarantine-first schema bridge for the Workspaces private-service release.

Run only as a temporary Render migration job after every realm runtime has been
stopped and admission has been quarantined.  This utility advances an accepted
Utopia production schema to 0068, reapplies the execute-only realm grants, and
keeps admission closed.  It never provisions Workspaces membership or starts a
runtime service.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

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
from lucy.readiness import (
    ADMISSION_LOCK,
    PUBLIC_CONVERSATION_SCHEMA_REVISION,
    STAGE2_SCHEMA_REVISION,
    WORKSPACES_SCHEMA_REVISION,
    _v13_required_functions,
)

AUTHORIZATION = "workspaces-schema-quarantined-v1"
MAINTENANCE_LOCK = 0x4C5543594D53
ACCEPTED_SOURCE_REVISIONS = {
    STAGE2_SCHEMA_REVISION,
    PUBLIC_CONVERSATION_SCHEMA_REVISION,
    WORKSPACES_SCHEMA_REVISION,
}
REALM_LOGINS = {
    "realm_slug": "utopia",
    "routine_login": "lucy_utopia_routine",
    "policy_login": "lucy_utopia_policy",
    "workflow_login": "lucy_utopia_sensitive_workflow",
    "finality_login": "lucy_utopia_finality",
    "public_login": "lucy_utopia_public",
}
WORKSPACES_FUNCTIONS = (
    "lucy.enqueue_workspaces_task_v1(uuid,uuid,uuid,uuid,uuid,text,text)",
    "lucy.claim_workspaces_task_v1(uuid,integer)",
    "lucy.heartbeat_workspaces_task_v1(uuid,uuid,integer)",
    "lucy.complete_workspaces_task_v1(uuid,uuid,text,jsonb)",
)


class WorkspacesMigrationError(RuntimeError):
    """The Workspaces production schema bridge failed closed."""


class WorkspacesMigrationReceiptV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: str = "lucy.utopia.workspaces-schema-migration.v1"
    status: str
    source_revision: str
    target_revision: str
    admission_state: str
    storage_epoch_present: bool
    capture_boundary_safe: bool
    existing_surface_grants_verified: bool
    workspaces_queue_grants_verified: bool
    direct_table_access_denied: bool
    residual_schema_create: bool
    replayed: bool


def configuration_from_environment(
    environment: Mapping[str, str] | None = None,
) -> URL:
    values = os.environ if environment is None else environment
    if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
        raise WorkspacesMigrationError("migration requires production Render")
    if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
        raise WorkspacesMigrationError("the migration job must not capture transcripts")
    if values.get("LUCY_WORKSPACES_MIGRATION_AUTHORIZATION") != AUTHORIZATION:
        raise WorkspacesMigrationError("the exact migration authorization is required")
    raw = values.get("LUCY_MIGRATION_DATABASE_URL", "").strip()
    if not raw:
        raise WorkspacesMigrationError("LUCY_MIGRATION_DATABASE_URL is required")
    try:
        migration_url = _database_url(raw)
    except BootstrapError as exc:
        raise WorkspacesMigrationError("the migration database URL is invalid") from exc
    if (
        migration_url.username != "lucy_migration"
        or migration_url.host is None
        or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
        or migration_url.database is None
        or _LUCY_DATABASE.fullmatch(migration_url.database) is None
        or migration_url.port not in (None, 5432)
    ):
        raise WorkspacesMigrationError("the migration database boundary differs")
    return migration_url


def _boundary(connection: psycopg.Connection[Any]) -> tuple[object, ...]:
    row = connection.execute(
        "SELECT current_user,(SELECT version_num FROM public.alembic_version),"
        "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
        "(SELECT storage_epoch FROM lucy.runtime_admission WHERE singleton),"
        "(SELECT state FROM lucy.lifecycle WHERE singleton),"
        "lucy.capture_boundary_safe_v1(),"
        "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())"
    ).fetchone()
    if row is None:
        raise WorkspacesMigrationError("the database boundary is unavailable")
    return tuple(row)


def _residual_schema_create(connection: psycopg.Connection[Any]) -> bool:
    row = connection.execute(
        "SELECT has_schema_privilege('lucy_security_function_owner','lucy','CREATE') OR "
        "has_schema_privilege('lucy_directory_function_owner','lucy','CREATE') OR "
        "has_schema_privilege('lucy_cost_function_owner','lucy','CREATE') OR "
        "has_schema_privilege('lucy_authority_function_owner','lucy','CREATE') OR "
        "EXISTS(SELECT 1 FROM pg_namespace n,"
        "LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a "
        "WHERE n.nspname='lucy' AND a.grantee=0 AND a.privilege_type='CREATE')"
    ).fetchone()
    return row != (False,)


def _function_grants(
    connection: psycopg.Connection[Any], login: str, functions: tuple[str, ...]
) -> bool:
    return all(
        connection.execute(
            "SELECT has_function_privilege(%s,%s,'EXECUTE')", (login, function)
        ).fetchone()
        == (True,)
        for function in functions
    )


def migrate(migration_url: URL) -> WorkspacesMigrationReceiptV1:
    with psycopg.connect(_conninfo(migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout='15s'")
        connection.execute("SET LOCAL statement_timeout='120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (ADMISSION_LOCK,))
        before = _boundary(connection)
        if (
            before[0] != "lucy_migration"
            or before[1] not in ACCEPTED_SOURCE_REVISIONS
            or before[2] != "quarantined"
            or before[3] is None
            or before[4:] != ("ready", True, True)
        ):
            raise WorkspacesMigrationError("the pre-migration database boundary differs")
        source_revision = str(before[1])
        storage_epoch = before[3]

    migrate_realm_database(migration_url, target_revision=WORKSPACES_SCHEMA_REVISION)

    grants = render_realm_roles(**REALM_LOGINS)
    with psycopg.connect(_conninfo(migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout='15s'")
        connection.execute("SET LOCAL statement_timeout='120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (ADMISSION_LOCK,))
        if _boundary(connection)[2:] != (
            "quarantined",
            storage_epoch,
            "ready",
            True,
            True,
        ):
            raise WorkspacesMigrationError("the grant boundary differs")
        connection.execute(grants, prepare=False)

    routine_functions = _v13_required_functions(
        mode="routine",
        schema_revision=WORKSPACES_SCHEMA_REVISION,
        public_conversation_enabled=False,
        telegram_stage2=True,
    )
    policy_functions = _v13_required_functions(
        mode="policy",
        schema_revision=WORKSPACES_SCHEMA_REVISION,
        public_conversation_enabled=False,
        telegram_stage2=True,
    )
    public_functions = _v13_required_functions(
        mode="public",
        schema_revision=WORKSPACES_SCHEMA_REVISION,
        public_conversation_enabled=True,
        telegram_stage2=False,
    )
    with psycopg.connect(_conninfo(migration_url)) as connection:
        after = _boundary(connection)
        existing_grants = (
            _function_grants(
                connection, str(REALM_LOGINS["routine_login"]), routine_functions
            )
            and _function_grants(
                connection, str(REALM_LOGINS["policy_login"]), policy_functions
            )
            and _function_grants(
                connection, str(REALM_LOGINS["public_login"]), public_functions
            )
        )
        queue_grants = _function_grants(
            connection, str(REALM_LOGINS["routine_login"]), WORKSPACES_FUNCTIONS
        )
        direct_access = connection.execute(
            "SELECT has_table_privilege('lucy_utopia_routine',"
            "'lucy.workspaces_tasks_v1','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') OR "
            "has_table_privilege('lucy_utopia_routine',"
            "'lucy.workspaces_task_events_v1','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')"
        ).fetchone()
        direct_denied = direct_access == (False,)
        residual = _residual_schema_create(connection)
    if (
        after
        != (
            "lucy_migration",
            WORKSPACES_SCHEMA_REVISION,
            "quarantined",
            storage_epoch,
            "ready",
            True,
            True,
        )
        or not existing_grants
        or not queue_grants
        or not direct_denied
        or residual
    ):
        raise WorkspacesMigrationError("the post-migration database boundary differs")
    return WorkspacesMigrationReceiptV1(
        status="passed",
        source_revision=source_revision,
        target_revision=WORKSPACES_SCHEMA_REVISION,
        admission_state="quarantined",
        storage_epoch_present=True,
        capture_boundary_safe=True,
        existing_surface_grants_verified=True,
        workspaces_queue_grants_verified=True,
        direct_table_access_denied=True,
        residual_schema_create=False,
        replayed=source_revision == WORKSPACES_SCHEMA_REVISION,
    )


def main() -> int:
    try:
        report = migrate(configuration_from_environment())
    except WorkspacesMigrationError as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.utopia.workspaces-schema-migration.v1",
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
                    "contract": "lucy.utopia.workspaces-schema-migration.v1",
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
