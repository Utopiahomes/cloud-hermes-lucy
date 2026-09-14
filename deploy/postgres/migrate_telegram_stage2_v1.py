"""Quarantine-first 0053 -> 0054 migration for private Telegram Stage 2.

This job never enables transcript capture or reopens runtime admission. It adds
the two Stage 2 functions, grants them only to the exact realm routine login,
and emits a content-free receipt. Repeated execution is idempotent.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from typing import Any

import psycopg
from psycopg import sql
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

SOURCE_REVISION = "0053_r1_telegram_authority"
TARGET_REVISION = "0054_stage2_scoped_turn_commit"
AUTHORIZATION = "telegram-stage2-quarantined-v1"
_ROUTINE_LOGIN = re.compile(r"lucy_[a-z0-9]+_routine\Z")
_FUNCTIONS = (
    "lucy.set_and_accept_scoped_capture_turn_v1(text,text,boolean,text)",
    "lucy.commit_capturable_scoped_turn_v1(uuid,uuid)",
)


class Stage2MigrationReceiptV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: str = "lucy.telegram.private.stage2.migration.v1"
    status: str
    source_revision: str
    target_revision: str
    admission_state: str
    capture_enabled: bool
    capture_boundary_safe: bool
    exact_routine_grants: bool
    public_execute_denied: bool
    application_execute_denied: bool
    residual_schema_create: bool


def configuration_from_environment(
    environment: Mapping[str, str] | None = None,
) -> tuple[URL, str]:
    values = os.environ if environment is None else environment
    if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
        raise BootstrapError("Stage 2 migration requires production Render")
    if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
        raise BootstrapError("capture must remain disabled during Stage 2 migration")
    if values.get("LUCY_STAGE2_MIGRATION_AUTHORIZATION") != AUTHORIZATION:
        raise BootstrapError("the exact Stage 2 migration authorization is required")
    raw_url = values.get("LUCY_MIGRATION_DATABASE_URL", "").strip()
    routine_login = values.get("LUCY_STAGE2_ROUTINE_LOGIN", "").strip()
    if not raw_url or _ROUTINE_LOGIN.fullmatch(routine_login) is None:
        raise BootstrapError("Stage 2 migration identity is incomplete")
    migration_url = _database_url(raw_url)
    if (
        migration_url.username != "lucy_migration"
        or migration_url.host is None
        or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
        or migration_url.database is None
        or _LUCY_DATABASE.fullmatch(migration_url.database) is None
        or migration_url.port not in (None, 5432)
    ):
        raise BootstrapError("Stage 2 migration database boundary differs")
    return migration_url, routine_login


def _preflight(migration_url: URL) -> str:
    with psycopg.connect(_conninfo(migration_url)) as connection:
        row = connection.execute(
            "SELECT current_user,(SELECT version_num FROM public.alembic_version),"
            "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1()"
        ).fetchone()
    if row is None or row[0] != "lucy_migration":
        raise BootstrapError("Stage 2 migration principal differs")
    if row[1] not in {SOURCE_REVISION, TARGET_REVISION}:
        raise BootstrapError("database is not at an approved Stage 2 source revision")
    if row[2:] != ("quarantined", True):
        raise BootstrapError("database is not safely quarantined")
    return str(row[1])


def _grant_exact_functions(migration_url: URL, routine_login: str) -> None:
    with psycopg.connect(_conninfo(migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout='10s'")
        connection.execute("SET LOCAL statement_timeout='60s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (0x4C5543594144,))
        connection.execute("SET LOCAL ROLE lucy_security_function_owner")
        for function in _FUNCTIONS:
            connection.execute(
                sql.SQL("GRANT EXECUTE ON FUNCTION {} TO {}").format(
                    sql.SQL(function), sql.Identifier(routine_login)
                )
            )


def _has_function_privilege(connection: Any, grantee: str, function: str) -> bool:
    row = connection.execute(
        "SELECT has_function_privilege(%s,%s,'EXECUTE')", (grantee, function)
    ).fetchone()
    if row is None:
        raise BootstrapError("Stage 2 function privilege result is unavailable")
    return bool(row[0])


def migrate(migration_url: URL, routine_login: str) -> Stage2MigrationReceiptV1:
    source_revision = _preflight(migration_url)
    migrate_realm_database(migration_url, target_revision=TARGET_REVISION)
    _grant_exact_functions(migration_url, routine_login)
    with psycopg.connect(_conninfo(migration_url)) as connection:
        row = connection.execute(
            "SELECT (SELECT version_num FROM public.alembic_version),"
            "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1(),"
            "has_schema_privilege('lucy_security_function_owner','lucy','CREATE')"
        ).fetchone()
        grants = tuple(
            _has_function_privilege(connection, routine_login, function)
            for function in _FUNCTIONS
        )
        public_denied = all(
            not _has_function_privilege(connection, "public", function)
            for function in _FUNCTIONS
        )
        application_denied = all(
            not _has_function_privilege(connection, "lucy_app", function)
            for function in _FUNCTIONS
        )
    if row != (TARGET_REVISION, "quarantined", True, False):
        raise BootstrapError("Stage 2 post-migration boundary verification failed")
    if not all(grants) or not public_denied or not application_denied:
        raise BootstrapError("Stage 2 function grants differ")
    return Stage2MigrationReceiptV1(
        status="passed",
        source_revision=source_revision,
        target_revision=TARGET_REVISION,
        admission_state="quarantined",
        capture_enabled=False,
        capture_boundary_safe=True,
        exact_routine_grants=True,
        public_execute_denied=True,
        application_execute_denied=True,
        residual_schema_create=False,
    )


def main() -> None:
    migration_url, routine_login = configuration_from_environment()
    print(migrate(migration_url, routine_login).model_dump_json())


if __name__ == "__main__":
    main()
