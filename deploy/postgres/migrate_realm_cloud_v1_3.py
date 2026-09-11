"""Advance an existing quarantined V1.3 realm to the reviewed migration head.

This entry point deliberately performs no credential rotation or realm
provisioning. Temporary schema CREATE authority is transaction-scoped by the
shared V1.3 migration implementation and is verified absent before commit.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

import psycopg
from pydantic import BaseModel, ConfigDict
from sqlalchemy.engine import URL

from deploy.postgres.bootstrap_realm_cloud_v1_3 import (
    _LUCY_DATABASE,
    _PRIVATE_RENDER_HOST,
    AUTHORIZATION,
    EXPECTED_REVISION,
    BootstrapError,
    _conninfo,
    _database_url,
    migrate_realm_database,
)


class MigrationReceiptV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: str = "lucy.realm-cloud-migration.v1.3"
    status: str
    revision: str
    admission_state: str
    capture_boundary_safe: bool
    residual_schema_create: bool


def configuration_from_environment(
    environment: Mapping[str, str] | None = None,
) -> URL:
    values = os.environ if environment is None else environment
    if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
        raise BootstrapError("migration requires the production Render runtime")
    if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
        raise BootstrapError("transcript capture must remain disabled")
    if values.get("LUCY_REALM_BOOTSTRAP_AUTHORIZATION") != AUTHORIZATION:
        raise BootstrapError("the exact reviewed V1.3 migration authorization is required")
    raw = values.get("LUCY_MIGRATION_DATABASE_URL")
    if not raw:
        raise BootstrapError("LUCY_MIGRATION_DATABASE_URL is required")
    migration_url = _database_url(raw)
    if migration_url.username != "lucy_migration":
        raise BootstrapError("the migration URL must use lucy_migration")
    if migration_url.host is None or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None:
        raise BootstrapError("the migration URL must use the private Render database host")
    if (
        migration_url.database is None
        or _LUCY_DATABASE.fullmatch(migration_url.database) is None
        or migration_url.port not in (None, 5432)
    ):
        raise BootstrapError("the migration URL must target the reviewed Lucy database")
    return migration_url


def verify(migration_url: URL) -> MigrationReceiptV1:
    with psycopg.connect(_conninfo(migration_url)) as connection:
        row = connection.execute(
            "SELECT (SELECT version_num FROM public.alembic_version),"
            "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1(),"
            "has_schema_privilege('lucy_security_function_owner','lucy','CREATE') OR "
            "has_schema_privilege('lucy_directory_function_owner','lucy','CREATE') OR "
            "has_schema_privilege('lucy_cost_function_owner','lucy','CREATE') OR "
            "has_schema_privilege('lucy_authority_function_owner','lucy','CREATE')"
        ).fetchone()
    if row != (EXPECTED_REVISION, "quarantined", True, False):
        raise BootstrapError("post-migration security boundary verification failed")
    return MigrationReceiptV1(
        status="passed",
        revision=str(row[0]),
        admission_state=str(row[1]),
        capture_boundary_safe=bool(row[2]),
        residual_schema_create=bool(row[3]),
    )


def main() -> None:
    migration_url = configuration_from_environment()
    migrate_realm_database(migration_url)
    print(verify(migration_url).model_dump_json())


if __name__ == "__main__":
    main()
