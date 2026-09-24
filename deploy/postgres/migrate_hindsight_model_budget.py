"""Apply and verify the additive Raymond Hindsight spending bridge."""

from __future__ import annotations

import json
import os

import psycopg

from deploy.postgres.bootstrap_realm_cloud_v1_3 import (
    EXPECTED_REVISION,
    _conninfo,
    migrate_realm_database,
)
from deploy.postgres.migrate_realm_cloud_v1_3 import configuration_from_environment

AUTHORIZATION = "raymond-hindsight-model-budget-0074-v1"


def main() -> None:
    if os.getenv("LUCY_HINDSIGHT_BUDGET_MIGRATION_AUTHORIZATION") != AUTHORIZATION:
        raise PermissionError("exact Hindsight budget migration authorization required")
    url = configuration_from_environment()
    if url.database != "lucy_raymond":
        raise RuntimeError("Raymond app database required")
    with psycopg.connect(_conninfo(url)) as connection:
        before = connection.execute(
            "SELECT version_num FROM public.alembic_version"
        ).fetchone()
        if before not in (("0073_memory_candidate_correction",),
                          (EXPECTED_REVISION,)):
            raise RuntimeError("unexpected source revision")
        binding = connection.execute(
            "SELECT count(*) FROM lucy.realm_service_bindings_v1 b "
            "JOIN lucy.realm_content_scopes_v1 s ON s.id=b.content_scope_id "
            "JOIN lucy.telegram_budget_accounts_v1 a "
            "ON a.security_realm_id=s.security_realm_id "
            "WHERE b.session_login='lucy_raymond_routine' AND b.active "
            "AND b.service_role='realm_evidence'"
        ).fetchone()
        if binding != (1,):
            raise RuntimeError("Raymond routine budget binding unavailable")
    if before != (EXPECTED_REVISION,):
        migrate_realm_database(url, target_revision=EXPECTED_REVISION)
    with psycopg.connect(_conninfo(url)) as connection:
        result = connection.execute(
            "SELECT (SELECT version_num FROM public.alembic_version),"
            "has_function_privilege('lucy_raymond_routine',"
            "'lucy.begin_hindsight_model_operation_v1(uuid)','EXECUTE'),"
            "has_function_privilege('lucy_raymond_routine',"
            "'lucy.settle_hindsight_model_operation_v1(uuid,bigint,boolean)','EXECUTE'),"
            "has_table_privilege('lucy_raymond_routine',"
            "'lucy.telegram_budget_accounts_v1','SELECT'),"
            "has_table_privilege('lucy_raymond_routine',"
            "'lucy.hindsight_model_operations_v1','SELECT'),"
            "has_schema_privilege('lucy_security_function_owner','lucy','CREATE')"
        ).fetchone()
    if result != (EXPECTED_REVISION, True, True, False, False, False):
        raise RuntimeError("Hindsight budget boundary verification failed")
    print("HINDSIGHT_BUDGET_MIGRATION:" + json.dumps({
        "revision": result[0], "exact_grants": True,
        "routine_direct_table_access": False, "residual_schema_create": False,
    }), flush=True)


if __name__ == "__main__":
    main()
