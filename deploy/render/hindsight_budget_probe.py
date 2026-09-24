"""Content-free check of the routine model reservation path for Hindsight."""

from __future__ import annotations

import json
import os
import sys
from uuid import uuid4

from sqlalchemy import text

from lucy.db import create_session_factory
from lucy.model_execution import (
    ModelExecutionBegin,
    ModelExecutionService,
    ModelExecutionSettlement,
    ModelUsage,
)


def main() -> None:
    sessions = create_session_factory(os.environ["LUCY_DATABASE_URL"])
    if len(sys.argv) == 2 and sys.argv[1] == "status":
        with sessions() as session:
            row = session.execute(text(
                "SELECT (SELECT version_num FROM public.alembic_version),"
                "to_regprocedure('lucy.begin_hindsight_model_operation_v1(uuid)') "
                "IS NOT NULL,"
                "CASE WHEN to_regprocedure('lucy.begin_hindsight_model_operation_v1(uuid)') "
                "IS NULL THEN false ELSE has_function_privilege(session_user,"
                "'lucy.begin_hindsight_model_operation_v1(uuid)','EXECUTE') END,"
                "has_table_privilege(session_user,"
                "'lucy.telegram_budget_accounts_v1','SELECT')"
            )).one()
        print("HINDSIGHT_BUDGET_STATUS:" + json.dumps({
            "revision": row[0], "function_exists": row[1],
            "routine_can_execute": row[2], "direct_budget_access": row[3],
        }), flush=True)
        return
    with sessions() as session:
        row = session.execute(text(
            "SELECT current_user, "
            "has_table_privilege(current_user,'lucy.budget_accounts','SELECT,INSERT,UPDATE'),"
            "(SELECT limit_microusd FROM lucy.budget_accounts WHERE name='model.daily'),"
            "(SELECT spent_microusd FROM lucy.budget_accounts WHERE name='model.daily'),"
            "(SELECT reserved_microusd FROM lucy.budget_accounts WHERE name='model.daily')"
        )).one()
    print("HINDSIGHT_BUDGET:" + json.dumps({
        "role": row[0], "table_access": row[1],
        "limit": row[2], "spent": row[3], "reserved": row[4],
    }), flush=True)
    request_id = uuid4().hex
    service = ModelExecutionService(sessions)
    try:
        begun = service.begin(ModelExecutionBegin(
            idempotency_key=f"hermes-model:hindsight-budget-probe:{request_id}",
            model="openai/gpt-oss-20b", reservation_microusd=5000,
            session_id="hindsight-budget-probe", api_request_id=request_id,
        ))
    except Exception as exc:
        root = getattr(exc, "orig", None)
        print("HINDSIGHT_BUDGET:" + json.dumps({
            "begin_error": type(exc).__name__,
            "database_error": type(root).__name__ if root is not None else None,
            "sqlstate": getattr(root, "sqlstate", None),
        }), flush=True)
        raise
    if not begun.execute:
        raise RuntimeError("synthetic budget reservation did not execute")
    service.settle(ModelExecutionSettlement(
        action_id=begun.action_id, actual_microusd=0, succeeded=False,
        usage=ModelUsage(),
    ))
    print("HINDSIGHT_BUDGET:" + json.dumps({"reservation_released": True}), flush=True)


if __name__ == "__main__":
    main()
