from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

ROOT = Path(__file__).parents[2]
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
ROUTINE_URL = os.getenv("LUCY_TEST_UTOPIA_DATABASE_URL")
pytestmark = pytest.mark.skipif(not OWNER_URL, reason="requires PostgreSQL integration database")


def _renderer() -> ModuleType:
    path = ROOT / "deploy" / "postgres" / "render_security_v1_3_sql.py"
    spec = importlib.util.spec_from_file_location("render_security_v1_3_sql", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rendered_realm_stamp_applies_execute_only_permissions() -> None:
    assert OWNER_URL and ROUTINE_URL
    parsed = make_url(OWNER_URL)
    if (parsed.database, parsed.host, parsed.port) != ("lucy_test", "127.0.0.1", 54329):
        raise RuntimeError("refusing to alter grants outside the disposable test database")
    sql = _renderer().render_realm_roles(
        realm_slug="utopia",
        routine_login="lucy_utopia_routine",
        policy_login="lucy_utopia_policy",
        workflow_login="lucy_utopia_sensitive_workflow",
        finality_login="lucy_utopia_finality",
    )
    owner = create_engine(OWNER_URL)
    with owner.begin() as connection:
        connection.execute(text(sql))
        assert connection.scalar(
            text(
                "SELECT has_function_privilege('lucy_utopia_routine',"
                "'lucy.register_capturable_scoped_evidence_v2("
                "text,text,jsonb,jsonb,text,jsonb,text)','EXECUTE')"
            )
        )
        assert not connection.scalar(
            text(
                "SELECT has_function_privilege('lucy_utopia_routine',"
                "'lucy.register_scoped_evidence_v2(jsonb,jsonb,text,jsonb,text)','EXECUTE')"
            )
        )
        assert connection.scalar(
            text(
                "SELECT has_function_privilege('lucy_utopia_policy',"
                "'lucy.issue_sensitive_action_permit_v3(jsonb,text)','EXECUTE')"
            )
        )
        assert not connection.scalar(
            text(
                "SELECT has_function_privilege('lucy_utopia_routine',"
                "'lucy.issue_sensitive_action_permit_v3(jsonb,text)','EXECUTE')"
            )
        )
    routine = create_engine(ROUTINE_URL)
    with pytest.raises(DBAPIError, match="permission denied"), routine.connect() as connection:
        connection.execute(text("SELECT * FROM lucy.scoped_capture_receipts_v1"))
    routine.dispose()
    owner.dispose()
