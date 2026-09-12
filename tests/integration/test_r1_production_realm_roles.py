from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import ModuleType
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from lucy.readiness import ServiceReadiness

ROOT = Path(__file__).parents[2]
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
ROUTINE_URL = os.getenv("LUCY_TEST_UTOPIA_DATABASE_URL")
pytestmark = pytest.mark.skipif(not OWNER_URL, reason="requires PostgreSQL integration database")
SYNTHETIC_PORTS = {54329, 54339}


def _require_synthetic_database(url: str) -> None:
    parsed = make_url(url)
    if (parsed.database, parsed.host) != ("lucy_test", "127.0.0.1") or (
        parsed.port not in SYNTHETIC_PORTS
    ):
        raise RuntimeError("refusing to alter a non-synthetic database")


def _renderer() -> ModuleType:
    path = ROOT / "deploy" / "postgres" / "render_security_v1_3_sql.py"
    spec = importlib.util.spec_from_file_location("render_security_v1_3_sql", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rendered_realm_stamp_applies_execute_only_permissions() -> None:
    assert OWNER_URL and ROUTINE_URL
    _require_synthetic_database(OWNER_URL)
    sql = _renderer().render_realm_roles(
        realm_slug="utopia",
        routine_login="lucy_utopia_routine",
        policy_login="lucy_utopia_policy",
        workflow_login="lucy_utopia_sensitive_workflow",
        finality_login="lucy_utopia_finality",
        public_login="lucy_utopia_public",
    )
    owner = create_engine(OWNER_URL)
    with owner.begin() as connection:
        connection.execute(text(sql))
        assert not connection.scalar(
            text(
                "SELECT has_function_privilege('lucy_utopia_routine',"
                "'lucy.register_capturable_scoped_evidence_v2("
                "text,text,jsonb,jsonb,text,jsonb,text)','EXECUTE')"
            )
        )
        for signature in (
            "lucy.get_scoped_capture_mode_v1(text)",
            "lucy.claim_capturable_scoped_archive_v1(text,text,text,text,text,jsonb)",
            "lucy.record_scoped_archive_aws_outcome_v1(uuid,jsonb,text)",
            "lucy.reconcile_capturable_scoped_archive_v1(uuid)",
            "lucy.commit_capturable_scoped_turn_v1(uuid,uuid)",
        ):
            assert connection.scalar(
                text(
                    "SELECT has_function_privilege('lucy_utopia_routine',"
                    ":signature,'EXECUTE')"
                ),
                {"signature": signature},
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


def test_each_v13_http_boundary_passes_read_only_startup_with_its_exact_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert OWNER_URL
    _require_synthetic_database(OWNER_URL)
    parsed = make_url(OWNER_URL)
    sql = _renderer().render_realm_roles(
        realm_slug="utopia",
        routine_login="lucy_utopia_routine",
        policy_login="lucy_utopia_policy",
        workflow_login="lucy_utopia_sensitive_workflow",
        finality_login="lucy_utopia_finality",
        public_login="lucy_utopia_public",
    )
    owner = create_engine(OWNER_URL)
    epoch = uuid4()
    with owner.begin() as connection:
        connection.execute(text(sql))
        connection.execute(
            text("UPDATE lucy.runtime_admission SET state='ready',storage_epoch=:epoch"),
            {"epoch": epoch},
        )
        connection.execute(text("UPDATE lucy.lifecycle SET state='ready'"))
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", "2")
    monkeypatch.setenv("LUCY_PUBLIC_CONVERSATION_ENABLED", "true")
    boundaries = (
        ("public", "lucy_utopia_public", "synthetic-utopia-public-only"),
        ("routine", "lucy_utopia_routine", "synthetic-utopia-only"),
        ("policy", "lucy_utopia_policy", "synthetic-utopia-policy-only"),
        (
            "evidence",
            "lucy_utopia_sensitive_workflow",
            "synthetic-utopia-workflow-only",
        ),
        (
            "deletion",
            "lucy_utopia_sensitive_workflow",
            "synthetic-utopia-workflow-only",
        ),
    )
    for mode, login, password in boundaries:
        url = parsed.set(username=login, password=password)
        engine = create_engine(url)
        sessions = sessionmaker(engine, class_=Session)
        ServiceReadiness(
            sessions,
            mode=mode,
            storage_epoch=epoch,
            baseline="v1.3",
            expected_database_login=login,
        ).check()
        engine.dispose()
    owner.dispose()
