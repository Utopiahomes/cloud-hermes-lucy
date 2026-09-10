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

ROOT = Path(__file__).parents[2]
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
pytestmark = pytest.mark.skipif(not OWNER_URL, reason="requires PostgreSQL integration database")


def _renderer() -> ModuleType:
    path = ROOT / "deploy" / "postgres" / "render_recovery_roles_v1_3.py"
    spec = importlib.util.spec_from_file_location("render_recovery_roles_v1_3", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_recovery_logins_have_only_their_exact_function_surface() -> None:
    assert OWNER_URL
    parsed = make_url(OWNER_URL)
    if (parsed.database, parsed.host, parsed.port) != ("lucy_test", "127.0.0.1", 54329):
        raise RuntimeError("refusing to alter grants outside the disposable test database")
    logins = {
        "lucy_utopia_authority_writer": "synthetic-utopia-authority-writer-only",
        "lucy_utopia_cost_writer": "synthetic-utopia-cost-writer-only",
        "lucy_utopia_authority_recovery": "synthetic-utopia-authority-recovery-only",
        "lucy_utopia_cost_recovery": "synthetic-utopia-cost-recovery-only",
    }
    sql = _renderer().render_recovery_roles(
        realm_slug="utopia",
        authority_writer_login="lucy_utopia_authority_writer",
        cost_writer_login="lucy_utopia_cost_writer",
        authority_recovery_login="lucy_utopia_authority_recovery",
        cost_recovery_login="lucy_utopia_cost_recovery",
    )
    expected = {
        "lucy_utopia_authority_writer": {
            "lucy.get_pending_authority_event_v1(uuid)",
            "lucy.prepare_authority_event_v1(uuid,bigint,text,text)",
        },
        "lucy_utopia_cost_writer": {
            "lucy.get_pending_cost_event_v1(uuid)",
            "lucy.prepare_cost_journal_event_v1(uuid,bigint,text,text)",
        },
        "lucy_utopia_authority_recovery": {
            "lucy.get_pending_authority_event_v1(uuid)",
            "lucy.acknowledge_authority_event_v1(uuid,bigint,text,text)",
            "lucy.restored_recovery_head_v1(text)",
            "lucy.apply_authority_recovery_event_v1(jsonb,jsonb)",
        },
        "lucy_utopia_cost_recovery": {
            "lucy.get_pending_cost_event_v1(uuid)",
            "lucy.acknowledge_provider_reservation_v1(uuid,uuid,text)",
            "lucy.acknowledge_provider_outcome_v1(uuid,uuid,text)",
            "lucy.restored_cost_recovery_head_v1()",
            "lucy.apply_cost_recovery_event_v1(jsonb,jsonb)",
            "lucy.finalize_cost_recovery_v1(jsonb)",
        },
    }
    all_signatures = set().union(*expected.values())
    owner = create_engine(OWNER_URL)
    with owner.begin() as connection:
        connection.execute(text(sql))
        for login, allowed in expected.items():
            for signature in all_signatures:
                actual = connection.scalar(
                    text("SELECT has_function_privilege(:login,:signature,'EXECUTE')"),
                    {"login": login, "signature": signature},
                )
                assert actual is (signature in allowed)
            assert not connection.scalar(
                text(
                    "SELECT EXISTS(SELECT 1 FROM pg_auth_members m "
                    "JOIN pg_roles r ON r.oid=m.member WHERE r.rolname=:login)"
                ),
                {"login": login},
            )

    for login, password in logins.items():
        engine = create_engine(parsed.set(username=login, password=password))
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT current_user")) == login
            assert connection.scalar(text("SELECT version_num FROM public.alembic_version"))
            with pytest.raises(DBAPIError, match="permission denied"):
                connection.execute(text("SELECT * FROM lucy.cost_recovery_outbox_v1"))
            connection.rollback()
            pending_function = (
                "lucy.get_pending_authority_event_v1"
                if "authority" in login
                else "lucy.get_pending_cost_event_v1"
            )
            assert connection.scalar(
                text(f"SELECT {pending_function}(:event_id)"),
                {"event_id": uuid4()},
            ) is None
        engine.dispose()
    owner.dispose()
