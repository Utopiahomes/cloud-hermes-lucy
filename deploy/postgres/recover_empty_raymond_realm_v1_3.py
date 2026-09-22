"""Recover an empty, quarantined Raymond realm through the audited startup gate.

This utility is for the bounded synthetic commissioning run. It never reads or
prints content, and refuses recovery if the realm has work or stored evidence.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import make_url

from lucy.db.session import create_session_factory
from lucy.rejoining.service import RejoiningService

AUTHORIZATION = "recover-empty-raymond-synthetic-v1.3"
HOST = "dpg-dak5bqad0e5s73b2e3d0-a"
TABLES = (
    "operations", "evidence", "evidence_payloads", "conversation_turns",
    "memory_claims", "scoped_evidence_records_v2", "scoped_evidence_payloads_v2",
    "scoped_memory_claims_v1", "scoped_memory_candidate_versions_v1",
    "memory_import_campaigns_v1", "sensitive_operations_v2",
    "deletion_journal_binding",
)


def main() -> int:
    if (
        os.getenv("RENDER") != "true"
        or os.getenv("LUCY_ENVIRONMENT") != "production"
        or os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false"
        or os.getenv("LUCY_PRODUCT_INGRESS_ENABLED") != "false"
        or os.getenv("LUCY_RAYMOND_RECOVERY_AUTHORIZATION") != AUTHORIZATION
    ):
        raise RuntimeError("Raymond recovery environment is not authorized")
    url = make_url(os.environ["LUCY_MIGRATION_DATABASE_URL"])
    if (
        url.host != HOST or url.database != "lucy_raymond"
        or url.username != "lucy_migration" or not url.password
        or url.query.get("sslmode") != "require"
    ):
        raise RuntimeError("Raymond recovery database boundary changed")
    lock = dict(
        line.split("=", 1) for line in Path("hermes.lock").read_text().splitlines()
        if line and not line.startswith("#") and "=" in line
    )["commit"]
    if os.getenv("LUCY_OBSERVED_HERMES_COMMIT") != lock:
        raise RuntimeError("Hermes commit pin changed")
    sessions = create_session_factory(url.render_as_string(hide_password=False))
    try:
        with sessions() as session:
            session.execute(text("SET TRANSACTION READ ONLY"))
            state = session.execute(text(
                "SELECT (SELECT state FROM lucy.runtime_admission WHERE singleton),"
                "(SELECT state FROM lucy.lifecycle WHERE singleton),"
                "(SELECT version_num FROM public.alembic_version)"
            )).one()
            if tuple(state) != ("quarantined", "offline", "0073_memory_candidate_correction"):
                raise RuntimeError("Raymond recovery state is not the reviewed empty head")
            for table in TABLES:
                count = session.execute(text(f"SELECT count(*) FROM lucy.{table}")).scalar_one()
                if count:
                    raise RuntimeError(f"Raymond recovery blocked by existing {table}")
            sessions_count = session.execute(text(
                "SELECT count(*) FROM pg_stat_activity WHERE pid<>pg_backend_pid() "
                "AND usename LIKE 'lucy_raymond_%'"
            )).scalar_one()
            if sessions_count:
                raise RuntimeError("Raymond runtime sessions are active")
        result = RejoiningService(sessions, expected_hermes_commit=lock).run(
            observed_hermes_commit=lock
        )
        if result.state.value != "ready" or any(v != "ok" for v in result.checks.values()):
            raise RuntimeError("Raymond audited startup did not reach ready")
        print(json.dumps({
            "contract": "lucy.empty-raymond-recovery.v1.3",
            "status": "passed", "lifecycle": "ready",
            "checks": sorted(result.checks),
        }, sort_keys=True))
        return 0
    finally:
        sessions.kw["bind"].dispose()


if __name__ == "__main__":
    raise SystemExit(main())
