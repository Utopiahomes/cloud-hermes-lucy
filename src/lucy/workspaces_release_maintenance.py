"""Quarantine-first Workspaces release maintenance for the temporary Render service."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys

import psycopg

from deploy.postgres.migrate_workspaces_v1 import configuration_from_environment, migrate


MAINTENANCE_LOCK = 0x4C5543594D53
ADMISSION_LOCK = 0x4C5543594144
SOURCE_REVISION = "0057_public_conversation"
TARGET_REVISION = "0068_workspaces_service_auth"


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path not in {"/", "/health"}:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"maintenance receipt retained\n")

    def log_message(self, format: str, *args: object) -> None:
        return


def _locked_connection() -> psycopg.Connection[object]:
    connection = psycopg.connect(os.environ["LUCY_MIGRATION_DATABASE_URL"])
    connection.execute("SET LOCAL lock_timeout='15s'")
    connection.execute("SET LOCAL statement_timeout='120s'")
    connection.execute("SELECT pg_advisory_xact_lock(%s)", (MAINTENANCE_LOCK,))
    connection.execute("SELECT pg_advisory_xact_lock(%s)", (ADMISSION_LOCK,))
    return connection


def _contain() -> dict[str, object]:
    with _locked_connection() as connection:
        boundary = connection.execute(
            "SELECT (SELECT version_num FROM public.alembic_version),"
            "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1()"
        ).fetchone()
        if (
            boundary[0] != SOURCE_REVISION
            or boundary[1] not in {"ready", "quarantined"}
            or boundary[2] is not True
        ):
            raise RuntimeError(f"containment boundary differs: {boundary!r}")
        if boundary[1] == "ready":
            connection.execute(
                "UPDATE lucy.runtime_admission SET state='quarantined',updated_at=now() "
                "WHERE singleton"
            )
    with psycopg.connect(
        os.environ["LUCY_MIGRATION_DATABASE_URL"], autocommit=True
    ) as connection:
        session_rows = connection.execute(
            "SELECT usename,state,count(*) FROM pg_stat_activity "
            "WHERE datname=current_database() "
            "AND usename IN ('lucy_utopia_routine','lucy_utopia_public') "
            "AND pid<>pg_backend_pid() GROUP BY usename,state ORDER BY usename,state"
        ).fetchall()
        role_boundary = connection.execute(
            "SELECT current_user,"
            "(SELECT rolcreaterole FROM pg_roles WHERE rolname=current_user),"
            "pg_has_role(current_user,'lucy_utopia_routine','MEMBER'),"
            "pg_has_role(current_user,'lucy_utopia_public','MEMBER')"
        ).fetchone()
        print(
            json.dumps(
                {
                    "phase": "contain-pre-termination",
                    "sessions": session_rows,
                    "role_boundary": role_boundary,
                },
                separators=(",", ":"),
            ),
            flush=True,
        )
        target_pids = [
            row[0]
            for row in connection.execute(
                "SELECT pid FROM pg_stat_activity WHERE datname=current_database() "
                "AND usename IN ('lucy_utopia_routine','lucy_utopia_public') "
                "AND pid<>pg_backend_pid()"
            ).fetchall()
        ]
        terminated = sum(
            bool(connection.execute("SELECT pg_terminate_backend(%s)", (pid,)).fetchone()[0])
            for pid in target_pids
        )
        remaining = connection.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
            "AND usename IN ('lucy_utopia_routine','lucy_utopia_public') "
            "AND pid<>pg_backend_pid()"
        ).fetchone()[0]
        state, safe = connection.execute(
            "SELECT (SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1()"
        ).fetchone()
    if remaining != 0 or state != "quarantined" or safe is not True:
        raise RuntimeError("containment verification failed")
    return {
        "status": "passed",
        "phase": "contain",
        "schema_revision": SOURCE_REVISION,
        "admission_state": state,
        "capture_boundary_safe": safe,
        "affected_sessions_terminated": terminated,
        "affected_sessions_remaining": remaining,
    }


def _migrate() -> dict[str, object]:
    receipt = migrate(configuration_from_environment())
    return {"phase": "migrate", **json.loads(receipt.model_dump_json())}


def _restore() -> dict[str, object]:
    with _locked_connection() as connection:
        boundary = connection.execute(
            "SELECT (SELECT version_num FROM public.alembic_version),"
            "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1(),"
            "EXISTS(SELECT 1 FROM lucy.node_memberships "
            "WHERE id='f506166d-3c88-40e7-b0cc-ccd1949b8ae4' "
            "AND principal_id='2af90726-9e4b-4b65-98d1-3c7181217f0d' "
            "AND workspace_id='e57e7270-77d7-4734-b5d2-e6ecfb6509d5' "
            "AND status='active'),"
            "EXISTS(SELECT 1 FROM lucy.public_projection_versions WHERE snapshot_digest="
            "'95e2e20a9e4a3786e3daa63a73bb5ff2866b5bae295e6dc138bf432e4361c422'),"
            "(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
            "AND usename IN ('lucy_utopia_routine','lucy_utopia_public') "
            "AND pid<>pg_backend_pid())"
        ).fetchone()
        if boundary[0] != TARGET_REVISION or boundary[1] not in (
            "quarantined",
            "ready",
        ) or boundary[2:] != (True, True, True, 0):
            raise RuntimeError(f"restore boundary differs: {boundary!r}")
        connection.execute(
            "UPDATE lucy.runtime_admission SET state='ready',updated_at=now() "
            "WHERE singleton"
        )
    return {
        "status": "passed",
        "phase": "restore",
        "schema_revision": TARGET_REVISION,
        "admission_state": "ready",
        "capture_boundary_safe": True,
        "membership_active": True,
        "public_projection_preserved": True,
    }


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"contain", "migrate", "restore"}:
        raise SystemExit("expected exactly one phase: contain, migrate, or restore")
    phase = sys.argv[1]
    receipt = {"contain": _contain, "migrate": _migrate, "restore": _restore}[phase]()
    print(json.dumps(receipt, separators=(",", ":")), flush=True)
    port = int(os.environ.get("PORT", "10000"))
    ThreadingHTTPServer(("0.0.0.0", port), _HealthHandler).serve_forever()


if __name__ == "__main__":
    main()
