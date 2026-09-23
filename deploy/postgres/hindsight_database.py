"""Provision Hindsight's independent logical database from Raymond's private network.

This is an operator command, not a Lucy application migration. Never log URLs,
passwords, or SQL parameters. Usage: python deploy/postgres/hindsight_database.py
inspect|provision
"""

from __future__ import annotations

import json
import os
import sys

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

DATABASE = "lucy_hindsight"
ROLE = "lucy_hindsight"


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is unavailable")
    return value


def _one(cursor: psycopg.Cursor[tuple[object, ...]]) -> tuple[object, ...]:
    row = cursor.fetchone()
    if row is None:
        raise RuntimeError("PostgreSQL prerequisite query returned no row")
    return row


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"inspect", "provision"}:
        raise SystemExit("usage: hindsight_database.py inspect|provision")
    admin_url = _required("HINDSIGHT_ADMIN_DATABASE_URL")
    with psycopg.connect(admin_url, autocommit=True, connect_timeout=10) as conn:
        version = int(str(_one(conn.execute("SHOW server_version_num"))[0]))
        privileges = _one(conn.execute(
            "SELECT rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname=current_user"
        ))
        vector = _one(conn.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name='vector')"
        ))[0]
        existing = conn.execute(
            "SELECT d.datname, r.rolname FROM pg_database d JOIN pg_roles r "
            "ON r.oid=d.datdba WHERE d.datname=%s", (DATABASE,)
        ).fetchone()
        inspection = {
            "postgres_major": version // 10000,
            "can_create_database": bool(privileges[0]),
            "can_create_role": bool(privileges[1]),
            "pgvector_available": bool(vector),
            "hindsight_database_exists": existing is not None,
            "hindsight_database_owned_by_expected_role":
                existing is not None and existing[1] == ROLE,
        }
        if sys.argv[1] == "inspect":
            print(json.dumps(inspection, sort_keys=True))
            return
        if version < 140000 or not all((privileges[0], privileges[1], vector)):
            raise RuntimeError("PostgreSQL prerequisites unavailable")
        if existing is not None and existing[1] != ROLE:
            raise RuntimeError("Hindsight database has unexpected owner")
        password = _required("HINDSIGHT_DATABASE_PASSWORD")
        role_exists = _one(conn.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=%s)", (ROLE,)
        ))[0]
        if role_exists:
            conn.execute(
                sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {}").format(
                    sql.Identifier(ROLE), sql.Literal(password)
                ),
            )
        else:
            conn.execute(
                sql.SQL("CREATE ROLE {} WITH LOGIN PASSWORD {}").format(
                    sql.Identifier(ROLE), sql.Literal(password)
                ),
            )
        if existing is None:
            conn.execute(
                sql.SQL("CREATE DATABASE {} OWNER {}").format(
                    sql.Identifier(DATABASE), sql.Identifier(ROLE)
                )
            )
        conn.execute(sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(
            sql.Identifier(DATABASE)
        ))
        conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
            sql.Identifier(DATABASE), sql.Identifier(ROLE)
        ))
    # The database owner can install pgvector on supported Render Postgres plans.
    owner_info = make_conninfo(admin_url, dbname=DATABASE, user=ROLE, password=password)
    with psycopg.connect(owner_info, autocommit=True,
                         connect_timeout=10) as owner:
        owner.execute("CREATE EXTENSION IF NOT EXISTS vector")
        installed = _one(owner.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='vector')"
        ))[0]
        if not installed:
            raise RuntimeError("pgvector installation unavailable")
    print(json.dumps({"database": DATABASE, "role": ROLE,
                      "pgvector_installed": True}, sort_keys=True))


if __name__ == "__main__":
    main()
