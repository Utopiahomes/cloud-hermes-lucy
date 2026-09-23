"""Give a disposable ledger's release manager a login, for Control's one-off runner only.

Gate 2 Proof 2 decision D4: on a DISPOSABLE ledger, ``tiamat_release_manager`` becomes a login
with its existing narrow grants and nothing more. Run by the owner boundary with
``TIAMAT_MIGRATION_DATABASE_URL``; the password comes from ``TIAMAT_RELEASE_MANAGER_PASSWORD``
(24 characters or more), is never printed, and belongs only in the release runner's secret.
``--confirm-disposable-login`` must repeat ``release-manager-login:<database>:<ledger id>``.
The role's other attributes must stay least-privilege; the new login is verified over TLS.
"""

from __future__ import annotations

import argparse
import json
import os
from uuid import UUID

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url


def enable_release_manager_login(
    owner_url: str, *, ledger_id: UUID, password: str
) -> dict[str, object]:
    if len(password) < 24:
        raise ValueError("TIAMAT_RELEASE_MANAGER_PASSWORD must contain at least 24 characters")
    owner_url = (
        make_url(owner_url).set(drivername="postgresql").render_as_string(hide_password=False)
    )
    with psycopg.connect(owner_url, autocommit=True) as connection:
        row = connection.execute(
            "SELECT current_database(), "
            "(SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton)"
        ).fetchone()
        if row is None or row[1] is None or UUID(str(row[1])) != ledger_id:
            raise ValueError("the owner URL does not name the expected disposable ledger")
        database = str(row[0])
        connection.execute(
            sql.SQL("ALTER ROLE tiamat_release_manager LOGIN PASSWORD {}").format(
                sql.Literal(password)
            )
        )
        flags = connection.execute(
            """
            SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls,
                   rolinherit, rolcanlogin
            FROM pg_catalog.pg_roles WHERE rolname = 'tiamat_release_manager'
            """
        ).fetchone()
    if flags is None or tuple(flags) != (False, False, False, False, False, False, True):
        raise RuntimeError("release manager attributes are not least-privilege")
    manager_url = (
        make_url(owner_url)
        .set(drivername="postgresql", username="tiamat_release_manager", password=password)
        .update_query_dict({"sslmode": "require"})
        .render_as_string(hide_password=False)
    )
    with psycopg.connect(manager_url) as manager:
        check = manager.execute(
            """
            SELECT current_user::text,
                   (SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid())
            """
        ).fetchone()
    if check is None or tuple(check) != ("tiamat_release_manager", True):
        raise RuntimeError("release manager login did not verify over TLS")
    return {
        "database": database,
        "ledger_id": str(ledger_id),
        "login": "tiamat_release_manager",
        "tls": True,
        "password_recorded": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-ledger-id", type=UUID, required=True)
    parser.add_argument("--confirm-disposable-login", required=True)
    args = parser.parse_args()
    owner_url = os.environ.get("TIAMAT_MIGRATION_DATABASE_URL", "")
    password = os.environ.get("TIAMAT_RELEASE_MANAGER_PASSWORD", "")
    if not owner_url:
        raise ValueError("TIAMAT_MIGRATION_DATABASE_URL is required")
    database = make_url(owner_url).database
    expected = f"release-manager-login:{database}:{args.expected_ledger_id}"
    if args.confirm_disposable_login != expected:
        raise ValueError("exact disposable-ledger confirmation is required")
    report = enable_release_manager_login(
        owner_url, ledger_id=args.expected_ledger_id, password=password
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
