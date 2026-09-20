"""Finalize D1 function ownership after Tiamat service roles have been created.

This is a separate, explicit step because migration 0007 also runs on fresh
databases before ``tiamat_recovery`` exists. It never prints credentials.
"""

from __future__ import annotations

import argparse
import os
from uuid import UUID

import psycopg
from psycopg import sql


class D1FinalizationRejected(RuntimeError):
    """The database is not the expected blocked ledger or role topology."""


_FUNCTIONS = (
    ("consume_startup_attestation", "text"),
    ("verify_attestation_current", "bigint"),
    ("block_dispatch", "text"),
)


def finalize_d1(database_url: str, *, environment: str, expected_ledger_id: UUID) -> None:
    """Transfer locked functions to recovery, then expose only their runtime calls.

    Every role grant and ownership change is one PostgreSQL transaction. A failed
    step rolls the entire finalization back; it never leaves an owner-privileged
    function executable by the serving role.
    """

    if not environment or not isinstance(expected_ledger_id, UUID):
        raise ValueError("exact environment and ledger UUID are required")
    with psycopg.connect(database_url) as connection, connection.transaction():
        connection.execute("SELECT set_config('tiamat.environment', %s, true)", (environment,))
        row = connection.execute(
            """
            SELECT current_user, current_database(), i.ledger_id, g.dispatch_blocked
            FROM tiamat.ledger_identity AS i
            JOIN tiamat.restore_gate AS g ON i.singleton AND g.environment = %s
            """,
            (environment,),
        ).fetchone()
        if row is None or row[2] != expected_ledger_id or not row[3]:
            raise D1FinalizationRejected("expected blocked ledger was not found")
        owner = str(row[0])
        roles = connection.execute(
            """
            SELECT rolname, rolcanlogin FROM pg_catalog.pg_roles
            WHERE rolname IN ('tiamat_recovery', 'tiamat_runtime')
            """
        ).fetchall()
        if {str(role[0]) for role in roles} != {"tiamat_recovery", "tiamat_runtime"}:
            raise D1FinalizationRejected("required service roles are missing")
        if not all(bool(role[1]) for role in roles):
            raise D1FinalizationRejected("required service roles are not logins")
        topology = connection.execute(
            """
            SELECT pg_catalog.pg_has_role(current_user, 'tiamat_recovery', 'MEMBER'),
                   pg_catalog.has_schema_privilege('tiamat_recovery', 'tiamat', 'CREATE')
            """
        ).fetchone()
        if topology is None or bool(topology[0]) or bool(topology[1]):
            raise D1FinalizationRejected("recovery role topology is not the expected baseline")
        for name, argument in _FUNCTIONS:
            function_owner = connection.execute(
                """
                SELECT pg_catalog.pg_get_userbyid(p.proowner)
                FROM pg_catalog.pg_proc AS p
                WHERE p.oid = pg_catalog.to_regprocedure(%s)
                """,
                (f"tiamat.{name}({argument})",),
            ).fetchone()
            if function_owner is None or str(function_owner[0]) != owner:
                raise D1FinalizationRejected("D1 function owner is not the migration owner")
        connection.execute(
            sql.SQL("GRANT tiamat_recovery TO {} WITH SET TRUE").format(sql.Identifier(owner))
        )
        connection.execute("GRANT CREATE ON SCHEMA tiamat TO tiamat_recovery")
        for name, argument in _FUNCTIONS:
            signature = sql.SQL("tiamat.{}({})").format(sql.Identifier(name), sql.SQL(argument))
            connection.execute(sql.SQL("REVOKE ALL ON FUNCTION {} FROM PUBLIC").format(signature))
            connection.execute(
                sql.SQL("GRANT EXECUTE ON FUNCTION {} TO tiamat_runtime").format(signature)
            )
            connection.execute(
                sql.SQL("ALTER FUNCTION {} OWNER TO tiamat_recovery").format(signature)
            )
        connection.execute("REVOKE CREATE ON SCHEMA tiamat FROM tiamat_recovery")
        connection.execute(sql.SQL("REVOKE tiamat_recovery FROM {}").format(sql.Identifier(owner)))
        connection.execute(
            "GRANT SELECT, INSERT, UPDATE ON tiamat.startup_attestations TO tiamat_recovery"
        )
        connection.execute("REVOKE UPDATE ON tiamat.restore_gate FROM tiamat_runtime")
        remaining_update = connection.execute(
            """
            SELECT pg_catalog.has_table_privilege(
              'tiamat_runtime', 'tiamat.restore_gate', 'UPDATE'
            )
            """
        ).fetchone()
        if remaining_update is None or bool(remaining_update[0]):
            raise D1FinalizationRejected("runtime retains direct restore-gate UPDATE")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--expected-ledger-id", required=True, type=UUID)
    parser.add_argument("--confirm-blocked-ledger", required=True)
    args = parser.parse_args()
    confirmation = f"finalize-d1:{args.environment}:{args.expected_ledger_id}"
    if args.confirm_blocked_ledger != confirmation:
        raise ValueError("exact blocked-ledger confirmation is required")
    database_url = os.environ.get("TIAMAT_MIGRATION_DATABASE_URL")
    if not database_url:
        raise ValueError("TIAMAT_MIGRATION_DATABASE_URL is required")
    finalize_d1(
        database_url,
        environment=args.environment,
        expected_ledger_id=args.expected_ledger_id,
    )
    print("D1 role finalization completed on the blocked ledger")


if __name__ == "__main__":
    main()
