"""Apply a migration that replaces an already-finalized definer function.

After finalization the definer functions belong to ``tiamat_recovery``, so the migration owner
can no longer replace them, while Alembic needs that same owner for its version table. A revision
which corrects one of those functions therefore cannot be applied by Alembic alone on a finalized
ledger.

This runner closes that gap in one transaction: it takes a temporary ownership handoff, replaces
the function as its owner, advances the Alembic version, restores the intended ownership and
grants, and verifies them before committing. Any failure rolls the whole thing back, so the
ledger is never left with a half-applied function or an Alembic version that does not describe it.

It prints no credentials and writes nothing else.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg
from psycopg import sql


class DefinerMigrationRejected(RuntimeError):
    """The ledger is not in the state this revision may be applied to."""


@dataclass(frozen=True)
class DefinerMigration:
    """One revision that replaces a definer function the recovery role may already own."""

    revision: str
    previous_revision: str
    function: str
    signature: str
    statement: str
    runtime_executes: bool = True


def load_migration(path: Path, *, function: str, signature: str) -> DefinerMigration:
    """Read the revision's own exported statement rather than a copy of it."""

    specification = importlib.util.spec_from_file_location("tiamat_definer_migration", path)
    if specification is None or specification.loader is None:
        raise DefinerMigrationRejected("migration module could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    statement = getattr(module, "DEFINER_STATEMENT", None)
    revision = getattr(module, "revision", None)
    previous = getattr(module, "down_revision", None)
    if not isinstance(statement, str) or not isinstance(revision, str) or not isinstance(
        previous, str
    ):
        raise DefinerMigrationRejected("migration does not export a definer statement")
    return DefinerMigration(
        revision=revision,
        previous_revision=previous,
        function=function,
        signature=signature,
        statement=statement,
    )


def apply_definer_migration(database_url: str, migration: DefinerMigration) -> str:
    """Replace the function and advance Alembic atomically, then verify the restored topology."""

    qualified = f"tiamat.{migration.function}({migration.signature})"
    with psycopg.connect(database_url) as connection, connection.transaction():
        owner_row = connection.execute("SELECT current_user").fetchone()
        version_row = connection.execute(
            "SELECT version_num FROM tiamat.alembic_version FOR UPDATE"
        ).fetchone()
        if owner_row is None or version_row is None:
            raise DefinerMigrationRejected("ledger version could not be read")
        owner = str(owner_row[0])
        version = str(version_row[0])
        if version == migration.revision:
            raise DefinerMigrationRejected("revision is already applied")
        if version != migration.previous_revision:
            raise DefinerMigrationRejected("ledger is not at this revision's predecessor")
        current_owner = _function_owner(connection, qualified)
        if current_owner not in {owner, "tiamat_recovery"}:
            raise DefinerMigrationRejected("function owner is not eligible for this handoff")
        finalized = current_owner == "tiamat_recovery"
        if finalized:
            connection.execute(
                sql.SQL("GRANT tiamat_recovery TO {} WITH SET TRUE").format(
                    sql.Identifier(owner)
                )
            )
            connection.execute("GRANT CREATE ON SCHEMA tiamat TO tiamat_recovery")
            connection.execute("SET LOCAL ROLE tiamat_recovery")
        connection.execute(migration.statement)
        if finalized:
            connection.execute("RESET ROLE")
        connection.execute(
            "UPDATE tiamat.alembic_version SET version_num = %s", (migration.revision,)
        )
        if finalized:
            connection.execute("REVOKE CREATE ON SCHEMA tiamat FROM tiamat_recovery")
            connection.execute(
                sql.SQL("REVOKE tiamat_recovery FROM {}").format(sql.Identifier(owner))
            )
        _require_restored_topology(connection, qualified, owner, finalized, migration)
        return "applied_and_verified" if finalized else "applied_as_migration_owner"


def _function_owner(connection: psycopg.Connection[Any], qualified: str) -> str:
    row = connection.execute(
        """
        SELECT pg_catalog.pg_get_userbyid(p.proowner)
        FROM pg_catalog.pg_proc AS p
        WHERE p.oid = pg_catalog.to_regprocedure(%s)
        """,
        (qualified,),
    ).fetchone()
    if row is None:
        raise DefinerMigrationRejected("function does not exist on this ledger")
    return str(row[0])


def _require_restored_topology(
    connection: psycopg.Connection[Any],
    qualified: str,
    owner: str,
    finalized: bool,
    migration: DefinerMigration,
) -> None:
    """The handoff must leave exactly the topology it borrowed from."""

    if finalized and _function_owner(connection, qualified) != "tiamat_recovery":
        raise DefinerMigrationRejected("function ownership was not restored")
    row = connection.execute(
        """
        SELECT pg_catalog.has_function_privilege('tiamat_runtime', %s, 'EXECUTE'),
               pg_catalog.pg_has_role(current_user, 'tiamat_recovery', 'SET'),
               pg_catalog.pg_has_role(current_user, 'tiamat_recovery', 'USAGE'),
               pg_catalog.has_schema_privilege('tiamat_recovery', 'tiamat', 'CREATE')
        """,
        (qualified,),
    ).fetchone()
    if row is None:
        raise DefinerMigrationRejected("restored topology could not be read")
    executes, may_set, may_inherit, may_create = (bool(value) for value in row)
    if migration.runtime_executes and not executes:
        raise DefinerMigrationRejected("runtime lost execution of the replaced function")
    if finalized and (may_set or may_inherit or may_create):
        raise DefinerMigrationRejected("temporary handoff privileges remain")
    del owner


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--migration", required=True, type=Path)
    parser.add_argument("--function", required=True)
    parser.add_argument("--signature", default="")
    parser.add_argument("--confirm-revision", required=True)
    args = parser.parse_args()
    migration = load_migration(args.migration, function=args.function, signature=args.signature)
    if args.confirm_revision != migration.revision:
        raise ValueError("--confirm-revision must equal the migration's own revision")
    database_url = os.environ.get("TIAMAT_MIGRATION_DATABASE_URL")
    if not database_url:
        raise ValueError("TIAMAT_MIGRATION_DATABASE_URL is required")
    print(apply_definer_migration(database_url, migration))


if __name__ == "__main__":
    main()
