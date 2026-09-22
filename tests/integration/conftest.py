"""Shared provisioning for the disposable-database integration proofs.

The recovery and runtime role names are fixed by the schema: row-level security policies and the
security-definer functions both test ``current_user``. Two modules cannot therefore each reset
those passwords for themselves, because the second reset invalidates the first module's
connection URLs halfway through a session. Roles are provisioned once per session here instead.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from secrets import token_urlsafe

import psycopg
import pytest
from psycopg import sql
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE_PREFIX = "tiamat_test_d1"
EXECUTION_TABLES = (
    "tiamat.spending_partitions, tiamat.grant_releases, tiamat.execution_records, "
    "tiamat.execution_idempotency_aliases, tiamat.jti_replay, "
    "tiamat.financial_events, tiamat.route_rate_quarantines, tiamat.replay_cache"
)


@dataclass(frozen=True, repr=False)
class DisposableRoles:
    owner: str
    recovery: str
    runtime: str

    def __repr__(self) -> str:
        return "DisposableRoles(credentials=redacted)"


@pytest.fixture(scope="session")
def disposable_roles() -> DisposableRoles:
    owner_url = os.environ.get("TIAMAT_D1_TEST_DATABASE_URL")
    if not owner_url:
        pytest.skip("TIAMAT_D1_TEST_DATABASE_URL is not configured")
    if not (make_url(owner_url).database or "").startswith(TEST_DATABASE_PREFIX):
        pytest.fail("these proofs run only on a disposable database", pytrace=False)
    environment = os.environ.copy()
    environment["TIAMAT_MIGRATION_DATABASE_URL"] = owner_url
    migrated = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "tiamat_alembic.ini", "upgrade", "head"],
        cwd=str(ROOT),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if migrated.returncode != 0:
        pytest.fail("disposable database migration failed", pytrace=False)
    recovery_password, runtime_password = token_urlsafe(32), token_urlsafe(32)
    with psycopg.connect(owner_url, autocommit=True) as owner:
        for role, password in (
            ("tiamat_recovery", recovery_password),
            ("tiamat_runtime", runtime_password),
        ):
            existing = owner.execute(
                "SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)
            ).fetchone()
            if existing:
                # Only the password is reset: a managed owner may not set attributes it does not
                # hold, and the role's least-privilege attributes are what these proofs test.
                owner.execute(
                    sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(password)
                    )
                )
            else:
                owner.execute(
                    sql.SQL(
                        "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
                        "NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}"
                    ).format(sql.Identifier(role), sql.Literal(password))
                )
        owner.execute("GRANT USAGE ON SCHEMA tiamat TO tiamat_recovery, tiamat_runtime")
        owner.execute(
            "GRANT SELECT, INSERT, UPDATE ON tiamat.startup_attestations TO tiamat_recovery"
        )
        owner.execute(
            "GRANT SELECT, INSERT ON tiamat.recovery_checkpoints TO tiamat_recovery"
        )
        owner.execute("GRANT SELECT, INSERT, UPDATE ON tiamat.restore_gate TO tiamat_recovery")
        owner.execute("GRANT SELECT ON tiamat.ledger_identity TO tiamat_recovery")
        owner.execute("GRANT SELECT ON tiamat.restore_gate TO tiamat_runtime")
        owner.execute(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {EXECUTION_TABLES} "
            "TO tiamat_runtime, tiamat_recovery"
        )
        _own_share_locked_gate_reader(owner)
    return DisposableRoles(
        owner=owner_url,
        recovery=_url_for(owner_url, "tiamat_recovery", recovery_password),
        runtime=_url_for(owner_url, "tiamat_runtime", runtime_password),
    )


def _own_share_locked_gate_reader(owner: psycopg.Connection[tuple[object, ...]]) -> None:
    """Grant and transfer migration 0012's gate reader the way the finalizer does.

    The runtime cannot take the gate's shared lock directly once D1 revokes its UPDATE, so it
    calls this definer function instead. Execution is granted while the migration owner still
    owns the function, and the temporary SET grant needed to transfer ownership is removed again.
    """

    current = owner.execute("SELECT current_user").fetchone()
    assert current is not None
    state = owner.execute(
        """
        SELECT pg_catalog.pg_get_userbyid(p.proowner) = 'tiamat_recovery',
               pg_catalog.has_function_privilege('tiamat_runtime', p.oid, 'EXECUTE')
        FROM pg_catalog.pg_proc AS p
        WHERE p.oid = pg_catalog.to_regprocedure('tiamat.share_locked_restore_gate()')
        """
    ).fetchone()
    assert state is not None
    if state[0]:
        # Already transferred by an earlier run: the migration owner can no longer grant on it,
        # so the runtime's execution must already be in place.
        if not state[1]:
            pytest.fail(
                "the gate reader is recovery-owned without runtime execution", pytrace=False
            )
        return
    owner.execute(
        "GRANT EXECUTE ON FUNCTION tiamat.share_locked_restore_gate() TO tiamat_runtime"
    )
    owner.execute(
        "GRANT EXECUTE ON FUNCTION tiamat.retire_coordinator(bigint) TO tiamat_runtime"
    )
    owner_name = sql.Identifier(str(current[0]))
    owner.execute(sql.SQL("GRANT tiamat_recovery TO {} WITH SET TRUE").format(owner_name))
    owner.execute("GRANT CREATE ON SCHEMA tiamat TO tiamat_recovery")
    owner.execute("ALTER FUNCTION tiamat.share_locked_restore_gate() OWNER TO tiamat_recovery")
    owner.execute("ALTER FUNCTION tiamat.retire_coordinator(bigint) OWNER TO tiamat_recovery")
    owner.execute("REVOKE CREATE ON SCHEMA tiamat FROM tiamat_recovery")
    owner.execute(sql.SQL("REVOKE tiamat_recovery FROM {}").format(owner_name))


def _url_for(owner_url: str, role: str, password: str) -> str:
    return (
        make_url(owner_url)
        .set(username=role, password=password)
        .render_as_string(hide_password=False)
    )
