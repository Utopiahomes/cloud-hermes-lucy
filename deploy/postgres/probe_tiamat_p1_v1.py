"""Bounded Render PostgreSQL P1 role-capability probe; leaves no durable changes.

Run only against the blocked staging ledger, from a one-off job with a temporary
owner URL. All DDL is savepoint-scoped and rolled back. Output contains no URLs,
passwords, session text, or SQL error details.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import time
from collections.abc import Callable

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict


class ProbeRejected(RuntimeError):
    """A non-secret, stable reason code for a P1 preflight rejection."""


def _one(cursor: psycopg.Cursor[tuple[object, ...]]) -> tuple[object, ...]:
    row = cursor.fetchone()
    if row is None:
        raise ProbeRejected("expected_row_missing")
    return row


def _connection_info(name: str) -> str | None:
    value = os.environ.get(name)
    if not value:
        return None
    value = value.replace("postgresql+psycopg://", "postgresql://", 1)
    if conninfo_to_dict(value).get("sslmode") not in {"require", "verify-ca", "verify-full"}:
        raise ValueError(f"{name} must require TLS")
    return value


def _attempt(
    connection: psycopg.Connection[tuple[object, ...]], action: Callable[[], object]
) -> dict[str, object]:
    connection.execute("SAVEPOINT p1_probe")
    try:
        result = action()
        return {"supported": result is not False}
    except psycopg.Error as exc:
        return {"supported": False, "sqlstate": exc.sqlstate}
    finally:
        connection.execute("ROLLBACK TO SAVEPOINT p1_probe")
        connection.execute("RELEASE SAVEPOINT p1_probe")


def _revoke_effective(
    connection: psycopg.Connection[tuple[object, ...]], function_name: str
) -> bool:
    connection.execute(
        sql.SQL("REVOKE EXECUTE ON FUNCTION pg_catalog.{}() FROM PUBLIC").format(
            sql.Identifier(function_name)
        )
    )
    # PostgreSQL can warn about a no-op REVOKE without raising an error. Check the
    # serving role's effective privilege inside the savepoint before rolling back.
    execute_allowed = _one(
        connection.execute(
            "SELECT has_function_privilege('tiamat_runtime', %s, 'EXECUTE')",
            (f"pg_catalog.{function_name}()",),
        )
    )[0]
    return execute_allowed is False


def diagnose_gate(*, expected_ledger: str) -> dict[str, object]:
    """Read only the staging identity and gate; disclose no connection material."""
    owner_url = _connection_info("TIAMAT_P1_OWNER_DATABASE_URL")
    if owner_url is None:
        raise ValueError("temporary staging owner URL is required")
    with psycopg.connect(owner_url) as connection:
        connection.execute("SET LOCAL tiamat.environment = 'staging'")
        ledger = _one(
            connection.execute("SELECT ledger_id::text FROM tiamat.ledger_identity WHERE singleton")
        )[0]
        gate_rows = connection.execute(
            "SELECT environment, dispatch_blocked FROM tiamat.restore_gate"
        ).fetchall()
        tls = _one(connection.execute("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"))[
            0
        ]
        return {
            "ledger_matches": ledger == expected_ledger,
            "transport_tls": tls is True,
            "gate_row_count": len(gate_rows),
            "staging_gate_present": any(row[0] == "staging" for row in gate_rows),
            "staging_gate_blocked": next(
                (row[1] for row in gate_rows if row[0] == "staging"), None
            ),
        }


def hold_runtime_session() -> None:
    """Hold one disposable serving-login session for the separate owner probe."""
    runtime_url = _connection_info("TIAMAT_RUNTIME_DATABASE_URL")
    if runtime_url is None:
        raise ValueError("staging runtime URL is required")
    with psycopg.connect(
        runtime_url, autocommit=True, application_name="tiamat_p1_probe"
    ) as connection:
        role, database, pid, tls = _one(
            connection.execute(
                "SELECT current_user, current_database(), pg_backend_pid(), "
                "(SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid())"
            )
        )
        if role != "tiamat_runtime" or database != "tiamat_staging" or tls is not True:
            raise ProbeRejected("runtime_probe_identity_or_tls_mismatch")
        print(json.dumps({"status": "runtime_session_ready", "pid": pid}), flush=True)
        for _ in range(45):
            time.sleep(2)
            try:
                connection.execute("SELECT 1")
            except psycopg.OperationalError:
                print(json.dumps({"status": "runtime_session_terminated"}), flush=True)
                return
        raise ProbeRejected("runtime_session_not_terminated_in_window")


def terminate_runtime_probe(*, expected_ledger: str, runtime_pid: int) -> dict[str, object]:
    """Test owner self-grant plus termination of exactly one observed runtime PID."""
    if runtime_pid <= 0:
        raise ValueError("runtime probe PID must be positive")
    owner_url = _connection_info("TIAMAT_P1_OWNER_DATABASE_URL")
    if owner_url is None:
        raise ValueError("temporary staging owner URL is required")
    with psycopg.connect(owner_url) as connection:
        connection.execute("SET LOCAL tiamat.environment = 'staging'")
        owner, database, ledger, blocked, tls = _one(
            connection.execute(
                "SELECT current_user, current_database(), "
                "(SELECT ledger_id::text FROM tiamat.ledger_identity WHERE singleton), "
                "(SELECT dispatch_blocked FROM tiamat.restore_gate WHERE environment = 'staging'), "
                "(SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid())"
            )
        )
        if database != "tiamat_staging" or ledger != expected_ledger or blocked is not True:
            raise ProbeRejected("owner_probe_staging_gate_mismatch")
        if tls is not True:
            raise ProbeRejected("transport_not_tls")
        target = connection.execute(
            "SELECT usename, datname FROM pg_stat_activity WHERE pid = %s", (runtime_pid,)
        ).fetchone()
        if target != ("tiamat_runtime", "tiamat_staging"):
            raise ProbeRejected("runtime_probe_session_not_identified")

        def grant_and_terminate() -> bool:
            connection.execute(
                sql.SQL("GRANT tiamat_runtime TO {} WITH INHERIT TRUE, SET TRUE").format(
                    sql.Identifier(str(owner))
                )
            )
            return bool(
                _one(connection.execute("SELECT pg_terminate_backend(%s)", (runtime_pid,)))[0]
            )

        result = _attempt(connection, grant_and_terminate)
        connection.rollback()
        return {
            "termination_with_self_grant": result,
            "runtime_pid_matched_exact_role_and_database": True,
            "durable_membership_change": False,
        }


def run(*, expected_ledger: str) -> dict[str, object]:
    owner_url = _connection_info("TIAMAT_P1_OWNER_DATABASE_URL")
    runtime_url = _connection_info("TIAMAT_P1_RUNTIME_DATABASE_URL")
    if owner_url is None:
        raise ValueError("temporary staging owner URL is required")
    if not expected_ledger:
        raise ValueError("expected ledger ID is required")

    with psycopg.connect(owner_url) as connection:
        connection.execute("SET LOCAL tiamat.environment = 'staging'")
        owner, ledger, blocked, tls = _one(
            connection.execute(
                """SELECT current_user,
                      (SELECT ledger_id::text FROM tiamat.ledger_identity WHERE singleton),
                      (SELECT dispatch_blocked FROM tiamat.restore_gate
                       WHERE environment = 'staging'),
                      (SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid())"""
            )
        )
        if ledger != expected_ledger:
            raise ProbeRejected("ledger_mismatch")
        if blocked is None:
            raise ProbeRejected("staging_gate_missing")
        if blocked is not True:
            raise ProbeRejected("staging_gate_open")
        if tls is not True:
            raise ProbeRejected("transport_not_tls")

        results: dict[str, object] = {"ledger_matches": True, "dispatch_blocked": True, "tls": True}
        results["alter_runtime_nologin"] = _attempt(
            connection,
            lambda: connection.execute("ALTER ROLE tiamat_runtime NOLOGIN"),
        )
        temporary_password = secrets.token_urlsafe(36)
        results["alter_runtime_password"] = _attempt(
            connection,
            lambda: connection.execute(
                sql.SQL("ALTER ROLE tiamat_runtime PASSWORD {}").format(
                    sql.Literal(temporary_password)
                )
            ),
        )
        temporary_password = ""
        results["self_grant_runtime_inherit"] = _attempt(
            connection,
            lambda: connection.execute(
                sql.SQL("GRANT tiamat_runtime TO {} WITH INHERIT TRUE, SET TRUE").format(
                    sql.Identifier(str(owner))
                )
            ),
        )
        results["pg_signal_backend_member"] = bool(
            _one(
                connection.execute(
                    "SELECT pg_has_role(current_user, 'pg_signal_backend', 'MEMBER')"
                )
            )[0]
        )
        results["query_runtime_sessions"] = _attempt(
            connection,
            lambda: connection.execute(
                "SELECT pid, usename FROM pg_stat_activity WHERE usename = 'tiamat_runtime'"
            ).fetchall(),
        )
        results["grant_recovery_set"] = _attempt(
            connection,
            lambda: connection.execute(
                sql.SQL("GRANT tiamat_recovery TO {} WITH SET TRUE").format(
                    sql.Identifier(str(owner))
                )
            ),
        )
        function_name = "p1_probe_" + secrets.token_hex(6)

        ownership_stage = "grant_membership"

        def transfer_function(*, grant_schema_create: bool) -> None:
            nonlocal ownership_stage
            connection.execute(
                sql.SQL("GRANT tiamat_recovery TO {} WITH SET TRUE").format(
                    sql.Identifier(str(owner))
                )
            )
            if grant_schema_create:
                ownership_stage = "grant_schema_create"
                connection.execute("GRANT CREATE ON SCHEMA tiamat TO tiamat_recovery")
            ownership_stage = "create_function"
            connection.execute(
                sql.SQL(
                    "CREATE FUNCTION tiamat.{}() RETURNS boolean LANGUAGE sql AS 'SELECT true'"
                ).format(sql.Identifier(function_name))
            )
            ownership_stage = "alter_function_owner"
            connection.execute(
                sql.SQL("ALTER FUNCTION tiamat.{}() OWNER TO tiamat_recovery").format(
                    sql.Identifier(function_name)
                )
            )

        owner_result = _attempt(connection, lambda: transfer_function(grant_schema_create=False))
        if owner_result["supported"] is False:
            owner_result["stage"] = ownership_stage
        results["transfer_function_to_recovery"] = owner_result

        ownership_stage = "grant_membership"
        create_grant_result = _attempt(
            connection, lambda: transfer_function(grant_schema_create=True)
        )
        if create_grant_result["supported"] is False:
            create_grant_result["stage"] = ownership_stage
        results["transfer_function_with_temporary_schema_create"] = create_grant_result

        for name in ("pg_control_system", "pg_control_checkpoint", "pg_current_wal_flush_lsn"):

            def revoke_public(function_name: str = name) -> bool:
                return _revoke_effective(connection, function_name)

            results[f"revoke_public_{name}"] = _attempt(
                connection,
                revoke_public,
            )
        if runtime_url:
            with psycopg.connect(runtime_url, autocommit=True) as runtime:
                runtime_user, runtime_pid = _one(
                    runtime.execute("SELECT current_user, pg_backend_pid()")
                )
                if runtime_user != "tiamat_runtime":
                    raise ProbeRejected("runtime_probe_role_mismatch")
                visible = _one(
                    connection.execute(
                        "SELECT count(*) FROM pg_stat_activity WHERE pid = %s "
                        "AND usename = 'tiamat_runtime'",
                        (runtime_pid,),
                    )
                )[0]
                results["see_runtime_probe_session"] = visible == 1

                def terminate_probe() -> bool:
                    return bool(
                        _one(connection.execute("SELECT pg_terminate_backend(%s)", (runtime_pid,)))[
                            0
                        ]
                    )

                results["terminate_probe_runtime_session"] = _attempt(
                    connection,
                    terminate_probe,
                )
        else:
            results["terminate_probe_runtime_session"] = {"status": "not_run_no_runtime_probe_url"}
        connection.rollback()
        results["durable_role_or_function_changes"] = False
        return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-ledger-id", required=True)
    parser.add_argument("--diagnose-gate-only", action="store_true")
    parser.add_argument("--hold-runtime-session", action="store_true")
    parser.add_argument("--terminate-runtime-pid", type=int)
    args = parser.parse_args()
    try:
        if args.hold_runtime_session:
            hold_runtime_session()
            return
        if args.terminate_runtime_pid is not None:
            result = terminate_runtime_probe(
                expected_ledger=args.expected_ledger_id, runtime_pid=args.terminate_runtime_pid
            )
        elif args.diagnose_gate_only:
            result = diagnose_gate(expected_ledger=args.expected_ledger_id)
        else:
            result = run(expected_ledger=args.expected_ledger_id)
    except ProbeRejected as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}))
        raise SystemExit(1) from None
    except Exception as exc:
        # In particular, never emit psycopg's connection diagnostic with credentials.
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
