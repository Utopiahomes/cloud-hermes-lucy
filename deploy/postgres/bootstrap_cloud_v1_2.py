"""One-shot private PostgreSQL bootstrap for Security Baseline v1.2.

Run this only from the temporary Render migration utility. The utility has no
AWS identity, transcript capture stays disabled, and every runtime login is
validated before direct grants are applied.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg
import render_security_v1_2_sql as renderer
from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy.engine import URL, make_url

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_REVISION = "0019_security_v1_2_reconcile"
AUTHORIZATION = "security-v1.2-private-quarantined"
LOGIN_NAMES = {
    "routine": "lucy_routine_workflow",
    "policy": "lucy_policy_notary",
    "evidence": "lucy_evidence_workflow",
    "deletion": "lucy_deletion_workflow",
    "finality": "lucy_finality_verifier",
}
CAPABILITY_ROLES = {
    "lucy_app",
    "lucy_routine",
    "lucy_policy",
    "lucy_evidence_reader",
    "lucy_evidence_deleter",
    "lucy_security_function_owner",
}
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LUCY_DATABASE = re.compile(r"lucy(?:_[a-z0-9]+)?\Z")


class BootstrapError(RuntimeError):
    """A fail-closed deployment precondition or verification failure."""


@dataclass(frozen=True)
class BootstrapConfig:
    migration_url: URL
    runtime_urls: Mapping[str, URL]
    aws_account_id: str
    retrieval_alias_arn: str
    deletion_alias_arn: str
    retrieval_receipt_key_arn: str
    deletion_receipt_key_arn: str
    retrieval_version: int
    deletion_version: int
    storage_epoch: int
    registry_epoch: int
    key_epoch: int

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> BootstrapConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true":
            raise BootstrapError("bootstrap requires the Render private-network runtime")
        if values.get("LUCY_ENVIRONMENT") != "production":
            raise BootstrapError("bootstrap requires the production environment")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise BootstrapError("transcript capture must remain disabled")
        if values.get("LUCY_DATABASE_BOOTSTRAP_AUTHORIZATION") != AUTHORIZATION:
            raise BootstrapError("the exact reviewed bootstrap authorization is required")

        migration = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if migration.username != "lucy_migration":
            raise BootstrapError("the migration URL must use lucy_migration")
        if migration.host is None or _PRIVATE_RENDER_HOST.fullmatch(migration.host) is None:
            raise BootstrapError("the migration URL must use the private Render database host")
        if (
            migration.database is None
            or _LUCY_DATABASE.fullmatch(migration.database) is None
            or migration.port not in (None, 5432)
        ):
            raise BootstrapError("the migration URL must target the reviewed Lucy database")

        runtime_urls: dict[str, URL] = {}
        for mode, login in LOGIN_NAMES.items():
            url = _database_url(_required(values, f"LUCY_{mode.upper()}_DATABASE_URL"))
            if url.username != login or not url.password:
                raise BootstrapError(f"{mode} URL must use its exact password-bearing login")
            if (url.host, url.port or 5432, url.database) != (
                migration.host,
                migration.port or 5432,
                migration.database,
            ):
                raise BootstrapError(f"{mode} URL must target the same private database")
            runtime_urls[mode] = url

        return cls(
            migration_url=migration,
            runtime_urls=runtime_urls,
            aws_account_id=_required(values, "LUCY_AWS_ACCOUNT_ID"),
            retrieval_alias_arn=_required(values, "LUCY_RETRIEVAL_EXECUTOR_ALIAS_ARN"),
            deletion_alias_arn=_required(values, "LUCY_DELETION_EXECUTOR_ALIAS_ARN"),
            retrieval_receipt_key_arn=_required(values, "LUCY_RETRIEVAL_RECEIPT_KEY_ARN"),
            deletion_receipt_key_arn=_required(values, "LUCY_DELETION_RECEIPT_KEY_ARN"),
            retrieval_version=_positive_int(values, "LUCY_RETRIEVAL_EXECUTOR_VERSION"),
            deletion_version=_positive_int(values, "LUCY_DELETION_EXECUTOR_VERSION"),
            storage_epoch=_positive_int(values, "LUCY_SECURITY_STORAGE_EPOCH"),
            registry_epoch=_positive_int(values, "LUCY_SECURITY_REGISTRY_EPOCH"),
            key_epoch=_positive_int(values, "LUCY_SECURITY_KEY_EPOCH"),
        )


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise BootstrapError(f"missing required configuration: {name}")
    return value


def _positive_int(values: Mapping[str, str], name: str) -> int:
    raw = _required(values, name)
    try:
        value = int(raw)
    except ValueError as exc:
        raise BootstrapError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise BootstrapError(f"{name} must be a positive integer")
    return value


def _database_url(raw: str) -> URL:
    try:
        parsed = make_url(raw)
    except Exception as exc:
        raise BootstrapError("invalid PostgreSQL URL") from exc
    if parsed.drivername not in {"postgresql", "postgresql+psycopg"}:
        raise BootstrapError("only PostgreSQL psycopg URLs are accepted")
    if not parsed.username or not parsed.password or not parsed.host or not parsed.database:
        raise BootstrapError("database URLs require user, password, host, and database")
    return parsed.set(drivername="postgresql+psycopg").update_query_dict({"sslmode": "require"})


def _conninfo(url: URL) -> str:
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


def _strip_reviewed_psql_header(script: str) -> str:
    lines = script.splitlines()
    meta = [line.strip() for line in lines if line.lstrip().startswith("\\")]
    if meta not in ([], [r"\set ON_ERROR_STOP on"]):
        raise BootstrapError("unexpected psql meta-command in reviewed SQL")
    return "\n".join(line for line in lines if not line.lstrip().startswith("\\")) + "\n"


def _digest(script: str) -> str:
    return hashlib.sha256(script.encode("utf-8")).hexdigest()


def _postgres_diagnostic(exc: BaseException) -> tuple[str, str] | None:
    """Extract only PostgreSQL's code and primary message, never SQL or parameters."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, psycopg.Error):
            primary = current.diag.message_primary or type(current).__name__
            return current.sqlstate or "unknown", primary
        original = getattr(current, "orig", None)
        if isinstance(original, BaseException) and id(original) not in seen:
            current = original
            continue
        current = current.__cause__ or current.__context__
    return None


def _bootstrap_stage[T](name: str, operation: Callable[[], T]) -> T:
    try:
        return operation()
    except BootstrapError:
        raise
    except Exception as exc:
        diagnostic = _postgres_diagnostic(exc)
        if diagnostic is None:
            raise
        sqlstate, primary = diagnostic
        raise BootstrapError(f"{name} failed ({sqlstate}): {primary}") from exc


def _role_rows(connection: psycopg.Connection[Any], names: set[str]) -> dict[str, tuple[Any, ...]]:
    rows = connection.execute(
        "SELECT rolname,rolcanlogin,rolsuper,rolinherit,rolcreaterole,rolcreatedb,"
        "rolreplication,rolbypassrls FROM pg_roles WHERE rolname = ANY(%s)",
        (sorted(names),),
    ).fetchall()
    return {str(row[0]): tuple(row[1:]) for row in rows}


def _assert_inert_roles(rows: Mapping[str, tuple[Any, ...]], expected: set[str]) -> None:
    if set(rows) != expected:
        raise BootstrapError("capability-role set is partial or unexpected")
    for name, flags in rows.items():
        can_login, superuser, inherit, create_role, create_db, replication, bypass_rls = flags
        if (
            can_login
            or superuser
            or inherit
            or create_role
            or create_db
            or replication
            or bypass_rls
        ):
            raise BootstrapError(f"capability role is not inert: {name}")


def _assert_runtime_role(name: str, flags: tuple[Any, ...]) -> None:
    can_login, superuser, inherit, create_role, create_db, replication, bypass_rls = flags
    if (
        not can_login
        or superuser
        or inherit
        or create_role
        or create_db
        or replication
        or bypass_rls
    ):
        raise BootstrapError(f"runtime login is missing or elevated: {name}")


def _has_membership(connection: psycopg.Connection[Any], login: str) -> bool:
    return bool(
        _scalar(
            connection,
            "SELECT EXISTS (SELECT 1 FROM pg_auth_members m "
            "JOIN pg_roles r ON r.oid=m.member WHERE r.rolname=%s)",
            (login,),
        )
    )


def _scalar(
    connection: psycopg.Connection[Any],
    query: str,
    params: tuple[Any, ...] | None = None,
) -> Any:
    row = connection.execute(query, params).fetchone()
    if row is None:
        raise BootstrapError("database verification query returned no row")
    return row[0]


def _bootstrap_roles(config: BootstrapConfig) -> None:
    bootstrap_sql = (ROOT / "deploy/postgres/production_bootstrap.sql.example").read_text(
        encoding="utf-8"
    )
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        if _scalar(connection, "SELECT current_user") != "lucy_migration":
            raise BootstrapError("database session is not the migration owner")
        capability_rows = _role_rows(connection, CAPABILITY_ROLES)
        if not capability_rows:
            connection.execute(bootstrap_sql, prepare=False)
        else:
            _assert_inert_roles(capability_rows, CAPABILITY_ROLES)
        capability_rows = _role_rows(connection, CAPABILITY_ROLES)
        _assert_inert_roles(capability_rows, CAPABILITY_ROLES)

        runtime_rows = _role_rows(connection, set(LOGIN_NAMES.values()))
        for login, flags in runtime_rows.items():
            _assert_runtime_role(login, flags)
            if _has_membership(connection, login):
                raise BootstrapError(f"runtime login has inherited membership: {login}")
        for mode, login in LOGIN_NAMES.items():
            password = config.runtime_urls[mode].password
            assert password is not None
            if login in runtime_rows:
                statement = sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                    sql.Identifier(login), sql.Literal(password)
                )
            else:
                statement = sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOREPLICATION NOBYPASSRLS"
                ).format(sql.Identifier(login), sql.Literal(password))
            connection.execute(statement)


def _run_migrations(config: BootstrapConfig) -> None:
    previous = os.environ.get("LUCY_MIGRATION_DATABASE_URL")
    os.environ["LUCY_MIGRATION_DATABASE_URL"] = config.migration_url.render_as_string(
        hide_password=False
    )
    try:
        alembic = Config(str(ROOT / "alembic.ini"))
        alembic.set_main_option("script_location", str(ROOT / "migrations"))
        command.upgrade(alembic, "head")
    finally:
        if previous is None:
            os.environ.pop("LUCY_MIGRATION_DATABASE_URL", None)
        else:
            os.environ["LUCY_MIGRATION_DATABASE_URL"] = previous


def _apply_reviewed_security(config: BootstrapConfig) -> tuple[str, str]:
    roles_sql = renderer.render_roles(
        routine_login=LOGIN_NAMES["routine"],
        policy_login=LOGIN_NAMES["policy"],
        evidence_login=LOGIN_NAMES["evidence"],
        deletion_login=LOGIN_NAMES["deletion"],
        finality_login=LOGIN_NAMES["finality"],
    )
    bindings_sql = renderer.render_bindings(
        aws_account_id=config.aws_account_id,
        retrieval_alias_arn=config.retrieval_alias_arn,
        deletion_alias_arn=config.deletion_alias_arn,
        retrieval_receipt_key_arn=config.retrieval_receipt_key_arn,
        deletion_receipt_key_arn=config.deletion_receipt_key_arn,
        retrieval_version=config.retrieval_version,
        deletion_version=config.deletion_version,
        security_storage_epoch=config.storage_epoch,
        security_registry_epoch=config.registry_epoch,
        security_key_epoch=config.key_epoch,
    )
    with psycopg.connect(_conninfo(config.migration_url), autocommit=True) as connection:
        try:
            connection.execute(f"BEGIN;\n{roles_sql}\nCOMMIT;", prepare=False)
        except psycopg.Error as exc:
            primary = exc.diag.message_primary or type(exc).__name__
            raise BootstrapError(
                f"reviewed runtime grants failed ({exc.sqlstate or 'unknown'}): {primary}"
            ) from exc
        try:
            connection.execute(_strip_reviewed_psql_header(bindings_sql), prepare=False)
        except psycopg.Error as exc:
            primary = exc.diag.message_primary or type(exc).__name__
            raise BootstrapError(
                f"reviewed executor bindings failed ({exc.sqlstate or 'unknown'}): {primary}"
            ) from exc
    return _digest(roles_sql), _digest(bindings_sql)


def _verify_tls(connection: psycopg.Connection[Any]) -> None:
    encrypted = _scalar(connection, "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
    if encrypted is not True:
        raise BootstrapError("database connection is not TLS protected")


def _verify(config: BootstrapConfig) -> dict[str, Any]:
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        _verify_tls(connection)
        revision = _scalar(connection, "SELECT version_num FROM public.alembic_version")
        admission = _scalar(connection, "SELECT state FROM lucy.runtime_admission WHERE singleton")
        active_bindings = _scalar(
            connection,
            "SELECT count(*) FROM lucy.executor_bindings_v1 "
            "WHERE environment='production' AND active",
        )
        capture_enabled = _scalar(
            connection,
            "SELECT EXISTS (SELECT 1 FROM lucy.conversation_capture_states WHERE capture_enabled) "
            "OR EXISTS (SELECT 1 FROM lucy.capture_receipts WHERE capture_enabled)",
        )
    if revision != EXPECTED_REVISION:
        raise BootstrapError("database did not reach the reviewed migration head")
    if admission != "quarantined" or capture_enabled:
        raise BootstrapError("database did not remain quarantined with capture disabled")
    if active_bindings != 2:
        raise BootstrapError("database does not contain both immutable executor bindings")

    verified_logins: list[str] = []
    for mode, login in LOGIN_NAMES.items():
        with psycopg.connect(_conninfo(config.runtime_urls[mode])) as connection:
            _verify_tls(connection)
            observed = _scalar(connection, "SELECT current_user")
            if observed != login:
                raise BootstrapError(f"{mode} connected as the wrong runtime login")
            rows = _role_rows(connection, {login})
            if login not in rows:
                raise BootstrapError(f"{mode} runtime login is missing")
            _assert_runtime_role(login, rows[login])
            if _has_membership(connection, login):
                raise BootstrapError(f"{mode} runtime login has inherited membership")
            can_read_admission = bool(
                _scalar(
                    connection,
                    "SELECT has_table_privilege(current_user, "
                    "'lucy.runtime_admission', 'SELECT')",
                )
            )
            if mode == "finality":
                if can_read_admission:
                    raise BootstrapError("finality can read the runtime admission boundary")
            else:
                if not can_read_admission:
                    raise BootstrapError(f"{mode} cannot read the runtime admission boundary")
                state = _scalar(
                    connection, "SELECT state FROM lucy.runtime_admission WHERE singleton"
                )
                if state != "quarantined":
                    raise BootstrapError(f"{mode} did not observe quarantined admission")
        verified_logins.append(login)
    return {
        "migration_revision": revision,
        "runtime_admission": admission,
        "capture_enabled": False,
        "active_executor_bindings": active_bindings,
        "verified_runtime_logins": verified_logins,
    }


def run(config: BootstrapConfig) -> dict[str, Any]:
    _bootstrap_stage("role bootstrap", lambda: _bootstrap_roles(config))
    _bootstrap_stage("migration", lambda: _run_migrations(config))
    roles_digest, bindings_digest = _bootstrap_stage(
        "security grant application", lambda: _apply_reviewed_security(config)
    )
    report = _bootstrap_stage("verification", lambda: _verify(config))
    report.update(
        {
            "contract": "lucy.security-database-bootstrap.v1.2",
            "status": "passed",
            "roles_sql_sha256": roles_digest,
            "bindings_sql_sha256": bindings_digest,
        }
    )
    return report


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        raise BootstrapError("this deployment utility accepts no command-line values")
    try:
        report = run(BootstrapConfig.from_environment())
    except BootstrapError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
