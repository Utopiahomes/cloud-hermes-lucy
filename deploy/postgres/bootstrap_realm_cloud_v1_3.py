"""Quarantine-first PostgreSQL commissioning for one Security Baseline V1.3 realm.

Run only as a temporary Render migration job. The job has no AWS identity and
must be removed after its content-free receipt is retained.
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
from alembic import command
from alembic.config import Config
from psycopg import sql
from pydantic import ValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool

from deploy.postgres.provision_realm_bindings_v1_3 import apply_manifest
from deploy.postgres.provision_realm_foundation_v1_3 import (
    RealmFoundationSeedV1,
    apply_foundation,
)
from deploy.postgres.render_security_v1_3_sql import render_realm_roles
from lucy.realm_provisioning import RealmSecurityStampV1

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_SOURCE_REVISIONS = {
    "0021_recovery_capture_safety",
    "0039_r1_scoped_capture_runtime",
    "0040_r1_grant_authority_snapshot",
    "0041_r1_deletion_authority_snapshot",
}
EXPECTED_REVISION = "0041_r1_deletion_authority_snapshot"
AUTHORIZATION = "security-v1.3-private-quarantined"
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LUCY_DATABASE = re.compile(r"lucy(?:_[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAINTENANCE_LOCK = 0x4C5543594D53
_ADMISSION_LOCK = 0x4C5543594144
_PREREQUISITE_ROLES = {
    "lucy_public_runtime",
    "lucy_directory_function_owner",
    "lucy_directory_admission",
}


class BootstrapError(RuntimeError):
    """A fail-closed commissioning precondition or verification failure."""


@dataclass(frozen=True)
class BootstrapConfig:
    migration_url: URL
    runtime_urls: Mapping[str, URL]
    stamp: RealmSecurityStampV1
    seed: RealmFoundationSeedV1

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> BootstrapConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise BootstrapError("commissioning requires the production Render runtime")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise BootstrapError("transcript capture must remain disabled")
        if values.get("LUCY_REALM_BOOTSTRAP_AUTHORIZATION") != AUTHORIZATION:
            raise BootstrapError("the exact reviewed V1.3 bootstrap authorization is required")

        migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if migration_url.username != "lucy_migration":
            raise BootstrapError("the migration URL must use lucy_migration")
        if migration_url.host is None or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None:
            raise BootstrapError("the migration URL must use the private Render database host")
        if (
            migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
        ):
            raise BootstrapError("the migration URL must target the reviewed Lucy database")

        try:
            stamp = RealmSecurityStampV1.model_validate_json(
                _required(values, "LUCY_REALM_SECURITY_STAMP_JSON")
            )
            seed = RealmFoundationSeedV1.model_validate_json(
                _required(values, "LUCY_REALM_FOUNDATION_SEED_JSON")
            )
        except (ValidationError, ValueError) as exc:
            raise BootstrapError("realm commissioning input is invalid") from exc
        if seed.realm_slug != stamp.realm_slug:
            raise BootstrapError("realm foundation does not match the security stamp")
        for name, actual in (
            ("LUCY_REALM_SECURITY_STAMP_SHA256", stamp.digest_hex()),
            ("LUCY_REALM_FOUNDATION_SEED_SHA256", seed.digest_hex()),
        ):
            reviewed = _required(values, name)
            if _DIGEST.fullmatch(reviewed) is None or reviewed != actual:
                raise BootstrapError("realm commissioning digest does not match")

        expected_logins = {
            "routine": stamp.routine_login,
            "policy": stamp.policy_login,
            "workflow": stamp.workflow_login,
            "finality": stamp.finality_login,
        }
        runtime_urls: dict[str, URL] = {}
        for mode, login in expected_logins.items():
            url = _database_url(_required(values, f"LUCY_{mode.upper()}_DATABASE_URL"))
            if url.username != login or not url.password:
                raise BootstrapError(f"{mode} URL must use its exact password-bearing login")
            if (url.host, url.port or 5432, url.database) != (
                migration_url.host,
                migration_url.port or 5432,
                migration_url.database,
            ):
                raise BootstrapError(f"{mode} URL must target the same private database")
            runtime_urls[mode] = url
        return cls(migration_url=migration_url, runtime_urls=runtime_urls, stamp=stamp, seed=seed)


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise BootstrapError(f"missing required configuration: {name}")
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


def _scalar(
    connection: psycopg.Connection[Any], query: str, params: tuple[Any, ...] | None = None
) -> Any:
    row = connection.execute(query, params).fetchone()
    if row is None:
        raise BootstrapError("database verification query returned no row")
    return row[0]


def _stage[T](name: str, operation: Callable[[], T]) -> T:
    try:
        return operation()
    except BootstrapError:
        raise
    except Exception as exc:
        if isinstance(exc, psycopg.Error):
            primary = exc.diag.message_primary or type(exc).__name__
            raise BootstrapError(
                f"{name} failed ({exc.sqlstate or 'unknown'}): {primary}"
            ) from exc
        if isinstance(exc, DBAPIError):
            original = exc.orig
            if isinstance(original, psycopg.Error):
                primary = original.diag.message_primary or type(original).__name__
                raise BootstrapError(
                    f"{name} failed ({original.sqlstate or 'unknown'}): {primary}"
                ) from exc
            raise BootstrapError(f"{name} failed ({type(original).__name__})") from exc
        raise


def _quarantine(config: BootstrapConfig) -> str:
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '10s'")
        connection.execute("SET LOCAL statement_timeout = '120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_ADMISSION_LOCK,))
        if _scalar(connection, "SELECT current_user") != "lucy_migration":
            raise BootstrapError("database session is not the migration owner")
        tls = _scalar(connection, "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
        if tls is not True:
            raise BootstrapError("database connection is not TLS protected")
        revision = str(_scalar(connection, "SELECT version_num FROM public.alembic_version"))
        if revision not in EXPECTED_SOURCE_REVISIONS:
            raise BootstrapError("database is not at an approved V1.2 or V1.3 migration revision")
        if _scalar(connection, "SELECT lucy.capture_boundary_safe_v1()") is not True:
            raise BootstrapError("database capture boundary is not safe")
        connection.execute(
            "UPDATE lucy.runtime_admission SET state='quarantined', updated_at=now() "
            "WHERE singleton"
        )
        if _scalar(connection, "SELECT state FROM lucy.runtime_admission WHERE singleton") != (
            "quarantined"
        ):
            raise BootstrapError("database did not enter quarantine")
    return revision


def _role_rows(connection: psycopg.Connection[Any], names: set[str]) -> dict[str, tuple[Any, ...]]:
    rows = connection.execute(
        "SELECT rolname,rolcanlogin,rolsuper,rolinherit,rolcreaterole,rolcreatedb,"
        "rolreplication,rolbypassrls FROM pg_roles WHERE rolname=ANY(%s)",
        (sorted(names),),
    ).fetchall()
    return {str(row[0]): tuple(row[1:]) for row in rows}


def _assert_runtime_role(name: str, flags: tuple[Any, ...]) -> None:
    if flags != (True, False, False, False, False, False, False):
        raise BootstrapError(f"runtime login is missing or elevated: {name}")


def _assert_inert_role(name: str, flags: tuple[Any, ...]) -> None:
    if flags != (False, False, False, False, False, False, False):
        raise BootstrapError(f"prerequisite role is not inert: {name}")


def _validate_prerequisite_memberships(rows: Sequence[Sequence[Any]]) -> None:
    grants = {
        (str(row[0]), str(row[1]), bool(row[2]), bool(row[3]), bool(row[4]))
        for row in rows
    }
    owner_grants = {
        grant for grant in grants if grant[0] == "lucy_directory_function_owner"
    }
    caller_grants = grants - owner_grants
    owner_isolated = (
        bool(owner_grants)
        and all(member == "lucy_migration" for _, member, *_ in owner_grants)
        and any(set_option for *_, set_option in owner_grants)
    )
    callers_inert = all(
        member == "lucy_migration" and not inherit_option and not set_option
        for _, member, _, inherit_option, set_option in caller_grants
    )
    if not owner_isolated or not callers_inert:
        raise BootstrapError(f"prerequisite role membership is not isolated: {sorted(grants)}")


def _bootstrap_roles(config: BootstrapConfig) -> None:
    expected = {url.username for url in config.runtime_urls.values()}
    if None in expected or len(expected) != 4:
        raise BootstrapError("realm runtime LOGIN set is invalid")
    names = {str(name) for name in expected}
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        prerequisite_rows = _role_rows(connection, _PREREQUISITE_ROLES)
        for name, flags in prerequisite_rows.items():
            _assert_inert_role(name, flags)
        for name in sorted(_PREREQUISITE_ROLES - set(prerequisite_rows)):
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOREPLICATION NOBYPASSRLS"
                ).format(sql.Identifier(name))
            )
        connection.execute("GRANT lucy_directory_function_owner TO lucy_migration")
        connection.execute("REVOKE lucy_public_runtime FROM lucy_migration")
        connection.execute("REVOKE lucy_directory_admission FROM lucy_migration")
        prerequisite_rows = _role_rows(connection, _PREREQUISITE_ROLES)
        if set(prerequisite_rows) != _PREREQUISITE_ROLES:
            raise BootstrapError("one or more prerequisite roles are missing")
        for name, flags in prerequisite_rows.items():
            _assert_inert_role(name, flags)
        membership_rows = connection.execute(
            "SELECT parent.rolname,member.rolname,m.admin_option,m.inherit_option,m.set_option "
            "FROM pg_auth_members m "
            "JOIN pg_roles parent ON parent.oid=m.roleid "
            "JOIN pg_roles member ON member.oid=m.member "
            "WHERE parent.rolname=ANY(%s)",
            (sorted(_PREREQUISITE_ROLES),),
        ).fetchall()
        _validate_prerequisite_memberships(membership_rows)

        rows = _role_rows(connection, names)
        for name, flags in rows.items():
            _assert_runtime_role(name, flags)
        for url in config.runtime_urls.values():
            name = str(url.username)
            password = url.password
            assert password is not None
            statement = (
                sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                    sql.Identifier(name), sql.Literal(password)
                )
                if name in rows
                else sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOREPLICATION NOBYPASSRLS"
                ).format(sql.Identifier(name), sql.Literal(password))
            )
            connection.execute(statement)
        rows = _role_rows(connection, names)
        if set(rows) != names:
            raise BootstrapError("one or more realm runtime LOGINs are missing")
        for name, flags in rows.items():
            _assert_runtime_role(name, flags)
        members = connection.execute(
            "SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member "
            "WHERE r.rolname=ANY(%s)",
            (sorted(names),),
        ).fetchall()
        if members:
            raise BootstrapError("realm runtime LOGIN has inherited membership")


def _run_migrations(config: BootstrapConfig) -> None:
    engine = create_engine(config.migration_url, poolclass=NullPool)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": _MAINTENANCE_LOCK},
            )
            connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _ADMISSION_LOCK})
            boundary = connection.execute(
                text(
                    "SELECT n.nspowner::regrole::text,"
                    "(SELECT rolsuper FROM pg_roles WHERE rolname='lucy_migration'),"
                    "(SELECT rolsuper FROM pg_roles "
                    " WHERE rolname='lucy_security_function_owner'),"
                    "EXISTS(SELECT 1 FROM aclexplode(COALESCE(n.nspacl,"
                    " acldefault('n',n.nspowner))) "
                    " WHERE grantee=0 AND privilege_type='CREATE') "
                    "FROM pg_namespace n WHERE n.nspname='lucy'"
                )
            ).one()
            if boundary[0] != "lucy_migration":
                raise BootstrapError("Lucy schema owner is not the reviewed migration principal")
            if boundary[1] is not False or boundary[2] is not False or boundary[3] is not False:
                raise BootstrapError("migration schema authority boundary is unsafe")

            connection.execute(
                text(
                    "GRANT USAGE, CREATE ON SCHEMA lucy TO "
                    "lucy_security_function_owner,lucy_directory_function_owner"
                )
            )
            alembic = Config(str(ROOT / "alembic.ini"))
            alembic.set_main_option("script_location", str(ROOT / "migrations"))
            alembic.attributes["connection"] = connection
            command.upgrade(alembic, "head")
            connection.execute(
                text(
                    "REVOKE CREATE ON SCHEMA lucy FROM "
                    "lucy_security_function_owner,lucy_directory_function_owner"
                )
            )
            residual = connection.execute(
                text(
                    "SELECT has_schema_privilege("
                    "'lucy_security_function_owner','lucy','CREATE'),"
                    "has_schema_privilege("
                    "'lucy_directory_function_owner','lucy','CREATE'),"
                    "EXISTS(SELECT 1 FROM pg_namespace n,"
                    "LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a "
                    "WHERE n.nspname='lucy' AND a.grantee=0 "
                    "AND a.privilege_type='CREATE')"
                )
            ).one()
            if any(value is not False for value in residual):
                raise BootstrapError("temporary function-owner schema CREATE was not removed")
    finally:
        engine.dispose()


def _apply_grants_and_provision(config: BootstrapConfig) -> tuple[str, bool, bool]:
    roles_sql = render_realm_roles(
        realm_slug=config.stamp.realm_slug,
        routine_login=config.stamp.routine_login,
        policy_login=config.stamp.policy_login,
        workflow_login=config.stamp.workflow_login,
        finality_login=config.stamp.finality_login,
    )
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '10s'")
        connection.execute("SET LOCAL statement_timeout = '120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_ADMISSION_LOCK,))
        boundary = connection.execute(
            "SELECT (SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1(),"
            "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())"
        ).fetchone()
        if boundary != ("quarantined", True, True):
            raise BootstrapError("database left the reviewed commissioning boundary")
        connection.execute(roles_sql, prepare=False)
        foundation_inserted = apply_foundation(connection, config.stamp, config.seed)
        binding_inserted = apply_manifest(connection, config.stamp)
    digest = hashlib.sha256(roles_sql.encode("utf-8")).hexdigest()
    return digest, foundation_inserted, binding_inserted


def _verify(config: BootstrapConfig) -> dict[str, Any]:
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        revision = _scalar(connection, "SELECT version_num FROM public.alembic_version")
        admission = _scalar(connection, "SELECT state FROM lucy.runtime_admission WHERE singleton")
        safe = _scalar(connection, "SELECT lucy.capture_boundary_safe_v1()")
        scope_count = _scalar(
            connection,
            "SELECT count(*) FROM lucy.realm_content_scopes_v1 WHERE id=%s",
            (config.stamp.content_scope_id,),
        )
        actor_count = _scalar(
            connection,
            "SELECT count(*) FROM lucy.realm_sensitive_actor_bindings_v1 "
            "WHERE target_service_binding_id=%s AND active",
            (config.stamp.service_binding_id,),
        )
        executor_count = _scalar(
            connection,
            "SELECT count(*) FROM lucy.realm_executor_bindings_v2 "
            "WHERE content_scope_id=%s AND active",
            (config.stamp.content_scope_id,),
        )
        directory_signature = (
            "lucy.resolve_internal_admission_v1(text,text,text,uuid,uuid,uuid,bigint,uuid,"
            "bigint,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,bigint,timestamptz)"
        )
        directory_acl = {
            name: _scalar(
                connection,
                "SELECT has_function_privilege(%s,%s,'EXECUTE')",
                (name, directory_signature),
            )
            for name in {
                "lucy_app",
                "lucy_public_runtime",
                "lucy_directory_admission",
                *(str(url.username) for url in config.runtime_urls.values()),
            }
        }
        schema_boundary = connection.execute(
            "SELECT n.nspowner::regrole::text,"
            "has_schema_privilege('lucy_security_function_owner','lucy','CREATE'),"
            "has_schema_privilege('lucy_directory_function_owner','lucy','CREATE'),"
            "EXISTS(SELECT 1 FROM aclexplode(COALESCE(n.nspacl,"
            "acldefault('n',n.nspowner))) "
            "WHERE grantee=0 AND privilege_type='CREATE') "
            "FROM pg_namespace n WHERE n.nspname='lucy'"
        ).fetchone()
        if schema_boundary is None:
            raise BootstrapError("Lucy schema authority boundary is unavailable")
        residual_schema_create = (
            str(schema_boundary[0]) != "lucy_migration"
            or schema_boundary[1] is not False
            or schema_boundary[2] is not False
            or schema_boundary[3] is not False
        )
    if revision != EXPECTED_REVISION:
        raise BootstrapError("database did not reach the reviewed V1.3 migration head")
    if admission != "quarantined" or safe is not True:
        raise BootstrapError("database did not remain quarantined with capture disabled")
    if (scope_count, actor_count, executor_count) != (1, 4, 2):
        raise BootstrapError("realm foundation or immutable bindings are incomplete")
    if directory_acl.get("lucy_directory_admission") is not True or any(
        allowed
        for name, allowed in directory_acl.items()
        if name != "lucy_directory_admission"
    ):
        raise BootstrapError("directory admission function ACL is not isolated")
    if residual_schema_create:
        raise BootstrapError("temporary function-owner schema CREATE was not removed")

    verified_logins: list[str] = []
    for mode, url in config.runtime_urls.items():
        with psycopg.connect(_conninfo(url)) as connection:
            if _scalar(connection, "SELECT session_user") != url.username:
                raise BootstrapError(f"{mode} connected as the wrong runtime login")
            if _scalar(connection, "SELECT state FROM lucy.runtime_admission WHERE singleton") != (
                "quarantined"
            ):
                raise BootstrapError(f"{mode} did not observe quarantined admission")
            direct_content = _scalar(
                connection,
                "SELECT EXISTS(SELECT 1 FROM pg_class c "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname='lucy' AND c.relkind IN ('r','p') "
                "AND c.relname NOT IN ('lifecycle','runtime_admission') "
                "AND has_table_privilege(session_user,c.oid,"
                "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'))",
            )
            if direct_content:
                raise BootstrapError(f"{mode} has direct Lucy table authority")
        verified_logins.append(str(url.username))
    return {
        "migration_revision": revision,
        "runtime_admission": admission,
        "capture_enabled": False,
        "content_scope_count": scope_count,
        "active_actor_bindings": actor_count,
        "active_executor_bindings": executor_count,
        "directory_admission_acl_isolated": True,
        "offline_migration_schema_owner": True,
        "function_owner_schema_create_removed": True,
        "verified_runtime_logins": verified_logins,
    }


def run(config: BootstrapConfig) -> dict[str, Any]:
    source_revision = _stage("quarantine", lambda: _quarantine(config))
    _stage("role bootstrap", lambda: _bootstrap_roles(config))
    _stage("migration", lambda: _run_migrations(config))
    roles_digest, foundation_inserted, binding_inserted = _stage(
        "realm provisioning", lambda: _apply_grants_and_provision(config)
    )
    report = _stage("verification", lambda: _verify(config))
    report.update(
        {
            "contract": "lucy.realm-cloud-bootstrap.v1.3",
            "status": "passed",
            "realm_slug": config.stamp.realm_slug,
            "security_realm_id": str(config.stamp.security_realm_id),
            "source_revision": source_revision,
            "roles_sql_sha256": roles_digest,
            "foundation_digest": config.seed.digest_hex(),
            "stamp_digest": config.stamp.digest_hex(),
            "foundation_replayed": not foundation_inserted,
            "binding_replayed": not binding_inserted,
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
