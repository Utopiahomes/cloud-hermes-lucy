"""Bootstrap the isolated Tiamat staging ledger from a disposable owner-only runner.

This command is intentionally one-time operational tooling. It migrates only the dedicated Tiamat
schema through the reviewed head, creates the three least-privilege roles, activates only the two
roles with existing service boundaries, verifies each active login over the private TLS connection,
and emits content-free evidence. The release-manager role remains NOLOGIN until its own boundary
exists, so no password has to be retained without an owner. It neither initializes the ledger,
contacts AWS, installs an anchor, nor enables provider dispatch.

The owner URL and two active-role passwords must be Render service secrets attached only to the
temporary runner. They are never printed, written, or returned by this command.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql
from render_tiamat_role_template_v1 import render_role_template
from sqlalchemy.engine import URL, make_url

ROOT = Path(__file__).resolve().parents[2]
MIGRATION_HEAD = "0005_ledger_identity"
ROLE_NAMES = ("tiamat_runtime", "tiamat_recovery", "tiamat_release_manager")
ACTIVE_BOOTSTRAP_ROLES = ("tiamat_runtime", "tiamat_recovery")
ROLE_PASSWORD_ENV = {
    "tiamat_runtime": "TIAMAT_RUNTIME_PASSWORD",
    "tiamat_recovery": "TIAMAT_RECOVERY_PASSWORD",
}
ROLE_PERMISSION_PROBES = {
    "tiamat_runtime": "SELECT count(*) FROM tiamat.execution_records",
    "tiamat_recovery": "SELECT ledger_id FROM tiamat.ledger_identity WHERE singleton",
}


class BootstrapRejected(RuntimeError):
    """The temporary runner configuration is unsafe or incomplete."""


@dataclass(frozen=True)
class BootstrapConfig:
    environment: str
    database_name: str
    owner_url: URL
    role_urls: dict[str, URL]


@dataclass(frozen=True)
class BootstrapReport:
    environment: str
    database_name: str
    migration_head: str
    verified_logins: tuple[str, ...]
    dispatch_enabled: bool
    secrets_recorded: bool


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise BootstrapRejected(f"{name} is required")
    return value


def _parse_private_tls_url(value: str, *, expected_username: str | None = None) -> URL:
    try:
        parsed = make_url(value)
    except Exception as exc:  # SQLAlchemy exposes multiple parse exceptions.
        raise BootstrapRejected("database URL is invalid") from exc
    if parsed.drivername not in {"postgresql", "postgresql+psycopg"}:
        raise BootstrapRejected("only PostgreSQL psycopg URLs are accepted")
    if not parsed.host or not parsed.database or not parsed.username or parsed.password is None:
        raise BootstrapRejected("database URL must contain host, database, username, and password")
    supplied_sslmode = parsed.query.get("sslmode")
    if supplied_sslmode not in {None, "require"}:
        raise BootstrapRejected("database URL must not weaken Render internal TLS")
    if expected_username is not None and parsed.username != expected_username:
        raise BootstrapRejected("database URL has an unexpected login")
    # Render's dashboard supplies a private URL without a query string. Always set the exact
    # required mode here rather than accepting a connection whose transport would be ambiguous.
    # Alembic opens this URL through SQLAlchemy. Pin its psycopg v3 dialect here as
    # well, otherwise a dashboard-supplied ``postgresql://`` URL makes SQLAlchemy
    # try its legacy psycopg2 dialect even though the image deliberately ships
    # psycopg v3 only.
    return parsed.set(drivername="postgresql+psycopg").update_query_dict({"sslmode": "require"})


def _role_url(owner_url: URL, *, role: str, password: str) -> URL:
    if len(password) < 24:
        raise BootstrapRejected(f"{ROLE_PASSWORD_ENV[role]} must contain at least 24 characters")
    return (
        owner_url.set(username=role, password=password)
        .update_query_dict({"sslmode": "require"})
    )


def load_config_from_environment() -> BootstrapConfig:
    environment = _required("TIAMAT_ENVIRONMENT")
    owner_url = _parse_private_tls_url(_required("TIAMAT_BOOTSTRAP_DATABASE_URL"))
    if owner_url.username in ROLE_NAMES:
        raise BootstrapRejected("temporary bootstrap owner must not be a Tiamat serving login")
    role_urls = {
        role: _role_url(owner_url, role=role, password=_required(password_env))
        for role, password_env in ROLE_PASSWORD_ENV.items()
    }
    return BootstrapConfig(
        environment=environment,
        database_name=str(owner_url.database),
        owner_url=owner_url,
        role_urls=role_urls,
    )


def _connection_info(url: URL) -> str:
    return url.render_as_string(hide_password=False).replace(
        "postgresql+psycopg://", "postgresql://", 1
    )


def _migrate(owner_url: URL) -> None:
    config = Config(str(ROOT / "tiamat_alembic.ini"))
    config.set_main_option("sqlalchemy.url", owner_url.render_as_string(hide_password=False))
    command.upgrade(config, MIGRATION_HEAD)


def _existing_roles(connection: psycopg.Connection[Any]) -> set[str]:
    rows = connection.execute(
        "SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (list(ROLE_NAMES),)
    ).fetchall()
    return {str(row[0]) for row in rows}


def _assert_role_flags(connection: psycopg.Connection[Any]) -> None:
    rows = connection.execute(
        "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication, "
        "rolbypassrls, rolinherit, rolcanlogin FROM pg_roles WHERE rolname = ANY(%s)",
        (list(ROLE_NAMES),),
    ).fetchall()
    if len(rows) != len(ROLE_NAMES):
        raise BootstrapRejected("one or more Tiamat roles are missing")
    for name, superuser, createdb, createrole, replication, bypass_rls, inherit, can_login in rows:
        name_text = str(name)
        expected_bypass = name_text == "tiamat_recovery"
        expected_login = name_text in ACTIVE_BOOTSTRAP_ROLES
        if (
            bool(superuser)
            or bool(createdb)
            or bool(createrole)
            or bool(replication)
            or bool(inherit)
            or bool(can_login) != expected_login
            or bool(bypass_rls) != expected_bypass
        ):
            raise BootstrapRejected(f"Tiamat role flags are unsafe: {name}")
    memberships = connection.execute(
        "SELECT member.rolname FROM pg_auth_members membership "
        "JOIN pg_roles member ON member.oid = membership.member "
        "WHERE member.rolname = ANY(%s)",
        (list(ROLE_NAMES),),
    ).fetchall()
    if memberships:
        raise BootstrapRejected("Tiamat login roles must not inherit membership")


def _create_and_password_roles(config: BootstrapConfig) -> None:
    with psycopg.connect(_connection_info(config.owner_url)) as connection:
        existing = _existing_roles(connection)
        if existing and existing != set(ROLE_NAMES):
            raise BootstrapRejected("partial Tiamat role bootstrap requires manual remediation")
        if not existing:
            connection.execute(render_role_template(config.database_name), prepare=False)
        _assert_role_flags(connection)
        for role, role_url in config.role_urls.items():
            assert role_url.password is not None
            connection.execute(
                sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(role_url.password)
                )
            )


def _verify_role_connections(config: BootstrapConfig) -> None:
    for role, role_url in config.role_urls.items():
        with psycopg.connect(_connection_info(role_url)) as connection:
            current_user = connection.execute("SELECT current_user").fetchone()
            if current_user is None or str(current_user[0]) != role:
                raise BootstrapRejected("role authentication did not bind the expected login")
            connection.execute(ROLE_PERMISSION_PROBES[role]).fetchone()


def bootstrap_tiamat_staging(config: BootstrapConfig) -> BootstrapReport:
    _migrate(config.owner_url)
    _create_and_password_roles(config)
    _verify_role_connections(config)
    return BootstrapReport(
        environment=config.environment,
        database_name=config.database_name,
        migration_head=MIGRATION_HEAD,
        verified_logins=ACTIVE_BOOTSTRAP_ROLES,
        dispatch_enabled=False,
        secrets_recorded=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-bootstrap",
        help="Required exact acknowledgement: bootstrap:<environment>:<database>",
    )
    args = parser.parse_args()
    config = load_config_from_environment()
    expected_confirmation = f"bootstrap:{config.environment}:{config.database_name}"
    if args.confirm_bootstrap != expected_confirmation:
        raise BootstrapRejected(f"confirmation must equal {expected_confirmation!r}")
    report = bootstrap_tiamat_staging(config)
    print(json.dumps(asdict(report), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
