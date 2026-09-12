"""Provision one reviewed V1.3 realm stamp while production admission is closed."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb
from pydantic import ValidationError
from sqlalchemy.engine import URL, make_url

from lucy.realm_provisioning import RealmSecurityStampV1

AUTHORIZATION = "security-v1.3-quarantined-realm-binding-provision"
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LUCY_DATABASE = re.compile(r"lucy(?:_[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAINTENANCE_LOCK = 0x4C5543594D53
_ADMISSION_LOCK = 0x4C5543594144


class RealmProvisioningError(RuntimeError):
    """Realm provisioning failed closed without admitting a partial stamp."""


@dataclass(frozen=True)
class RealmProvisioningConfig:
    migration_url: URL
    manifest: RealmSecurityStampV1
    reviewed_digest: str

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> RealmProvisioningConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise RealmProvisioningError("provisioning requires the production Render runtime")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise RealmProvisioningError("transcript capture must remain disabled")
        if values.get("LUCY_REALM_PROVISIONING_AUTHORIZATION") != AUTHORIZATION:
            raise RealmProvisioningError(
                "the exact reviewed provisioning authorization is required"
            )
        migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if (
            migration_url.username != "lucy_migration"
            or migration_url.host is None
            or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
            or migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
        ):
            raise RealmProvisioningError("provisioning requires the private Lucy migration login")
        try:
            manifest = RealmSecurityStampV1.model_validate_json(
                _required(values, "LUCY_REALM_SECURITY_STAMP_JSON")
            )
        except (ValidationError, ValueError) as exc:
            raise RealmProvisioningError("realm security stamp is invalid") from exc
        reviewed_digest = _required(values, "LUCY_REALM_SECURITY_STAMP_SHA256")
        if _DIGEST.fullmatch(reviewed_digest) is None or reviewed_digest != manifest.digest_hex():
            raise RealmProvisioningError("realm security stamp digest does not match")
        return cls(migration_url, manifest, reviewed_digest)


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise RealmProvisioningError(f"missing required configuration: {name}")
    return value


def _database_url(raw: str) -> URL:
    parsed = make_url(raw)
    if parsed.drivername not in {"postgresql", "postgresql+psycopg"}:
        raise RealmProvisioningError("only PostgreSQL psycopg URLs are accepted")
    if not parsed.username or not parsed.password or not parsed.host or not parsed.database:
        raise RealmProvisioningError("database URL requires user, password, host, and database")
    return parsed.set(drivername="postgresql+psycopg").update_query_dict({"sslmode": "require"})


def _conninfo(url: URL) -> str:
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


def _check_roles(connection: psycopg.Connection[Any], manifest: RealmSecurityStampV1) -> None:
    logins = (
        manifest.routine_login,
        manifest.policy_login,
        manifest.workflow_login,
        manifest.finality_login,
    )
    rows = connection.execute(
        "SELECT rolname,rolcanlogin,rolsuper,rolcreaterole,rolcreatedb,rolinherit,"
        "rolreplication,rolbypassrls FROM pg_roles WHERE rolname=ANY(%s)",
        (list(logins),),
    ).fetchall()
    if len(rows) != 4:
        raise RealmProvisioningError("one or more stamped PostgreSQL LOGINs are missing")
    for row in rows:
        if row[1:] != (True, False, False, False, False, False, False):
            raise RealmProvisioningError(f"stamped PostgreSQL LOGIN is elevated: {row[0]}")
    members = connection.execute(
        "SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member "
        "WHERE r.rolname=ANY(%s)",
        (list(logins),),
    ).fetchall()
    if members:
        raise RealmProvisioningError("stamped PostgreSQL LOGIN has inherited membership")


def _check_foundation(
    connection: psycopg.Connection[Any], manifest: RealmSecurityStampV1
) -> None:
    valid = connection.execute(
        "SELECT EXISTS(SELECT 1 FROM lucy.tenant_accounts a "
        "JOIN lucy.nodes n ON n.id=%s "
        "JOIN lucy.node_tenures t ON t.id=%s AND t.node_id=n.id "
        "AND t.account_id=a.id AND t.sequence=%s AND t.ends_at IS NULL "
        "JOIN lucy.security_realms r ON r.id=%s AND r.slug=%s "
        "JOIN lucy.realm_bindings b ON b.id=%s AND b.tenure_id=t.id "
        "AND b.realm_id=r.id AND b.valid_to IS NULL "
        "JOIN lucy.workspaces w ON w.id=%s AND w.node_id=n.id AND w.tenure_id=t.id "
        "WHERE a.id=%s) AND NOT EXISTS("
        "SELECT 1 FROM (VALUES (%s),(%s),(%s),(%s)) AS expected(id) "
        "LEFT JOIN lucy.principals p ON p.id=expected.id "
        "WHERE p.id IS NULL OR p.status<>'active' OR p.principal_kind<>'service')",
        (
            manifest.node_id,
            manifest.node_tenure_id,
            manifest.tenure_epoch,
            manifest.security_realm_id,
            manifest.realm_slug,
            manifest.realm_binding_id,
            manifest.workspace_id,
            manifest.tenant_account_id,
            manifest.routine_principal_id,
            manifest.policy_principal_id,
            manifest.workflow_principal_id,
            manifest.finality_principal_id,
        ),
    ).fetchone()
    if valid != (True,):
        raise RealmProvisioningError("stamped realm foundation or principals are unavailable")


def _insert_exact(
    connection: psycopg.Connection[Any],
    table: str,
    key_column: str,
    values: Mapping[str, Any],
) -> bool:
    columns = tuple(values)
    parameters = tuple(
        Jsonb(value) if isinstance(value, (list, dict)) else value
        for value in values.values()
    )
    statement = sql.SQL("INSERT INTO lucy.{} ({}) VALUES ({}) ON CONFLICT DO NOTHING").format(
        sql.Identifier(table),
        sql.SQL(",").join(map(sql.Identifier, columns)),
        sql.SQL(",").join(sql.Placeholder() for _ in columns),
    )
    inserted = connection.execute(statement, parameters).rowcount == 1
    compared_columns = tuple(column for column in columns if column != "created_at")
    selected = connection.execute(
        sql.SQL("SELECT {} FROM lucy.{} WHERE {}=%s").format(
            sql.SQL(",").join(map(sql.Identifier, compared_columns)),
            sql.Identifier(table),
            sql.Identifier(key_column),
        ),
        (values[key_column],),
    ).fetchone()
    expected = tuple(values[column] for column in compared_columns)
    if selected is None or tuple(selected) != expected:
        raise RealmProvisioningError(f"existing {table} row conflicts with reviewed stamp")
    return inserted


def apply_manifest(
    connection: psycopg.Connection[Any], manifest: RealmSecurityStampV1
) -> bool:
    """Insert the complete stamp transactionally; return False on exact replay."""

    _check_roles(connection, manifest)
    _check_foundation(connection, manifest)
    now = connection.execute("SELECT clock_timestamp()").fetchone()
    if now is None:
        raise RealmProvisioningError("database time is unavailable")
    created_at = now[0]
    inserted: list[bool] = []
    inserted.append(
        _insert_exact(
            connection,
            "realm_content_scopes_v1",
            "id",
            {
                "id": manifest.content_scope_id,
                "tenant_account_id": manifest.tenant_account_id,
                "node_id": manifest.node_id,
                "node_tenure_id": manifest.node_tenure_id,
                "tenure_epoch": manifest.tenure_epoch,
                "security_realm_id": manifest.security_realm_id,
                "storage_epoch": manifest.storage_epoch,
                "realm_binding_id": manifest.realm_binding_id,
                "workspace_id": manifest.workspace_id,
                "deployment_id": manifest.deployment_id,
                "created_at": created_at,
            },
        )
    )
    inserted.append(
        _insert_exact(
            connection,
            "realm_service_bindings_v1",
            "id",
            {
                "id": manifest.service_binding_id,
                "session_login": manifest.routine_login,
                "service_principal_id": manifest.routine_principal_id,
                "content_scope_id": manifest.content_scope_id,
                "service_role": "realm_evidence",
                "allowed_actions": [
                    "evidence.archive",
                    "evidence.retrieve",
                    "evidence.delete",
                    "memory.read",
                    "memory.propose",
                ],
                "binding_generation": manifest.binding_generation,
                "node_authz_epoch": manifest.node_authz_epoch,
                "active": True,
                "created_at": created_at,
                "policy_version": manifest.policy_version,
            },
        )
    )
    actors = (
        (
            manifest.archive_actor_binding_id,
            manifest.routine_login,
            manifest.routine_principal_id,
            "archive_writer",
            ["evidence.archive"],
        ),
        (
            manifest.policy_actor_binding_id,
            manifest.policy_login,
            manifest.policy_principal_id,
            "policy_notary",
            [
                "sensitive.permit.issue",
                "sensitive.grant.issue",
                "sensitive.receipt.attest",
                "sensitive.deletion_manifest.issue",
                "memory.candidate.approve",
                "memory.candidate.promote",
                "memory.protected.read",
            ],
        ),
        (
            manifest.workflow_actor_binding_id,
            manifest.workflow_login,
            manifest.workflow_principal_id,
            "sensitive_workflow",
            ["sensitive.operation.claim", "sensitive.operation.reconcile"],
        ),
        (
            manifest.finality_actor_binding_id,
            manifest.finality_login,
            manifest.finality_principal_id,
            "finality_verifier",
            ["sensitive.finality.record"],
        ),
    )
    for binding_id, login, principal_id, role, actions in actors:
        inserted.append(
            _insert_exact(
                connection,
                "realm_sensitive_actor_bindings_v1",
                "id",
                {
                    "id": binding_id,
                    "session_login": login,
                    "actor_principal_id": principal_id,
                    "target_service_binding_id": manifest.service_binding_id,
                    "content_scope_id": manifest.content_scope_id,
                    "actor_role": role,
                    "allowed_actions": actions,
                    "binding_generation": manifest.binding_generation,
                    "node_authz_epoch": manifest.node_authz_epoch,
                    "policy_version": manifest.policy_version,
                    "active": True,
                    "created_at": created_at,
                },
            )
        )
    for action, executor in (
        ("evidence.retrieve", manifest.retrieval_executor),
        ("evidence.delete", manifest.deletion_executor),
    ):
        inserted.append(
            _insert_exact(
                connection,
                "realm_executor_bindings_v2",
                "id",
                {
                    "id": executor.binding_id,
                    "content_scope_id": manifest.content_scope_id,
                    "action": action,
                    "caller_identity": executor.caller_identity,
                    "executor_identity": executor.executor_identity,
                    "executor_alias_arn": executor.executor_alias_arn,
                    "executor_version": executor.executor_version,
                    "receipt_key_id": executor.receipt_key_id,
                    "binding_generation": manifest.binding_generation,
                    "node_authz_epoch": manifest.node_authz_epoch,
                    "policy_version": manifest.policy_version,
                    "active": True,
                    "created_at": created_at,
                },
            )
        )
    if any(inserted) and not all(inserted):
        raise RealmProvisioningError("realm stamp exists only partially")
    return all(inserted)


def run(config: RealmProvisioningConfig) -> dict[str, Any]:
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '10s'")
        connection.execute("SET LOCAL statement_timeout = '120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_ADMISSION_LOCK,))
        tls = connection.execute(
            "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
        ).fetchone()
        boundary = connection.execute(
            "SELECT (SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1()"
        ).fetchone()
        if tls != (True,) or boundary != ("quarantined", True):
            raise RealmProvisioningError("database is outside the reviewed provisioning boundary")
        inserted = apply_manifest(connection, config.manifest)
    return {
        "contract": "lucy.realm-security-stamp-application.v1",
        "status": "passed",
        "realm_slug": config.manifest.realm_slug,
        "security_realm_id": str(config.manifest.security_realm_id),
        "content_scope_id": str(config.manifest.content_scope_id),
        "stamp_digest": config.reviewed_digest,
        "replayed": not inserted,
    }


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        raise RealmProvisioningError("this deployment utility accepts no command-line values")
    try:
        report = run(RealmProvisioningConfig.from_environment())
    except RealmProvisioningError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
