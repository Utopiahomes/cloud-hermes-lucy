"""Provision the explicit service membership used by Workspaces admission."""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal, Self
from uuid import UUID

import psycopg
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from deploy.postgres.provision_realm_bindings_v1_3 import (
    _ADMISSION_LOCK,
    _LUCY_DATABASE,
    _MAINTENANCE_LOCK,
    _PRIVATE_RENDER_HOST,
    RealmProvisioningError,
    _conninfo,
    _database_url,
    _insert_exact,
    _required,
)
from lucy.contracts.canonical import canonical_sha256

AUTHORIZATION = "workspaces-service-authority-membership-v1"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SLUG = re.compile(r"[a-z][a-z0-9]{0,30}\Z")
_PREFIX = b"LUCY-WORKSPACES-AUTHORITY-MEMBERSHIP-V1\0"


class WorkspacesAuthorityMembershipV1(BaseModel):
    """Reviewed, content-free membership for one bound realm service principal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.workspaces-authority-membership.v1"] = (
        "lucy.workspaces-authority-membership.v1"
    )
    realm_slug: str = Field(min_length=1, max_length=31)
    membership_id: UUID
    service_principal_id: UUID
    service_binding_id: UUID
    workspace_id: UUID
    identity_issuer: str = Field(min_length=1, max_length=512)
    identity_subject: str = Field(min_length=1, max_length=512)
    role: Literal["member"] = "member"
    granted_at: datetime

    @model_validator(mode="after")
    def validate_boundary(self) -> Self:
        if _SLUG.fullmatch(self.realm_slug) is None:
            raise ValueError("realm slug is invalid")
        if self.granted_at.utcoffset() is None:
            raise ValueError("membership timestamp must be timezone-aware")
        return self

    def digest_hex(self) -> str:
        return canonical_sha256(self.model_dump(mode="python"), prefix=_PREFIX)


class WorkspacesAuthorityConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    migration_url: Any
    manifest: WorkspacesAuthorityMembershipV1

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> WorkspacesAuthorityConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise RealmProvisioningError("Workspaces authority requires production Render")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise RealmProvisioningError("transcript capture must remain disabled")
        if values.get("LUCY_WORKSPACES_AUTHORITY_AUTHORIZATION") != AUTHORIZATION:
            raise RealmProvisioningError("the reviewed Workspaces authorization is required")
        migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if (
            migration_url.username != "lucy_migration"
            or migration_url.host is None
            or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
            or migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
        ):
            raise RealmProvisioningError("Workspaces authority requires the migration login")
        try:
            manifest = WorkspacesAuthorityMembershipV1.model_validate_json(
                _required(values, "LUCY_WORKSPACES_AUTHORITY_MEMBERSHIP_JSON")
            )
        except (ValidationError, ValueError) as exc:
            raise RealmProvisioningError("Workspaces authority manifest is invalid") from exc
        reviewed = _required(values, "LUCY_WORKSPACES_AUTHORITY_MEMBERSHIP_SHA256")
        if _DIGEST.fullmatch(reviewed) is None or reviewed != manifest.digest_hex():
            raise RealmProvisioningError("Workspaces authority manifest digest does not match")
        return cls(migration_url=migration_url, manifest=manifest)


def apply_membership(
    connection: psycopg.Connection[Any], manifest: WorkspacesAuthorityMembershipV1
) -> bool:
    valid = connection.execute(
        "SELECT EXISTS(SELECT 1 FROM lucy.realm_service_bindings_v1 sb "
        "JOIN lucy.realm_content_scopes_v1 cs ON cs.id=sb.content_scope_id "
        "JOIN lucy.security_realms r ON r.id=cs.security_realm_id "
        "JOIN lucy.workspaces w ON w.id=cs.workspace_id "
        "JOIN lucy.principals p ON p.id=sb.service_principal_id "
        "WHERE sb.id=%s AND sb.service_principal_id=%s AND cs.workspace_id=%s "
        "AND r.slug=%s AND w.workspace_kind='private_realm' "
        "AND p.issuer=%s AND p.subject=%s AND p.principal_kind='service' "
        "AND p.status='active' AND sb.active "
        "AND sb.allowed_actions @> '[\"memory.read\",\"task.delegate\"]'::jsonb)",
        (
            manifest.service_binding_id,
            manifest.service_principal_id,
            manifest.workspace_id,
            manifest.realm_slug,
            manifest.identity_issuer,
            manifest.identity_subject,
        ),
    ).fetchone()
    if valid != (True,):
        raise RealmProvisioningError("bound Workspaces service authority is unavailable")
    existing = connection.execute(
        "SELECT id FROM lucy.node_memberships "
        "WHERE principal_id=%s AND workspace_id=%s AND id<>%s",
        (
            manifest.service_principal_id,
            manifest.workspace_id,
            manifest.membership_id,
        ),
    ).fetchone()
    if existing is not None:
        raise RealmProvisioningError("Workspaces service authority membership conflicts")
    return _insert_exact(
        connection,
        "node_memberships",
        "id",
        {
            "id": manifest.membership_id,
            "principal_id": manifest.service_principal_id,
            "workspace_id": manifest.workspace_id,
            "role": manifest.role,
            "status": "active",
            "generation": 1,
            "granted_at": manifest.granted_at,
        },
    )


def run(config: WorkspacesAuthorityConfig) -> dict[str, object]:
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '10s'")
        connection.execute("SET LOCAL statement_timeout = '120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_ADMISSION_LOCK,))
        boundary = connection.execute(
            "SELECT (SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1(),"
            "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),"
            "(SELECT version_num FROM alembic_version)"
        ).fetchone()
        if boundary != ("quarantined", True, True, "0068_workspaces_service_auth"):
            raise RealmProvisioningError("database is outside the Workspaces authority boundary")
        inserted = apply_membership(connection, config.manifest)
    return {
        "contract": "lucy.workspaces-authority-application.v1",
        "status": "passed",
        "realm_slug": config.manifest.realm_slug,
        "membership_digest": config.manifest.digest_hex(),
        "replayed": not inserted,
    }


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise RealmProvisioningError("this deployment utility accepts no command-line values")
    try:
        report = run(WorkspacesAuthorityConfig.from_environment())
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
