"""Read the content-free identifiers required for a Public Lucy R1 release."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping

import psycopg
from sqlalchemy.engine import URL

from deploy.postgres.bootstrap_realm_cloud_v1_3 import (
    _LUCY_DATABASE,
    _PRIVATE_RENDER_HOST,
    BootstrapError,
    _conninfo,
    _database_url,
)

AUTHORIZATION = "utopia-public-conversation-inspect-v1"


class PublicConversationInspectionError(RuntimeError):
    """The release-state inspection failed closed."""


def configuration_from_environment(
    environment: Mapping[str, str] | None = None,
) -> URL:
    values = os.environ if environment is None else environment
    if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
        raise PublicConversationInspectionError("inspection requires production Render")
    if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
        raise PublicConversationInspectionError("the inspection job must not capture transcripts")
    if values.get("LUCY_PUBLIC_CONVERSATION_INSPECT_AUTHORIZATION") != AUTHORIZATION:
        raise PublicConversationInspectionError("the exact inspection authorization is required")
    raw = values.get("LUCY_MIGRATION_DATABASE_URL", "").strip()
    if not raw:
        raise PublicConversationInspectionError("LUCY_MIGRATION_DATABASE_URL is required")
    try:
        migration_url = _database_url(raw)
    except BootstrapError as exc:
        raise PublicConversationInspectionError("the migration database URL is invalid") from exc
    if (
        migration_url.username != "lucy_migration"
        or migration_url.host is None
        or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
        or migration_url.database is None
        or _LUCY_DATABASE.fullmatch(migration_url.database) is None
        or migration_url.port not in (None, 5432)
    ):
        raise PublicConversationInspectionError("the migration database boundary differs")
    return migration_url


def inspect(migration_url: URL) -> dict[str, object]:
    with psycopg.connect(_conninfo(migration_url)) as connection:
        boundary = connection.execute(
            "SELECT current_user,(SELECT version_num FROM public.alembic_version),"
            "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "(SELECT storage_epoch FROM lucy.runtime_admission WHERE singleton),"
            "(SELECT state FROM lucy.lifecycle WHERE singleton),"
            "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())"
        ).fetchone()
        if (
            boundary is None
            or boundary[0] != "lucy_migration"
            or boundary[3] is None
            or boundary[4:] != ("ready", True)
        ):
            raise PublicConversationInspectionError("the database boundary differs")
        route = connection.execute(
            "SELECT c.id,n.slug,c.channel_kind,c.active,v.id,v.version,v.snapshot_digest "
            "FROM lucy.channel_bindings c JOIN lucy.nodes n ON n.id=c.node_id "
            "JOIN lucy.public_projection_routes r ON r.channel_binding_id=c.id "
            "JOIN lucy.public_projection_versions v ON v.id=r.active_version_id "
            "WHERE c.hostname='www.utopiahomes.com'"
        ).fetchall()
        if len(route) != 1 or route[0][1:4] != ("utopia", "website_public", True):
            raise PublicConversationInspectionError("the public channel differs")
        memberships = connection.execute(
            "SELECT m.role,m.principal_id FROM lucy.node_memberships m "
            "JOIN lucy.channel_bindings c ON c.workspace_id=m.workspace_id "
            "WHERE c.id=%s AND m.status='active' AND m.role IN ('publisher','approver') "
            "ORDER BY m.role",
            (route[0][0],),
        ).fetchall()
        by_role = {str(role): principal_id for role, principal_id in memberships}
        if (
            len(memberships) != 2
            or set(by_role) != {"publisher", "approver"}
            or by_role["publisher"] == by_role["approver"]
        ):
            raise PublicConversationInspectionError("the release actor separation differs")
    return {
        "contract": "lucy.utopia.public-conversation-inspection.v1",
        "status": "passed",
        "schema_revision": str(boundary[1]),
        "runtime_admission": str(boundary[2]),
        "storage_epoch": str(boundary[3]),
        "channel_binding_id": str(route[0][0]),
        "active_version_id": str(route[0][4]),
        "active_version": int(route[0][5]),
        "active_snapshot_digest": str(route[0][6]),
        "publisher_actor_id": str(by_role["publisher"]),
        "approver_actor_id": str(by_role["approver"]),
        "transcript_content_read": False,
    }


def main() -> int:
    try:
        report = inspect(configuration_from_environment())
    except PublicConversationInspectionError as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.utopia.public-conversation-inspection.v1",
                    "status": "failed",
                    "error": str(exc),
                },
                sort_keys=True,
            )
        )
        return 1
    except Exception as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.utopia.public-conversation-inspection.v1",
                    "status": "failed",
                    "error_type": type(exc).__name__,
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
