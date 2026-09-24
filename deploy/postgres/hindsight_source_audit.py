"""Count-only Raymond source and deletion audit for Hindsight backfill."""

from __future__ import annotations

import json
import os

import psycopg
from sqlalchemy.engine import make_url

from deploy.postgres.bootstrap_realm_cloud_v1_3 import _conninfo
from deploy.postgres.promote_raymond_interpretations_v1 import SCOPE_ID


def main() -> None:
    if os.environ.get("RENDER") != "true" or os.environ.get("LUCY_ENVIRONMENT") != "production":
        raise RuntimeError("Raymond source audit boundary unavailable")
    url = make_url(os.environ["LUCY_MIGRATION_DATABASE_URL"])
    if (url.host != "dpg-dak5bqad0e5s73b2e3d0-a"
            or url.database != "lucy_raymond"
            or url.username != "lucy_migration"
            or url.query.get("sslmode") != "require"):
        raise RuntimeError("Raymond source audit database differs")
    with psycopg.connect(_conninfo(url)) as connection:
        connection.execute("BEGIN READ ONLY")
        identity = connection.execute(
            "SELECT current_database(),session_user"
        ).fetchone()
        if identity != ("lucy_raymond", "lucy_migration"):
            raise RuntimeError("Raymond source audit login differs")
        scoped = connection.execute(
            "SELECT status,count(*) FROM lucy.scoped_evidence_records_v2 "
            "WHERE content_scope_id=%s GROUP BY status ORDER BY status", (SCOPE_ID,),
        ).fetchall()
        deletion_fences = connection.execute(
            "SELECT count(*) FROM lucy.scoped_evidence_deletion_fences_v2 "
            "WHERE content_scope_id=%s", (SCOPE_ID,),
        ).fetchone()
        recovery_fences = connection.execute(
            "SELECT count(*) FROM lucy.scoped_recovery_deletion_fences_v2 "
            "WHERE content_scope_id=%s", (SCOPE_ID,),
        ).fetchone()
        captures = connection.execute(
            "SELECT count(*),count(*) FILTER (WHERE capture_enabled) "
            "FROM lucy.scoped_capture_receipts_v1 "
            "WHERE content_scope_id=%s AND platform='telegram'", (SCOPE_ID,),
        ).fetchone()
        archive_roles = connection.execute(
            "SELECT count(*) FILTER (WHERE right(idempotency_key,5)=':user'),"
            "count(*) FILTER (WHERE right(idempotency_key,10)=':assistant') "
            "FROM lucy.scoped_archive_intents_v1 WHERE content_scope_id=%s "
            "AND content_classification='owner_conversation'", (SCOPE_ID,),
        ).fetchone()
        commits = connection.execute(
            "SELECT count(*) FROM lucy.scoped_conversation_turn_commits_v1 "
            "WHERE content_scope_id=%s", (SCOPE_ID,),
        ).fetchone()
    print("HINDSIGHT_SOURCE_AUDIT:" + json.dumps({
        "scope": str(SCOPE_ID),
        "scoped_evidence_by_status": scoped,
        "deletion_fences": deletion_fences[0] if deletion_fences else None,
        "recovery_deletion_fences": recovery_fences[0] if recovery_fences else None,
        "telegram_capture_receipts": captures,
        "telegram_archived_roles": archive_roles,
        "telegram_committed_turns": commits[0] if commits else None,
        "content_read": False,
    }, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
