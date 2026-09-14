"""Reopen the existing Utopia runtime after Public Lucy R1 activation.

This gate preserves the reviewed storage epoch and the existing encrypted
Private Lucy capture mode.  It only reopens admission after the exact approved
public digest is active, all runtime database sessions are stopped, and the
execute-only public grant is installed.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from typing import Any

import psycopg

from deploy.postgres import commission_realm_runtime_v1_3 as commission
from lucy.readiness import ADMISSION_LOCK, PUBLIC_CONVERSATION_SCHEMA_REVISION

AUTHORIZATION = "utopia-public-conversation-reopen-v1"
MAINTENANCE_LOCK = 0x4C5543594D53
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class PublicConversationReopenError(RuntimeError):
    """The post-activation runtime reopen failed closed."""


def configuration_from_environment(
    environment: Mapping[str, str] | None = None,
) -> tuple[commission.CommissionConfig, str, bool]:
    values = os.environ if environment is None else environment
    if values.get("LUCY_PUBLIC_CONVERSATION_REOPEN_AUTHORIZATION") != AUTHORIZATION:
        raise PublicConversationReopenError("the exact reopen authorization is required")
    if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
        raise PublicConversationReopenError("the reopen job must not capture transcripts")
    digest = values.get("LUCY_PUBLIC_SNAPSHOT_DIGEST", "").strip()
    if _DIGEST.fullmatch(digest) is None:
        raise PublicConversationReopenError("the approved public digest is invalid")
    expected_capture = values.get("LUCY_EXPECTED_PRIVATE_CAPTURE_ENABLED")
    if expected_capture not in {"true", "false"}:
        raise PublicConversationReopenError("the expected private capture state is required")
    try:
        config = commission.CommissionConfig.from_environment("status", values)
    except commission.CommissionError as exc:
        raise PublicConversationReopenError("the realm configuration is invalid") from exc
    return config, digest, expected_capture == "true"


def _scalar(connection: psycopg.Connection[Any], query: str, params: tuple[Any, ...] = ()) -> Any:
    row = connection.execute(query, params).fetchone()
    if row is None:
        raise PublicConversationReopenError("a required database result is unavailable")
    return row[0]


def reopen(
    config: commission.CommissionConfig,
    snapshot_digest: str,
    expected_private_capture: bool,
) -> dict[str, object]:
    stamp, runtime_epoch, _ = commission._full_config(config)
    with psycopg.connect(commission._conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout='15s'")
        connection.execute("SET LOCAL statement_timeout='120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (ADMISSION_LOCK,))
        state, epoch = commission._verify_target_boundary(connection)
        if _scalar(connection, "SELECT version_num FROM public.alembic_version") != (
            PUBLIC_CONVERSATION_SCHEMA_REVISION
        ):
            raise PublicConversationReopenError("the database is not at Public Lucy R1")
        if state != "quarantined" or epoch != runtime_epoch:
            raise PublicConversationReopenError("the quarantined storage epoch differs")
        commission._verify_open_boundary(connection, config, ())
        capture_enabled = bool(
            _scalar(
                connection,
                "SELECT EXISTS(SELECT 1 FROM lucy.scoped_capture_states_v1 "
                "WHERE content_scope_id=%s AND capture_enabled)",
                (stamp.content_scope_id,),
            )
        )
        if capture_enabled != expected_private_capture:
            raise PublicConversationReopenError("the private capture state changed")
        pending = commission._work_in_flight(connection, config)
        sessions = commission._runtime_sessions(connection, config)
        if pending or sessions:
            raise PublicConversationReopenError("runtime work or sessions remain active")
        active = connection.execute(
            "SELECT n.slug,c.hostname,v.snapshot_digest "
            "FROM lucy.channel_bindings c JOIN lucy.nodes n ON n.id=c.node_id "
            "JOIN lucy.public_projection_routes r ON r.channel_binding_id=c.id "
            "JOIN lucy.public_projection_versions v ON v.id=r.active_version_id "
            "WHERE c.hostname='www.utopiahomes.com' AND c.active"
        ).fetchone()
        if active != ("utopia", "www.utopiahomes.com", snapshot_digest):
            raise PublicConversationReopenError("the active public route differs")
        public_grant = _scalar(
            connection,
            "SELECT has_function_privilege('lucy_utopia_public',"
            "'lucy.public_projection_knowledge_v1(text,uuid)','EXECUTE')",
        )
        if public_grant is not True:
            raise PublicConversationReopenError("the public execute-only grant is unavailable")
        connection.execute(
            "UPDATE lucy.runtime_admission SET state='ready',updated_at=now() WHERE singleton"
        )
    return {
        "contract": "lucy.utopia.public-conversation-reopen.v1",
        "status": "passed",
        "schema_revision": PUBLIC_CONVERSATION_SCHEMA_REVISION,
        "runtime_admission": "ready",
        "runtime_epoch_preserved": True,
        "private_capture_state_preserved": True,
        "active_snapshot_digest": snapshot_digest,
        "unresolved_sensitive_authority": 0,
        "runtime_sessions": 0,
        "public_execute_only_grant": True,
    }


def main() -> int:
    try:
        config, digest, expected_capture = configuration_from_environment()
        report = reopen(config, digest, expected_capture)
    except PublicConversationReopenError as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.utopia.public-conversation-reopen.v1",
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
                    "contract": "lucy.utopia.public-conversation-reopen.v1",
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
