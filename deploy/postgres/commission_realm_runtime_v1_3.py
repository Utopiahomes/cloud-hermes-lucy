"""Open or quarantine one V1.3 realm for bounded synthetic commissioning.

Run only as a temporary Render migration job. The command emits content-free
state and never returns database URLs, customer content, or realm identifiers.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID

import psycopg
from pydantic import ValidationError
from sqlalchemy.engine import URL, make_url

from lucy.readiness import ADMISSION_LOCK, R1_SCHEMA_REVISION
from lucy.realm_provisioning import RealmSecurityStampV1

Action = Literal["status", "open", "quarantine"]

AUTHORIZATIONS: dict[Action, str] = {
    "status": "security-v1.3-commission-status",
    "open": "security-v1.3-synthetic-open-capture-disabled",
    "quarantine": "security-v1.3-commission-quarantine",
}
MAINTENANCE_LOCK = 0x4C5543594D53
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LUCY_DATABASE = re.compile(r"lucy(?:_[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class CommissionError(RuntimeError):
    """A content-free commissioning precondition failure."""


@dataclass(frozen=True)
class CommissionConfig:
    migration_url: URL
    stamp: RealmSecurityStampV1 | None
    runtime_epoch: UUID | None
    declared_capture_enabled: bool | None
    approved_synthetic_receipts: frozenset[tuple[str, str]]

    @classmethod
    def from_environment(
        cls,
        action: Action,
        environment: Mapping[str, str] | None = None,
    ) -> CommissionConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise CommissionError("commissioning requires the production Render runtime")
        capture_value = values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED")
        if action != "quarantine" and capture_value not in {"true", "false"}:
            raise CommissionError("transcript capture declaration is missing or invalid")
        declared_capture_enabled = capture_value == "true"
        if action == "open" and declared_capture_enabled:
            raise CommissionError("transcript capture must remain disabled")
        migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if migration_url.username != "lucy_migration":
            raise CommissionError("the migration URL must use lucy_migration")
        if migration_url.host is None or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None:
            raise CommissionError("the migration URL must use the private Render database host")
        if (
            migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
        ):
            raise CommissionError("the migration URL must target the reviewed Lucy database")
        stamp = None
        runtime_epoch = None
        approved_synthetic_receipts: frozenset[tuple[str, str]] = frozenset()
        if action != "quarantine":
            try:
                stamp = RealmSecurityStampV1.model_validate_json(
                    _required(values, "LUCY_REALM_SECURITY_STAMP_JSON")
                )
                runtime_epoch = UUID(_required(values, "LUCY_STORAGE_EPOCH"))
            except (ValidationError, ValueError) as exc:
                raise CommissionError("realm commissioning input is invalid") from exc
            digest = _required(values, "LUCY_REALM_SECURITY_STAMP_SHA256")
            if _DIGEST.fullmatch(digest) is None or digest != stamp.digest_hex():
                raise CommissionError("realm commissioning digest does not match")
            approved_synthetic_receipts = _approved_synthetic_receipts(
                values.get("LUCY_APPROVED_SYNTHETIC_CAPTURE_RECEIPTS_JSON", "[]")
            )
        return cls(
            migration_url=migration_url,
            stamp=stamp,
            runtime_epoch=runtime_epoch,
            declared_capture_enabled=(
                declared_capture_enabled if capture_value in {"true", "false"} else None
            ),
            approved_synthetic_receipts=approved_synthetic_receipts,
        )


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise CommissionError(f"missing required configuration: {name}")
    return value


def _database_url(raw: str) -> URL:
    try:
        parsed = make_url(raw)
    except Exception as exc:
        raise CommissionError("invalid PostgreSQL URL") from exc
    if parsed.drivername not in {"postgresql", "postgresql+psycopg"}:
        raise CommissionError("only PostgreSQL psycopg URLs are accepted")
    if not parsed.username or not parsed.password or not parsed.host or not parsed.database:
        raise CommissionError("database URLs require user, password, host, and database")
    return parsed.set(drivername="postgresql+psycopg").update_query_dict({"sslmode": "require"})


def _approved_synthetic_receipts(raw: str) -> frozenset[tuple[str, str]]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CommissionError("approved synthetic receipt list is invalid") from exc
    if not isinstance(value, list) or len(value) > 20:
        raise CommissionError("approved synthetic receipt list is invalid")
    receipts: set[tuple[str, str]] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "source_conversation_id",
            "source_turn_id",
        }:
            raise CommissionError("approved synthetic receipt list is invalid")
        conversation = item["source_conversation_id"]
        turn = item["source_turn_id"]
        if (
            not isinstance(conversation, str)
            or not isinstance(turn, str)
            or not conversation.startswith("synthetic-")
            or not turn.startswith("synthetic-")
            or len(conversation) > 512
            or len(turn) > 512
        ):
            raise CommissionError("approved synthetic receipt list is invalid")
        receipts.add((conversation, turn))
    if len(receipts) != len(value):
        raise CommissionError("approved synthetic receipt list contains duplicates")
    return frozenset(receipts)


def _conninfo(url: URL) -> str:
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


def _scalar(
    connection: psycopg.Connection[Any], query: str, params: tuple[Any, ...] | None = None
) -> Any:
    row = connection.execute(query, params).fetchone()
    if row is None:
        raise CommissionError("database verification query returned no row")
    return row[0]


def _full_config(config: CommissionConfig) -> tuple[RealmSecurityStampV1, UUID, bool]:
    if (
        config.stamp is None
        or config.runtime_epoch is None
        or config.declared_capture_enabled is None
    ):
        raise CommissionError("full realm commissioning configuration is required")
    return config.stamp, config.runtime_epoch, config.declared_capture_enabled


def _verify_target_boundary(
    connection: psycopg.Connection[Any],
) -> tuple[str, UUID | None]:
    if _scalar(connection, "SELECT current_user") != "lucy_migration":
        raise CommissionError("database session is not the migration owner")
    if _scalar(connection, "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()") is not True:
        raise CommissionError("database connection is not TLS protected")
    admission = connection.execute(
        "SELECT state,storage_epoch FROM lucy.runtime_admission WHERE singleton"
    ).fetchone()
    if admission is None:
        raise CommissionError("storage admission row is unavailable")
    return str(admission[0]), admission[1]


def _verify_reviewed_revision(connection: psycopg.Connection[Any]) -> None:
    if _scalar(connection, "SELECT version_num FROM public.alembic_version") != R1_SCHEMA_REVISION:
        raise CommissionError("database is not at the reviewed V1.3 revision")


def _capture_enabled(connection: psycopg.Connection[Any], config: CommissionConfig) -> bool:
    stamp, _, declared_capture_enabled = _full_config(config)
    legacy_unsafe = _scalar(connection, "SELECT NOT lucy.capture_boundary_safe_v1()")
    scoped_enabled = _scalar(
        connection,
        "SELECT EXISTS(SELECT 1 FROM lucy.scoped_capture_states_v1 "
        "WHERE content_scope_id=%s AND capture_enabled)",
        (stamp.content_scope_id,),
    )
    enabled_receipts = set(
        connection.execute(
            "SELECT source_conversation_id,source_turn_id "
            "FROM lucy.scoped_capture_receipts_v1 "
            "WHERE content_scope_id=%s AND capture_enabled",
            (stamp.content_scope_id,),
        ).fetchall()
    )
    unapproved_receipts = enabled_receipts - config.approved_synthetic_receipts
    return bool(
        declared_capture_enabled
        or legacy_unsafe
        or scoped_enabled
        or unapproved_receipts
    )


def _verify_open_boundary(
    connection: psycopg.Connection[Any], config: CommissionConfig, capture_enabled: bool
) -> None:
    if capture_enabled:
        raise CommissionError("database capture boundary is not safe")
    if _scalar(connection, "SELECT state FROM lucy.lifecycle WHERE singleton") != "ready":
        raise CommissionError("control-plane recovery is not ready")

    stamp, _, _ = _full_config(config)
    scope = connection.execute(
        "SELECT tenant_account_id,node_id,node_tenure_id,tenure_epoch,security_realm_id,"
        "storage_epoch,realm_binding_id,workspace_id,deployment_id "
        "FROM lucy.realm_content_scopes_v1 WHERE id=%s",
        (stamp.content_scope_id,),
    ).fetchone()
    expected_scope = (
        stamp.tenant_account_id,
        stamp.node_id,
        stamp.node_tenure_id,
        stamp.tenure_epoch,
        stamp.security_realm_id,
        stamp.storage_epoch,
        stamp.realm_binding_id,
        stamp.workspace_id,
        stamp.deployment_id,
    )
    if scope != expected_scope:
        raise CommissionError("realm content scope does not match the reviewed stamp")
    if _scalar(
        connection,
        "SELECT count(*) FROM lucy.realm_service_bindings_v1 "
        "WHERE id=%s AND content_scope_id=%s AND session_login=%s AND active",
        (stamp.service_binding_id, stamp.content_scope_id, stamp.routine_login),
    ) != 1:
        raise CommissionError("realm service binding is unavailable")
    expected_actors = (
        (stamp.archive_actor_binding_id, stamp.routine_login),
        (stamp.policy_actor_binding_id, stamp.policy_login),
        (stamp.workflow_actor_binding_id, stamp.workflow_login),
        (stamp.finality_actor_binding_id, stamp.finality_login),
    )
    for binding_id, login in expected_actors:
        if _scalar(
            connection,
            "SELECT count(*) FROM lucy.realm_sensitive_actor_bindings_v1 "
            "WHERE id=%s AND content_scope_id=%s AND session_login=%s AND active",
            (binding_id, stamp.content_scope_id, login),
        ) != 1:
            raise CommissionError("realm actor binding is unavailable")
    for executor in (stamp.retrieval_executor, stamp.deletion_executor):
        if _scalar(
            connection,
            "SELECT count(*) FROM lucy.realm_executor_bindings_v2 "
            "WHERE id=%s AND content_scope_id=%s AND active",
            (executor.binding_id, stamp.content_scope_id),
        ) != 1:
            raise CommissionError("realm executor binding is unavailable")


def _work_in_flight(connection: psycopg.Connection[Any], config: CommissionConfig) -> int:
    stamp, _, _ = _full_config(config)
    return int(
        _scalar(
            connection,
            "SELECT count(*) FROM lucy.sensitive_action_permits_v3 p "
            "LEFT JOIN lucy.sensitive_operations_v2 o ON o.permit_id=p.id "
            "WHERE p.content_scope_id=%s AND ((p.state='ISSUED' AND o.id IS NULL) "
            "OR (p.state='CLAIMED' AND (o.id IS NULL OR o.state='CLAIMED')))",
            (stamp.content_scope_id,),
        )
    )


def _finality_pending(connection: psycopg.Connection[Any], config: CommissionConfig) -> int:
    stamp, _, _ = _full_config(config)
    return int(
        _scalar(
            connection,
            "SELECT count(*) FROM lucy.sensitive_operations_v2 "
            "WHERE content_scope_id=%s AND state='FINALITY_PENDING'",
            (stamp.content_scope_id,),
        )
    )


def _runtime_sessions(connection: psycopg.Connection[Any], config: CommissionConfig) -> int:
    stamp, _, _ = _full_config(config)
    logins = (
        stamp.routine_login,
        stamp.policy_login,
        stamp.workflow_login,
        stamp.finality_login,
    )
    return int(
        _scalar(
            connection,
            "SELECT count(*) FROM pg_stat_activity WHERE pid<>pg_backend_pid() "
            "AND usename=ANY(%s)",
            (list(logins),),
        )
    )


def run(config: CommissionConfig, action: Action, authorization: str) -> dict[str, object]:
    if authorization != AUTHORIZATIONS[action]:
        raise CommissionError("the exact commissioning authorization is required")
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '15s'")
        connection.execute("SET LOCAL statement_timeout = '120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (ADMISSION_LOCK,))
        state, epoch = _verify_target_boundary(connection)
        replayed = False
        if action == "quarantine":
            replayed = state == "quarantined"
            connection.execute(
                "UPDATE lucy.runtime_admission SET state='quarantined',updated_at=now() "
                "WHERE singleton"
            )
            return {
                "contract": "lucy.realm-runtime-commission.v1.3",
                "status": "passed",
                "action": action,
                "runtime_admission": "quarantined",
                "runtime_epoch_present": epoch is not None,
                "capture_enabled": None,
                "unresolved_sensitive_authority": None,
                "finality_pending": None,
                "runtime_sessions": None,
                "replayed": replayed,
            }

        _verify_reviewed_revision(connection)
        capture_enabled = _capture_enabled(connection, config)
        pending = _work_in_flight(connection, config)
        finality_pending = _finality_pending(connection, config)
        sessions = _runtime_sessions(connection, config)
        if action == "open":
            _, runtime_epoch, _ = _full_config(config)
            _verify_open_boundary(connection, config, capture_enabled)
            if pending:
                raise CommissionError("realm has unresolved sensitive authority")
            if sessions:
                raise CommissionError("realm runtime sessions must be stopped before opening")
            if state == "ready" and epoch == runtime_epoch:
                replayed = True
            elif state != "quarantined":
                raise CommissionError("storage admission is not quarantined")
            else:
                connection.execute(
                    "UPDATE lucy.runtime_admission SET state='ready',storage_epoch=%s,"
                    "updated_at=now() WHERE singleton",
                    (runtime_epoch,),
                )
                state, epoch = "ready", runtime_epoch
        return {
            "contract": "lucy.realm-runtime-commission.v1.3",
            "status": "passed",
            "action": action,
            "runtime_admission": state,
            "runtime_epoch_present": epoch is not None,
            "capture_enabled": capture_enabled,
            "unresolved_sensitive_authority": pending,
            "finality_pending": finality_pending,
            "runtime_sessions": sessions,
            "replayed": replayed,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=tuple(AUTHORIZATIONS))
    parser.add_argument("--authorization", required=True)
    args = parser.parse_args()
    try:
        config = CommissionConfig.from_environment(args.action)
        report = run(config, args.action, args.authorization)
    except CommissionError as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.realm-runtime-commission.v1.3",
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
                    "contract": "lucy.realm-runtime-commission.v1.3",
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
