"""Close one expired synthetic retrieval without replaying its executor.

This utility exists only for the quarantined Security Baseline v1.2 cloud
acceptance recovery. It refuses real evidence, deletion work, non-expired
operations, operations with a receipt, or any database containing another
unresolved operation. The transaction preserves the evidence, permit, grant,
and historical rows while recording that executor effect is unknown and owner
delivery was not attempted.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import psycopg
from sqlalchemy.engine import URL, make_url

AUTHORIZATION = "security-v1.2-expired-synthetic-retrieval-recovery"
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LUCY_DATABASE = re.compile(r"lucy(?:_[a-z0-9]+)?\Z")
_SYNTHETIC_KEY = re.compile(
    r"cloud-acceptance-retrieve:"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_MAINTENANCE_LOCK = 0x4C5543594D53
_ADMISSION_LOCK = 0x4C5543594144
_EVENT_TYPE = "sensitive.retrieval_expired_without_receipt"
_CAPTURE_SAFETY_QUERY = r"""
SELECT
  EXISTS(SELECT 1 FROM lucy.conversation_capture_states WHERE capture_enabled),
  EXISTS(
    SELECT 1 FROM lucy.capture_receipts r
    WHERE r.capture_enabled AND NOT (
      r.platform='telegram'
      AND r.source_conversation_id ~
        '^cloud-acceptance-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      AND r.source_turn_id=regexp_replace(
        r.source_conversation_id,'^cloud-acceptance-','turn-'
      )
      AND EXISTS(
        SELECT 1 FROM lucy.evidence e
        WHERE e.source='hermes'
          AND e.source_conversation_id='telegram:' || r.source_conversation_id
      )
    )
  )
"""
_RESULT = {
    "state": "FAILED_FINAL",
    "recovery_disposition": "expired_without_executor_receipt",
    "executor_effect": "unknown",
    "owner_delivery": "not_attempted",
}


class RecoveryError(RuntimeError):
    """Fail-closed recovery precondition or verification failure."""


@dataclass(frozen=True)
class RecoveryConfig:
    migration_url: URL
    operation_id: UUID
    expected_retrieval_version: int
    storage_epoch: int
    registry_epoch: int
    key_epoch: int

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> RecoveryConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true":
            raise RecoveryError("recovery requires the Render private-network runtime")
        if values.get("LUCY_ENVIRONMENT") != "production":
            raise RecoveryError("recovery requires the production environment")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise RecoveryError("transcript capture must remain disabled")
        if values.get("LUCY_SYNTHETIC_RETRIEVAL_RECOVERY_AUTHORIZATION") != AUTHORIZATION:
            raise RecoveryError("the exact reviewed recovery authorization is required")

        migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if migration_url.username != "lucy_migration":
            raise RecoveryError("the migration URL must use lucy_migration")
        if (
            migration_url.host is None
            or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
            or migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
        ):
            raise RecoveryError("the migration URL must target the private Lucy database")
        try:
            operation_id = UUID(_required(values, "LUCY_SYNTHETIC_RETRIEVAL_OPERATION_ID"))
        except ValueError as exc:
            raise RecoveryError("the recovery operation ID must be a UUID") from exc
        return cls(
            migration_url=migration_url,
            operation_id=operation_id,
            expected_retrieval_version=_positive_int(
                values, "LUCY_EXPECTED_RETRIEVAL_EXECUTOR_VERSION"
            ),
            storage_epoch=_positive_int(values, "LUCY_SECURITY_STORAGE_EPOCH"),
            registry_epoch=_positive_int(values, "LUCY_SECURITY_REGISTRY_EPOCH"),
            key_epoch=_positive_int(values, "LUCY_SECURITY_KEY_EPOCH"),
        )


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise RecoveryError(f"missing required configuration: {name}")
    return value


def _positive_int(values: Mapping[str, str], name: str) -> int:
    try:
        value = int(_required(values, name))
    except ValueError as exc:
        raise RecoveryError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise RecoveryError(f"{name} must be a positive integer")
    return value


def _database_url(raw: str) -> URL:
    try:
        parsed = make_url(raw)
    except Exception as exc:
        raise RecoveryError("invalid PostgreSQL URL") from exc
    if parsed.drivername not in {"postgresql", "postgresql+psycopg"}:
        raise RecoveryError("only PostgreSQL psycopg URLs are accepted")
    if not parsed.username or not parsed.password or not parsed.host or not parsed.database:
        raise RecoveryError("database URL requires user, password, host, and database")
    return parsed.set(drivername="postgresql+psycopg").update_query_dict({"sslmode": "require"})


def _conninfo(url: URL) -> str:
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


def _safety_state(connection: psycopg.Connection[Any], config: RecoveryConfig) -> None:
    tls = connection.execute("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone()
    admission = connection.execute(
        "SELECT state FROM lucy.runtime_admission WHERE singleton"
    ).fetchone()
    capture = connection.execute(_CAPTURE_SAFETY_QUERY).fetchone()
    epochs = connection.execute(
        "SELECT storage_epoch,registry_epoch,key_epoch "
        "FROM lucy.security_contract_epochs WHERE singleton"
    ).fetchone()
    if tls != (True,):
        raise RecoveryError("database connection is not TLS protected")
    if admission != ("quarantined",) or capture != (False, False):
        raise RecoveryError("database safety state differs from the reviewed quarantine")
    if epochs != (config.storage_epoch, config.registry_epoch, config.key_epoch):
        raise RecoveryError("security contract epochs differ from the reviewed state")


def _unresolved_state(connection: psycopg.Connection[Any], operation_id: UUID) -> tuple[int, bool]:
    row = connection.execute(
        "SELECT count(*),coalesce(bool_and(id=%s),false) FROM lucy.operations "
        "WHERE outcome NOT IN ('succeeded','failed')",
        (operation_id,),
    ).fetchone()
    if row is None:
        raise RecoveryError("unresolved-operation inventory was unavailable")
    return int(row[0]), bool(row[1])


def _target_state(connection: psycopg.Connection[Any], config: RecoveryConfig) -> tuple[Any, ...]:
    row = connection.execute(
        "SELECT o.outcome,o.completed_at,o.result,o.idempotency_key,s.action,s.state,"
        "s.execution_deadline < clock_timestamp(),s.manifest_id IS NULL,"
        "s.executor_receipt_digest IS NULL,s.caller_session_user,"
        "(SELECT count(*) FROM lucy.sensitive_execution_grants_v1 g "
        " WHERE g.operation_id=o.id),"
        "(SELECT count(*) FROM lucy.executor_receipt_attestations_v1 r "
        " WHERE r.operation_id=o.id),"
        "(SELECT count(*) FROM lucy.evidence_deletion_fences_v1 f "
        " WHERE f.operation_id=o.id),"
        "EXISTS(SELECT 1 FROM lucy.sensitive_execution_grants_v1 g "
        " JOIN lucy.executor_bindings_v1 b ON b.action='evidence.retrieve' "
        "  AND b.environment='production' AND b.active "
        " WHERE g.operation_id=o.id AND g.executor_identity=b.executor_identity "
        "  AND g.executor_alias_arn=b.executor_alias_arn AND g.executor_version=%s),"
        "EXISTS(SELECT 1 FROM lucy.sensitive_action_permits_v2 p "
        " JOIN lucy.owner_interaction_assertions_v1 a ON a.id=p.owner_assertion_id "
        " WHERE p.id=s.permit_id AND p.action='evidence.retrieve' AND p.state='CLAIMED' "
        "  AND a.serialized_assertion->>'channel'='synthetic_acceptance' "
        "  AND a.serialized_assertion->>'authentication_method'='synthetic_acceptance' "
        "  AND a.issuer='owner-broker.synthetic-acceptance'),"
        "EXISTS(SELECT 1 FROM lucy.evidence e WHERE e.id=s.evidence_id "
        " AND e.source='hermes' "
        " AND e.source_conversation_id LIKE 'telegram:cloud-acceptance-%%' "
        " AND EXISTS(SELECT 1 FROM lucy.evidence_payloads p WHERE p.evidence_id=e.id) "
        " AND NOT EXISTS(SELECT 1 FROM lucy.evidence_tombstones t WHERE t.evidence_id=e.id)) "
        "FROM lucy.operations o JOIN lucy.sensitive_operations_v1 s ON s.id=o.id "
        "WHERE o.id=%s FOR UPDATE OF o,s",
        (config.expected_retrieval_version, config.operation_id),
    ).fetchone()
    if row is None:
        raise RecoveryError("the exact synthetic recovery operation does not exist")
    return tuple(row)


def _event_count(connection: psycopg.Connection[Any], operation_id: UUID) -> int:
    row = connection.execute(
        "SELECT count(*) FROM lucy.sensitive_operation_events_v1 "
        "WHERE operation_id=%s AND event_type=%s",
        (operation_id, _EVENT_TYPE),
    ).fetchone()
    if row is None:
        raise RecoveryError("recovery event inventory was unavailable")
    return int(row[0])


def _is_recovered(state: tuple[Any, ...]) -> bool:
    return (
        state[0] == "failed"
        and state[1] is not None
        and state[2] == _RESULT
        and isinstance(state[3], str)
        and _SYNTHETIC_KEY.fullmatch(state[3]) is not None
        and state[4] == "evidence.retrieve"
        and state[5] == "FAILED_FINAL"
        and state[6] is True
        and state[7] is True
        and state[8] is True
        and state[9] == "lucy_evidence_workflow"
        and state[10:] == (1, 0, 0, True, True, True)
    )


def _require_recoverable(state: tuple[Any, ...]) -> None:
    if not isinstance(state[3], str) or _SYNTHETIC_KEY.fullmatch(state[3]) is None:
        raise RecoveryError("the operation is not the synthetic retrieval acceptance case")
    expected = (
        "pending",
        None,
        None,
        "evidence.retrieve",
        "EXECUTING",
        True,
        True,
        True,
        "lucy_evidence_workflow",
        1,
        0,
        0,
        True,
        True,
        True,
    )
    observed = (state[0], state[1], state[2], *state[4:])
    if observed != expected:
        raise RecoveryError("the operation shape is outside the approved recovery boundary")


def run(config: RecoveryConfig) -> dict[str, Any]:
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '10s'")
        connection.execute("SET LOCAL statement_timeout = '60s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_ADMISSION_LOCK,))
        _safety_state(connection, config)
        unresolved = _unresolved_state(connection, config.operation_id)
        state = _target_state(connection, config)
        if unresolved == (0, False):
            if not _is_recovered(state) or _event_count(connection, config.operation_id) != 1:
                raise RecoveryError("the completed recovery state is not replay-safe")
            replayed = True
        else:
            if unresolved != (1, True):
                raise RecoveryError("another unresolved operation prevents recovery")
            _require_recoverable(state)
            before_events = _event_count(connection, config.operation_id)
            if before_events != 0:
                raise RecoveryError("the recovery event already exists on a pending operation")
            now = connection.execute("SELECT clock_timestamp()").fetchone()
            if now is None:
                raise RecoveryError("database clock was unavailable")
            updated = connection.execute(
                "UPDATE lucy.sensitive_operations_v1 SET state='FAILED_FINAL',updated_at=%s "
                "WHERE id=%s AND state='EXECUTING' AND executor_receipt_digest IS NULL",
                (now[0], config.operation_id),
            )
            completed = connection.execute(
                "UPDATE lucy.operations SET outcome='failed',completed_at=%s,result=%s::jsonb "
                "WHERE id=%s AND outcome='pending' AND completed_at IS NULL",
                (now[0], json.dumps(_RESULT, sort_keys=True), config.operation_id),
            )
            if updated.rowcount != 1 or completed.rowcount != 1:
                raise RecoveryError("recovery update cardinality differed")
            connection.execute(
                "SELECT lucy.append_sensitive_event_v1(%s,%s,%s::jsonb)",
                (
                    config.operation_id,
                    _EVENT_TYPE,
                    json.dumps(
                        {
                            "state": "FAILED_FINAL",
                            "recovery_disposition": "expired_without_executor_receipt",
                            "executor_effect": "unknown",
                            "owner_delivery": "not_attempted",
                            "grant_preserved": True,
                            "evidence_preserved": True,
                        },
                        sort_keys=True,
                    ),
                ),
            )
            if _unresolved_state(connection, config.operation_id) != (0, False):
                raise RecoveryError("recovery did not close the unresolved operation")
            if not _is_recovered(_target_state(connection, config)):
                raise RecoveryError("recovery did not reach the exact terminal state")
            if _event_count(connection, config.operation_id) != 1:
                raise RecoveryError("recovery event was not recorded exactly once")
            replayed = False
    return {
        "contract": "lucy.security-v1.2-expired-synthetic-retrieval-recovery",
        "status": "passed",
        "operation_id": str(config.operation_id),
        "terminal_state": "FAILED_FINAL",
        "executor_effect": "unknown",
        "owner_delivery": "not_attempted",
        "receipt_present": False,
        "grant_preserved": True,
        "evidence_preserved": True,
        "runtime_admission": "quarantined",
        "capture_enabled": False,
        "replayed": replayed,
    }


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        raise RecoveryError("this deployment utility accepts no command-line values")
    try:
        report = run(RecoveryConfig.from_environment())
    except RecoveryError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
