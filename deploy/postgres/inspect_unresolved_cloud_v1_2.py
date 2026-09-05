"""Authenticated content-free inventory for quarantined unresolved operations.

This utility is deployed only as a temporary Render command while every normal
PostgreSQL client is suspended. It selects state metadata and reference counts;
it never selects evidence content, encrypted packages, permits, ciphertext,
wrapped keys, credentials, or model/user messages.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import psycopg
from sqlalchemy.engine import URL, make_url

AUTHORIZATION = "security-v1.2-unresolved-inventory"
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LUCY_DATABASE = re.compile(r"lucy(?:_[a-z0-9]+)?\Z")
_SENSITIVE_KEY = re.compile(
    r"cloud-acceptance-(?P<action>retrieve|delete):"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)

QUERY = """
SELECT o.id::text,o.idempotency_key,o.outcome,o.created_at::text,o.completed_at::text,
  ARRAY(SELECT DISTINCT a.event_type FROM lucy.audit_events a
        WHERE a.operation_id=o.id ORDER BY a.event_type),
  (SELECT count(*) FROM lucy.evidence e WHERE e.operation_id=o.id),
  (SELECT count(*) FROM lucy.sensitive_action_permits p WHERE p.issued_operation_id=o.id),
  (SELECT count(*) FROM lucy.sensitive_action_permits_v2 p
   WHERE p.issued_operation_id=o.id),
  (SELECT count(*) FROM lucy.budget_reservations b WHERE b.operation_id=o.id),
  s.action,s.state,(s.execution_deadline < clock_timestamp()),
  (SELECT count(*) FROM lucy.sensitive_execution_grants_v1 g WHERE g.operation_id=o.id),
  (SELECT count(*) FROM lucy.executor_receipt_attestations_v1 r
   WHERE r.operation_id=o.id),
  (SELECT max(r.result) FROM lucy.executor_receipt_attestations_v1 r
   WHERE r.operation_id=o.id),
  (SELECT count(*) FROM lucy.deletion_target_manifests_v1 m WHERE m.id=s.manifest_id),
  (SELECT count(*) FROM lucy.evidence_deletion_fences_v1 f WHERE f.operation_id=o.id),
  CASE WHEN s.id IS NULL THEN NULL ELSE EXISTS(
    SELECT 1 FROM lucy.sensitive_action_permits_v2 p
    JOIN lucy.owner_interaction_assertions_v1 a ON a.id=p.owner_assertion_id
    WHERE p.id=s.permit_id
      AND a.serialized_assertion->>'channel'='synthetic_acceptance'
      AND a.serialized_assertion->>'authentication_method'='synthetic_acceptance'
      AND a.issuer='owner-broker.synthetic-acceptance'
  ) END,
  CASE WHEN s.id IS NULL THEN NULL ELSE EXISTS(
    SELECT 1 FROM lucy.evidence e
    WHERE e.id=s.evidence_id AND e.source='hermes'
      AND e.source_conversation_id LIKE 'telegram:cloud-acceptance-%'
      AND EXISTS (SELECT 1 FROM lucy.evidence_payloads p WHERE p.evidence_id=e.id)
      AND NOT EXISTS (SELECT 1 FROM lucy.evidence_tombstones t WHERE t.evidence_id=e.id)
  ) END
FROM lucy.operations o
LEFT JOIN lucy.sensitive_operations_v1 s ON s.id=o.id
WHERE o.outcome NOT IN ('succeeded','failed')
ORDER BY o.created_at,o.id
"""


class InventoryError(RuntimeError):
    """Fail-closed configuration or inventory error."""


@dataclass(frozen=True)
class InventoryConfig:
    migration_url: URL
    bearer_token: str
    port: int

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> InventoryConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise InventoryError("inventory requires the Render production runtime")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise InventoryError("transcript capture must remain disabled")
        if values.get("LUCY_UNRESOLVED_DIAGNOSTIC_AUTHORIZATION") != AUTHORIZATION:
            raise InventoryError("exact unresolved-inventory authorization is required")
        raw_url = values.get("LUCY_MAINTENANCE_DATABASE_URL", "").strip()
        token = values.get("LUCY_DIAGNOSTIC_TOKEN", "").strip()
        if not raw_url or len(token) < 32:
            raise InventoryError("inventory authority is incomplete")
        try:
            parsed = make_url(raw_url)
            port = int(values.get("PORT", ""))
        except (TypeError, ValueError) as exc:
            raise InventoryError("inventory configuration is invalid") from exc
        if (
            parsed.drivername not in {"postgresql", "postgresql+psycopg"}
            or parsed.username != "lucy_migration"
            or not parsed.password
            or parsed.host is None
            or _PRIVATE_RENDER_HOST.fullmatch(parsed.host) is None
            or parsed.database is None
            or _LUCY_DATABASE.fullmatch(parsed.database) is None
            or parsed.port not in (None, 5432)
            or port not in range(1, 65_536)
        ):
            raise InventoryError("inventory configuration is outside the reviewed boundary")
        return cls(
            migration_url=parsed.set(drivername="postgresql+psycopg").update_query_dict(
                {"sslmode": "require"}
            ),
            bearer_token=token,
            port=port,
        )


def _conninfo(url: URL) -> str:
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


def _classify_idempotency_key(value: str) -> str:
    if _SENSITIVE_KEY.fullmatch(value):
        return "cloud-acceptance-sensitive"
    if value.startswith("cloud-acceptance-"):
        return "cloud-acceptance-other"
    if value.startswith("external:synthetic:"):
        return "external-synthetic"
    if value.startswith("startup:"):
        return "startup"
    if value.startswith("recovery:ambiguous:"):
        return "recovery"
    return "other"


def sanitize_row(row: Sequence[Any]) -> dict[str, Any]:
    key = str(row[1])
    return {
        "operation_id": str(row[0]),
        "idempotency_sha256": hashlib.sha256(key.encode()).hexdigest(),
        "idempotency_class": _classify_idempotency_key(key),
        "outcome": row[2],
        "created_at": row[3],
        "completed_at": row[4],
        "audit_event_types": row[5],
        "evidence_refs": row[6],
        "legacy_permit_refs": row[7],
        "v2_permit_issuance_refs": row[8],
        "budget_refs": row[9],
        "sensitive_action": row[10],
        "sensitive_state": row[11],
        "execution_deadline_expired": row[12],
        "execution_grant_count": row[13],
        "receipt_attestation_count": row[14],
        "receipt_result": row[15],
        "deletion_manifest_count": row[16],
        "deletion_fence_count": row[17],
        "synthetic_owner_assertion": row[18],
        "active_synthetic_evidence": row[19],
    }


def collect(config: InventoryConfig) -> dict[str, Any]:
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL statement_timeout = '30s'")
        tls = connection.execute(
            "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
        ).fetchone()
        admission = connection.execute(
            "SELECT state FROM lucy.runtime_admission WHERE singleton"
        ).fetchone()
        capture = connection.execute(
            "SELECT EXISTS (SELECT 1 FROM lucy.conversation_capture_states "
            "WHERE capture_enabled) OR EXISTS (SELECT 1 FROM lucy.capture_receipts "
            "WHERE capture_enabled)"
        ).fetchone()
        if tls != (True,) or admission != ("quarantined",) or capture != (False,):
            raise InventoryError("database safety state differs from the reviewed boundary")
        rows = connection.execute(QUERY).fetchall()
    return {"count": len(rows), "operations": [sanitize_row(row) for row in rows]}


def serve(port: int, bearer_token: str) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/diagnostic" and self.headers.get(
                "Authorization"
            ) == f"Bearer {bearer_token}":
                try:
                    config = InventoryConfig.from_environment()
                    response = json.dumps(
                        collect(config), separators=(",", ":"), sort_keys=True
                    ).encode()
                    if len(response) > 262_144:
                        raise InventoryError(
                            "content-free inventory exceeds its fixed response bound"
                        )
                    status = 200
                except InventoryError as exc:
                    status = 503
                    response = json.dumps({"error": str(exc)}).encode()
                except psycopg.Error as exc:
                    status = 503
                    response = json.dumps(
                        {
                            "error": "postgresql_inventory_failed",
                            "sqlstate": exc.sqlstate or "unknown",
                            "primary": exc.diag.message_primary or type(exc).__name__,
                        }
                    ).encode()
                except Exception as exc:
                    status = 503
                    response = json.dumps(
                        {"error": "inventory_failed", "error_type": type(exc).__name__}
                    ).encode()
            elif self.path == "/diagnostic":
                status, response = 404, b'{"error":"not_found"}'
            else:
                status, response = 200, b'{"ok":true}'
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, _format: str, *args: Any) -> None:
            return

    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


def main() -> None:
    try:
        port = int(os.environ.get("PORT", ""))
    except ValueError as exc:
        raise InventoryError("diagnostic port is invalid") from exc
    token = os.environ.get("LUCY_DIAGNOSTIC_TOKEN", "").strip()
    if port not in range(1, 65_536) or len(token) < 32:
        raise InventoryError("diagnostic listener configuration is invalid")
    serve(port, token)


if __name__ == "__main__":
    main()
