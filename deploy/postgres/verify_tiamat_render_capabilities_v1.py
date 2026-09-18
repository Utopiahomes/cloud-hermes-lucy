"""Read-only managed-PostgreSQL capability gate for a blocked Tiamat ledger.

This tool deliberately does not migrate, initialize, sign, write DynamoDB, or start model dispatch.
It proves only that the intended recovery login can read the control/WAL continuity beacon through a
TLS-protected connection, while the new ledger remains dispatch-blocked.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, dataclass
from uuid import UUID

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row


class CapabilityRejected(RuntimeError):
    """The managed database does not meet the reviewed Tiamat prerequisite."""


@dataclass(frozen=True)
class RenderPostgresCapabilityReport:
    environment: str
    ledger_id: str
    storage_epoch: str
    recovery_generation: int
    database_user: str
    server_version_num: int
    transport_tls: bool
    system_identifier: str
    timeline_id: int
    flushed_wal_lsn: str
    dispatch_blocked: bool


def _connection_info(database_url: str) -> str:
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


def _require_tls(database_url: str) -> str:
    connection_info = _connection_info(database_url)
    sslmode = conninfo_to_dict(connection_info).get("sslmode")
    if sslmode not in {"require", "verify-ca", "verify-full"}:
        raise CapabilityRejected("database connection must require TLS")
    return connection_info


def verify_render_capabilities(
    *, database_url: str, environment: str, expected_recovery_login: str
) -> RenderPostgresCapabilityReport:
    """Read the exact managed-PostgreSQL prerequisites without changing durable state."""

    if not environment or not expected_recovery_login:
        raise ValueError("environment and expected recovery login are required")
    connection_info = _require_tls(database_url)
    try:
        with psycopg.connect(connection_info, row_factory=dict_row) as connection:
            capability = connection.execute(
                """
                SELECT
                    current_user AS database_user,
                    current_setting('server_version_num')::integer AS server_version_num,
                    COALESCE(
                        (SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false
                    ) AS transport_tls,
                    (pg_control_system()).system_identifier::text AS system_identifier,
                    (pg_control_checkpoint()).timeline_id::bigint AS timeline_id,
                    pg_current_wal_flush_lsn()::text AS flushed_wal_lsn
                """
            ).fetchone()
            identity = connection.execute(
                """
                SELECT ledger_id::text AS ledger_id
                FROM tiamat.ledger_identity
                WHERE singleton
                """
            ).fetchone()
            gate = connection.execute(
                """
                SELECT storage_epoch::text AS storage_epoch, recovery_generation, dispatch_blocked
                FROM tiamat.restore_gate
                WHERE environment = %s
                """,
                (environment,),
            ).fetchone()
    except psycopg.Error as exc:
        raise CapabilityRejected("managed PostgreSQL recovery capability is unavailable") from exc
    if capability is None or identity is None or gate is None:
        raise CapabilityRejected("managed PostgreSQL prerequisite is missing")
    if capability["database_user"] != expected_recovery_login:
        raise CapabilityRejected("unexpected database recovery login")
    if not bool(capability["transport_tls"]):
        raise CapabilityRejected("managed PostgreSQL connection is not TLS protected")
    if not bool(gate["dispatch_blocked"]):
        raise CapabilityRejected("Tiamat ledger is not blocked for commissioning")
    try:
        return RenderPostgresCapabilityReport(
            environment=environment,
            ledger_id=str(UUID(str(identity["ledger_id"]))),
            storage_epoch=str(UUID(str(gate["storage_epoch"]))),
            recovery_generation=int(gate["recovery_generation"]),
            database_user=str(capability["database_user"]),
            server_version_num=int(capability["server_version_num"]),
            transport_tls=True,
            system_identifier=str(capability["system_identifier"]),
            timeline_id=int(capability["timeline_id"]),
            flushed_wal_lsn=str(capability["flushed_wal_lsn"]),
            dispatch_blocked=True,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CapabilityRejected("managed PostgreSQL capability response is invalid") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default=os.environ.get("TIAMAT_RECOVERY_DATABASE_URL"))
    parser.add_argument("--environment", default=os.environ.get("TIAMAT_ENVIRONMENT"))
    parser.add_argument("--expected-recovery-login", default="tiamat_recovery")
    args = parser.parse_args()
    if not args.database_url or not args.environment:
        raise ValueError("Tiamat recovery database URL and environment are required")
    report = verify_render_capabilities(
        database_url=args.database_url,
        environment=args.environment,
        expected_recovery_login=args.expected_recovery_login,
    )
    print(json.dumps(asdict(report), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
