"""The ephemeral response body a replay needs, kept apart from the ledger that records it.

The interface is deliberately small - put, get, expire - so the backing store can be replaced
without touching its callers. Today it is a table beside the ledger; the content may later belong
to the realm rather than to Tiamat, and that move should be a storage change, not a redesign.

Nothing here is authority. The ledger states what the response was, by digest; this only holds
it, and only until the replay guarantee it serves expires.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


class ReplayCacheUnavailable(RuntimeError):
    """The cache could not be reached, so a clean completion cannot be claimed."""


class ReplayOutputMismatch(RuntimeError):
    """Cached output disagrees with the digest the ledger recorded, so it is not served."""


def response_body_digest(response_body: object) -> str:
    """Digest the exact response body, canonically, so both sides agree on the bytes."""

    return hashlib.sha256(
        json.dumps(response_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    ).hexdigest()


@dataclass(frozen=True)
class CachedOutput:
    execution_id: UUID
    response_body: Any
    response_body_sha256: str


class ReplayCache(Protocol):
    """Where a replayable response body lives for as long as the replay window."""

    def put(
        self,
        *,
        caller_id: str,
        idempotency_key_digest: str,
        execution_id: UUID,
        response_body: Any,
        expires_at: datetime,
    ) -> str: ...

    def get(self, *, caller_id: str, idempotency_key_digest: str) -> CachedOutput | None: ...


@dataclass(frozen=True)
class PostgresReplayCache:
    """A table beside the ledger, scoped by the same caller and environment settings."""

    database_url: str
    environment: str

    def put(
        self,
        *,
        caller_id: str,
        idempotency_key_digest: str,
        execution_id: UUID,
        response_body: Any,
        expires_at: datetime,
    ) -> str:
        """Store the output idempotently and return its digest.

        Writing the same execution's output twice is a retry, not a conflict. Writing a different
        execution's output under the same key is refused rather than overwritten.
        """

        digest = response_body_digest(response_body)
        try:
            with (
                psycopg.connect(_conninfo(self.database_url), row_factory=dict_row) as connection,
                connection.transaction(),
            ):
                self._scope(connection, caller_id)
                row = connection.execute(
                    """
                    INSERT INTO tiamat.replay_cache (
                        environment, caller_id, idempotency_key_digest, execution_id,
                        response_body_sha256, response_body, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (environment, caller_id, idempotency_key_digest) DO UPDATE
                      SET response_body = EXCLUDED.response_body,
                          response_body_sha256 = EXCLUDED.response_body_sha256,
                          expires_at = EXCLUDED.expires_at
                      WHERE tiamat.replay_cache.execution_id = EXCLUDED.execution_id
                    RETURNING response_body_sha256
                    """,
                    (
                        self.environment,
                        caller_id,
                        idempotency_key_digest,
                        execution_id,
                        digest,
                        Jsonb(response_body),
                        expires_at,
                    ),
                ).fetchone()
        except psycopg.Error as exc:
            raise ReplayCacheUnavailable("replay cache write failed") from exc
        if row is None:
            raise ReplayCacheUnavailable("replay cache holds another execution for this key")
        return str(row["response_body_sha256"])

    def get(self, *, caller_id: str, idempotency_key_digest: str) -> CachedOutput | None:
        try:
            with psycopg.connect(
                _conninfo(self.database_url), row_factory=dict_row
            ) as connection:
                self._scope(connection, caller_id)
                row = connection.execute(
                    """
                    SELECT execution_id, response_body, response_body_sha256
                    FROM tiamat.replay_cache
                    WHERE environment = %s AND caller_id = %s AND idempotency_key_digest = %s
                      AND expires_at > clock_timestamp()
                    """,
                    (self.environment, caller_id, idempotency_key_digest),
                ).fetchone()
        except psycopg.Error as exc:
            raise ReplayCacheUnavailable("replay cache read failed") from exc
        if row is None:
            return None
        return CachedOutput(
            execution_id=UUID(str(row["execution_id"])),
            response_body=row["response_body"],
            response_body_sha256=str(row["response_body_sha256"]),
        )

    def expire(self, *, now: datetime) -> int:
        """Drop what the replay guarantee no longer covers. Accounting is untouched."""

        try:
            with (
                psycopg.connect(_conninfo(self.database_url)) as connection,
                connection.transaction(),
            ):
                connection.execute(
                    "SELECT set_config('tiamat.environment', %s, true)", (self.environment,)
                )
                result = connection.execute(
                    "DELETE FROM tiamat.replay_cache WHERE environment = %s AND expires_at <= %s",
                    (self.environment, now),
                )
        except psycopg.Error as exc:
            raise ReplayCacheUnavailable("replay cache expiry failed") from exc
        return int(result.rowcount)

    def _scope(self, connection: psycopg.Connection[Any], caller_id: str) -> None:
        connection.execute(
            "SELECT set_config('tiamat.environment', %s, true)", (self.environment,)
        )
        connection.execute("SELECT set_config('tiamat.caller_id', %s, true)", (caller_id,))


def require_matching_output(cached: CachedOutput, ledger_digest: str | None) -> Any:
    """Serve cached output only when the ledger agrees it is what that execution produced."""

    if ledger_digest is None or cached.response_body_sha256 != ledger_digest:
        raise ReplayOutputMismatch("cached output does not match the recorded response digest")
    if response_body_digest(cached.response_body) != ledger_digest:
        raise ReplayOutputMismatch("cached output does not hash to its recorded digest")
    return cached.response_body


def _conninfo(database_url: str) -> str:
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)
