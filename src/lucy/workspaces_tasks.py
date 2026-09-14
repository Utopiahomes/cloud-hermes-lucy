"""Durable, realm-bound task queue for admitted Workspaces operations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from lucy.contracts.security_v1_3 import ResolvedExecutionContextV1


class WorkspacesTaskUnavailable(RuntimeError):
    """Content-free queue failure safe to translate at the private API boundary."""


@dataclass(frozen=True)
class WorkspacesTaskClaim:
    task_id: UUID
    request_id: UUID
    room_id: UUID
    instruction: str
    attempt: int
    lease_token: UUID
    lease_expires_at: datetime


class PostgresWorkspacesTaskQueue:
    """Execute-only client for the database-enforced Workspaces task lifecycle."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def delegate(
        self,
        *,
        context: ResolvedExecutionContextV1,
        request_id: UUID,
        room_id: UUID,
        instruction: str,
    ) -> UUID:
        digest = hashlib.sha256(instruction.encode("utf-8")).hexdigest()
        try:
            with self._sessions.begin() as session:
                value = session.scalar(
                    text(
                        "SELECT lucy.enqueue_workspaces_task_v1("
                        ":service_binding_id,:workspace_id,:channel_binding_id,"
                        ":request_id,:room_id,:instruction,:instruction_digest)"
                    ),
                    {
                        "service_binding_id": context.service_binding_id,
                        "workspace_id": context.workspace_id,
                        "channel_binding_id": context.channel_binding_id,
                        "request_id": request_id,
                        "room_id": room_id,
                        "instruction": instruction,
                        "instruction_digest": digest,
                    },
                )
        except SQLAlchemyError as exc:
            raise WorkspacesTaskUnavailable("task queue is unavailable") from exc
        try:
            return UUID(str(_mapping(value)["task_id"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkspacesTaskUnavailable("task queue is unavailable") from exc

    def claim(self, *, worker_id: UUID, lease_seconds: int = 60) -> WorkspacesTaskClaim | None:
        if not 15 <= lease_seconds <= 300:
            raise ValueError("task lease must be between 15 and 300 seconds")
        try:
            with self._sessions.begin() as session:
                value = session.scalar(
                    text("SELECT lucy.claim_workspaces_task_v1(:worker_id,:lease_seconds)"),
                    {"worker_id": worker_id, "lease_seconds": lease_seconds},
                )
        except SQLAlchemyError as exc:
            raise WorkspacesTaskUnavailable("task queue is unavailable") from exc
        if value is None:
            return None
        try:
            item = _mapping(value)
            return WorkspacesTaskClaim(
                task_id=UUID(str(item["task_id"])),
                request_id=UUID(str(item["request_id"])),
                room_id=UUID(str(item["room_id"])),
                instruction=str(item["instruction"]),
                attempt=int(str(item["attempt"])),
                lease_token=UUID(str(item["lease_token"])),
                lease_expires_at=datetime.fromisoformat(str(item["lease_expires_at"])),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkspacesTaskUnavailable("task queue is unavailable") from exc

    def heartbeat(
        self, *, task_id: UUID, lease_token: UUID, lease_seconds: int = 60
    ) -> datetime:
        if not 15 <= lease_seconds <= 300:
            raise ValueError("task lease must be between 15 and 300 seconds")
        value = self._call(
            "SELECT lucy.heartbeat_workspaces_task_v1("
            ":task_id,:lease_token,:lease_seconds)",
            {
                "task_id": task_id,
                "lease_token": lease_token,
                "lease_seconds": lease_seconds,
            },
        )
        try:
            return datetime.fromisoformat(str(_mapping(value)["lease_expires_at"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkspacesTaskUnavailable("task queue is unavailable") from exc

    def complete(
        self,
        *,
        task_id: UUID,
        lease_token: UUID,
        outcome: Literal["completed", "failed"],
        result: dict[str, Any],
    ) -> bool:
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 65_536:
            raise ValueError("task result exceeds 65536 bytes")
        value = self._call(
            "SELECT lucy.complete_workspaces_task_v1("
            ":task_id,:lease_token,:outcome,CAST(:result AS jsonb))",
            {
                "task_id": task_id,
                "lease_token": lease_token,
                "outcome": outcome,
                "result": encoded,
            },
        )
        try:
            return bool(_mapping(value)["replayed"])
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkspacesTaskUnavailable("task queue is unavailable") from exc

    def _call(self, statement: str, parameters: dict[str, object]) -> object:
        try:
            with self._sessions.begin() as session:
                return session.scalar(text(statement), parameters)
        except SQLAlchemyError as exc:
            raise WorkspacesTaskUnavailable("task queue is unavailable") from exc


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError("database result is not an object")
    return value
