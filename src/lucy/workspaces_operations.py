"""Deployment-bound Workspaces operations executed after fresh admission."""

from __future__ import annotations

import re
import secrets
from typing import Protocol
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from lucy.contracts.security_v1_3 import ResolvedExecutionContextV1
from lucy.publication import PublicProjectionReader
from lucy.tenancy import ScopeNotFound


class WorkspacesOperationUnavailable(RuntimeError):
    pass


class WorkspacesTaskDelegator(Protocol):
    def delegate(
        self,
        *,
        context: ResolvedExecutionContextV1,
        request_id: UUID,
        instruction: str,
    ) -> UUID: ...


class ApprovedProjectionWorkspacesOperations:
    """Read one reviewed projection and delegate only through an injected queue."""

    def __init__(
        self,
        *,
        reader: PublicProjectionReader,
        hostname: str,
        storage_epoch: UUID,
        snapshot_digest: str,
        task_delegator: WorkspacesTaskDelegator | None = None,
    ) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", snapshot_digest) is None:
            raise ValueError("approved snapshot digest is invalid")
        self._reader = reader
        self._hostname = hostname
        self._storage_epoch = storage_epoch
        self._snapshot_digest = snapshot_digest
        self._task_delegator = task_delegator

    def query_knowledge(
        self,
        *,
        context: ResolvedExecutionContextV1,
        question: str,
    ) -> tuple[str, str, int, str]:
        del context  # Admission already selected this process and its fixed projection.
        try:
            answer = self._reader.answer_admitted(
                hostname=self._hostname,
                question=question,
                storage_epoch=self._storage_epoch,
            )
        except (ScopeNotFound, SQLAlchemyError) as exc:
            raise WorkspacesOperationUnavailable("approved knowledge is unavailable") from exc
        if not secrets.compare_digest(answer.snapshot_digest, self._snapshot_digest):
            raise WorkspacesOperationUnavailable("approved knowledge is unavailable")
        return answer.answer, answer.source, answer.version, answer.snapshot_digest

    def delegate_task(
        self,
        *,
        context: ResolvedExecutionContextV1,
        request_id: UUID,
        instruction: str,
    ) -> UUID:
        if self._task_delegator is None:
            raise WorkspacesOperationUnavailable("task delegation is unavailable")
        return self._task_delegator.delegate(
            context=context,
            request_id=request_id,
            instruction=instruction,
        )
