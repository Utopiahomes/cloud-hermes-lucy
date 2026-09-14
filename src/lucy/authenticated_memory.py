"""Authenticated realm-local gateway for scoped semantic memory."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import SecretStr

from lucy.contracts.security_v1_3 import ExactObjectSelectorV1
from lucy.internal_admission import RealmInternalAdmissionService
from lucy.scoped_memory import ScopedMemoryClaim


class AuthenticatedScopedMemoryGateway:
    """Admit each request before invoking one process's fixed memory client.

    The workspace selector is deployment configuration, never caller input. The
    resolved context remains server-only and is not accepted back from callers.
    """

    def __init__(
        self,
        *,
        admission: RealmInternalAdmissionService,
        workspace_id: UUID,
        workspace_version: int = 1,
    ) -> None:
        self._admission = admission
        self._workspace_selector = ExactObjectSelectorV1(
            object_id=workspace_id,
            object_version=workspace_version,
        )

    def search(
        self,
        *,
        credential: SecretStr,
        request_id: UUID,
        query: str,
        checked_at: datetime,
        limit: int = 10,
    ) -> tuple[ScopedMemoryClaim, ...]:
        self._admit(
            credential=credential,
            request_id=request_id,
            action="memory.read",
            checked_at=checked_at,
        )
        return self._admission._scoped_memory_for_effect(action="memory.read").search(
            query, limit=limit
        )

    def _admit(
        self,
        *,
        credential: SecretStr,
        request_id: UUID,
        action: str,
        checked_at: datetime,
    ) -> None:
        # Do not return or accept the context across the caller boundary. Its digest
        # protects accidental mutation inside this process; it is not a bearer token.
        self._admission.admit(
            credential=credential,
            request_id=request_id,
            action=action,
            resource_selector=self._workspace_selector,
            checked_at=checked_at,
        )
