"""Private Workspaces experience adapter over realm-local admission.

The adapter accepts no node, realm, workspace, or channel selector. Those values
come exclusively from the deployment's fixed ``RealmRuntimeBindingV1``. Admission
receipts are diagnostic metadata and are never accepted back as authorization.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Literal, TypeVar
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from lucy.contracts.security_v1_3 import ExactObjectSelectorV1, ResolvedExecutionContextV1
from lucy.internal_admission import InternalAdmissionDenied, RealmInternalAdmissionService

CapabilityName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.:-]{0,127}$")]
EffectResult = TypeVar("EffectResult")


class WorkspacesRoomAdmissionRequestV1(BaseModel):
    """Content-free preflight request from the private Workspaces backend."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.workspaces-room-admission-request.v1"] = (
        "lucy.workspaces-room-admission-request.v1"
    )
    request_id: UUID
    room_id: UUID
    experience_mode: Literal["workspaces"] = "workspaces"
    requested_capabilities: tuple[CapabilityName, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def capabilities_are_unique(self) -> WorkspacesRoomAdmissionRequestV1:
        if len(set(self.requested_capabilities)) != len(self.requested_capabilities):
            raise ValueError("requested capabilities must be unique")
        return self


class WorkspacesRoomAdmissionReceiptV1(BaseModel):
    """Non-authorizing acknowledgement of a successful policy preflight."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.workspaces-room-admission-receipt.v1"] = (
        "lucy.workspaces-room-admission-receipt.v1"
    )
    admission_id: UUID
    request_id: UUID
    room_id: UUID
    experience_mode: Literal["workspaces"] = "workspaces"
    admitted_capabilities: tuple[CapabilityName, ...]
    issued_at: datetime
    expires_at: datetime
    usable_as_bearer: Literal[False] = False


class WorkspacesExperienceGateway:
    """Admit Workspaces calls against one fixed Cloud Lucy channel binding.

    ``room_capabilities`` is deployment policy and can only narrow the fixed
    realm binding's actions. The caller's requested capabilities are therefore
    restrictions, never selectors that can expand authority.
    """

    def __init__(
        self,
        *,
        admission: RealmInternalAdmissionService,
        workspace_id: UUID,
        room_capabilities: frozenset[str],
        workspace_version: int = 1,
    ) -> None:
        if not room_capabilities:
            raise ValueError("Workspaces room policy must allow at least one capability")
        self._admission = admission
        self._room_capabilities = room_capabilities
        self._workspace_selector = ExactObjectSelectorV1(
            object_id=workspace_id,
            object_version=workspace_version,
        )

    def preflight(
        self,
        *,
        lucy_authority_credential: SecretStr,
        request: WorkspacesRoomAdmissionRequestV1,
        checked_at: datetime,
    ) -> WorkspacesRoomAdmissionReceiptV1:
        requested = frozenset(request.requested_capabilities)
        if not requested.issubset(self._room_capabilities):
            raise InternalAdmissionDenied("Workspaces request is not authorized")

        contexts = tuple(
            self._admit(
                credential=lucy_authority_credential,
                request_id=request.request_id,
                capability=capability,
                checked_at=checked_at,
            )
            for capability in request.requested_capabilities
        )
        self._require_same_authority(contexts)
        return WorkspacesRoomAdmissionReceiptV1(
            admission_id=uuid4(),
            request_id=request.request_id,
            room_id=request.room_id,
            admitted_capabilities=request.requested_capabilities,
            issued_at=max(context.issued_at for context in contexts),
            expires_at=min(context.expires_at for context in contexts),
        )

    def execute(
        self,
        *,
        lucy_authority_credential: SecretStr,
        request_id: UUID,
        room_id: UUID,
        capability: str,
        checked_at: datetime,
        effect: Callable[[ResolvedExecutionContextV1], EffectResult],
    ) -> EffectResult:
        """Re-admit current authority immediately before one in-process effect."""

        del room_id  # Correlation only; it is never an authority selector.
        if capability not in self._room_capabilities:
            raise InternalAdmissionDenied("Workspaces request is not authorized")
        context = self._admit(
            credential=lucy_authority_credential,
            request_id=request_id,
            capability=capability,
            checked_at=checked_at,
        )
        return effect(context)

    def _admit(
        self,
        *,
        credential: SecretStr,
        request_id: UUID,
        capability: str,
        checked_at: datetime,
    ) -> ResolvedExecutionContextV1:
        return self._admission.admit(
            credential=credential,
            request_id=request_id,
            action=capability,
            resource_selector=self._workspace_selector,
            checked_at=checked_at,
        )

    @staticmethod
    def _require_same_authority(contexts: tuple[ResolvedExecutionContextV1, ...]) -> None:
        first = contexts[0]
        authority = (
            first.principal_id,
            first.target_scope,
            first.workspace_id,
            first.channel_binding_id,
            first.execution_binding,
            first.membership_generations,
        )
        for context in contexts[1:]:
            candidate = (
                context.principal_id,
                context.target_scope,
                context.workspace_id,
                context.channel_binding_id,
                context.execution_binding,
                context.membership_generations,
            )
            if candidate != authority:
                raise InternalAdmissionDenied("Workspaces request is not authorized")
