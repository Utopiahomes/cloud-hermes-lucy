"""Connection selection from verified workload identity, never request scope."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy.orm import Session, sessionmaker

from lucy.contracts.security_v1_3 import AuthenticationStrength, OriginScopeV1
from lucy.db import create_session_factory


class RealmBindingConfigurationError(ValueError):
    pass


class RealmAccessDenied(PermissionError):
    pass


class RealmRuntimeBindingV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: str = Field(default="1", pattern="^1$")
    workload_subject: str = Field(min_length=1, max_length=512)
    service_principal_id: UUID
    service_binding_id: UUID
    target_scope: OriginScopeV1
    workspace_id: UUID
    deployment_id: UUID
    channel_binding_id: UUID
    identity_issuer: str = Field(min_length=1, max_length=512)
    identity_audience: str = Field(min_length=1, max_length=512)
    context_issuer: str = Field(min_length=1, max_length=512)
    database_url: SecretStr
    allowed_actions: frozenset[str] = Field(min_length=1)
    allowed_authentication_strengths: frozenset[AuthenticationStrength] = Field(min_length=1)
    binding_generation: int = Field(ge=1)
    policy_version: int = Field(ge=1)
    lucy_instance_id: UUID | None = None


@dataclass(frozen=True)
class BoundRealmSessions:
    binding: RealmRuntimeBindingV1
    sessions: sessionmaker[Session]


class RealmSessionRegistry:
    """One deployment process's fixed realm credential and session factory."""

    def __init__(self, bindings: tuple[RealmRuntimeBindingV1, ...]) -> None:
        if len(bindings) != 1:
            raise RealmBindingConfigurationError(
                "a realm process must contain exactly one runtime binding"
            )
        self._binding = bindings[0]
        self._sessions = create_session_factory(self._binding.database_url.get_secret_value())

    def for_verified_workload(
        self,
        workload_subject: str,
        *,
        action: str,
        requested_realm_id: UUID | None = None,
        requested_workspace_id: UUID | None = None,
    ) -> BoundRealmSessions:
        """Resolve a verified subject and reject any conflicting request hint."""
        binding = self._binding
        if workload_subject != binding.workload_subject or action not in binding.allowed_actions:
            raise RealmAccessDenied("realm workload is not authorized")
        if requested_realm_id is not None and (
            requested_realm_id != binding.target_scope.security_realm_id
        ):
            raise RealmAccessDenied("realm workload is not authorized")
        if requested_workspace_id is not None and requested_workspace_id != binding.workspace_id:
            raise RealmAccessDenied("realm workload is not authorized")
        return BoundRealmSessions(binding=binding, sessions=self._sessions)
