"""Connection selection from verified workload identity, never request scope."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy.orm import Session, sessionmaker

from lucy.contracts.security_v1_3 import OriginScopeV1
from lucy.db import create_session_factory


class RealmBindingConfigurationError(ValueError):
    pass


class RealmAccessDenied(PermissionError):
    pass


class RealmRuntimeBindingV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: str = Field(default="1", pattern="^1$")
    workload_subject: str = Field(min_length=1, max_length=512)
    service_binding_id: UUID
    target_scope: OriginScopeV1
    workspace_id: UUID
    deployment_id: UUID
    database_url: SecretStr
    allowed_actions: frozenset[str] = Field(min_length=1)
    binding_generation: int = Field(ge=1)


@dataclass(frozen=True)
class BoundRealmSessions:
    binding: RealmRuntimeBindingV1
    sessions: sessionmaker[Session]


class RealmSessionRegistry:
    """Deployment-owned registry populated after workload-identity verification."""

    def __init__(self, bindings: tuple[RealmRuntimeBindingV1, ...]) -> None:
        by_subject = {binding.workload_subject: binding for binding in bindings}
        if not bindings or len(by_subject) != len(bindings):
            raise RealmBindingConfigurationError(
                "realm runtime bindings must contain unique workload subjects"
            )
        database_urls = [binding.database_url.get_secret_value() for binding in bindings]
        if len(set(database_urls)) != len(database_urls):
            raise RealmBindingConfigurationError(
                "R1 private realm workloads must not share database credentials"
            )
        self._bindings = by_subject
        self._sessions = {
            subject: create_session_factory(binding.database_url.get_secret_value())
            for subject, binding in by_subject.items()
        }

    def for_verified_workload(
        self,
        workload_subject: str,
        *,
        action: str,
        requested_realm_id: UUID | None = None,
        requested_workspace_id: UUID | None = None,
    ) -> BoundRealmSessions:
        """Resolve a verified subject and reject any conflicting request hint."""
        binding = self._bindings.get(workload_subject)
        if binding is None or action not in binding.allowed_actions:
            raise RealmAccessDenied("realm workload is not authorized")
        if requested_realm_id is not None and (
            requested_realm_id != binding.target_scope.security_realm_id
        ):
            raise RealmAccessDenied("realm workload is not authorized")
        if requested_workspace_id is not None and requested_workspace_id != binding.workspace_id:
            raise RealmAccessDenied("realm workload is not authorized")
        return BoundRealmSessions(binding=binding, sessions=self._sessions[workload_subject])
