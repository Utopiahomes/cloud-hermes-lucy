"""Realm-local authenticated request admission over content-free directory metadata."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from lucy.contracts.security_v1_3 import (
    AudienceClass,
    AuthenticationStrength,
    ExactObjectSelectorV1,
    ExecutionBindingV1,
    OriginScopeV1,
    PrincipalType,
    ResolvedExecutionContextV1,
    build_resolved_execution_context_v1,
)
from lucy.realm_sessions import RealmSessionRegistry


class InternalAdmissionDenied(PermissionError):
    """Identity or current directory authority did not admit the request."""


class VerifiedCustomerIdentityV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: str = Field(default="1", pattern="^1$")
    issuer: str = Field(min_length=1, max_length=512)
    subject: str = Field(min_length=1, max_length=512)
    audience: str = Field(min_length=1, max_length=512)
    principal_type: PrincipalType
    authentication_strength: AuthenticationStrength
    auth_time: datetime
    expires_at: datetime
    session_id: UUID

    @model_validator(mode="after")
    def validate_times(self) -> VerifiedCustomerIdentityV1:
        if self.auth_time.tzinfo is None or self.auth_time.utcoffset() is None:
            raise ValueError("identity auth_time must be timezone-aware")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("identity expires_at must be timezone-aware")
        if not self.auth_time < self.expires_at:
            raise ValueError("identity expiration must follow authentication")
        return self


class CustomerIdentityVerifier(Protocol):
    def verify(
        self,
        credential: SecretStr,
        *,
        expected_issuer: str,
        expected_audience: str,
        checked_at: datetime,
    ) -> VerifiedCustomerIdentityV1: ...


class DirectoryAdmissionRequestV1(BaseModel):
    """Content-free metadata sent to the directory authorization boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    identity_issuer: str
    identity_subject: str
    principal_type: PrincipalType
    target_scope: OriginScopeV1
    workspace_id: UUID
    deployment_id: UUID
    service_principal_id: UUID
    service_binding_id: UUID
    service_binding_generation: int = Field(ge=1)
    channel_binding_id: UUID
    action: str = Field(min_length=1, max_length=512)
    resource_selector: ExactObjectSelectorV1


class DirectoryAdmissionDecisionV1(BaseModel):
    """Current, content-free authority facts returned to one realm process."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    principal_id: UUID
    identity_issuer: str
    identity_subject: str
    principal_type: PrincipalType
    target_scope: OriginScopeV1
    workspace_id: UUID
    deployment_id: UUID
    service_principal_id: UUID
    service_binding_id: UUID
    service_binding_generation: int = Field(ge=1)
    channel_binding_id: UUID
    channel_generation: int = Field(ge=1)
    membership_generations: tuple[int, ...] = Field(min_length=1)
    realm_binding_generation: int = Field(ge=1)
    node_authz_epoch: int = Field(ge=1)
    policy_version: int = Field(ge=1)
    authorized_action: str = Field(min_length=1, max_length=512)
    resource_selector: ExactObjectSelectorV1


class DirectoryAdmissionAuthorizer(Protocol):
    def authorize(
        self,
        request: DirectoryAdmissionRequestV1,
        *,
        checked_at: datetime,
    ) -> DirectoryAdmissionDecisionV1: ...


class PostgresDirectoryAdmissionAuthorizer:
    """Execute-only client for the content-free directory decision function."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def authorize(
        self,
        request: DirectoryAdmissionRequestV1,
        *,
        checked_at: datetime,
    ) -> DirectoryAdmissionDecisionV1:
        scope = request.target_scope
        selector = request.resource_selector
        try:
            with self._sessions() as session:
                result = session.execute(
                    text(
                        "SELECT lucy.resolve_internal_admission_v1("
                        ":identity_issuer,:identity_subject,:principal_type,"
                        ":tenant_account_id,:node_id,:node_tenure_id,:tenure_epoch,"
                        ":security_realm_id,:storage_epoch,:workspace_id,:deployment_id,"
                        ":service_principal_id,:service_binding_id,"
                        ":service_binding_generation,:channel_binding_id,:action,"
                        ":resource_object_id,:resource_object_version,:checked_at)"
                    ),
                    {
                        "identity_issuer": request.identity_issuer,
                        "identity_subject": request.identity_subject,
                        "principal_type": request.principal_type.value,
                        "tenant_account_id": scope.tenant_account_id,
                        "node_id": scope.node_id,
                        "node_tenure_id": scope.node_tenure_id,
                        "tenure_epoch": scope.tenure_epoch,
                        "security_realm_id": scope.security_realm_id,
                        "storage_epoch": scope.storage_epoch,
                        "workspace_id": request.workspace_id,
                        "deployment_id": request.deployment_id,
                        "service_principal_id": request.service_principal_id,
                        "service_binding_id": request.service_binding_id,
                        "service_binding_generation": request.service_binding_generation,
                        "channel_binding_id": request.channel_binding_id,
                        "action": request.action,
                        "resource_object_id": selector.object_id,
                        "resource_object_version": selector.object_version,
                        "checked_at": checked_at,
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise InternalAdmissionDenied("internal request is not authorized") from exc
        return DirectoryAdmissionDecisionV1.model_validate(result)


class RealmInternalAdmissionService:
    """Resolve a server-only context inside a single fixed realm process."""

    def __init__(
        self,
        *,
        sessions: RealmSessionRegistry,
        verified_workload_subject: str,
        identity_verifier: CustomerIdentityVerifier,
        directory: DirectoryAdmissionAuthorizer,
    ) -> None:
        self._sessions = sessions
        self._workload_subject = verified_workload_subject
        self._identity_verifier = identity_verifier
        self._directory = directory

    def admit(
        self,
        *,
        credential: SecretStr,
        request_id: UUID,
        action: str,
        resource_selector: ExactObjectSelectorV1,
        checked_at: datetime,
    ) -> ResolvedExecutionContextV1:
        if checked_at.tzinfo is None or checked_at.utcoffset() is None:
            raise ValueError("checked_at must be timezone-aware")
        try:
            bound = self._sessions.for_verified_workload(
                self._workload_subject,
                action=action,
            )
            binding = bound.binding
            identity = self._identity_verifier.verify(
                credential,
                expected_issuer=binding.identity_issuer,
                expected_audience=binding.identity_audience,
                checked_at=checked_at,
            )
            if (
                identity.issuer != binding.identity_issuer
                or identity.audience != binding.identity_audience
                or identity.authentication_strength
                not in binding.allowed_authentication_strengths
                or identity.expires_at <= checked_at
                or identity.auth_time > checked_at
            ):
                raise InternalAdmissionDenied("internal request is not authorized")
            directory_request = DirectoryAdmissionRequestV1(
                identity_issuer=identity.issuer,
                identity_subject=identity.subject,
                principal_type=identity.principal_type,
                target_scope=binding.target_scope,
                workspace_id=binding.workspace_id,
                deployment_id=binding.deployment_id,
                service_principal_id=binding.service_principal_id,
                service_binding_id=binding.service_binding_id,
                service_binding_generation=binding.binding_generation,
                channel_binding_id=binding.channel_binding_id,
                action=action,
                resource_selector=resource_selector,
            )
            decision = self._directory.authorize(directory_request, checked_at=checked_at)
            self._validate_decision(directory_request, decision, binding.policy_version)
        except InternalAdmissionDenied:
            raise
        except Exception as exc:
            raise InternalAdmissionDenied("internal request is not authorized") from exc

        expires_at = min(identity.expires_at, checked_at + timedelta(minutes=5))
        return build_resolved_execution_context_v1(
            {
                "context_id": uuid4(),
                "request_id": request_id,
                "issued_at": checked_at,
                "expires_at": expires_at,
                "principal_id": decision.principal_id,
                "principal_type": identity.principal_type,
                "identity_issuer": identity.issuer,
                "identity_subject": identity.subject,
                "authn_strength": identity.authentication_strength,
                "auth_time": identity.auth_time,
                "target_scope": decision.target_scope,
                "workspace_id": decision.workspace_id,
                "service_principal_id": decision.service_principal_id,
                "service_binding_id": decision.service_binding_id,
                "execution_binding": ExecutionBindingV1(
                    deployment_id=binding.deployment_id,
                    active_realm_id=decision.target_scope.security_realm_id,
                    active_storage_epoch=decision.target_scope.storage_epoch,
                    realm_binding_generation=decision.realm_binding_generation,
                    node_authz_epoch=decision.node_authz_epoch,
                ),
                "lucy_instance_id": binding.lucy_instance_id,
                "channel_binding_id": decision.channel_binding_id,
                "channel_generation": decision.channel_generation,
                "audience_class": AudienceClass.AUTHENTICATED_INTERNAL,
                "session_id": identity.session_id,
                "action": action,
                "resource_selector": decision.resource_selector,
                "policy_version": decision.policy_version,
                "membership_generations": decision.membership_generations,
                "context_issuer": binding.context_issuer,
            }
        )

    @staticmethod
    def _validate_decision(
        request: DirectoryAdmissionRequestV1,
        decision: DirectoryAdmissionDecisionV1,
        policy_version: int,
    ) -> None:
        if (
            decision.identity_issuer != request.identity_issuer
            or decision.identity_subject != request.identity_subject
            or decision.principal_type != request.principal_type
            or decision.target_scope != request.target_scope
            or decision.workspace_id != request.workspace_id
            or decision.deployment_id != request.deployment_id
            or decision.service_principal_id != request.service_principal_id
            or decision.service_binding_id != request.service_binding_id
            or decision.service_binding_generation != request.service_binding_generation
            or decision.channel_binding_id != request.channel_binding_id
            or decision.authorized_action != request.action
            or decision.resource_selector != request.resource_selector
            or decision.policy_version != policy_version
        ):
            raise InternalAdmissionDenied("internal request is not authorized")
