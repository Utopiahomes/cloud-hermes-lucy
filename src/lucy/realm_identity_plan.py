"""Content-free, pre-commissioning identity plan for one private realm."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from lucy.contracts.canonical import canonical_sha256

_SLUG = re.compile(r"[a-z][a-z0-9-]{0,79}\Z")
_REALM_SLUG = re.compile(r"[a-z][a-z0-9]{0,30}\Z")
_NAMESPACE = re.compile(r"[a-z0-9-]{3,32}\Z")
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_PLAN_PREFIX = b"LUCY-REALM-IDENTITY-PLAN-V1\0"
_UUID_FIELDS = (
    "tenant_account_id",
    "node_id",
    "node_tenure_id",
    "security_realm_id",
    "content_scope_id",
    "realm_binding_id",
    "workspace_id",
    "deployment_id",
    "wallet_id",
    "service_binding_id",
    "routine_principal_id",
    "archive_actor_binding_id",
    "policy_principal_id",
    "policy_actor_binding_id",
    "workflow_principal_id",
    "workflow_actor_binding_id",
    "finality_principal_id",
    "finality_actor_binding_id",
    "retrieval_executor_binding_id",
    "deletion_executor_binding_id",
    "archive_registry_id",
    "deletion_journal_id",
)


class RealmIdentityPlanV1(BaseModel):
    """Stable non-secret identities created before any cloud effect is authorized."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.realm-identity-plan.v1"] = (
        "lucy.realm-identity-plan.v1"
    )
    status: Literal["planned_not_authorized"] = "planned_not_authorized"
    realm_slug: str = Field(min_length=1, max_length=31)
    resource_namespace: str = Field(min_length=3, max_length=32)
    aws_account_id: str = Field(min_length=12, max_length=12)
    aws_region: Literal["us-east-1"] = "us-east-1"

    account_slug: str = Field(min_length=1, max_length=80)
    account_display_name: str = Field(min_length=1, max_length=200)
    node_slug: str = Field(min_length=1, max_length=80)
    node_display_name: str = Field(min_length=1, max_length=200)
    node_kind: Literal["person", "organization", "project", "community", "service"]
    workspace_slug: str = Field(min_length=1, max_length=80)
    service_issuer: str = Field(min_length=1, max_length=300)

    tenant_account_id: UUID
    node_id: UUID
    node_tenure_id: UUID
    tenure_epoch: int = Field(default=1, ge=1)
    security_realm_id: UUID
    content_scope_id: UUID
    realm_binding_id: UUID
    workspace_id: UUID
    deployment_id: UUID
    wallet_id: UUID
    service_binding_id: UUID
    routine_principal_id: UUID
    archive_actor_binding_id: UUID
    policy_principal_id: UUID
    policy_actor_binding_id: UUID
    workflow_principal_id: UUID
    workflow_actor_binding_id: UUID
    finality_principal_id: UUID
    finality_actor_binding_id: UUID
    retrieval_executor_binding_id: UUID
    deletion_executor_binding_id: UUID
    archive_registry_id: UUID
    deletion_journal_id: UUID
    binding_generation: int = Field(default=1, ge=1)
    node_authz_epoch: int = Field(default=1, ge=1)
    policy_version: int = Field(default=1, ge=1)
    storage_epoch: int = Field(default=1, ge=1)
    planned_at: datetime

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        if _REALM_SLUG.fullmatch(self.realm_slug) is None:
            raise ValueError("realm slug is invalid")
        if _NAMESPACE.fullmatch(self.resource_namespace) is None:
            raise ValueError("resource namespace is invalid")
        if _ACCOUNT.fullmatch(self.aws_account_id) is None:
            raise ValueError("AWS account ID is invalid")
        if any(
            _SLUG.fullmatch(value) is None
            for value in (self.account_slug, self.node_slug, self.workspace_slug)
        ):
            raise ValueError("realm identity plan contains an invalid slug")
        if self.service_issuer != f"lucy://{self.realm_slug}/services":
            raise ValueError("realm service issuer is invalid")
        if self.planned_at.utcoffset() is None:
            raise ValueError("realm identity plan timestamp must be timezone-aware")
        identities = tuple(getattr(self, name) for name in _UUID_FIELDS)
        if len(identities) != len(set(identities)):
            raise ValueError("realm identity UUIDs must be distinct")
        return self

    @property
    def routine_login(self) -> str:
        return f"lucy_{self.realm_slug}_routine"

    @property
    def policy_login(self) -> str:
        return f"lucy_{self.realm_slug}_policy"

    @property
    def workflow_login(self) -> str:
        return f"lucy_{self.realm_slug}_sensitive_workflow"

    @property
    def finality_login(self) -> str:
        return f"lucy_{self.realm_slug}_finality"

    @property
    def digest(self) -> str:
        return canonical_sha256(self, prefix=_PLAN_PREFIX)


def create_realm_identity_plan(
    *,
    realm_slug: str,
    resource_namespace: str,
    aws_account_id: str,
    account_slug: str,
    account_display_name: str,
    node_slug: str,
    node_display_name: str,
    node_kind: Literal["person", "organization", "project", "community", "service"],
    workspace_slug: str,
    planned_at: datetime,
) -> RealmIdentityPlanV1:
    identities = [uuid4() for _ in range(22)]
    return RealmIdentityPlanV1(
        realm_slug=realm_slug,
        resource_namespace=resource_namespace,
        aws_account_id=aws_account_id,
        account_slug=account_slug,
        account_display_name=account_display_name,
        node_slug=node_slug,
        node_display_name=node_display_name,
        node_kind=node_kind,
        workspace_slug=workspace_slug,
        service_issuer=f"lucy://{realm_slug}/services",
        tenant_account_id=identities[0],
        node_id=identities[1],
        node_tenure_id=identities[2],
        security_realm_id=identities[3],
        content_scope_id=identities[4],
        realm_binding_id=identities[5],
        workspace_id=identities[6],
        deployment_id=identities[7],
        wallet_id=identities[8],
        service_binding_id=identities[9],
        routine_principal_id=identities[10],
        archive_actor_binding_id=identities[11],
        policy_principal_id=identities[12],
        policy_actor_binding_id=identities[13],
        workflow_principal_id=identities[14],
        workflow_actor_binding_id=identities[15],
        finality_principal_id=identities[16],
        finality_actor_binding_id=identities[17],
        retrieval_executor_binding_id=identities[18],
        deletion_executor_binding_id=identities[19],
        archive_registry_id=identities[20],
        deletion_journal_id=identities[21],
        planned_at=planned_at,
    )
