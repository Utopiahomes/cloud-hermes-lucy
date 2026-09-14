"""Strict, content-free manifest for one R1 V1.3 realm security stamp."""

from __future__ import annotations

import re
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from lucy.contracts.canonical import canonical_sha256

_LOGIN = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")
_SLUG = re.compile(r"[a-z][a-z0-9]{0,30}\Z")
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_IAM_ROLE = re.compile(r"arn:aws:iam::(?P<account>[0-9]{12}):role/[A-Za-z0-9_+=,.@/-]{1,512}\Z")
_LAMBDA_ALIAS = re.compile(
    r"arn:aws:lambda:(?P<region>[a-z0-9-]+):(?P<account>[0-9]{12}):"
    r"function:[A-Za-z0-9_-]{1,64}:(?![0-9]+\Z|\$LATEST\Z)[A-Za-z0-9_-]{1,128}\Z"
)
_KMS_KEY = re.compile(
    r"arn:aws:kms:(?P<region>[a-z0-9-]+):(?P<account>[0-9]{12}):"
    r"key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_STAMP_PREFIX = b"LUCY-REALM-SECURITY-STAMP-V1\0"


class RealmExecutorStampV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    binding_id: UUID
    caller_identity: str = Field(min_length=1, max_length=512)
    executor_identity: str = Field(min_length=1, max_length=512)
    executor_alias_arn: str = Field(min_length=1, max_length=300)
    executor_version: int = Field(ge=1)
    receipt_key_id: str = Field(min_length=1, max_length=512)


class RealmSecurityStampV1(BaseModel):
    """All non-secret bindings needed to admit one private realm generation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.realm-security-stamp.v1"] = "lucy.realm-security-stamp.v1"
    realm_slug: str = Field(min_length=1, max_length=31)
    aws_account_id: str = Field(min_length=12, max_length=12)
    aws_region: Literal["us-east-1"] = "us-east-1"

    content_scope_id: UUID
    tenant_account_id: UUID
    node_id: UUID
    node_tenure_id: UUID
    tenure_epoch: int = Field(ge=1)
    security_realm_id: UUID
    storage_epoch: int = Field(ge=1)
    realm_binding_id: UUID
    workspace_id: UUID
    deployment_id: UUID

    service_binding_id: UUID
    routine_login: str = Field(min_length=1, max_length=63)
    routine_principal_id: UUID
    archive_actor_binding_id: UUID
    policy_login: str = Field(min_length=1, max_length=63)
    policy_principal_id: UUID
    policy_actor_binding_id: UUID
    workflow_login: str = Field(min_length=1, max_length=63)
    workflow_principal_id: UUID
    workflow_actor_binding_id: UUID
    finality_login: str = Field(min_length=1, max_length=63)
    finality_principal_id: UUID
    finality_actor_binding_id: UUID

    binding_generation: int = Field(ge=1)
    node_authz_epoch: int = Field(ge=1)
    policy_version: int = Field(ge=1)
    retrieval_executor: RealmExecutorStampV1
    deletion_executor: RealmExecutorStampV1

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if _SLUG.fullmatch(self.realm_slug) is None:
            raise ValueError("realm slug is invalid")
        if _ACCOUNT.fullmatch(self.aws_account_id) is None:
            raise ValueError("AWS account ID is invalid")
        logins = (self.routine_login, self.policy_login, self.workflow_login, self.finality_login)
        if len(set(logins)) != len(logins):
            raise ValueError("realm LOGIN identifiers must be distinct")
        prefix = f"lucy_{self.realm_slug}_"
        if any(_LOGIN.fullmatch(login) is None or not login.startswith(prefix) for login in logins):
            raise ValueError("realm LOGIN does not match its reviewed namespace")
        principals = (
            self.routine_principal_id,
            self.policy_principal_id,
            self.workflow_principal_id,
            self.finality_principal_id,
        )
        if len(set(principals)) != len(principals):
            raise ValueError("realm service principals must be distinct")
        binding_ids = (
            self.service_binding_id,
            self.archive_actor_binding_id,
            self.policy_actor_binding_id,
            self.workflow_actor_binding_id,
            self.finality_actor_binding_id,
            self.retrieval_executor.binding_id,
            self.deletion_executor.binding_id,
        )
        if len(set(binding_ids)) != len(binding_ids):
            raise ValueError("realm binding identifiers must be distinct")
        self._validate_executor(self.retrieval_executor, "retrieval")
        self._validate_executor(self.deletion_executor, "deletion")
        if (
            self.retrieval_executor.executor_identity
            == self.deletion_executor.executor_identity
            or self.retrieval_executor.executor_alias_arn
            == self.deletion_executor.executor_alias_arn
            or self.retrieval_executor.receipt_key_id == self.deletion_executor.receipt_key_id
        ):
            raise ValueError("retrieval and deletion executor bindings must be distinct")
        return self

    def _validate_executor(self, executor: RealmExecutorStampV1, label: str) -> None:
        caller = _IAM_ROLE.fullmatch(executor.caller_identity)
        alias = _LAMBDA_ALIAS.fullmatch(executor.executor_alias_arn)
        key = _KMS_KEY.fullmatch(executor.receipt_key_id)
        if caller is None or alias is None or key is None:
            raise ValueError(f"{label} executor AWS binding is invalid")
        accounts = {caller.group("account"), alias.group("account"), key.group("account")}
        regions = {alias.group("region"), key.group("region")}
        if accounts != {self.aws_account_id} or regions != {self.aws_region}:
            raise ValueError(f"{label} executor is outside the stamped AWS boundary")

    def digest_hex(self) -> str:
        return canonical_sha256(self.model_dump(mode="python"), prefix=_STAMP_PREFIX)
