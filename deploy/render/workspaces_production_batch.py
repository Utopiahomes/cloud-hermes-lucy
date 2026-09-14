"""Content-free coordinator for the paused Workspaces production rollout.

This module does not call Render, AWS, PostgreSQL, or a Lucy endpoint.  It binds
the independently reviewed production operations into one resumable plan and
validates the content-free receipts emitted by those operations.  Live drivers
remain separate so a plan cannot turn into production authority by being loaded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, model_validator

from deploy.postgres.provision_workspaces_authority_v1 import WorkspacesAuthorityMembershipV1
from lucy.contracts.canonical import canonical_json_bytes, canonical_sha256

PLAN_PREFIX = b"LUCY-WORKSPACES-PRODUCTION-BATCH-V1\0"
RECEIPT_PREFIX = b"LUCY-WORKSPACES-PRODUCTION-BATCH-RECEIPT-V1\0"
TRANSPORT_TOKEN_PREFIX = b"LUCY-WORKSPACES-TRANSPORT-TOKEN-V1\0"
AUTHORITY_TOKEN_PREFIX = b"LUCY-WORKSPACES-AUTHORITY-TOKEN-V1\0"
PRIVATE_SERVICE_PREFIX = b"LUCY-WORKSPACES-PRIVATE-SERVICE-V1\0"

TARGET_SCHEMA = "0068_workspaces_service_auth"
ACCEPTED_SOURCE_SCHEMAS = (
    "0054_stage2_scoped_turn_commit",
    "0057_public_conversation",
    TARGET_SCHEMA,
)
REQUIRED_ACTIONS = (
    "freeze_workspaces_autodeploy",
    "contain_existing_surfaces",
    "migrate_schema",
    "apply_service_membership",
    "restore_existing_surfaces",
    "create_private_service",
    "connect_workspaces_worker",
    "run_acceptance",
)
BUILD_AUTHORIZATION = "build-workspaces-production-batch-v1"

_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_RENDER_SERVICE = re.compile(r"(?:srv|crn)-[a-z0-9]{20}\Z")
_RENDER_DEPLOY = re.compile(r"dep-[a-z0-9]{20}\Z")
_SLUG = re.compile(r"[a-z][a-z0-9]{0,30}\Z")


class BatchContractError(RuntimeError):
    """The batch plan or receipt ledger differs from its reviewed boundary."""


class Stage(StrEnum):
    PREFLIGHT = "preflight"
    CONTAINED = "contained"
    MIGRATED = "migrated"
    MEMBERSHIP_APPLIED = "membership_applied"
    EXISTING_SURFACES_RESTORED = "existing_surfaces_restored"
    PRIVATE_SERVICE_READY = "private_service_ready"
    WORKER_CONNECTED = "worker_connected"
    ACCEPTED = "accepted"


STAGE_ORDER = tuple(Stage)


class RenderServiceTargetV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    service_id: str
    name: str = Field(min_length=1, max_length=100)
    expected_commit: str
    rollback_deploy_id: str

    @model_validator(mode="after")
    def validate_identifiers(self) -> RenderServiceTargetV1:
        if _RENDER_SERVICE.fullmatch(self.service_id) is None:
            raise ValueError("Render service ID is invalid")
        if _COMMIT.fullmatch(self.expected_commit) is None:
            raise ValueError("expected commit must be a full lowercase Git SHA")
        if _RENDER_DEPLOY.fullmatch(self.rollback_deploy_id) is None:
            raise ValueError("rollback deploy ID is invalid")
        return self


class ExistingServicesV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cloud_public: RenderServiceTargetV1
    cloud_routine: RenderServiceTargetV1
    cloud_gateway: RenderServiceTargetV1
    workspaces_api: RenderServiceTargetV1
    workspaces_operations: RenderServiceTargetV1
    workspaces_lucy: RenderServiceTargetV1

    @model_validator(mode="after")
    def require_distinct_services(self) -> ExistingServicesV1:
        targets = tuple(self.__dict__.values())
        ids = {target.service_id for target in targets}
        names = {target.name for target in targets}
        if len(ids) != len(targets) or len(names) != len(targets):
            raise ValueError("each existing service target must be distinct")
        return self


class PrivateServiceTargetV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Literal["lucy-workspaces-private"] = "lucy-workspaces-private"
    owner_id: str = Field(pattern=r"^tea-[a-z0-9]{20}$")
    environment_id: str = Field(pattern=r"^evm-[a-z0-9]{20}$")
    repo: Literal["https://github.com/Utopiahomes/cloud-hermes-lucy"]
    branch: Literal["main"] = "main"
    region: Literal["virginia"] = "virginia"
    plan: Literal["0.5c-512mb"] = "0.5c-512mb"
    docker_command: Literal["python -m lucy.workspaces_runtime"] = (
        "python -m lucy.workspaces_runtime"
    )
    health_path: Literal["/health"] = "/health"
    auto_deploy: Literal[False] = False

    def digest_hex(self) -> str:
        return canonical_sha256(self.model_dump(mode="python"), prefix=PRIVATE_SERVICE_PREFIX)


class WorkspacesProductionBatchV1(BaseModel):
    """Exact, content-free production batch reviewed before any live action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["lucy.workspaces-production-batch.v1"] = (
        "lucy.workspaces-production-batch.v1"
    )
    batch_id: UUID
    environment: Literal["production"] = "production"
    realm_slug: Literal["utopia"] = "utopia"
    issued_at: datetime
    expires_at: datetime
    cloud_release_commit: str
    workspaces_release_commit: str
    accepted_source_schemas: tuple[str, ...] = ACCEPTED_SOURCE_SCHEMAS
    target_schema: Literal["0068_workspaces_service_auth"] = TARGET_SCHEMA
    membership: WorkspacesAuthorityMembershipV1
    membership_manifest_sha256: str
    private_service_config_sha256: str
    transport_token_commitment: str
    authority_token_commitment: str
    existing_services: ExistingServicesV1
    private_service: PrivateServiceTargetV1
    actions: tuple[str, ...] = REQUIRED_ACTIONS
    capture_enabled: Literal[False] = False
    paid_inference_enabled: Literal[False] = False
    customer_memory_import_enabled: Literal[False] = False
    node_switching_enabled: Literal[False] = False

    @model_validator(mode="after")
    def validate_boundary(self) -> WorkspacesProductionBatchV1:
        for value, label in (
            (self.cloud_release_commit, "cloud release commit"),
            (self.workspaces_release_commit, "Workspaces release commit"),
        ):
            if _COMMIT.fullmatch(value) is None:
                raise ValueError(f"{label} must be a full lowercase Git SHA")
        for value, label in (
            (self.membership_manifest_sha256, "membership manifest digest"),
            (self.private_service_config_sha256, "private service config digest"),
            (self.transport_token_commitment, "transport token commitment"),
            (self.authority_token_commitment, "authority token commitment"),
        ):
            if _DIGEST.fullmatch(value) is None:
                raise ValueError(f"{label} is invalid")
        if self.transport_token_commitment == self.authority_token_commitment:
            raise ValueError("transport and authority credentials must be independently derived")
        if self.membership.digest_hex() != self.membership_manifest_sha256:
            raise ValueError("membership manifest digest does not match its canonical payload")
        if self.private_service.digest_hex() != self.private_service_config_sha256:
            raise ValueError("private service config digest does not match its canonical payload")
        if self.accepted_source_schemas != ACCEPTED_SOURCE_SCHEMAS:
            raise ValueError("accepted source schema set differs from the reviewed migration gate")
        if self.actions != REQUIRED_ACTIONS:
            raise ValueError("batch action order differs from the reviewed rollout")
        if _SLUG.fullmatch(self.realm_slug) is None:
            raise ValueError("realm slug is invalid")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("batch timestamps must be timezone-aware")
        lifetime = self.expires_at - self.issued_at
        if lifetime <= timedelta(0) or lifetime > timedelta(hours=6):
            raise ValueError("batch lifetime must be positive and no longer than six hours")
        expected_names = {
            "cloud_public": "lucy-public",
            "cloud_routine": "lucy-routine",
            "cloud_gateway": "lucy-telegram-private-stage1",
            "workspaces_api": "utopia-studio-api",
            "workspaces_operations": "utopia-studio-operations",
            "workspaces_lucy": "utopia-studio-lucy",
        }
        for field, expected_name in expected_names.items():
            target = getattr(self.existing_services, field)
            if target.name != expected_name:
                raise ValueError(f"{field} identifies the wrong Render service")
        for field in ("workspaces_api", "workspaces_operations", "workspaces_lucy"):
            target = getattr(self.existing_services, field)
            if target.expected_commit != self.workspaces_release_commit:
                raise ValueError("Workspaces services must bind the reviewed release commit")
        return self

    def digest_hex(self) -> str:
        return canonical_sha256(self.model_dump(mode="python"), prefix=PLAN_PREFIX)


class WorkspacesProductionBatchInputsV1(BaseModel):
    """Non-secret inputs used to construct the exact batch manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    batch_id: UUID
    issued_at: datetime
    expires_at: datetime
    cloud_release_commit: str
    workspaces_release_commit: str
    membership: WorkspacesAuthorityMembershipV1
    existing_services: ExistingServicesV1
    private_service: PrivateServiceTargetV1


class PreflightEvidenceV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    aws_verifier_passed: Literal[True]
    render_drift_passed: Literal[True]
    cloud_release_commit: str
    workspaces_release_commit: str
    workspaces_transport_disabled: Literal[True]
    affected_autodeploy_disabled: Literal[True]


class ContainedEvidenceV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    cloud_public_suspended: Literal[True]
    cloud_routine_suspended: Literal[True]
    cloud_gateway_suspended: Literal[True]
    database_sessions_drained: Literal[True]
    admission_state: Literal["quarantined"]
    capture_boundary_safe: Literal[True]


class MigratedEvidenceV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source_revision: str
    target_revision: Literal["0068_workspaces_service_auth"]
    admission_state: Literal["quarantined"]
    capture_boundary_safe: Literal[True]
    existing_surface_grants_verified: Literal[True]
    workspaces_queue_grants_verified: Literal[True]
    direct_table_access_denied: Literal[True]
    residual_schema_create: Literal[False]

    @model_validator(mode="after")
    def validate_source(self) -> MigratedEvidenceV1:
        if self.source_revision not in ACCEPTED_SOURCE_SCHEMAS:
            raise ValueError("migration source revision is outside the reviewed set")
        return self


class MembershipEvidenceV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    membership_manifest_sha256: str
    applied: Literal[True]
    admission_state: Literal["quarantined"]


class RestoredEvidenceV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    telegram_stage2_reopened: Literal[True]
    public_lucy_reopened: Literal[True]
    telegram_negative_controls_passed: Literal[True]
    public_negative_controls_passed: Literal[True]


class PrivateServiceEvidenceV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    service_id: str
    deployed_commit: str
    auto_deploy_disabled: Literal[True]
    health_passed: Literal[True]
    readiness_passed: Literal[True]
    capture_refusal_passed: Literal[True]
    wrong_login_denied: Literal[True]
    wrong_token_denied: Literal[True]
    missing_membership_denied: Literal[True]
    direct_table_access_denied: Literal[True]


class WorkerConnectedEvidenceV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    workspaces_release_commit: str
    transport_commitment: str
    admission_preflight_passed: Literal[True]
    denial_preserved_human_room: Literal[True]


class AcceptanceEvidenceV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    approved_knowledge_query_passed: Literal[True]
    idempotent_task_delegation_passed: Literal[True]
    cross_node_denied: Literal[True]
    excluded_capability_denied: Literal[True]
    unavailable_lucy_preserved_human_room: Literal[True]
    capture_remained_disabled: Literal[True]
    paid_inference_remained_disabled: Literal[True]


Evidence = Annotated[
    PreflightEvidenceV1
    | ContainedEvidenceV1
    | MigratedEvidenceV1
    | MembershipEvidenceV1
    | RestoredEvidenceV1
    | PrivateServiceEvidenceV1
    | WorkerConnectedEvidenceV1
    | AcceptanceEvidenceV1,
    Field(union_mode="left_to_right"),
]


class BatchStageReceiptV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["lucy.workspaces-production-batch-receipt.v1"] = (
        "lucy.workspaces-production-batch-receipt.v1"
    )
    batch_digest: str
    stage: Stage
    prior_receipt_sha256: str | None
    started_at: datetime
    completed_at: datetime
    evidence: Evidence
    status: Literal["passed"] = "passed"

    @model_validator(mode="after")
    def validate_receipt(self) -> BatchStageReceiptV1:
        if _DIGEST.fullmatch(self.batch_digest) is None:
            raise ValueError("batch digest is invalid")
        if self.prior_receipt_sha256 is not None and _DIGEST.fullmatch(
            self.prior_receipt_sha256
        ) is None:
            raise ValueError("prior receipt digest is invalid")
        if self.started_at.tzinfo is None or self.completed_at.tzinfo is None:
            raise ValueError("receipt timestamps must be timezone-aware")
        if self.completed_at < self.started_at:
            raise ValueError("receipt completion precedes its start")
        expected_type = EVIDENCE_BY_STAGE[self.stage]
        if type(self.evidence) is not expected_type:
            raise ValueError("receipt evidence does not match its stage")
        return self

    def digest_hex(self) -> str:
        return canonical_sha256(self.model_dump(mode="python"), prefix=RECEIPT_PREFIX)


class BatchContainmentReceiptV1(BaseModel):
    """Terminal proof that a failed batch was left in a bounded safe state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["lucy.workspaces-production-batch-containment.v1"] = (
        "lucy.workspaces-production-batch-containment.v1"
    )
    batch_digest: str
    failed_stage: Stage
    prior_receipt_sha256: str | None
    occurred_at: datetime
    reason: Literal[
        "precondition_failed",
        "operation_failed",
        "verification_failed",
        "timeout",
        "operator_abort",
    ]
    workspaces_transport_disabled: Literal[True]
    affected_autodeploy_disabled: Literal[True]
    existing_surfaces: Literal["contained", "restored"]
    admission_state: Literal["quarantined", "ready"]
    capture_boundary_safe: Literal[True]
    private_service: Literal["absent", "suspended"]

    @model_validator(mode="after")
    def validate_identifiers(self) -> BatchContainmentReceiptV1:
        if _DIGEST.fullmatch(self.batch_digest) is None:
            raise ValueError("batch digest is invalid")
        if self.prior_receipt_sha256 is not None and _DIGEST.fullmatch(
            self.prior_receipt_sha256
        ) is None:
            raise ValueError("prior receipt digest is invalid")
        if self.occurred_at.tzinfo is None:
            raise ValueError("containment timestamp must be timezone-aware")
        return self


class BatchDriver(Protocol):
    """Live-operation boundary supplied only inside an approved maintenance job."""

    def execute_stage(
        self,
        plan: WorkspacesProductionBatchV1,
        stage: Stage,
        prior_receipt_sha256: str | None,
    ) -> BatchStageReceiptV1: ...

    def contain_failure(
        self,
        plan: WorkspacesProductionBatchV1,
        failed_stage: Stage,
        prior_receipt_sha256: str | None,
        error: Exception,
    ) -> BatchContainmentReceiptV1: ...


EVIDENCE_BY_STAGE: dict[Stage, type[BaseModel]] = {
    Stage.PREFLIGHT: PreflightEvidenceV1,
    Stage.CONTAINED: ContainedEvidenceV1,
    Stage.MIGRATED: MigratedEvidenceV1,
    Stage.MEMBERSHIP_APPLIED: MembershipEvidenceV1,
    Stage.EXISTING_SURFACES_RESTORED: RestoredEvidenceV1,
    Stage.PRIVATE_SERVICE_READY: PrivateServiceEvidenceV1,
    Stage.WORKER_CONNECTED: WorkerConnectedEvidenceV1,
    Stage.ACCEPTED: AcceptanceEvidenceV1,
}

STAGE_INSTRUCTIONS: dict[Stage, str] = {
    Stage.PREFLIGHT: (
        "Re-run AWS and Render drift checks, bind exact commits and rollback deploys, "
        "disable auto-deploy on all affected Workspaces services, and prove the "
        "transport pair absent."
    ),
    Stage.CONTAINED: (
        "Suspend Public Lucy and the private Telegram gateway/routine, drain database sessions, "
        "quarantine admission, and establish a capture-safe boundary."
    ),
    Stage.MIGRATED: (
        "Run migrate_workspaces_v1.py through the private migration login and retain "
        "its exact receipt."
    ),
    Stage.MEMBERSHIP_APPLIED: (
        "Run provision_workspaces_authority_v1.py with the digest-bound membership manifest."
    ),
    Stage.EXISTING_SURFACES_RESTORED: (
        "Reopen Telegram Stage 2 and Public Lucy with their existing controllers; verify denials."
    ),
    Stage.PRIVATE_SERVICE_READY: (
        "Create the private manual-deploy Workspaces service at the exact Cloud release "
        "and run health and denial checks."
    ),
    Stage.WORKER_CONNECTED: (
        "Install only the private address and independent transport token on the "
        "Workspaces Lucy worker, deploy the exact Workspaces release, and run "
        "content-free preflight."
    ),
    Stage.ACCEPTED: (
        "Run the bounded Homes Workspace query, idempotent delegation, "
        "cross-node/capability denials, and human-room continuity checks."
    ),
}


def token_commitment(token: str, *, authority: bool) -> str:
    if len(token.encode("utf-8")) < 32:
        raise BatchContractError("production tokens must contain at least 32 UTF-8 bytes")
    prefix = AUTHORITY_TOKEN_PREFIX if authority else TRANSPORT_TOKEN_PREFIX
    return hashlib.sha256(prefix + token.encode("utf-8")).hexdigest()


def verify_token_pair(plan: WorkspacesProductionBatchV1, transport: str, authority: str) -> None:
    if transport == authority:
        raise BatchContractError("transport and authority credentials must differ")
    if token_commitment(transport, authority=False) != plan.transport_token_commitment:
        raise BatchContractError("transport token does not match the reviewed commitment")
    if token_commitment(authority, authority=True) != plan.authority_token_commitment:
        raise BatchContractError("authority token does not match the reviewed commitment")


def build_plan(
    inputs: WorkspacesProductionBatchInputsV1,
    *,
    transport_token: str,
    authority_token: str,
) -> WorkspacesProductionBatchV1:
    if transport_token == authority_token:
        raise BatchContractError("transport and authority credentials must differ")
    return WorkspacesProductionBatchV1(
        **inputs.model_dump(mode="python"),
        membership_manifest_sha256=inputs.membership.digest_hex(),
        private_service_config_sha256=inputs.private_service.digest_hex(),
        transport_token_commitment=token_commitment(transport_token, authority=False),
        authority_token_commitment=token_commitment(authority_token, authority=True),
    )


def validate_ledger(
    plan: WorkspacesProductionBatchV1,
    receipts: Sequence[BatchStageReceiptV1],
    *,
    now: datetime | None = None,
) -> Stage | None:
    current = datetime.now(UTC) if now is None else now
    if current.tzinfo is None:
        raise BatchContractError("ledger validation time must be timezone-aware")
    if current > plan.expires_at:
        raise BatchContractError("production batch has expired")
    if len(receipts) > len(STAGE_ORDER):
        raise BatchContractError("receipt ledger contains too many stages")
    plan_digest = plan.digest_hex()
    prior: str | None = None
    prior_completed: datetime | None = None
    for index, receipt in enumerate(receipts):
        if receipt.stage != STAGE_ORDER[index]:
            raise BatchContractError("receipt stages are missing, duplicated, or reordered")
        if receipt.batch_digest != plan_digest:
            raise BatchContractError("receipt belongs to a different production batch")
        if receipt.prior_receipt_sha256 != prior:
            raise BatchContractError("receipt chain does not match")
        if receipt.started_at < plan.issued_at or receipt.completed_at > plan.expires_at:
            raise BatchContractError("receipt falls outside the reviewed batch window")
        if prior_completed is not None and receipt.started_at < prior_completed:
            raise BatchContractError("receipt stages overlap or move backward in time")
        _validate_evidence_binding(plan, receipt)
        prior = receipt.digest_hex()
        prior_completed = receipt.completed_at
    return None if len(receipts) == len(STAGE_ORDER) else STAGE_ORDER[len(receipts)]


def validate_containment(
    plan: WorkspacesProductionBatchV1,
    receipts: Sequence[BatchStageReceiptV1],
    containment: BatchContainmentReceiptV1,
) -> None:
    next_stage = validate_ledger(plan, receipts, now=containment.occurred_at)
    if next_stage is None or containment.failed_stage != next_stage:
        raise BatchContractError("containment does not identify the next incomplete stage")
    if containment.batch_digest != plan.digest_hex():
        raise BatchContractError("containment belongs to a different production batch")
    prior = None if not receipts else receipts[-1].digest_hex()
    if containment.prior_receipt_sha256 != prior:
        raise BatchContractError("containment receipt chain does not match")
    if receipts and containment.occurred_at < receipts[-1].completed_at:
        raise BatchContractError("containment precedes the completed receipt chain")
    stage_index = STAGE_ORDER.index(next_stage)
    restored_index = STAGE_ORDER.index(Stage.EXISTING_SURFACES_RESTORED)
    if stage_index >= restored_index:
        if containment.existing_surfaces != "restored":
            raise BatchContractError(
                "post-restore containment must keep existing surfaces restored"
            )
    elif next_stage != Stage.PREFLIGHT and (
        containment.existing_surfaces != "contained"
        or containment.admission_state != "quarantined"
    ):
        raise BatchContractError("pre-restore failure must remain contained and quarantined")


def run_remaining_stages(
    plan: WorkspacesProductionBatchV1,
    receipts: Sequence[BatchStageReceiptV1],
    *,
    driver: BatchDriver,
    persist_receipt: Callable[[BatchStageReceiptV1], None],
    persist_containment: Callable[[BatchContainmentReceiptV1], None],
    now: datetime | None = None,
) -> tuple[list[BatchStageReceiptV1], BatchContainmentReceiptV1 | None]:
    """Run an approved driver from the exact next stage and persist every checkpoint."""

    completed = list(receipts)
    next_stage = validate_ledger(plan, completed, now=now)
    while next_stage is not None:
        prior = None if not completed else completed[-1].digest_hex()
        try:
            receipt = driver.execute_stage(plan, next_stage, prior)
            candidate = [*completed, receipt]
            validate_ledger(plan, candidate, now=receipt.completed_at)
            persist_receipt(receipt)
            completed.append(receipt)
            next_stage = validate_ledger(plan, completed, now=receipt.completed_at)
        except Exception as exc:
            containment = driver.contain_failure(plan, next_stage, prior, exc)
            validate_containment(plan, completed, containment)
            persist_containment(containment)
            return completed, containment
    return completed, None


def _validate_evidence_binding(
    plan: WorkspacesProductionBatchV1, receipt: BatchStageReceiptV1
) -> None:
    evidence = receipt.evidence
    if isinstance(evidence, PreflightEvidenceV1):
        if (
            evidence.cloud_release_commit != plan.cloud_release_commit
            or evidence.workspaces_release_commit != plan.workspaces_release_commit
        ):
            raise BatchContractError("preflight commits differ from the reviewed batch")
    elif isinstance(evidence, MembershipEvidenceV1):
        if evidence.membership_manifest_sha256 != plan.membership_manifest_sha256:
            raise BatchContractError("membership receipt digest differs from the reviewed manifest")
    elif isinstance(evidence, PrivateServiceEvidenceV1):
        if _RENDER_SERVICE.fullmatch(evidence.service_id) is None:
            raise BatchContractError("private service receipt contains an invalid service ID")
        if evidence.deployed_commit != plan.cloud_release_commit:
            raise BatchContractError("private service deployed the wrong Cloud release")
    elif isinstance(evidence, WorkerConnectedEvidenceV1):
        if evidence.workspaces_release_commit != plan.workspaces_release_commit:
            raise BatchContractError("worker receipt identifies the wrong Workspaces release")
        if evidence.transport_commitment != plan.transport_token_commitment:
            raise BatchContractError("worker receipt identifies the wrong transport credential")


def status_report(
    plan: WorkspacesProductionBatchV1,
    receipts: Sequence[BatchStageReceiptV1],
    *,
    now: datetime | None = None,
    containment: BatchContainmentReceiptV1 | None = None,
) -> dict[str, Any]:
    validation_time = now
    if containment is not None:
        validation_time = containment.occurred_at
    elif len(receipts) == len(STAGE_ORDER):
        validation_time = receipts[-1].completed_at
    next_stage = validate_ledger(plan, receipts, now=validation_time)
    if containment is not None:
        validate_containment(plan, receipts, containment)
    return {
        "contract": "lucy.workspaces-production-batch-status.v1",
        "batch_digest": plan.digest_hex(),
        "completed_stages": [receipt.stage.value for receipt in receipts],
        "next_stage": None if containment is not None or next_stage is None else next_stage.value,
        "next_instruction": (
            None
            if containment is not None or next_stage is None
            else STAGE_INSTRUCTIONS[next_stage]
        ),
        "complete": next_stage is None and containment is None,
        "contained": containment is not None,
        "live_actions_performed_by_coordinator": False,
    }


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_receipts(path: Path | None) -> list[BatchStageReceiptV1]:
    if path is None:
        return []
    value = _load_json(path)
    if not isinstance(value, list):
        raise BatchContractError("receipt ledger must be a JSON array")
    return TypeAdapter(list[BatchStageReceiptV1]).validate_python(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build a secret-free canonical plan")
    build.add_argument("inputs", type=Path)
    build.add_argument("output", type=Path)
    status = commands.add_parser("status", help="validate a plan and receipt ledger")
    status.add_argument("plan", type=Path)
    status.add_argument("--ledger", type=Path)
    status.add_argument("--containment", type=Path)
    status.add_argument("--canonical-plan", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            if os.environ.get("LUCY_WORKSPACES_PRODUCTION_BATCH_BUILD_AUTHORIZATION") != (
                BUILD_AUTHORIZATION
            ):
                raise BatchContractError("the exact batch-build authorization is required")
            inputs = WorkspacesProductionBatchInputsV1.model_validate(_load_json(args.inputs))
            plan = build_plan(
                inputs,
                transport_token=os.environ.get("LUCY_WORKSPACES_TRANSPORT_TOKEN", ""),
                authority_token=os.environ.get("LUCY_WORKSPACES_AUTHORITY_TOKEN", ""),
            )
            output = canonical_json_bytes(plan.model_dump(mode="python")) + b"\n"
            with args.output.open("xb") as destination:
                destination.write(output)
            print(
                json.dumps(
                    {
                        "status": "built",
                        "batch_digest": plan.digest_hex(),
                        "output": str(args.output),
                        "secrets_written": False,
                    },
                    sort_keys=True,
                )
            )
        else:
            plan = WorkspacesProductionBatchV1.model_validate(_load_json(args.plan))
            receipts = _load_receipts(args.ledger)
            containment = (
                None
                if args.containment is None
                else BatchContainmentReceiptV1.model_validate(_load_json(args.containment))
            )
            if args.canonical_plan:
                print(canonical_json_bytes(plan.model_dump(mode="python")).decode("utf-8"))
            else:
                print(
                    json.dumps(
                        status_report(plan, receipts, containment=containment), sort_keys=True
                    )
                )
    except (BatchContractError, OSError, ValueError, ValidationError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
