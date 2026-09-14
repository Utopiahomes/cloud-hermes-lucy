"""Synthetic-only real-cloud acceptance commands for Security Baseline V1.3."""

from __future__ import annotations

import argparse
import base64
import json
import os
from typing import Literal
from uuid import UUID

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.asymmetric import ed25519

from lucy.api import (
    _ready_sessions,
    _realm_deletion_executor,
    _realm_policy_workflow_client,
    _realm_retrieval_executor,
)
from lucy.archive import ConversationMessageArchiveInput, TurnCaptureInput
from lucy.contracts.security_v1_2 import (
    DeploymentEnvironment,
    SensitiveActionV2,
    SensitiveReasonCode,
)
from lucy.contracts.security_v1_3 import (
    Ed25519V13Signer,
    OwnerInteractionAssertionV2,
    V13ContractVerifier,
    V13SigningKeyPurpose,
    V13VerificationKeyV1,
)
from lucy.readiness import security_baseline_from_environment, service_mode_from_environment
from lucy.realm_archive_commit import (
    PostgresRealmArchiveCommitStore,
    RealmConversationArchiveService,
    realm_archive_commit_from_environment,
)
from lucy.realm_security_workflows import (
    PostgresRealmPolicyStore,
    PostgresRealmWorkflowStore,
    RealmDeletionCoordinator,
    RealmPolicyPermitService,
    RealmRetrievalCoordinator,
)

_RESULT_PREFIX = "LUCY_CLOUD_ACCEPTANCE_V13_RESULT="


class CloudAcceptanceV13Error(RuntimeError):
    """Content-free synthetic commissioning failure."""


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise CloudAcceptanceV13Error(f"required acceptance configuration missing: {name}")
    return value


def _preflight(mode: Literal["routine", "policy", "evidence", "deletion"]) -> None:
    if _required("LUCY_CLOUD_ACCEPTANCE_AUTHORIZED") != "synthetic-only-v1.3":
        raise CloudAcceptanceV13Error("synthetic V1.3 acceptance is not authorized")
    if os.getenv("LUCY_ENVIRONMENT") != "production":
        raise CloudAcceptanceV13Error("acceptance requires production Render")
    if os.getenv("LUCY_SECURITY_ENVIRONMENT") != "production":
        raise CloudAcceptanceV13Error("acceptance requires production security domain")
    if security_baseline_from_environment() != "v1.3":
        raise CloudAcceptanceV13Error("acceptance requires Security Baseline V1.3")
    if os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "false") != "false":
        raise CloudAcceptanceV13Error("live transcript capture must remain disabled")
    if service_mode_from_environment() != mode:
        raise CloudAcceptanceV13Error("acceptance ran under the wrong service identity")
    _ready_sessions()


def _report(value: dict[str, object]) -> None:
    print(_RESULT_PREFIX + json.dumps(value, separators=(",", ":"), sort_keys=True))


def _synthetic_content(run_id: UUID, role: str) -> str:
    return f"Cloud Lucy V1.3 synthetic acceptance {run_id} {role}; no customer data."


def _aws_denials(opposite_alias_arn: str, wrapped_key_table: str) -> dict[str, bool]:
    region = _required("AWS_REGION")
    invoke_denied = False
    try:
        boto3.client("lambda", region_name=region).invoke(
            FunctionName=opposite_alias_arn,
            InvocationType="RequestResponse",
            Payload=b"{}",
        )
    except ClientError as exc:
        invoke_denied = exc.response.get("Error", {}).get("Code") in {
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
        }
    if not invoke_denied:
        raise CloudAcceptanceV13Error("cross-boundary Lambda invocation was not denied")
    scan_denied = False
    try:
        boto3.client("dynamodb", region_name=region).scan(
            TableName=wrapped_key_table, Limit=1
        )
    except ClientError as exc:
        scan_denied = exc.response.get("Error", {}).get("Code") in {
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
        }
    if not scan_denied:
        raise CloudAcceptanceV13Error("wrapped-key enumeration was not denied")
    return {"opposite_executor_denied": True, "wrapped_key_scan_denied": True}


def archive_phase(run_id: UUID, opposite_alias_arn: str, wrapped_key_table: str) -> None:
    _preflight("routine")
    denials = _aws_denials(opposite_alias_arn, wrapped_key_table)
    store = PostgresRealmArchiveCommitStore(_ready_sessions())
    service = RealmConversationArchiveService(
        store,
        realm_archive_commit_from_environment(),
        # Only this manually invoked synthetic CLI bypasses the live capture switch.
        capture_authorized=True,
    )
    conversation = f"synthetic-v13-{run_id}"
    turn = f"synthetic-v13-turn-{run_id}"
    if not service.accept_turn(
        TurnCaptureInput(
            platform="telegram",
            source_conversation_id=conversation,
            source_turn_id=turn,
        )
    ).capture_enabled:
        raise CloudAcceptanceV13Error("synthetic turn was not accepted")
    user_request = ConversationMessageArchiveInput(
        platform="telegram",
        source_conversation_id=conversation,
        source_turn_id=turn,
        source_message_id=f"synthetic-user-{run_id}",
        role="user",
        content=_synthetic_content(run_id, "user"),
    )
    user_key = f"synthetic-v13-user:{run_id}"
    user = service.preserve_message(user_key, user_request)
    replay = service.preserve_message(user_key, user_request)
    if user.evidence_id is None or replay.evidence_id != user.evidence_id or not replay.replayed:
        raise CloudAcceptanceV13Error("archive replay was not exactly once")
    assistant = service.preserve_message(
        f"synthetic-v13-assistant:{run_id}",
        ConversationMessageArchiveInput(
            platform="telegram",
            source_conversation_id=conversation,
            source_turn_id=turn,
            source_message_id=f"synthetic-assistant-{run_id}",
            role="assistant",
            content=_synthetic_content(run_id, "assistant"),
            source_evidence_ids=(user.evidence_id,),
        ),
    )
    if assistant.evidence_id is None:
        raise CloudAcceptanceV13Error("derived synthetic evidence was not archived")
    _report(
        {
            "phase": "archive",
            "run_id": str(run_id),
            "root_evidence_id": str(user.evidence_id),
            "derived_evidence_id": str(assistant.evidence_id),
            "archive_replay_exactly_once": True,
            "capture_flag_remained_false": True,
            "aws_denials": denials,
        }
    )


def _verification_keys(name: str) -> tuple[V13VerificationKeyV1, ...]:
    try:
        value = json.loads(_required(name))
        if not isinstance(value, list):
            raise ValueError
        result = tuple(V13VerificationKeyV1.model_validate(item) for item in value)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CloudAcceptanceV13Error("acceptance trust store is invalid") from exc
    if not result:
        raise CloudAcceptanceV13Error("acceptance trust store is empty")
    return result


def issue_permit_phase() -> None:
    _preflight("policy")
    try:
        assertion = OwnerInteractionAssertionV2.model_validate_json(
            _required("LUCY_CLOUD_ACCEPTANCE_OWNER_ASSERTION_JSON")
        )
        seed = base64.b64decode(
            _required("LUCY_V13_POLICY_SIGNING_PRIVATE_KEY_B64"), validate=True
        )
        private = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        reason = SensitiveReasonCode(_required("LUCY_CLOUD_ACCEPTANCE_REASON"))
    except ValueError as exc:
        raise CloudAcceptanceV13Error("acceptance permit input is invalid") from exc
    key_id = _required("LUCY_V13_POLICY_KEY_ID")
    policy_keys = _verification_keys("LUCY_V13_POLICY_TRUST_STORE_JSON")
    policy_key = next((item for item in policy_keys if item.key_id == key_id), None)
    if policy_key is None:
        raise CloudAcceptanceV13Error("active policy key is not trusted")
    store = PostgresRealmPolicyStore(_ready_sessions())
    permit = RealmPolicyPermitService(
        store,
        owner_verifier=V13ContractVerifier(
            _verification_keys("LUCY_CLOUD_ACCEPTANCE_OWNER_TRUST_STORE_JSON")
        ),
        policy_verifier=V13ContractVerifier(policy_keys),
        signer=Ed25519V13Signer(
            private, key_id=key_id, purpose=V13SigningKeyPurpose.POLICY_NOTARY
        ),
        issuer=policy_key.issuer,
        environment=DeploymentEnvironment.PRODUCTION,
    ).issue_permit(
        assertion,
        reason=reason,
        idempotency_key=_required("LUCY_CLOUD_ACCEPTANCE_PERMIT_IDEMPOTENCY_KEY"),
    )
    _report(
        {
            "phase": "permit",
            "action": permit.action.value,
            "permit_id": str(permit.permit_id),
            "operation_id": str(permit.operation_id),
            "resource_object_id": str(permit.resource_selector.object_id),
            "owner_assertion_verified": True,
            "policy_signature_verified_before_storage": True,
        }
    )


def retrieve_phase(
    run_id: UUID, permit_id: UUID, opposite_alias_arn: str, wrapped_key_table: str
) -> None:
    _preflight("evidence")
    denials = _aws_denials(opposite_alias_arn, wrapped_key_table)
    workflow = PostgresRealmWorkflowStore(_ready_sessions())
    permit = workflow.load_permit(permit_id, SensitiveActionV2.EVIDENCE_RETRIEVE)
    key = f"synthetic-v13-retrieve:{run_id}"
    first = RealmRetrievalCoordinator(
        workflow, _realm_policy_workflow_client(), _realm_retrieval_executor()
    ).execute(permit, idempotency_key=key)
    if first.plaintext_b64 is None or first.receipt_digest is None:
        raise CloudAcceptanceV13Error("retrieval produced no receipted plaintext")
    try:
        plaintext = base64.b64decode(first.plaintext_b64, validate=True).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise CloudAcceptanceV13Error("retrieval plaintext was invalid") from exc
    if plaintext != _synthetic_content(run_id, "user"):
        raise CloudAcceptanceV13Error("retrieval plaintext differed from synthetic input")
    replay = RealmRetrievalCoordinator(
        workflow, _realm_policy_workflow_client(), _realm_retrieval_executor()
    ).execute(permit, idempotency_key=key)
    if replay.operation_id != first.operation_id or replay.plaintext_b64 is not None:
        raise CloudAcceptanceV13Error("retrieval replay was not content free")
    _report(
        {
            "phase": "retrieve",
            "run_id": str(run_id),
            "operation_id": str(first.operation_id),
            "executor_receipt_verified": True,
            "replay_released_no_plaintext": True,
            "aws_denials": denials,
        }
    )


def delete_phase(
    run_id: UUID, permit_id: UUID, opposite_alias_arn: str, wrapped_key_table: str
) -> None:
    _preflight("deletion")
    denials = _aws_denials(opposite_alias_arn, wrapped_key_table)
    workflow = PostgresRealmWorkflowStore(_ready_sessions())
    permit = workflow.load_permit(permit_id, SensitiveActionV2.EVIDENCE_DELETE)
    key = f"synthetic-v13-delete:{run_id}"
    coordinator = RealmDeletionCoordinator(
        workflow, _realm_policy_workflow_client(), _realm_deletion_executor()
    )
    first = coordinator.execute(permit, idempotency_key=key)
    if first.state != "FINALITY_PENDING" or first.receipt_digest is None:
        raise CloudAcceptanceV13Error("deletion did not reach operational finality")
    replay = coordinator.execute(permit, idempotency_key=key)
    if replay.operation_id != first.operation_id or not replay.executor_replayed:
        raise CloudAcceptanceV13Error("deletion replay was not exactly once")
    _report(
        {
            "phase": "delete",
            "run_id": str(run_id),
            "operation_id": str(first.operation_id),
            "finality_status": first.state,
            "executor_receipt_verified": True,
            "deletion_replay_exactly_once": True,
            "aws_denials": denials,
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="phase", required=True)
    archive = sub.add_parser("archive")
    archive.add_argument("--run-id", type=UUID, required=True)
    permit = sub.add_parser("permit")
    permit.set_defaults()
    for name in ("retrieve", "delete"):
        child = sub.add_parser(name)
        child.add_argument("--run-id", type=UUID, required=True)
        child.add_argument("--permit-id", type=UUID, required=True)
    for child in (archive, *[sub.choices[name] for name in ("retrieve", "delete")]):
        child.add_argument("--opposite-alias-arn", required=True)
        child.add_argument("--wrapped-key-table", required=True)
    args = parser.parse_args()
    if args.phase == "archive":
        archive_phase(args.run_id, args.opposite_alias_arn, args.wrapped_key_table)
    elif args.phase == "permit":
        issue_permit_phase()
    elif args.phase == "retrieve":
        retrieve_phase(
            args.run_id, args.permit_id, args.opposite_alias_arn, args.wrapped_key_table
        )
    else:
        delete_phase(
            args.run_id, args.permit_id, args.opposite_alias_arn, args.wrapped_key_table
        )


if __name__ == "__main__":
    main()
