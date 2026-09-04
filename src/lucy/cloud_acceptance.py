"""Synthetic-only real-cloud acceptance commands for Security Baseline v1.2.

These commands run only as manually requested Render one-off jobs. They never
change ``LUCY_TRANSCRIPT_CAPTURE_ENABLED`` and never print plaintext, bearer
tokens, signing seeds, ciphertext, wrapped keys, or database credentials.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import re
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.api import _executor_invoker, _policy_workflow_client, _ready_sessions
from lucy.archive import (
    ConversationArchiveService,
    ConversationMessageArchiveInput,
    TurnCaptureInput,
)
from lucy.archive_crypto import archive_dependencies_from_environment
from lucy.contracts import (
    Ed25519ContractSigner,
    OwnerInteractionAssertionV1,
    RetrievalOperationState,
    SensitiveActionPermitV2,
    SensitiveActionV2,
)
from lucy.contracts.security_v1_2 import (
    DeploymentEnvironment,
    OwnerAuthenticationMethod,
    OwnerInteractionChannel,
    SensitiveReasonCode,
)
from lucy.readiness import service_mode_from_environment
from lucy.security_workflows import (
    DeletionCoordinator,
    RetrievalCoordinator,
    SqlSecurityWorkflowStore,
)

_RESULT_PREFIX = "LUCY_CLOUD_ACCEPTANCE_RESULT="
_HOSTPORT = re.compile(r"([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?):([0-9]{2,5})")


class CloudAcceptanceError(RuntimeError):
    """Content-free failure safe to emit from the synthetic harness."""


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise CloudAcceptanceError(f"required acceptance configuration is missing: {name}")
    return value


def _preflight(mode: Literal["routine", "evidence", "deletion"]) -> None:
    if _required("LUCY_CLOUD_ACCEPTANCE_AUTHORIZED") != "synthetic-only-v1.2":
        raise CloudAcceptanceError("synthetic cloud acceptance is not explicitly authorized")
    if os.getenv("LUCY_ENVIRONMENT") != "production":
        raise CloudAcceptanceError("cloud acceptance requires the production-shaped runtime")
    if os.getenv("LUCY_SECURITY_ENVIRONMENT") != "production":
        raise CloudAcceptanceError("cloud acceptance requires the production security domain")
    if os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "false") != "false":
        raise CloudAcceptanceError("live transcript capture must remain disabled")
    if service_mode_from_environment() != mode:
        raise CloudAcceptanceError("cloud acceptance command ran under the wrong service identity")
    _ready_sessions()


def _report(value: dict[str, object]) -> None:
    print(_RESULT_PREFIX + json.dumps(value, separators=(",", ":"), sort_keys=True))


def _assert_aws_denied(*, opposite_alias_arn: str, wrapped_key_table: str) -> dict[str, bool]:
    region = _required("AWS_REGION")
    lambda_denied = False
    try:
        boto3.client("lambda", region_name=region).invoke(
            FunctionName=opposite_alias_arn,
            InvocationType="RequestResponse",
            Payload=b"{}",
        )
    except ClientError as exc:
        lambda_denied = exc.response.get("Error", {}).get("Code") in {
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
        }
    if not lambda_denied:
        raise CloudAcceptanceError("cross-boundary Lambda invocation was not denied")

    scan_denied = False
    try:
        boto3.client("dynamodb", region_name=region).scan(
            TableName=wrapped_key_table,
            Limit=1,
        )
    except ClientError as exc:
        scan_denied = exc.response.get("Error", {}).get("Code") in {
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
        }
    if not scan_denied:
        raise CloudAcceptanceError("wrapped-key enumeration was not denied")
    return {"opposite_executor_denied": True, "wrapped_key_scan_denied": True}


def _synthetic_content(run_id: UUID, role: str) -> str:
    return f"Cloud Lucy synthetic acceptance {run_id} {role}; contains no user data."


def archive_phase(run_id: UUID, opposite_alias_arn: str, wrapped_key_table: str) -> None:
    _preflight("routine")
    denials = _assert_aws_denied(
        opposite_alias_arn=opposite_alias_arn,
        wrapped_key_table=wrapped_key_table,
    )
    cipher, key_store = archive_dependencies_from_environment()
    archive = ConversationArchiveService(
        _ready_sessions(),
        cipher,
        key_store,
        # This object is reachable only from this manual synthetic CLI. The live
        # API process still reads false from LUCY_TRANSCRIPT_CAPTURE_ENABLED.
        capture_authorized=True,
    )
    conversation_id = f"cloud-acceptance-{run_id}"
    turn_id = f"turn-{run_id}"
    accepted = archive.accept_turn(
        TurnCaptureInput(
            platform="telegram",
            source_conversation_id=conversation_id,
            source_turn_id=turn_id,
        )
    )
    if not accepted.capture_enabled:
        raise CloudAcceptanceError("synthetic turn was not accepted by the isolated harness")
    user_request = ConversationMessageArchiveInput(
        platform="telegram",
        source_conversation_id=conversation_id,
        source_turn_id=turn_id,
        source_message_id=f"user-{run_id}",
        role="user",
        content=_synthetic_content(run_id, "user"),
    )
    user_key = f"cloud-acceptance-archive-user:{run_id}"
    user = archive.preserve_message(user_key, user_request)
    replay = archive.preserve_message(user_key, user_request)
    if (
        user.evidence_id is None
        or replay.evidence_id != user.evidence_id
        or not replay.replayed
    ):
        raise CloudAcceptanceError("synthetic archive replay was not exactly-once")
    assistant = archive.preserve_message(
        f"cloud-acceptance-archive-assistant:{run_id}",
        ConversationMessageArchiveInput(
            platform="telegram",
            source_conversation_id=conversation_id,
            source_turn_id=turn_id,
            source_message_id=f"assistant-{run_id}",
            role="assistant",
            content=_synthetic_content(run_id, "assistant"),
            source_evidence_ids=(user.evidence_id,),
        ),
    )
    if assistant.evidence_id is None or not assistant.turn_committed:
        raise CloudAcceptanceError("synthetic conversation did not commit both roles")
    _report(
        {
            "phase": "archive",
            "run_id": str(run_id),
            "root_evidence_id": str(user.evidence_id),
            "derived_evidence_id": str(assistant.evidence_id),
            "turn_committed": True,
            "archive_replay_exactly_once": True,
            "capture_flag_remained_false": True,
            "aws_denials": denials,
        }
    )


def _owner_signer() -> Ed25519ContractSigner:
    try:
        seed = base64.b64decode(
            _required("LUCY_ACCEPTANCE_OWNER_SIGNING_PRIVATE_KEY_B64"),
            validate=True,
        )
        private = Ed25519PrivateKey.from_private_bytes(seed)
    except ValueError as exc:
        raise CloudAcceptanceError("synthetic owner signing key is invalid") from exc
    return Ed25519ContractSigner(
        private,
        key_id=_required("LUCY_ACCEPTANCE_OWNER_KEY_ID"),
    )


def _assertion(
    run_id: UUID,
    evidence_id: UUID,
    action: SensitiveActionV2,
) -> OwnerInteractionAssertionV1:
    signer = _owner_signer()
    now = datetime.now(UTC)
    label = "retrieve" if action == SensitiveActionV2.EVIDENCE_RETRIEVE else "delete"
    return signer.sign(
        OwnerInteractionAssertionV1(
            key_id=signer.key_id,
            issuer=_required("LUCY_ACCEPTANCE_OWNER_ISSUER"),
            environment=DeploymentEnvironment.PRODUCTION,
            issued_at=now,
            storage_epoch=int(_required("LUCY_SECURITY_STORAGE_EPOCH")),
            registry_epoch=int(_required("LUCY_SECURITY_REGISTRY_EPOCH")),
            key_epoch=int(_required("LUCY_SECURITY_KEY_EPOCH")),
            assertion_id=uuid4(),
            broker_identity=_required("LUCY_ACCEPTANCE_OWNER_ISSUER"),
            channel=OwnerInteractionChannel.SYNTHETIC_ACCEPTANCE,
            owner_subject=_required("LUCY_OWNER_SUBJECT"),
            source_interaction_id=f"cloud-acceptance-{label}-{run_id}",
            source_message_id=f"cloud-acceptance-message-{label}-{run_id}",
            requested_action=action,
            evidence_id=evidence_id,
            authentication_method=OwnerAuthenticationMethod.SYNTHETIC_ACCEPTANCE,
            interaction_created_at=now,
            max_age_seconds=300,
            expires_at=now + timedelta(minutes=4),
            nonce=f"cloud-acceptance-nonce-{label}-{uuid4()}",
            anti_replay_id=f"cloud-acceptance-replay-{label}-{uuid4()}",
            signature="",
        )
    )


def _policy_permit(
    assertion: OwnerInteractionAssertionV1,
    *,
    reason: SensitiveReasonCode,
    idempotency_key: str,
) -> SensitiveActionPermitV2:
    hostport = _required("LUCY_POLICY_HOSTPORT")
    match = _HOSTPORT.fullmatch(hostport)
    if match is None or int(match.group(2)) > 65_535:
        raise CloudAcceptanceError("private policy endpoint is invalid")
    payload = json.dumps(
        {
            "assertion": assertion.model_dump(mode="json"),
            "reason": reason.value,
            "record_version": 1,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    connection = http.client.HTTPConnection(match.group(1), int(match.group(2)), timeout=20)
    try:
        connection.request(
            "POST",
            "/owner/v2/security/permits",
            body=payload,
            headers={
                "Authorization": f"Bearer {_required('LUCY_OWNER_TOKEN')}",
                "Content-Type": "application/json",
                "Content-Length": str(len(payload)),
                "Idempotency-Key": idempotency_key,
            },
        )
        response = connection.getresponse()
        raw = response.read(262_145)
    except (OSError, http.client.HTTPException) as exc:
        raise CloudAcceptanceError("private policy request was unavailable") from exc
    finally:
        connection.close()
    if response.status != 201 or len(raw) > 262_144:
        raise CloudAcceptanceError(
            "private policy rejected the synthetic owner assertion "
            f"(HTTP {response.status})"
        )
    try:
        return SensitiveActionPermitV2.model_validate_json(raw)
    except ValueError as exc:
        raise CloudAcceptanceError("private policy returned an invalid permit") from exc


def retrieve_phase(
    run_id: UUID,
    evidence_id: UUID,
    opposite_alias_arn: str,
    wrapped_key_table: str,
) -> None:
    _preflight("evidence")
    denials = _assert_aws_denied(
        opposite_alias_arn=opposite_alias_arn,
        wrapped_key_table=wrapped_key_table,
    )
    permit = _policy_permit(
        _assertion(run_id, evidence_id, SensitiveActionV2.EVIDENCE_RETRIEVE),
        reason=SensitiveReasonCode.OWNER_REVIEW,
        idempotency_key=f"cloud-acceptance-permit-retrieve:{run_id}",
    )
    coordinator = RetrievalCoordinator(
        SqlSecurityWorkflowStore(_ready_sessions()),
        _policy_workflow_client("evidence"),
        _executor_invoker("evidence"),
    )
    idempotency_key = f"cloud-acceptance-retrieve:{run_id}"
    first = coordinator.execute(permit, idempotency_key=idempotency_key)
    if first.plaintext_b64 is None or first.receipt_digest is None:
        raise CloudAcceptanceError("retrieval executor did not return a receipted payload")
    try:
        plaintext = json.loads(base64.b64decode(first.plaintext_b64, validate=True))
    except (ValueError, json.JSONDecodeError) as exc:
        raise CloudAcceptanceError("retrieval plaintext envelope was invalid") from exc
    if (
        not isinstance(plaintext, dict)
        or plaintext.get("content") != _synthetic_content(run_id, "user")
        or plaintext.get("role") != "user"
    ):
        raise CloudAcceptanceError("retrieval plaintext did not match the synthetic record")
    state = coordinator.record_delivery(first.operation_id, accepted=True)
    if state != RetrievalOperationState.DELIVERY_CONFIRMED:
        raise CloudAcceptanceError("retrieval delivery did not become confirmed")
    replay = coordinator.execute(permit, idempotency_key=idempotency_key)
    if (
        replay.operation_id != first.operation_id
        or replay.plaintext_b64 is not None
        or not replay.executor_replayed
        or replay.state != RetrievalOperationState.DELIVERY_CONFIRMED
    ):
        raise CloudAcceptanceError("retrieval replay was not content-free and exactly-once")
    _report(
        {
            "phase": "retrieve",
            "run_id": str(run_id),
            "evidence_id": str(evidence_id),
            "operation_id": str(first.operation_id),
            "executor_receipt_verified": True,
            "delivery_confirmed": True,
            "replay_released_no_plaintext": True,
            "capture_flag_remained_false": True,
            "aws_denials": denials,
        }
    )


def delete_phase(
    run_id: UUID,
    evidence_id: UUID,
    opposite_alias_arn: str,
    wrapped_key_table: str,
) -> None:
    _preflight("deletion")
    denials = _assert_aws_denied(
        opposite_alias_arn=opposite_alias_arn,
        wrapped_key_table=wrapped_key_table,
    )
    permit = _policy_permit(
        _assertion(run_id, evidence_id, SensitiveActionV2.EVIDENCE_DELETE),
        reason=SensitiveReasonCode.OWNER_REQUEST,
        idempotency_key=f"cloud-acceptance-permit-delete:{run_id}",
    )
    policy = _policy_workflow_client("deletion")
    idempotency_key = f"cloud-acceptance-delete:{run_id}"
    manifest = policy.prepare_deletion_manifest(permit, idempotency_key=idempotency_key)
    if manifest.target_count != 2:
        raise CloudAcceptanceError("deletion manifest did not close the two-record derivation")
    coordinator = DeletionCoordinator(
        SqlSecurityWorkflowStore(_ready_sessions()),
        policy,
        _executor_invoker("deletion"),
    )
    first = coordinator.execute(permit, manifest, idempotency_key=idempotency_key)
    summary = first.derived_summary or {}
    if first.state.value != "FINALITY_PENDING" or summary.get("evidence_records_deleted") != 2:
        raise CloudAcceptanceError("governed deletion did not become effective for both records")
    replay = coordinator.execute(permit, manifest, idempotency_key=idempotency_key)
    if replay.operation_id != first.operation_id or not replay.executor_replayed:
        raise CloudAcceptanceError("deletion replay was not exactly-once")
    _report(
        {
            "phase": "delete",
            "run_id": str(run_id),
            "root_evidence_id": str(evidence_id),
            "operation_id": str(first.operation_id),
            "manifest_target_count": manifest.target_count,
            "evidence_records_deleted": summary["evidence_records_deleted"],
            "finality_status": first.state.value,
            "executor_receipt_verified": True,
            "deletion_replay_exactly_once": True,
            "capture_flag_remained_false": True,
            "aws_denials": denials,
        }
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="phase", required=True)
    for phase in ("archive", "retrieve", "delete"):
        child = subparsers.add_parser(phase)
        child.add_argument("--run-id", type=UUID, required=True)
        child.add_argument("--opposite-alias-arn", required=True)
        child.add_argument("--wrapped-key-table", required=True)
        if phase != "archive":
            child.add_argument("--evidence-id", type=UUID, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    if args.phase == "archive":
        archive_phase(args.run_id, args.opposite_alias_arn, args.wrapped_key_table)
    elif args.phase == "retrieve":
        retrieve_phase(
            args.run_id,
            args.evidence_id,
            args.opposite_alias_arn,
            args.wrapped_key_table,
        )
    else:
        delete_phase(
            args.run_id,
            args.evidence_id,
            args.opposite_alias_arn,
            args.wrapped_key_table,
        )


if __name__ == "__main__":
    main()
