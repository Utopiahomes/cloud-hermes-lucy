"""AWS Lambda entry points for the v1.2 sensitive executors."""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from typing import Any, Protocol, cast

import boto3  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]
from pydantic import ValidationError

from lucy.contracts.security_v1_2 import (
    AWS_LAMBDA_SYNCHRONOUS_PAYLOAD_LIMIT,
    ContractTrustStore,
    DeploymentEnvironment,
    SensitiveActionV2,
    SignatureAlgorithm,
    SigningKeyPurpose,
    VerificationKeyV1,
)
from lucy.executors.aws import (
    AwsExecutorBackend,
    AwsExecutorTables,
    DynamoExecutorClient,
    KmsExecutorClient,
)
from lucy.executors.core import (
    DeletionExecutor,
    ExecutorIdentity,
    ExecutorRejected,
    RetrievalExecutor,
)
from lucy.executors.models import (
    DeletionExecutorInvocationV1,
    RetrievalExecutorInvocationV1,
)

_LOGGER = logging.getLogger("lucy.executor")
_METRIC_NAMESPACE = "CloudLucy/SecurityV1_2"
_INTEGRITY_DENIAL_CODES = frozenset(
    {
        "action_mismatch",
        "authorization_signature_invalid",
        "claim_deadline_mismatch",
        "contract_invalid",
        "database_caller_mismatch",
        "deployment_epoch_or_record_mismatch",
        "durable_receipt_binding_mismatch",
        "encrypted_package_binding_mismatch",
        "encrypted_package_digest_mismatch",
        "environment_mismatch",
        "epoch_or_record_mismatch",
        "evidence_binding_mismatch",
        "executor_action_misconfigured",
        "executor_binding_mismatch",
        "invoked_alias_mismatch",
        "manifest_binding_mismatch",
        "manifest_digest_mismatch",
        "manifest_signature_invalid",
        "permit_binding_mismatch",
        "published_version_mismatch",
        "receipt_signer_changed_contract",
        "unpublished_executor_version",
        "wrapped_key_version_mismatch",
    }
)
_RECEIPT_FAILURE_CODES = frozenset(
    {
        "deletion_state_ambiguous",
        "deletion_transaction_failed",
        "receipt_persistence_ambiguous",
        "receipt_persistence_failed",
        "receipt_signer_changed_contract",
        "receipt_signing_failed",
    }
)
_AWS_CLIENT_CONFIG = Config(
    connect_timeout=2,
    read_timeout=15,
    retries={"max_attempts": 3, "mode": "standard"},
)


class LambdaContext(Protocol):
    aws_request_id: str
    invoked_function_arn: str
    function_version: str


def retrieval_lambda_handler(event: object, context: LambdaContext) -> dict[str, Any]:
    return _handle(SensitiveActionV2.EVIDENCE_RETRIEVE, event, context)


def deletion_lambda_handler(event: object, context: LambdaContext) -> dict[str, Any]:
    return _handle(SensitiveActionV2.EVIDENCE_DELETE, event, context)


def _handle(
    action: SensitiveActionV2,
    event: object,
    context: LambdaContext,
) -> dict[str, Any]:
    try:
        raw = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(raw) > AWS_LAMBDA_SYNCHRONOUS_PAYLOAD_LIMIT:
            raise ExecutorRejected("lambda_payload_limit_exceeded")
        runtime = _runtime(action, context.invoked_function_arn, context.function_version)
        runtime.verify_context(context)
        if action == SensitiveActionV2.EVIDENCE_RETRIEVE:
            retrieval_invocation = RetrievalExecutorInvocationV1.model_validate_json(raw)
            result = cast(RetrievalExecutor, runtime.executor).execute(
                retrieval_invocation,
                lambda_request_id=context.aws_request_id,
            )
        else:
            deletion_invocation = DeletionExecutorInvocationV1.model_validate_json(raw)
            result = cast(DeletionExecutor, runtime.executor).execute(
                deletion_invocation,
                lambda_request_id=context.aws_request_id,
            )
        _LOGGER.info(
            "lucy_executor_outcome action=%s outcome=accepted replayed=%s",
            action.value,
            result.replayed,
        )
        metrics = ["Accepted"]
        if result.replayed:
            metrics.append("Replayed")
        _emit_metrics(action, metrics)
        return {"ok": True, "result": result.model_dump(mode="json")}
    except ExecutorRejected as exc:
        _LOGGER.warning(
            "lucy_executor_outcome action=%s outcome=denied code=%s",
            action.value,
            exc.code,
        )
        metrics = ["Denied"]
        if exc.code in _INTEGRITY_DENIAL_CODES:
            metrics.append("IntegrityDenied")
        if exc.code == "quota_denied":
            metrics.append("Throttled")
        if exc.code in _RECEIPT_FAILURE_CODES:
            metrics.append("ReceiptFailure")
        _emit_metrics(action, metrics)
        return {"ok": False, "error": "request_rejected", "code": exc.code}
    except (ValidationError, TypeError, ValueError, UnicodeError):
        _LOGGER.warning(
            "lucy_executor_outcome action=%s outcome=denied code=contract_invalid",
            action.value,
        )
        _emit_metrics(action, ["Denied", "IntegrityDenied"])
        return {"ok": False, "error": "request_rejected", "code": "contract_invalid"}
    except Exception as exc:
        # Never log exception text: provider errors can contain resource identifiers
        # and a future library exception could accidentally include request material.
        _LOGGER.error(
            "lucy_executor_outcome action=%s outcome=failed type=%s",
            action.value,
            type(exc).__name__,
        )
        _emit_metrics(action, ["Failed"])
        return {"ok": False, "error": "executor_unavailable", "code": "internal_failure"}


def _emit_metrics(action: SensitiveActionV2, names: list[str]) -> None:
    metrics = [{"Name": name, "Unit": "Count"} for name in names]
    payload: dict[str, Any] = {
        "_aws": {
            "CloudWatchMetrics": [
                {
                    "Namespace": _METRIC_NAMESPACE,
                    "Dimensions": [["Action"]],
                    "Metrics": metrics,
                }
            ]
        },
        "Action": action.value,
    }
    payload.update(dict.fromkeys(names, 1))
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True), flush=True)


class _ExecutorRuntime:
    def __init__(self, executor: RetrievalExecutor | DeletionExecutor, identity: ExecutorIdentity):
        self.executor = executor
        self._identity = identity

    def verify_context(self, context: LambdaContext) -> None:
        if context.invoked_function_arn != self._identity.executor_alias_arn:
            raise ExecutorRejected("invoked_alias_mismatch")
        if context.function_version != str(self._identity.executor_version):
            raise ExecutorRejected("published_version_mismatch")
        if context.function_version == "$LATEST":
            raise ExecutorRejected("unpublished_executor_version")
        if not context.aws_request_id.strip():
            raise ExecutorRejected("lambda_request_id_missing")


@lru_cache(maxsize=8)
def _runtime(
    action: SensitiveActionV2,
    invoked_function_arn: str,
    function_version: str,
) -> _ExecutorRuntime:
    environment = DeploymentEnvironment(_required("LUCY_EXECUTOR_ENVIRONMENT"))
    executor_version = _parse_positive_int(function_version, "AWS_LAMBDA_FUNCTION_VERSION")
    function_name = _required("AWS_LAMBDA_FUNCTION_NAME")
    alias_name = _required("LUCY_EXECUTOR_ALIAS_NAME")
    if not invoked_function_arn.endswith(f":function:{function_name}:{alias_name}"):
        raise ExecutorRejected("invoked_alias_mismatch")
    evidence_key_arn = (
        _required("LUCY_AWS_EVIDENCE_KEY_ARN")
        if action == SensitiveActionV2.EVIDENCE_RETRIEVE
        else None
    )
    identity = ExecutorIdentity(
        action=action,
        environment=environment,
        storage_epoch=_positive_int("LUCY_SECURITY_STORAGE_EPOCH"),
        registry_epoch=_positive_int("LUCY_SECURITY_REGISTRY_EPOCH"),
        key_epoch=_positive_int("LUCY_SECURITY_KEY_EPOCH"),
        record_version=_positive_int("LUCY_ARCHIVE_RECORD_VERSION"),
        executor_identity=_required("LUCY_EXECUTOR_IDENTITY"),
        executor_alias_arn=invoked_function_arn,
        executor_version=executor_version,
        database_session_user=_required("LUCY_EXPECTED_DATABASE_SESSION_USER"),
        receipt_key_id=_required("LUCY_AWS_RECEIPT_SIGNING_KEY_ARN"),
        evidence_key_arn=evidence_key_arn,
    )
    region = _required("AWS_REGION")
    dynamodb = cast(
        DynamoExecutorClient,
        boto3.client("dynamodb", region_name=region, config=_AWS_CLIENT_CONFIG),
    )
    kms = cast(
        KmsExecutorClient,
        boto3.client("kms", region_name=region, config=_AWS_CLIENT_CONFIG),
    )
    tables = AwsExecutorTables(
        wrapped_keys=_required("LUCY_AWS_WRAPPED_KEY_TABLE"),
        receipts=_required("LUCY_AWS_EXECUTOR_RECEIPT_TABLE"),
        quotas=_required("LUCY_AWS_EXECUTOR_QUOTA_TABLE"),
        intents=(
            _required("LUCY_AWS_DELETION_INTENT_TABLE")
            if action == SensitiveActionV2.EVIDENCE_DELETE
            else None
        ),
    )
    backend = AwsExecutorBackend(
        dynamodb,
        kms,
        tables=tables,
        evidence_key_arn=evidence_key_arn,
        receipt_key_arn=identity.receipt_key_id,
        minute_limit=_positive_int("LUCY_EXECUTOR_MINUTE_LIMIT"),
        day_limit=_positive_int("LUCY_EXECUTOR_DAY_LIMIT"),
    )
    trust_store = ContractTrustStore(_policy_keys(environment))
    executor: RetrievalExecutor | DeletionExecutor
    if action == SensitiveActionV2.EVIDENCE_RETRIEVE:
        executor = RetrievalExecutor(backend, trust_store, identity)
    else:
        executor = DeletionExecutor(backend, trust_store, identity)
    return _ExecutorRuntime(executor, identity)


def _policy_keys(environment: DeploymentEnvironment) -> tuple[VerificationKeyV1, ...]:
    raw = _required("LUCY_POLICY_TRUST_STORE_JSON")
    try:
        payload = json.loads(raw)
        if not isinstance(payload, list):
            raise ValueError("trust store must be a list")
        keys = tuple(VerificationKeyV1.model_validate(item) for item in payload)
    except (json.JSONDecodeError, ValidationError, TypeError, ValueError) as exc:
        raise ValueError("policy trust store is invalid") from exc
    if not keys:
        raise ValueError("policy trust store must contain at least one key")
    if any(
        key.purpose != SigningKeyPurpose.POLICY_NOTARY
        or key.environment != environment
        or key.algorithm != SignatureAlgorithm.ED25519
        for key in keys
    ):
        raise ValueError("policy trust store contains a cross-purpose or cross-environment key")
    return keys


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"required executor configuration is missing: {name}")
    return value


def _positive_int(name: str) -> int:
    return _parse_positive_int(_required(name), name)


def _parse_positive_int(raw: str, name: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"executor configuration is not an integer: {name}") from exc
    if value < 1:
        raise ValueError(f"executor configuration must be positive: {name}")
    return value
