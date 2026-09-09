"""AWS Lambda entry points for realm-scoped Security Baseline V1.3 executors."""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from typing import Any, Protocol, cast
from uuid import UUID

import boto3  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]
from pydantic import ValidationError

from lucy.contracts.security_v1_2 import (
    AWS_LAMBDA_SYNCHRONOUS_PAYLOAD_LIMIT,
    DeploymentEnvironment,
    SensitiveActionV2,
    SignatureAlgorithm,
)
from lucy.contracts.security_v1_3 import (
    ExecutionBindingV1,
    OriginScopeV1,
    V13ContractVerifier,
    V13SigningKeyPurpose,
    V13VerificationKeyV1,
)
from lucy.executors.admission_v1_3 import RealmExecutorIdentityV1
from lucy.executors.aws import (
    AwsExecutorBackend,
    AwsExecutorTables,
    DynamoExecutorClient,
    KmsExecutorClient,
)
from lucy.executors.core import ExecutorRejected
from lucy.executors.core_v1_3 import RealmDeletionExecutor, RealmRetrievalExecutor
from lucy.executors.models import DeletionExecutorInvocationV2, RetrievalExecutorInvocationV2

_LOGGER = logging.getLogger("lucy.executor.v1_3")
_METRIC_NAMESPACE = "CloudLucy/SecurityV1_3"
_AWS_CLIENT_CONFIG = Config(
    connect_timeout=2,
    read_timeout=15,
    retries={"max_attempts": 3, "mode": "standard"},
)
_INTEGRITY_CODES = frozenset(
    {
        "action_mismatch",
        "authorization_signature_invalid",
        "contract_invalid",
        "deadline_binding_mismatch",
        "durable_receipt_binding_mismatch",
        "encrypted_package_binding_mismatch",
        "encrypted_package_digest_mismatch",
        "executor_binding_mismatch",
        "invoked_alias_mismatch",
        "manifest_binding_mismatch",
        "manifest_digest_mismatch",
        "manifest_signature_invalid",
        "permit_binding_mismatch",
        "published_version_mismatch",
        "realm_scope_binding_mismatch",
        "receipt_signer_changed_contract",
        "unpublished_executor_version",
    }
)


class LambdaContext(Protocol):
    aws_request_id: str
    invoked_function_arn: str
    function_version: str


def realm_retrieval_lambda_handler(event: object, context: LambdaContext) -> dict[str, Any]:
    return _handle(SensitiveActionV2.EVIDENCE_RETRIEVE, event, context)


def realm_deletion_lambda_handler(event: object, context: LambdaContext) -> dict[str, Any]:
    return _handle(SensitiveActionV2.EVIDENCE_DELETE, event, context)


def _handle(
    action: SensitiveActionV2, event: object, context: LambdaContext
) -> dict[str, Any]:
    try:
        raw = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(raw) > AWS_LAMBDA_SYNCHRONOUS_PAYLOAD_LIMIT:
            raise ExecutorRejected("lambda_payload_limit_exceeded")
        runtime = _runtime(action, context.invoked_function_arn, context.function_version)
        runtime.verify_context(context)
        if action == SensitiveActionV2.EVIDENCE_RETRIEVE:
            retrieval_invocation = RetrievalExecutorInvocationV2.model_validate_json(raw)
            result = cast(RealmRetrievalExecutor, runtime.executor).execute(
                retrieval_invocation, lambda_request_id=context.aws_request_id
            )
        else:
            deletion_invocation = DeletionExecutorInvocationV2.model_validate_json(raw)
            result = cast(RealmDeletionExecutor, runtime.executor).execute(
                deletion_invocation, lambda_request_id=context.aws_request_id
            )
        _LOGGER.info(
            "lucy_realm_executor_outcome action=%s outcome=accepted replayed=%s",
            action.value,
            result.replayed,
        )
        metrics = ["Accepted", *( ["Replayed"] if result.replayed else [])]
        _emit_metrics(action, metrics)
        return {"ok": True, "result": result.model_dump(mode="json")}
    except ExecutorRejected as exc:
        _LOGGER.warning(
            "lucy_realm_executor_outcome action=%s outcome=denied code=%s",
            action.value,
            exc.code,
        )
        metrics = ["Denied", *( ["IntegrityDenied"] if exc.code in _INTEGRITY_CODES else [])]
        if exc.code == "quota_denied":
            metrics.append("Throttled")
        _emit_metrics(action, metrics)
        return {"ok": False, "error": "request_rejected", "code": exc.code}
    except (ValidationError, TypeError, ValueError, UnicodeError):
        _LOGGER.warning(
            "lucy_realm_executor_outcome action=%s outcome=denied code=contract_invalid",
            action.value,
        )
        _emit_metrics(action, ["Denied", "IntegrityDenied"])
        return {"ok": False, "error": "request_rejected", "code": "contract_invalid"}
    except Exception as exc:
        _LOGGER.error(
            "lucy_realm_executor_outcome action=%s outcome=failed type=%s",
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


class _RealmExecutorRuntime:
    def __init__(
        self,
        executor: RealmRetrievalExecutor | RealmDeletionExecutor,
        identity: RealmExecutorIdentityV1,
    ) -> None:
        self.executor = executor
        self.identity = identity

    def verify_context(self, context: LambdaContext) -> None:
        if context.invoked_function_arn != self.identity.executor_alias_arn:
            raise ExecutorRejected("invoked_alias_mismatch")
        if context.function_version != str(self.identity.executor_version):
            raise ExecutorRejected("published_version_mismatch")
        if context.function_version == "$LATEST":
            raise ExecutorRejected("unpublished_executor_version")
        if not context.aws_request_id.strip():
            raise ExecutorRejected("lambda_request_id_missing")


@lru_cache(maxsize=8)
def _runtime(
    action: SensitiveActionV2, invoked_function_arn: str, function_version: str
) -> _RealmExecutorRuntime:
    identity = _identity_from_environment(action, invoked_function_arn, function_version)
    region = _required("AWS_REGION")
    dynamodb = cast(
        DynamoExecutorClient,
        boto3.client("dynamodb", region_name=region, config=_AWS_CLIENT_CONFIG),
    )
    kms = cast(
        KmsExecutorClient,
        boto3.client("kms", region_name=region, config=_AWS_CLIENT_CONFIG),
    )
    backend = AwsExecutorBackend(
        dynamodb,
        kms,
        tables=AwsExecutorTables(
            wrapped_keys=_required("LUCY_AWS_WRAPPED_KEY_TABLE"),
            receipts=_required("LUCY_AWS_EXECUTOR_RECEIPT_TABLE"),
            quotas=_required("LUCY_AWS_EXECUTOR_QUOTA_TABLE"),
            intents=(
                _required("LUCY_AWS_DELETION_INTENT_TABLE")
                if action == SensitiveActionV2.EVIDENCE_DELETE
                else None
            ),
        ),
        evidence_key_arn=(
            _required("LUCY_AWS_EVIDENCE_KEY_ARN")
            if action == SensitiveActionV2.EVIDENCE_RETRIEVE
            else None
        ),
        receipt_key_arn=_required("LUCY_AWS_RECEIPT_SIGNING_KEY_ARN"),
        minute_limit=_positive_int("LUCY_EXECUTOR_MINUTE_LIMIT"),
        day_limit=_positive_int("LUCY_EXECUTOR_DAY_LIMIT"),
    )
    verifier = V13ContractVerifier(_policy_keys(identity.environment))
    if action == SensitiveActionV2.EVIDENCE_RETRIEVE:
        executor: RealmRetrievalExecutor | RealmDeletionExecutor = RealmRetrievalExecutor(
            backend,
            verifier,
            identity,
            receipt_key_id=_required("LUCY_AWS_RECEIPT_SIGNING_KEY_ARN"),
            evidence_key_arn=_required("LUCY_AWS_EVIDENCE_KEY_ARN"),
        )
    else:
        executor = RealmDeletionExecutor(
            backend,
            verifier,
            identity,
            receipt_key_id=_required("LUCY_AWS_RECEIPT_SIGNING_KEY_ARN"),
        )
    return _RealmExecutorRuntime(executor, identity)


def _identity_from_environment(
    action: SensitiveActionV2, invoked_function_arn: str, function_version: str
) -> RealmExecutorIdentityV1:
    function_name = _required("AWS_LAMBDA_FUNCTION_NAME")
    alias_name = _required("LUCY_EXECUTOR_ALIAS_NAME")
    if not invoked_function_arn.endswith(f":function:{function_name}:{alias_name}"):
        raise ExecutorRejected("invoked_alias_mismatch")
    try:
        scope = OriginScopeV1.model_validate_json(_required("LUCY_V13_TARGET_SCOPE_JSON"))
        binding = ExecutionBindingV1.model_validate_json(
            _required("LUCY_V13_EXECUTION_BINDING_JSON")
        )
        workspace_id = UUID(_required("LUCY_V13_WORKSPACE_ID"))
    except (ValidationError, ValueError) as exc:
        raise ValueError("realm executor scope configuration is invalid") from exc
    return RealmExecutorIdentityV1(
        action=action,
        environment=DeploymentEnvironment(_required("LUCY_EXECUTOR_ENVIRONMENT")),
        target_scope=scope,
        workspace_id=workspace_id,
        execution_binding=binding,
        caller_identity=_required("LUCY_V13_CALLER_IDENTITY"),
        executor_identity=_required("LUCY_EXECUTOR_IDENTITY"),
        executor_alias_arn=invoked_function_arn,
        executor_version=_parse_positive_int(function_version, "AWS_LAMBDA_FUNCTION_VERSION"),
        record_version=_positive_int("LUCY_ARCHIVE_RECORD_VERSION"),
    )


def _policy_keys(environment: DeploymentEnvironment) -> tuple[V13VerificationKeyV1, ...]:
    try:
        payload = json.loads(_required("LUCY_POLICY_TRUST_STORE_JSON"))
        if not isinstance(payload, list):
            raise ValueError("trust store must be a list")
        keys = tuple(V13VerificationKeyV1.model_validate(item) for item in payload)
    except (json.JSONDecodeError, ValidationError, TypeError, ValueError) as exc:
        raise ValueError("V1.3 policy trust store is invalid") from exc
    if not keys or any(
        key.purpose != V13SigningKeyPurpose.POLICY_NOTARY
        or key.environment != environment
        or key.algorithm != SignatureAlgorithm.ED25519
        for key in keys
    ):
        raise ValueError("V1.3 policy trust store crosses purpose or environment")
    return keys


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"required realm executor configuration is missing: {name}")
    return value


def _positive_int(name: str) -> int:
    return _parse_positive_int(_required(name), name)


def _parse_positive_int(raw: str, name: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"realm executor configuration is not an integer: {name}") from exc
    if value < 1:
        raise ValueError(f"realm executor configuration must be positive: {name}")
    return value
