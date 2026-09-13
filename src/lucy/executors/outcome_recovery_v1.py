"""Exact-job AWS Lambda executor for memory-provider outcome recovery."""

from __future__ import annotations

import base64
import json
import logging
import os
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Protocol
from uuid import UUID

import boto3  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from lucy.contracts.canonical import canonical_json_bytes
from lucy.contracts.memory_outcome_recovery_v1 import (
    MemoryOutcomeKmsContextV1,
    MemoryOutcomeRecoveryGrantV1,
    MemoryOutcomeRecoveryPackageV1,
    MemoryOutcomeRecoveryResultV1,
    recovery_grant_matches_package,
    require_environment,
)
from lucy.contracts.security_v1_2 import DeploymentEnvironment, SignatureAlgorithm
from lucy.contracts.security_v1_3 import (
    ExecutionBindingV1,
    OriginScopeV1,
    V13ContractVerifier,
    V13SigningKeyPurpose,
    V13VerificationKeyV1,
)

_LOGGER = logging.getLogger("lucy.memory_outcome_recovery.v1")
_AWS_CONFIG = Config(
    connect_timeout=2,
    read_timeout=15,
    retries={"max_attempts": 3, "mode": "standard"},
)


class LambdaContext(Protocol):
    aws_request_id: str
    invoked_function_arn: str
    function_version: str


class RecoveryDynamoClient(Protocol):
    def get_item(self, **kwargs: Any) -> dict[str, Any]: ...

    def put_item(self, **kwargs: Any) -> dict[str, Any]: ...


class RecoveryKmsClient(Protocol):
    def decrypt(self, **kwargs: Any) -> dict[str, Any]: ...


class _RecoveredProviderOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    output: str
    billed_microusd: int = Field(ge=0)
    provider_policy_id: str = Field(min_length=1, max_length=200)
    model_route: str = Field(min_length=1, max_length=200)
    provider_reference_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")


class MemoryOutcomeRecoveryRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class MemoryOutcomeRecoveryExecutor:
    def __init__(
        self,
        dynamodb: RecoveryDynamoClient,
        kms: RecoveryKmsClient,
        verifier: V13ContractVerifier,
        *,
        target_scope: OriginScopeV1,
        execution_binding: ExecutionBindingV1,
        environment: DeploymentEnvironment,
        caller_identity: str,
        key_arn: str,
        registry_id: str,
        key_table: str,
        receipt_table: str,
    ) -> None:
        self._dynamodb = dynamodb
        self._kms = kms
        self._verifier = verifier
        self._scope = target_scope
        self._binding = execution_binding
        self._environment = environment
        self._caller_identity = caller_identity
        self._key_arn = key_arn
        try:
            self._registry_id = UUID(registry_id)
        except ValueError as exc:
            raise ValueError("outcome registry identity must be a UUID") from exc
        if not key_arn.strip() or not key_table.strip() or not receipt_table.strip():
            raise ValueError("outcome recovery AWS resources must be configured")
        self._key_table = key_table
        self._receipt_table = receipt_table

    def execute(
        self,
        grant: MemoryOutcomeRecoveryGrantV1,
        package: MemoryOutcomeRecoveryPackageV1,
        *,
        now: datetime,
        lambda_request_id: str,
    ) -> MemoryOutcomeRecoveryResultV1:
        self._verifier.verify(
            grant,
            expected_purpose=V13SigningKeyPurpose.POLICY_NOTARY,
            checked_at=now,
        )
        require_environment(grant, self._environment)
        if not lambda_request_id.strip():
            raise MemoryOutcomeRecoveryRejected("lambda_request_id_missing")
        if (
            now > grant.permit_claim_deadline
            or now > grant.execution_completion_deadline
        ):
            raise MemoryOutcomeRecoveryRejected("grant_claim_expired")
        if (
            grant.caller_identity != self._caller_identity
            or grant.target_scope != self._scope
            or grant.execution_binding != self._binding
            or grant.registry_id != self._registry_id
        ):
            raise MemoryOutcomeRecoveryRejected("deployment_binding_mismatch")
        if not recovery_grant_matches_package(grant, package):
            raise MemoryOutcomeRecoveryRejected("package_binding_mismatch")
        replay = self._load_receipt(grant)
        if replay:
            return self._replayed(grant)
        wrapped = self._load_wrapped_key(grant)
        context = MemoryOutcomeKmsContextV1.from_scope(
            self._scope, encryption_id=grant.encryption_id
        ).as_aws_context()
        response = self._kms.decrypt(
            CiphertextBlob=wrapped,
            KeyId=self._key_arn,
            EncryptionContext=context,
        )
        dek = response.get("Plaintext")
        if (
            not isinstance(dek, (bytes, bytearray))
            or len(dek) != 32
            or str(response.get("KeyId", "")) != self._key_arn
        ):
            raise MemoryOutcomeRecoveryRejected("kms_response_invalid")
        envelope = package.envelope
        try:
            plaintext = AESGCM(bytes(dek)).decrypt(
                base64.b64decode(envelope.content_nonce_b64, validate=True),
                base64.b64decode(envelope.ciphertext_b64, validate=True),
                canonical_json_bytes(envelope.binding),
            )
            if len(plaintext) > grant.max_plaintext_bytes:
                raise MemoryOutcomeRecoveryRejected("plaintext_limit_exceeded")
            outcome = _RecoveredProviderOutcome.model_validate_json(plaintext)
        except MemoryOutcomeRecoveryRejected:
            raise
        except Exception as exc:
            raise MemoryOutcomeRecoveryRejected("outcome_decryption_failed") from exc
        if (
            outcome.billed_microusd != envelope.billed_microusd
            or outcome.billed_microusd > envelope.binding.maximum_microusd
            or outcome.provider_policy_id != envelope.binding.provider_policy_id
            or outcome.model_route != envelope.binding.model_route
            or outcome.provider_reference_commitment
            != envelope.provider_reference_commitment
        ):
            raise MemoryOutcomeRecoveryRejected("outcome_metadata_invalid")
        if not self._commit_receipt(grant, now=now, request_id=lambda_request_id):
            return self._replayed(grant)
        return MemoryOutcomeRecoveryResultV1(
            operation_id=grant.operation_id,
            extraction_job_id=grant.extraction_job_id,
            package_digest=grant.package_digest,
            released=True,
            replayed=False,
            output=outcome.output,
            billed_microusd=outcome.billed_microusd,
            provider_policy_id=outcome.provider_policy_id,
            model_route=outcome.model_route,
            provider_reference_commitment=outcome.provider_reference_commitment,
        )

    def _load_receipt(self, grant: MemoryOutcomeRecoveryGrantV1) -> bool:
        response = self._dynamodb.get_item(
            TableName=self._receipt_table,
            Key={"operation_id": {"S": str(grant.operation_id)}},
            ProjectionExpression="operation_id, package_digest, grant_digest",
            ConsistentRead=True,
        )
        item = response.get("Item")
        if item is None:
            return False
        try:
            if (
                item["operation_id"]["S"] != str(grant.operation_id)
                or item["package_digest"]["S"] != grant.package_digest
                or item["grant_digest"]["S"] != grant.unsigned_digest_hex()
            ):
                raise MemoryOutcomeRecoveryRejected("receipt_binding_mismatch")
        except (KeyError, TypeError) as exc:
            raise MemoryOutcomeRecoveryRejected("receipt_invalid") from exc
        return True

    def _load_wrapped_key(self, grant: MemoryOutcomeRecoveryGrantV1) -> bytes:
        response = self._dynamodb.get_item(
            TableName=self._key_table,
            Key={"key_ref": {"S": str(grant.encryption_id)}},
            ProjectionExpression="key_ref, registry_id, ciphertext, kek_version",
            ConsistentRead=True,
        )
        item = response.get("Item")
        try:
            if (
                not isinstance(item, dict)
                or item["key_ref"]["S"] != str(grant.encryption_id)
                or item["registry_id"]["S"] != str(self._registry_id)
                or item["kek_version"]["S"] != self._key_arn
            ):
                raise MemoryOutcomeRecoveryRejected("wrapped_key_binding_mismatch")
            return bytes(item["ciphertext"]["B"])
        except (KeyError, TypeError) as exc:
            raise MemoryOutcomeRecoveryRejected("wrapped_key_invalid") from exc

    def _commit_receipt(
        self, grant: MemoryOutcomeRecoveryGrantV1, *, now: datetime, request_id: str
    ) -> bool:
        try:
            self._dynamodb.put_item(
                TableName=self._receipt_table,
                Item={
                    "operation_id": {"S": str(grant.operation_id)},
                    "extraction_job_id": {"S": str(grant.extraction_job_id)},
                    "package_digest": {"S": grant.package_digest},
                    "grant_digest": {"S": grant.unsigned_digest_hex()},
                    "completed_at": {"S": now.astimezone(UTC).isoformat()},
                    "lambda_request_id": {"S": request_id},
                },
                ConditionExpression="attribute_not_exists(operation_id)",
            )
            return True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ConditionalCheckFailedException":
                return False
            raise

    @staticmethod
    def _replayed(grant: MemoryOutcomeRecoveryGrantV1) -> MemoryOutcomeRecoveryResultV1:
        return MemoryOutcomeRecoveryResultV1(
            operation_id=grant.operation_id,
            extraction_job_id=grant.extraction_job_id,
            package_digest=grant.package_digest,
            released=False,
            replayed=True,
            billed_microusd=0,
        )


def memory_outcome_recovery_lambda_handler(
    event: object, context: LambdaContext
) -> dict[str, Any]:
    try:
        runtime = _runtime(context.invoked_function_arn, context.function_version)
        runtime.verify_context(context)
        if not isinstance(event, dict):
            raise ValueError("event must be an object")
        grant = MemoryOutcomeRecoveryGrantV1.model_validate(event.get("grant"))
        package = MemoryOutcomeRecoveryPackageV1.model_validate(event.get("package"))
        result = runtime.executor.execute(
            grant,
            package,
            now=datetime.now(UTC),
            lambda_request_id=context.aws_request_id,
        )
        _LOGGER.info(
            "lucy_memory_outcome_recovery outcome=accepted replayed=%s", result.replayed
        )
        return {"ok": True, "result": result.model_dump(mode="json")}
    except MemoryOutcomeRecoveryRejected as exc:
        _LOGGER.warning(
            "lucy_memory_outcome_recovery outcome=denied code=%s", exc.code
        )
        return {"ok": False, "error": "request_rejected", "code": exc.code}
    except (ValidationError, PermissionError, TypeError, ValueError):
        _LOGGER.warning("lucy_memory_outcome_recovery outcome=denied code=contract_invalid")
        return {"ok": False, "error": "request_rejected", "code": "contract_invalid"}
    except Exception as exc:
        _LOGGER.error(
            "lucy_memory_outcome_recovery outcome=failed type=%s", type(exc).__name__
        )
        return {"ok": False, "error": "executor_unavailable", "code": "internal_failure"}


class _Runtime:
    def __init__(self, executor: MemoryOutcomeRecoveryExecutor, alias_arn: str, version: str):
        self.executor = executor
        self._alias_arn = alias_arn
        self._version = version

    def verify_context(self, context: LambdaContext) -> None:
        if (
            context.invoked_function_arn != self._alias_arn
            or context.function_version != self._version
            or context.function_version == "$LATEST"
        ):
            raise MemoryOutcomeRecoveryRejected("invoked_version_mismatch")


@lru_cache(maxsize=4)
def _runtime(invoked_function_arn: str, function_version: str) -> _Runtime:
    region = _required("AWS_REGION")
    environment = DeploymentEnvironment(_required("LUCY_EXECUTOR_ENVIRONMENT"))
    target_scope = OriginScopeV1.model_validate_json(_required("LUCY_V13_TARGET_SCOPE_JSON"))
    binding = ExecutionBindingV1.model_validate_json(
        _required("LUCY_V13_EXECUTION_BINDING_JSON")
    )
    verifier = V13ContractVerifier(_policy_keys(environment))
    dynamodb = boto3.client("dynamodb", region_name=region, config=_AWS_CONFIG)
    kms = boto3.client("kms", region_name=region, config=_AWS_CONFIG)
    executor = MemoryOutcomeRecoveryExecutor(
        dynamodb,
        kms,
        verifier,
        target_scope=target_scope,
        execution_binding=binding,
        environment=environment,
        caller_identity=_required("LUCY_V13_CALLER_IDENTITY"),
        key_arn=_required("LUCY_AWS_OUTCOME_KEY_ARN"),
        registry_id=_required("LUCY_OUTCOME_REGISTRY_ID"),
        key_table=_required("LUCY_AWS_OUTCOME_KEY_TABLE"),
        receipt_table=_required("LUCY_AWS_OUTCOME_RECOVERY_RECEIPT_TABLE"),
    )
    return _Runtime(executor, invoked_function_arn, function_version)


def _policy_keys(environment: DeploymentEnvironment) -> tuple[V13VerificationKeyV1, ...]:
    payload = json.loads(_required("LUCY_POLICY_TRUST_STORE_JSON"))
    if not isinstance(payload, list):
        raise ValueError("policy trust store must be a list")
    keys = tuple(V13VerificationKeyV1.model_validate(item) for item in payload)
    if not keys or any(
        key.purpose != V13SigningKeyPurpose.POLICY_NOTARY
        or key.environment != environment
        or key.algorithm != SignatureAlgorithm.ED25519
        for key in keys
    ):
        raise ValueError("policy trust store crosses purpose or environment")
    return keys


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"required outcome recovery configuration is missing: {name}")
    return value
