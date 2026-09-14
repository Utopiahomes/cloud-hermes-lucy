"""Fail-closed temporary runtime for the private-memory pilot executor."""

from __future__ import annotations

import base64
import binascii
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

import boto3  # type: ignore[import-untyped]
import uvicorn
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from lucy.contracts.security_v1_3 import OriginScopeV1
from lucy.db.session import create_session_factory
from lucy.governed_memory import GovernedMemoryArchive, GovernedMemoryExtractor
from lucy.governed_memory_outcome import PostgresMemoryOutcomeStore
from lucy.memory_openrouter import OpenRouterMemoryPolicyV1, OpenRouterMemoryProvider
from lucy.memory_outcome import WriteOnlyEncryptedMemoryOutcomeJournal
from lucy.memory_outcome_aws_v1 import (
    AwsKmsMemoryOutcomeEncryptor,
    DynamoMemoryOutcomeKeyWriter,
    OutcomeDynamoClient,
    OutcomeKmsClient,
)
from lucy.memory_outcome_recovery import memory_outcome_recovery_from_environment
from lucy.memory_pilot_intake_api import (
    MemoryPilotIntakeConfigurationV1,
    create_memory_pilot_execution_app,
)
from lucy.memory_pilot_transport import PostgresMemoryPilotTransportAdmission
from lucy.memory_pilot_transport_runner import VerifiedMemoryPilotBatchExecutor
from lucy.readiness import (
    ServiceReadiness,
)
from lucy.realm_archive_aws import realm_archive_from_environment
from lucy.runtime import _expected_commit, _listener_port


class MemoryPilotExecutorStartupError(RuntimeError):
    """The temporary private executor is not exactly commissioned."""


class MemoryPilotExecutorConfigurationV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    database_url: SecretStr = Field(exclude=True)
    expected_database_login: str = Field(min_length=1, max_length=63)
    storage_epoch: UUID
    transfer_key: SecretStr = Field(exclude=True)
    gateway_bearer_token: SecretStr = Field(exclude=True)
    archive_request_commitment_key: SecretStr = Field(exclude=True)
    outcome_commitment_key: SecretStr = Field(exclude=True)
    provider_reference_commitment_key: SecretStr = Field(exclude=True)
    openrouter_api_key: SecretStr = Field(exclude=True)
    target_scope: OriginScopeV1
    outcome_key_arn: str
    outcome_key_table: str
    outcome_registry_id: UUID
    outcome_registry_epoch: int = Field(ge=1)
    outcome_key_epoch: int = Field(ge=1)
    outcome_record_version: int = Field(ge=1)
    provider_policy: OpenRouterMemoryPolicyV1


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise MemoryPilotExecutorStartupError(
            f"private-memory pilot configuration is missing: {name}"
        )
    return value


def _key_b64(values: Mapping[str, str], name: str) -> SecretStr:
    encoded = _required(values, name)
    try:
        key = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise MemoryPilotExecutorStartupError(
            "private-memory pilot key configuration is invalid"
        ) from exc
    if len(key) != 32:
        raise MemoryPilotExecutorStartupError(
            "private-memory pilot key configuration is invalid"
        )
    return SecretStr(encoded)


def configuration_from_environment(
    environment: Mapping[str, str],
) -> MemoryPilotExecutorConfigurationV1:
    if (
        environment.get("LUCY_ENVIRONMENT") != "production"
        or environment.get("LUCY_SECURITY_BASELINE") != "v1.3"
        or environment.get("LUCY_SERVICE_MODE") != "routine"
        or environment.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false"
        or environment.get("LUCY_PRODUCT_INGRESS_ENABLED") != "false"
        or environment.get("LUCY_MEMORY_PILOT_EXECUTOR_ENABLED") != "true"
        or environment.get("LUCY_OBSERVED_HERMES_COMMIT") != _expected_commit()
        or environment.get("LUCY_TELEGRAM_STAGE") not in {None, "", "1"}
    ):
        raise MemoryPilotExecutorStartupError("private-memory pilot startup gate failed")
    if any(
        environment.get(name)
        for name in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_ALLOWED_USERS", "LUCY_OWNER_TOKEN")
    ):
        raise MemoryPilotExecutorStartupError(
            "private-memory pilot executor has forbidden ingress authority"
        )
    try:
        target_scope = OriginScopeV1.model_validate_json(
            _required(environment, "LUCY_V13_TARGET_SCOPE_JSON")
        )
        configuration = MemoryPilotExecutorConfigurationV1(
            database_url=SecretStr(_required(environment, "LUCY_DATABASE_URL")),
            expected_database_login=_required(
                environment, "LUCY_EXPECTED_DATABASE_LOGIN"
            ),
            storage_epoch=UUID(_required(environment, "LUCY_STORAGE_EPOCH")),
            transfer_key=_key_b64(environment, "LUCY_MEMORY_PILOT_TRANSFER_KEY_B64"),
            gateway_bearer_token=SecretStr(
                _required(environment, "LUCY_MEMORY_PILOT_GATEWAY_TOKEN")
            ),
            archive_request_commitment_key=_key_b64(
                environment, "LUCY_MEMORY_IMPORT_ARCHIVE_REQUEST_KEY_B64"
            ),
            outcome_commitment_key=_key_b64(
                environment, "LUCY_MEMORY_OUTCOME_COMMITMENT_KEY_B64"
            ),
            provider_reference_commitment_key=_key_b64(
                environment, "LUCY_MEMORY_PROVIDER_REFERENCE_KEY_B64"
            ),
            openrouter_api_key=SecretStr(_required(environment, "OPENROUTER_API_KEY")),
            target_scope=target_scope,
            outcome_key_arn=_required(environment, "LUCY_AWS_OUTCOME_KEY_ARN"),
            outcome_key_table=_required(environment, "LUCY_AWS_OUTCOME_KEY_TABLE"),
            outcome_registry_id=UUID(_required(environment, "LUCY_OUTCOME_REGISTRY_ID")),
            outcome_registry_epoch=int(
                _required(environment, "LUCY_OUTCOME_REGISTRY_EPOCH")
            ),
            outcome_key_epoch=int(_required(environment, "LUCY_OUTCOME_KEY_EPOCH")),
            outcome_record_version=int(
                _required(environment, "LUCY_OUTCOME_RECORD_VERSION")
            ),
            provider_policy=OpenRouterMemoryPolicyV1(
                provider_policy_id=_required(
                    environment, "LUCY_MEMORY_PROVIDER_POLICY_ID"
                ),
                model_route=_required(environment, "LUCY_MEMORY_MODEL_ROUTE"),
                extractor_version=_required(
                    environment, "LUCY_MEMORY_EXTRACTOR_VERSION"
                ),
                prompt_version=_required(environment, "LUCY_MEMORY_PROMPT_VERSION"),
                maximum_output_tokens=int(
                    _required(environment, "LUCY_MEMORY_MAX_OUTPUT_TOKENS")
                ),
                maximum_response_bytes=int(
                    _required(environment, "LUCY_MEMORY_MAX_RESPONSE_BYTES")
                ),
            ),
        )
    except (ValidationError, ValueError) as exc:
        raise MemoryPilotExecutorStartupError(
            "private-memory pilot configuration is invalid"
        ) from exc
    if len(configuration.gateway_bearer_token.get_secret_value()) < 32:
        raise MemoryPilotExecutorStartupError(
            "private-memory pilot gateway credential is invalid"
        )
    return configuration


def _decoded(secret: SecretStr) -> bytes:
    return base64.b64decode(secret.get_secret_value(), validate=True)


def build_app(
    environment: Mapping[str, str] | None = None,
    *,
    kms_client: OutcomeKmsClient | None = None,
    dynamodb_client: OutcomeDynamoClient | None = None,
) -> Any:
    values = dict(os.environ if environment is None else environment)
    configuration = configuration_from_environment(values)
    sessions = create_session_factory(configuration.database_url.get_secret_value())
    ServiceReadiness(
        sessions,
        mode="routine",
        storage_epoch=configuration.storage_epoch,
        baseline="v1.3",
        expected_database_login=configuration.expected_database_login,
    ).check()
    archive = GovernedMemoryArchive(
        sessions,
        realm_archive_from_environment(values),
        request_commitment_key=_decoded(
            configuration.archive_request_commitment_key
        ),
    )
    governed = GovernedMemoryExtractor(sessions)
    outcome_store = PostgresMemoryOutcomeStore(sessions)
    region = _required(values, "AWS_REGION")
    if kms_client is None:
        kms_client = cast(OutcomeKmsClient, boto3.client("kms", region_name=region))
    if dynamodb_client is None:
        dynamodb_client = cast(
            OutcomeDynamoClient, boto3.client("dynamodb", region_name=region)
        )
    outcomes = WriteOnlyEncryptedMemoryOutcomeJournal(
        outcome_store,
        cipher=AwsKmsMemoryOutcomeEncryptor(
            kms_client,
            key_arn=configuration.outcome_key_arn,
            commitment_key=_decoded(configuration.outcome_commitment_key),
            target_scope=configuration.target_scope,
            registry_epoch=configuration.outcome_registry_epoch,
            key_epoch=configuration.outcome_key_epoch,
            record_version=configuration.outcome_record_version,
        ),
        key_writer=DynamoMemoryOutcomeKeyWriter(
            dynamodb_client,
            table_name=configuration.outcome_key_table,
            registry_id=configuration.outcome_registry_id,
        ),
    )
    executor = VerifiedMemoryPilotBatchExecutor(
        admission=PostgresMemoryPilotTransportAdmission(
            sessions, transfer_key=_decoded(configuration.transfer_key)
        ),
        archive=archive,
        accounting=governed,
        eligibility=governed,
        provider=OpenRouterMemoryProvider(
            api_key=configuration.openrouter_api_key.get_secret_value(),
            policy=configuration.provider_policy,
            provider_reference_commitment_key=_decoded(
                configuration.provider_reference_commitment_key
            ),
        ),
        outcomes=outcomes,
        candidate_store=governed,
        outcome_recovery_factory=lambda authorization: (
            memory_outcome_recovery_from_environment(
                sessions, authorization, values=values
            )
        ),
        now=lambda: datetime.now(UTC),
    )
    return create_memory_pilot_execution_app(
        executor,
        configuration=MemoryPilotIntakeConfigurationV1(
            gateway_bearer_token=configuration.gateway_bearer_token
        ),
    )


def main() -> None:
    try:
        app = build_app()
    except (MemoryPilotExecutorStartupError, ValueError, RuntimeError):
        raise SystemExit("Private-memory pilot executor startup failed") from None
    print("Private-memory pilot executor admitted ASGI listener starting")
    uvicorn.run(app, host="0.0.0.0", port=_listener_port(), access_log=False)


if __name__ == "__main__":
    main()
