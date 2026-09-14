from __future__ import annotations

import base64
import json
from uuid import UUID

import pytest

from lucy.memory_pilot_executor_runtime import (
    MemoryPilotExecutorStartupError,
    configuration_from_environment,
)


def _environment() -> dict[str, str]:
    scope = {
        "tenant_account_id": "11111111-1111-4111-8111-111111111111",
        "node_id": "22222222-2222-4222-8222-222222222222",
        "node_tenure_id": "33333333-3333-4333-8333-333333333333",
        "tenure_epoch": 1,
        "security_realm_id": "44444444-4444-4444-8444-444444444444",
        "storage_epoch": 1,
    }
    key = base64.b64encode(b"k" * 32).decode("ascii")
    return {
        "LUCY_ENVIRONMENT": "production",
        "LUCY_SECURITY_BASELINE": "v1.3",
        "LUCY_SERVICE_MODE": "routine",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_PRODUCT_INGRESS_ENABLED": "false",
        "LUCY_MEMORY_PILOT_EXECUTOR_ENABLED": "true",
        "LUCY_OBSERVED_HERMES_COMMIT": "84bcd957a1f44150686f0f2f52b16b95f6e2e13a",
        "LUCY_DATABASE_URL": "postgresql://routine:secret@private/db",
        "LUCY_EXPECTED_DATABASE_LOGIN": "lucy_raymond_routine",
        "LUCY_STORAGE_EPOCH": "77777777-7777-4777-8777-777777777777",
        "LUCY_MEMORY_PILOT_TRANSFER_KEY_B64": key,
        "LUCY_MEMORY_PILOT_GATEWAY_TOKEN": "g" * 32,
        "LUCY_MEMORY_IMPORT_ARCHIVE_REQUEST_KEY_B64": key,
        "LUCY_MEMORY_OUTCOME_COMMITMENT_KEY_B64": key,
        "LUCY_MEMORY_PROVIDER_REFERENCE_KEY_B64": key,
        "OPENROUTER_API_KEY": "openrouter-secret",
        "LUCY_V13_TARGET_SCOPE_JSON": json.dumps(scope),
        "LUCY_AWS_OUTCOME_KEY_ARN": (
            "arn:aws:kms:us-east-1:123456789012:key/"
            "55555555-5555-4555-8555-555555555555"
        ),
        "LUCY_AWS_OUTCOME_KEY_TABLE": "lucy-outcome-keys",
        "LUCY_OUTCOME_REGISTRY_ID": "66666666-6666-4666-8666-666666666666",
        "LUCY_OUTCOME_REGISTRY_EPOCH": "1",
        "LUCY_OUTCOME_KEY_EPOCH": "1",
        "LUCY_OUTCOME_RECORD_VERSION": "1",
        "LUCY_MEMORY_PROVIDER_POLICY_ID": "openrouter-zdr-v1",
        "LUCY_MEMORY_MODEL_ROUTE": "google/gemini-3.1-flash-lite-preview",
        "LUCY_MEMORY_EXTRACTOR_VERSION": "extractor-v1",
        "LUCY_MEMORY_PROMPT_VERSION": "prompt-v1",
        "LUCY_MEMORY_MAX_OUTPUT_TOKENS": "4000",
        "LUCY_MEMORY_MAX_RESPONSE_BYTES": "1000000",
    }


def test_configuration_requires_exact_private_pilot_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "lucy.memory_pilot_executor_runtime._expected_commit",
        lambda: "84bcd957a1f44150686f0f2f52b16b95f6e2e13a",
    )
    configuration = configuration_from_environment(_environment())
    assert configuration.target_scope.storage_epoch == 1
    assert configuration.outcome_registry_id == UUID(
        "66666666-6666-4666-8666-666666666666"
    )
    assert configuration.provider_policy.maximum_output_tokens == 4000
    serialized = configuration.model_dump_json()
    assert "secret" not in serialized
    assert "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=" not in serialized


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_PRODUCT_INGRESS_ENABLED", "true"),
        ("LUCY_MEMORY_PILOT_EXECUTOR_ENABLED", "false"),
        ("LUCY_SERVICE_MODE", "evidence"),
        ("TELEGRAM_BOT_TOKEN", "forbidden"),
        ("LUCY_MEMORY_PILOT_TRANSFER_KEY_B64", "not-base64"),
        ("LUCY_OUTCOME_REGISTRY_EPOCH", "0"),
    ),
)
def test_configuration_fails_closed(
    monkeypatch: pytest.MonkeyPatch, key: str, value: str
) -> None:
    monkeypatch.setattr(
        "lucy.memory_pilot_executor_runtime._expected_commit",
        lambda: "84bcd957a1f44150686f0f2f52b16b95f6e2e13a",
    )
    environment = _environment()
    environment[key] = value
    with pytest.raises(MemoryPilotExecutorStartupError):
        configuration_from_environment(environment)
