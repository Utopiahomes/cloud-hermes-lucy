from __future__ import annotations

import pytest

from lucy.memory_pilot_proxy_runtime import (
    MemoryPilotProxyStartupError,
    configuration_from_environment,
)


def _environment() -> dict[str, str]:
    return {
        "LUCY_ENVIRONMENT": "production",
        "LUCY_SECURITY_BASELINE": "v1.3",
        "LUCY_SERVICE_MODE": "memory-pilot-intake",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_PRODUCT_INGRESS_ENABLED": "false",
        "LUCY_MEMORY_PILOT_INTAKE_ENABLED": "true",
        "LUCY_OBSERVED_HERMES_COMMIT": "84bcd957a1f44150686f0f2f52b16b95f6e2e13a",
        "LUCY_MEMORY_PILOT_EXECUTOR_HOSTPORT": "raymond-lucy-evidence:10000",
        "LUCY_MEMORY_PILOT_GATEWAY_TOKEN": "g" * 32,
    }


def test_runtime_requires_exact_temporary_database_free_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "lucy.memory_pilot_proxy_runtime._expected_commit",
        lambda: "84bcd957a1f44150686f0f2f52b16b95f6e2e13a",
    )
    configuration = configuration_from_environment(_environment())
    assert configuration.private_executor_hostport == "raymond-lucy-evidence:10000"
    assert configuration.model_dump() == {
        "private_executor_hostport": "raymond-lucy-evidence:10000",
        "maximum_request_bytes": 2_000_000,
        "maximum_response_bytes": 10_000_000,
        "private_timeout_seconds": 180,
    }


def test_runtime_rejects_capture_product_ingress_and_privileged_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "lucy.memory_pilot_proxy_runtime._expected_commit",
        lambda: "84bcd957a1f44150686f0f2f52b16b95f6e2e13a",
    )
    for key, value in (
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_PRODUCT_INGRESS_ENABLED", "true"),
        ("LUCY_MEMORY_PILOT_INTAKE_ENABLED", "false"),
        ("LUCY_DATABASE_URL", "postgresql://forbidden"),
        ("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/forbidden"),
        ("OPENROUTER_API_KEY", "forbidden"),
    ):
        environment = _environment()
        environment[key] = value
        with pytest.raises(MemoryPilotProxyStartupError):
            configuration_from_environment(environment)
