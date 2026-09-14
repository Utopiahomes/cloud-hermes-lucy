"""Fail-closed runtime for the temporary, database-free memory-pilot gateway."""

from __future__ import annotations

import os
from collections.abc import Mapping
from uuid import UUID

import uvicorn
from pydantic import SecretStr

from lucy.memory_pilot_proxy_api import (
    MemoryPilotProxyConfigurationV1,
    create_memory_pilot_proxy_app,
)
from lucy.runtime import _expected_commit, _listener_port


class MemoryPilotProxyStartupError(RuntimeError):
    """The temporary pilot gateway is not exactly commissioned."""


def configuration_from_environment(
    environment: Mapping[str, str],
) -> MemoryPilotProxyConfigurationV1:
    if (
        environment.get("LUCY_ENVIRONMENT") != "production"
        or environment.get("LUCY_SECURITY_BASELINE") != "v1.3"
        or environment.get("LUCY_SERVICE_MODE") != "memory-pilot-intake"
        or environment.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false"
        or environment.get("LUCY_PRODUCT_INGRESS_ENABLED") != "false"
        or environment.get("LUCY_MEMORY_PILOT_INTAKE_ENABLED") != "true"
        or environment.get("LUCY_OBSERVED_HERMES_COMMIT") != _expected_commit()
    ):
        raise MemoryPilotProxyStartupError("memory-pilot gateway startup gate failed")
    forbidden = (
        "LUCY_DATABASE_URL",
        "LUCY_MIGRATION_DATABASE_URL",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ROLE_ARN",
        "OPENROUTER_API_KEY",
    )
    if any(environment.get(key) for key in forbidden):
        raise MemoryPilotProxyStartupError("memory-pilot gateway has forbidden authority")
    try:
        hostport = environment["LUCY_MEMORY_PILOT_EXECUTOR_HOSTPORT"]
        gateway_token = environment["LUCY_MEMORY_PILOT_GATEWAY_TOKEN"]
    except KeyError:
        raise MemoryPilotProxyStartupError(
            "memory-pilot gateway configuration is incomplete"
        ) from None
    configuration = MemoryPilotProxyConfigurationV1(
        private_executor_hostport=hostport,
        gateway_bearer_token=SecretStr(gateway_token),
    )
    # Validate the fixed private binding before opening a public listener.
    configuration.private_url(
        UUID("00000000-0000-4000-8000-000000000001")
    )
    return configuration


def main() -> None:
    try:
        configuration = configuration_from_environment(dict(os.environ))
    except (MemoryPilotProxyStartupError, ValueError):
        raise SystemExit("Private-memory pilot gateway startup failed") from None
    app = create_memory_pilot_proxy_app(configuration)
    print("Private-memory pilot gateway admitted ASGI listener starting")
    uvicorn.run(app, host="0.0.0.0", port=_listener_port(), access_log=False)


if __name__ == "__main__":
    main()
