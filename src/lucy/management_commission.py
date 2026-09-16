"""One-shot Control commissioning probe for Management Contract v1.0.

The process reads a deployment-owned, fixed provider endpoint and dedicated
management-reader key from its environment, observes the four read-only
resources, checks the transitional Homes expectations, emits content-free JSON,
and exits. It has no database, scheduler, or durable state.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Protocol

from lucy.management_contract import (
    MANAGEMENT_BUNDLE_DIGEST,
    CapabilityState,
    HealthStatus,
    ManagementClient,
    ManagementContractError,
    ManagementJwtIssuer,
    ManagementObservation,
    ReasonCode,
    verify_management_bundle,
)

_PRINTABLE_ASCII = re.compile(r"^[\x20-\x7e]+$")


class Observer(Protocol):
    def observe(self) -> ManagementObservation: ...


@dataclass(frozen=True, slots=True)
class CommissioningConfig:
    provider_base_url: str
    expected_provider_release_id: str

    @classmethod
    def from_environment(
        cls, environment: dict[str, str] | None = None
    ) -> CommissioningConfig:
        values = environment if environment is not None else os.environ
        try:
            provider_base_url = values["STOIN_MANAGEMENT_PROVIDER_BASE_URL"]
            expected_release_id = values["STOIN_MANAGEMENT_EXPECTED_PROVIDER_RELEASE_ID"]
        except KeyError:
            raise ManagementContractError(
                "management commissioning configuration is invalid"
            ) from None
        if (
            not expected_release_id
            or len(expected_release_id) > 128
            or _PRINTABLE_ASCII.fullmatch(expected_release_id) is None
        ):
            raise ManagementContractError("management commissioning configuration is invalid")
        return cls(
            provider_base_url=provider_base_url,
            expected_provider_release_id=expected_release_id,
        )


def commission(
    observer: Observer,
    *,
    expected_provider_release_id: str,
) -> dict[str, Any]:
    """Validate one transitional Homes observation and return safe evidence."""

    observation = observer.observe()
    if observation.version.management_provider.release_id != expected_provider_release_id:
        raise ManagementContractError("management provider release differs from commissioning")
    if observation.health.status is not HealthStatus.UNKNOWN or observation.health.reason_codes != (
        ReasonCode.HEALTH_COVERAGE_LIMITED,
    ):
        raise ManagementContractError("management provider is not in transitional health mode")
    if observation.health.degraded_capabilities:
        raise ManagementContractError("transitional health names an impaired capability")

    enabled = tuple(
        capability.capability_id
        for capability in observation.capabilities.capabilities
        if capability.state is CapabilityState.ENABLED
    )
    if "guest.answer" not in enabled:
        raise ManagementContractError("required management capability is not enabled")

    return {
        "bundle_digest": MANAGEMENT_BUNDLE_DIGEST,
        "contract_version": observation.identity.contract_version,
        "enabled_capabilities": list(enabled),
        "health_reason_codes": [value.value for value in observation.health.reason_codes],
        "health_status": observation.health.status.value,
        "management_provider_release_id": expected_provider_release_id,
        "realm_id": observation.identity.realm_id,
        "resources_observed": 4,
        "synth_id": observation.identity.synth_id,
    }


def main() -> None:
    try:
        config = CommissioningConfig.from_environment()
        digest = verify_management_bundle()
        if digest != MANAGEMENT_BUNDLE_DIGEST:
            raise ManagementContractError("management contract bundle digest differs")
        client = ManagementClient(
            config.provider_base_url,
            ManagementJwtIssuer.from_environment(),
        )
        evidence = commission(
            client,
            expected_provider_release_id=config.expected_provider_release_id,
        )
    except (ManagementContractError, ValueError):
        print("management commissioning failed", file=sys.stderr)
        raise SystemExit(1) from None
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
