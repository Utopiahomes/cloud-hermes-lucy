from __future__ import annotations

import pytest

from lucy.management_commission import CommissioningConfig, commission, main
from lucy.management_contract import (
    CapabilitiesResponse,
    HealthResponse,
    IdentityResponse,
    ManagementContractError,
    ManagementObservation,
    VersionResponse,
)

RELEASE_ID = "homes-management:release:staging.1"


def _observation(
    *,
    release_id: str = RELEASE_ID,
    health_status: str = "unknown",
    reason_codes: list[str] | None = None,
    capability_state: str = "enabled",
    capability_id: str = "guest.answer",
) -> ManagementObservation:
    observed_at = "2026-09-16T12:00:00Z"
    return ManagementObservation(
        identity=IdentityResponse.model_validate(
            {
                "contract_version": "1.0",
                "observed_at": observed_at,
                "synth_id": "stoin:synth:utopia-homes-prime",
                "realm_id": "stoin:realm:utopia-homes",
                "synth_class": "business-prime",
                "display_name": "Utopia Homes Prime",
            }
        ),
        health=HealthResponse.model_validate(
            {
                "contract_version": "1.0",
                "observed_at": observed_at,
                "status": health_status,
                "management_provider_release_id": release_id,
                "degraded_capabilities": [],
                "reason_codes": reason_codes or ["health_coverage_limited"],
            }
        ),
        version=VersionResponse.model_validate(
            {
                "contract_version": "1.0",
                "observed_at": observed_at,
                "management_provider": {
                    "deployment_id": "stoin:deployment:utopia-homes-management:staging",
                    "runtime_id": "stoin:runtime:utopia-homes-management:staging.1",
                    "release_id": release_id,
                    "software_version": "0.1.0",
                    "artifact_digest": f"sha256:{'0' * 64}",
                    "deployed_at": observed_at,
                },
                "managed_synth": {"synth_id": "stoin:synth:utopia-homes-prime"},
                "supported_management_contracts": ["1.0"],
            }
        ),
        capabilities=CapabilitiesResponse.model_validate(
            {
                "contract_version": "1.0",
                "observed_at": observed_at,
                "capabilities": [
                    {
                        "capability_id": capability_id,
                        "contract_version": "1.0",
                        "state": capability_state,
                    }
                ],
            }
        ),
    )


class FakeObserver:
    def __init__(self, observation: ManagementObservation) -> None:
        self._observation = observation

    def observe(self) -> ManagementObservation:
        return self._observation


def test_config_requires_fixed_endpoint_and_release() -> None:
    config = CommissioningConfig.from_environment(
        {
            "STOIN_MANAGEMENT_PROVIDER_BASE_URL": "https://management-staging.example",
            "STOIN_MANAGEMENT_EXPECTED_PROVIDER_RELEASE_ID": RELEASE_ID,
        }
    )
    assert config.provider_base_url == "https://management-staging.example"
    assert config.expected_provider_release_id == RELEASE_ID

    with pytest.raises(ManagementContractError, match="configuration is invalid"):
        CommissioningConfig.from_environment({})


def test_commission_returns_only_content_free_evidence() -> None:
    evidence = commission(FakeObserver(_observation()), expected_provider_release_id=RELEASE_ID)
    assert evidence["resources_observed"] == 4
    assert evidence["health_status"] == "unknown"
    assert evidence["enabled_capabilities"] == ["guest.answer"]
    assert set(evidence) == {
        "bundle_digest",
        "contract_version",
        "enabled_capabilities",
        "health_reason_codes",
        "health_status",
        "management_provider_release_id",
        "realm_id",
        "resources_observed",
        "synth_id",
    }


@pytest.mark.parametrize(
    ("observation", "message"),
    [
        (_observation(release_id="different-release"), "release differs"),
        (
            _observation(health_status="healthy", reason_codes=[]),
            "not in transitional health mode",
        ),
        (_observation(capability_id="owner.summary"), "capability is not enabled"),
    ],
)
def test_commission_fails_closed_on_wrong_transitional_state(
    observation: ManagementObservation,
    message: str,
) -> None:
    with pytest.raises(ManagementContractError, match=message):
        commission(FakeObserver(observation), expected_provider_release_id=RELEASE_ID)


def test_main_emits_only_generic_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        CommissioningConfig,
        "from_environment",
        classmethod(lambda _cls: (_ for _ in ()).throw(ManagementContractError("secret"))),
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "management commissioning failed\n"
