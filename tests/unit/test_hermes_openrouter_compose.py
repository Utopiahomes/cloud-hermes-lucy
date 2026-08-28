from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).parents[2]


def test_live_openrouter_smoke_is_explicit_and_secret_free() -> None:
    compose = yaml.safe_load(
        (REPOSITORY_ROOT / "compose.hermes-spike.yaml").read_text(encoding="utf-8")
    )
    service = compose["services"]["hermes-openrouter-smoke"]
    assert service["profiles"] == ["live-openrouter"]
    assert service["image"].endswith(
        "@sha256:3811ed13da874fba2ac99b6d492db9a203d34cb6dccf90d886948c00d0ccec09"
    )
    assert service["environment"] == {
        "OPENROUTER_API_KEY": "${OPENROUTER_API_KEY:?set OPENROUTER_API_KEY outside Git}",
        "LUCY_COMPANION_URL": "http://lucy-api:8080",
        "LUCY_ADAPTER_TOKEN": "${LUCY_ADAPTER_TOKEN:?set LUCY_ADAPTER_TOKEN outside Git}",
    }
    assert "OPENROUTER_API_KEY" not in " ".join(service["command"])
    assert service["command"][-2:] == ["--toolsets", "clarify"]
    assert service["depends_on"] == {
        "hermes-plugin-preflight": {"condition": "service_completed_successfully"},
        "lucy-api": {"condition": "service_healthy"},
    }


def test_openrouter_key_is_withheld_until_plugin_preflight_passes() -> None:
    compose = yaml.safe_load(
        (REPOSITORY_ROOT / "compose.hermes-spike.yaml").read_text(encoding="utf-8")
    )
    preflight = compose["services"]["hermes-plugin-preflight"]
    assert preflight["profiles"] == ["live-openrouter"]
    assert preflight["image"].endswith(
        "@sha256:3811ed13da874fba2ac99b6d492db9a203d34cb6dccf90d886948c00d0ccec09"
    )
    assert preflight["command"] == ["plugins", "doctor", "--ci", "lucy_control"]
    assert "environment" not in preflight
    assert preflight["depends_on"] == {
        "hermes-profile-seed": {"condition": "service_completed_successfully"}
    }
