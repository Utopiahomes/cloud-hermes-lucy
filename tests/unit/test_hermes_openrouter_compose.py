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
        "OPENROUTER_API_KEY": "${OPENROUTER_API_KEY:?set OPENROUTER_API_KEY outside Git}"
    }
    assert "OPENROUTER_API_KEY" not in " ".join(service["command"])
    assert service["command"][-2:] == ["--toolsets", "clarify"]
    assert service["depends_on"] == {
        "hermes-profile-seed": {"condition": "service_completed_successfully"}
    }
