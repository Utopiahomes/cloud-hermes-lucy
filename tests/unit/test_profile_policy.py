from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).parents[2]
PROFILE_ROOT = REPOSITORY_ROOT / "profiles" / "lucy"


def test_profile_has_fail_closed_tool_surface() -> None:
    config = yaml.safe_load((PROFILE_ROOT / "config.yaml").read_text(encoding="utf-8"))
    assert config["_config_version"] == 38
    assert config["toolsets"] == ["clarify"]
    assert config["platform_toolsets"] == {"cli": ["clarify"], "telegram": ["clarify"]}
    assert config["known_plugin_toolsets"] == {
        "cli": ["a2a", "spotify"],
        "telegram": ["a2a", "spotify"],
    }
    known = config["known_builtin_toolsets"]
    assert known["cli"] == known["telegram"]
    assert "bfl" in known["cli"]
    assert "terminal" in known["cli"]
    assert "file" in known["cli"]
    assert "memory" in known["cli"]
    assert config["approvals"]["mode"] == "manual"
    assert config["approvals"]["cron_mode"] == "deny"
    assert config["approvals"]["denial_breaker_threshold"] == 3
    assert config["security"]["allow_lazy_installs"] is False
    assert config["unauthorized_dm_behavior"] == "ignore"
    assert config["command_allowlist"] == []


def test_profile_opts_out_of_all_bundled_skills() -> None:
    assert (PROFILE_ROOT / ".no-bundled-skills").is_file()
    local_skills = sorted(path.name for path in (PROFILE_ROOT / "skills").iterdir())
    assert local_skills == ["lucy-memory"]
