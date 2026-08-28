from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).parents[2]
PROFILE_ROOT = REPOSITORY_ROOT / "profiles" / "lucy"


def test_profile_has_fail_closed_tool_surface() -> None:
    config = yaml.safe_load((PROFILE_ROOT / "config.yaml").read_text(encoding="utf-8"))
    assert config["_config_version"] == 38
    assert config["toolsets"] == ["clarify", "lucy_memory"]
    assert config["platform_toolsets"] == {
        "cli": ["clarify", "lucy_memory"],
        "telegram": ["clarify", "lucy_memory"],
    }
    assert config["known_plugin_toolsets"] == {
        "cli": ["a2a", "lucy_memory", "spotify"],
        "telegram": ["a2a", "lucy_memory", "spotify"],
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


def test_profile_routes_openrouter_through_bounded_policy() -> None:
    config = yaml.safe_load((PROFILE_ROOT / "config.yaml").read_text(encoding="utf-8"))
    assert config["model"] == {
        "provider": "custom:lucy-openrouter",
        "default": "openai/gpt-oss-20b",
    }
    assert config["fallback_providers"] == []
    provider = config["providers"]["lucy-openrouter"]
    assert provider["api"] == "https://openrouter.ai/api/v1"
    assert provider["key_env"] == "OPENROUTER_API_KEY"
    assert "api_key" not in provider
    assert provider["discover_models"] is False
    assert list(provider["models"]) == ["openai/gpt-oss-20b"]
    routing = provider["extra_body"]["provider"]
    assert routing == {
        "zdr": True,
        "data_collection": "deny",
        "sort": "price",
        "require_parameters": True,
        "max_price": {"prompt": 0.10, "completion": 0.50},
    }
    assert config["openrouter"]["response_cache"] is False
    assert config["provider_routing"] == {
        "sort": "price",
        "require_parameters": True,
        "data_collection": "deny",
    }


def test_profile_bounds_primary_and_automatic_auxiliary_calls() -> None:
    config = yaml.safe_load((PROFILE_ROOT / "config.yaml").read_text(encoding="utf-8"))
    assert config["agent"] == {
        "max_turns": 4,
        "run_budget_seconds": 120,
        "api_max_retries": 1,
        "reasoning_effort": "low",
    }
    limits = config["model_overrides"]["custom:lucy-openrouter"][
        "openai/gpt-oss-20b"
    ]
    assert limits["context_window"] == 16384
    assert limits["max_output_tokens"] == 1024
    auxiliary = config["auxiliary"]
    assert auxiliary["transient_retries"] == 0
    assert auxiliary["free_only"] is True
    assert auxiliary["compression"]["extra_body"]["provider"] == config["providers"][
        "lucy-openrouter"
    ]["extra_body"]["provider"]
    assert auxiliary["title_generation"]["enabled"] is False
    assert auxiliary["background_review"]["enabled"] is False
    assert config["plugins"] == {"enabled": ["lucy_control"]}
    plugin = PROFILE_ROOT / "plugins" / "lucy_control"
    assert (plugin / "plugin.yaml").is_file()
    assert (plugin / "__init__.py").is_file()
    manifest = yaml.safe_load((plugin / "plugin.yaml").read_text(encoding="utf-8"))
    assert manifest["version"] == "1.1.0"
    assert manifest["provides_tools"] == [
        "lucy_memory_lookup",
        "lucy_memory_propose",
    ]
