from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).parents[2]
PREFLIGHT_PATH = REPOSITORY_ROOT / "deploy" / "hermes" / "telegram_preflight.py"


def _load_preflight() -> ModuleType:
    spec = importlib.util.spec_from_file_location("telegram_preflight", PREFLIGHT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _valid_environment() -> dict[str, str]:
    return {
        "OPENROUTER_API_KEY": "synthetic-openrouter-key-for-validation",
        "LUCY_ADAPTER_TOKEN": "synthetic-adapter-token",
        "TELEGRAM_BOT_TOKEN": "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdef",
        "TELEGRAM_ALLOWED_USERS": "123456789",
        "TELEGRAM_HOME_CHANNEL": "123456789",
    }


def test_telegram_preflight_requires_explicit_numeric_owner() -> None:
    preflight = _load_preflight()
    preflight.validate(_valid_environment())

    invalid = [
        {},
        {**_valid_environment(), "TELEGRAM_ALLOWED_USERS": ""},
        {**_valid_environment(), "TELEGRAM_ALLOWED_USERS": "*"},
        {**_valid_environment(), "TELEGRAM_ALLOWED_USERS": "@owner"},
        {**_valid_environment(), "TELEGRAM_HOME_CHANNEL": "987654321"},
        {**_valid_environment(), "OPENROUTER_API_KEY": ""},
        {**_valid_environment(), "LUCY_ADAPTER_TOKEN": "short"},
    ]
    for environment in invalid:
        with pytest.raises(ValueError):
            preflight.validate(environment)


def test_gateway_waits_for_keyless_plugin_and_telegram_preflights() -> None:
    compose = yaml.safe_load(
        (REPOSITORY_ROOT / "compose.hermes-spike.yaml").read_text(encoding="utf-8")
    )
    services = compose["services"]
    gateway = services["hermes-telegram-gateway"]
    telegram_preflight = services["hermes-telegram-preflight"]
    plugin_preflight = services["hermes-plugin-preflight"]

    assert gateway["profiles"] == ["live-telegram"]
    assert gateway["command"] == ["gateway", "run"]
    assert gateway["depends_on"] == {
        "hermes-plugin-preflight": {"condition": "service_completed_successfully"},
        "hermes-telegram-preflight": {"condition": "service_completed_successfully"},
        "lucy-api": {"condition": "service_healthy"},
    }
    assert telegram_preflight["depends_on"] == {
        "hermes-plugin-preflight": {"condition": "service_completed_successfully"}
    }
    assert "OPENROUTER_API_KEY" in telegram_preflight["environment"]
    assert "environment" not in plugin_preflight
    assert "live-telegram" in plugin_preflight["profiles"]
    assert gateway["restart"] == "unless-stopped"
