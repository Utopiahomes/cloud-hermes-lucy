"""Validate fail-closed Telegram gateway environment without printing secrets."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping

_BOT_TOKEN = re.compile(r"^\d+:[A-Za-z0-9_-]{30,}$")
_USER_ID = re.compile(r"^\d+$")


def validate(environment: Mapping[str, str]) -> None:
    openrouter_key = environment.get("OPENROUTER_API_KEY", "").strip()
    adapter_token = environment.get("LUCY_ADAPTER_TOKEN", "").strip()
    token = environment.get("TELEGRAM_BOT_TOKEN", "").strip()
    allowed_raw = environment.get("TELEGRAM_ALLOWED_USERS", "").strip()
    home = environment.get("TELEGRAM_HOME_CHANNEL", "").strip()

    if not openrouter_key or openrouter_key.startswith("replace-with-"):
        raise ValueError("OPENROUTER_API_KEY is not configured")
    if len(adapter_token) < 16 or adapter_token.startswith("replace-with-"):
        raise ValueError("LUCY_ADAPTER_TOKEN is not configured")
    if not _BOT_TOKEN.fullmatch(token):
        raise ValueError("TELEGRAM_BOT_TOKEN is missing or malformed")

    allowed = [item.strip() for item in allowed_raw.split(",") if item.strip()]
    if not allowed or any(not _USER_ID.fullmatch(item) for item in allowed):
        raise ValueError("TELEGRAM_ALLOWED_USERS must contain numeric IDs only")
    if len(allowed) != len(set(allowed)):
        raise ValueError("TELEGRAM_ALLOWED_USERS contains duplicate IDs")
    if not _USER_ID.fullmatch(home) or home not in allowed:
        raise ValueError("TELEGRAM_HOME_CHANNEL must be one of the allowed IDs")


if __name__ == "__main__":
    validate(os.environ)
    print("Telegram credential shape and explicit allowlist validated.")
