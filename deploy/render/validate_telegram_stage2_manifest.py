"""Validate private Telegram Stage 2 without printing identifiers."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from lucy.telegram_activation import TelegramStage2ActivationManifest


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_telegram_stage2_manifest.py MANIFEST")
    value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    manifest = TelegramStage2ActivationManifest.model_validate(value)
    print(
        json.dumps(
            {
                "contract": manifest.contract,
                "status": "valid",
                "capture_enabled": True,
                "two_message_commit": True,
                "off_record_history_rotation": True,
                "memory_writes_enabled": False,
                "sensitive_gateway_tools_enabled": False,
                "one_active_gateway": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
