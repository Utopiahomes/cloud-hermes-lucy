"""Validate a private Telegram Stage 1 activation manifest without printing identifiers."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from lucy.telegram_activation import TelegramStage1ActivationManifest


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_telegram_stage1_manifest.py <manifest.json>")
    value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    manifest = TelegramStage1ActivationManifest.model_validate(value)
    print(
        json.dumps(
            {
                "contract": manifest.contract,
                "status": "valid",
                "capture_enabled": False,
                "memory_writes_enabled": False,
                "one_active_gateway": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

