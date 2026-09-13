"""Validate a model-backed Public Lucy release manifest without echoing its values."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import ValidationError

from lucy.public_model_activation import UtopiaPublicModelActivationManifestV2


def validate(path: Path) -> dict[str, object]:
    try:
        manifest = UtopiaPublicModelActivationManifestV2.model_validate_json(
            path.read_text(encoding="utf-8")
        )
    except (OSError, ValidationError, ValueError):
        return {"contract": "lucy.public-model-activation-validation.v2", "status": "failed"}
    return {
        "contract": "lucy.public-model-activation-validation.v2",
        "status": "passed",
        "release_state": manifest.release_state,
        "model_traffic_enabled": manifest.model_traffic_enabled,
        "cost_policy_enabled": manifest.cost_policy.kill_state == "enabled",
        "capture_enabled": manifest.transcript_capture_enabled,
        "model_snapshot_count": len(manifest.publication.model_allowed_snapshot_sha256),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    result = validate(args.manifest)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
