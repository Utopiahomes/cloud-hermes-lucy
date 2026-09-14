"""Validate a private Utopia R1 activation manifest without echoing its values."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import ValidationError

from lucy.activation_manifest import UtopiaActivationManifestV1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        manifest = UtopiaActivationManifestV1.model_validate_json(
            args.manifest.read_text(encoding="utf-8")
        )
    except (OSError, ValidationError, ValueError):
        print(json.dumps({"contract": "lucy.activation-validation.v1", "status": "failed"}))
        return 1
    print(
        json.dumps(
            {
                "contract": "lucy.activation-validation.v1",
                "status": "passed",
                "realm": manifest.realm_slug,
                "capture_enabled": manifest.transcript_capture_enabled,
                "paid_inference_enabled": manifest.paid_inference_enabled,
                "public_hostname_count": len(manifest.ingress.public_hostnames),
                "private_hostname_count": len(manifest.ingress.private_hostnames),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
