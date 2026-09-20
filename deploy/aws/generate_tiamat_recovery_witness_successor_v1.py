"""Generate only a fresh offline witness identity for a quarantined anchor successor."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from generate_tiamat_recovery_identity_v1 import write_new


def generate_witness_identity(*, witness_key_id: str) -> tuple[dict[str, str], dict[str, str]]:
    if not witness_key_id or not witness_key_id.startswith("tiamat-recovery-witness."):
        raise ValueError("replacement witness key identifier is invalid")
    witness = Ed25519PrivateKey.generate()
    return (
        {
            "format_version": "1",
            "witness_key_id": witness_key_id,
            "witness_private_key_b64": base64.b64encode(witness.private_bytes_raw()).decode(
                "ascii"
            ),
        },
        {
            "format_version": "1",
            "witness_key_id": witness_key_id,
            "witness_public_key_b64": base64.b64encode(
                witness.public_key().public_bytes_raw()
            ).decode("ascii"),
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--witness-key-id", required=True)
    parser.add_argument("--witness-private-output", type=Path, required=True)
    parser.add_argument("--witness-public-output", type=Path, required=True)
    args = parser.parse_args()
    if args.witness_private_output.resolve() == args.witness_public_output.resolve():
        raise ValueError("replacement witness outputs must be distinct")
    secret, public = generate_witness_identity(witness_key_id=args.witness_key_id)
    write_new(args.witness_private_output, secret)
    try:
        write_new(args.witness_public_output, public)
    except Exception:
        args.witness_private_output.resolve().unlink(missing_ok=True)
        raise
    public_bytes = base64.b64decode(public["witness_public_key_b64"], validate=True)
    print(
        json.dumps(
            {
                "status": "created_witness_only",
                "witness_key_id": args.witness_key_id,
                "witness_public_key_sha256": hashlib.sha256(public_bytes).hexdigest(),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
