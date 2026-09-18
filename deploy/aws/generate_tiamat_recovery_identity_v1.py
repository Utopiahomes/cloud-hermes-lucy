"""Generate purpose-distinct offline Tiamat recovery root and witness identities."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_identities(
    *, root_key_id: str, witness_key_id: str
) -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, str]]:
    if not root_key_id or not witness_key_id or root_key_id == witness_key_id:
        raise ValueError("recovery key identifiers must be nonempty and purpose-distinct")
    root = Ed25519PrivateKey.generate()
    witness = Ed25519PrivateKey.generate()
    root_secret = {
        "format_version": "1",
        "root_key_id": root_key_id,
        "root_private_key_b64": base64.b64encode(root.private_bytes_raw()).decode("ascii"),
    }
    root_public = {
        "format_version": "1",
        "root_key_id": root_key_id,
        "root_public_key_b64": base64.b64encode(root.public_key().public_bytes_raw()).decode(
            "ascii"
        ),
    }
    witness_secret = {
        "format_version": "1",
        "witness_key_id": witness_key_id,
        "witness_private_key_b64": base64.b64encode(witness.private_bytes_raw()).decode("ascii"),
    }
    witness_public = {
        "format_version": "1",
        "witness_key_id": witness_key_id,
        "witness_public_key_b64": base64.b64encode(witness.public_key().public_bytes_raw()).decode(
            "ascii"
        ),
    }
    return root_secret, root_public, witness_secret, witness_public


def write_new(path: Path, payload: object) -> None:
    resolved = path.resolve()
    if resolved.exists():
        raise FileExistsError(f"refusing to overwrite recovery identity file: {resolved}")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    try:
        os.chmod(resolved, 0o600)
    except OSError:
        resolved.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-key-id", required=True)
    parser.add_argument("--witness-key-id", required=True)
    parser.add_argument("--root-private-output", type=Path, required=True)
    parser.add_argument("--root-public-output", type=Path, required=True)
    parser.add_argument("--witness-private-output", type=Path, required=True)
    parser.add_argument("--witness-public-output", type=Path, required=True)
    args = parser.parse_args()
    outputs = {
        args.root_private_output.resolve(),
        args.root_public_output.resolve(),
        args.witness_private_output.resolve(),
        args.witness_public_output.resolve(),
    }
    if len(outputs) != 4:
        raise ValueError("all recovery identity outputs must be distinct")
    root_secret, root_public, witness_secret, witness_public = generate_identities(
        root_key_id=args.root_key_id,
        witness_key_id=args.witness_key_id,
    )
    written: list[Path] = []
    try:
        for path, payload in (
            (args.root_private_output, root_secret),
            (args.root_public_output, root_public),
            (args.witness_private_output, witness_secret),
            (args.witness_public_output, witness_public),
        ):
            write_new(path, payload)
            written.append(path.resolve())
    except Exception:
        for path in written:
            path.unlink(missing_ok=True)
        raise
    canonical_root = json.dumps(root_public, separators=(",", ":"), sort_keys=True).encode("utf-8")
    canonical_witness = json.dumps(witness_public, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    root_public_bytes = base64.b64decode(root_public["root_public_key_b64"], validate=True)
    print(
        json.dumps(
            {
                "status": "created",
                "root_public_identity_sha256": hashlib.sha256(canonical_root).hexdigest(),
                "witness_public_identity_sha256": hashlib.sha256(canonical_witness).hexdigest(),
                "root_public_key_sha256": hashlib.sha256(root_public_bytes).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
