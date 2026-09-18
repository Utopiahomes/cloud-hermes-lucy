"""Generate purpose-distinct offline Tiamat recovery root and witness identities."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_RECOVERY_SECRET_ROOT = (_REPOSITORY_ROOT / "secrets" / "generated" / "tiamat-recovery").resolve()


def generate_identities(
    *, root_key_id: str, witness_key_id: str
) -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, str]]:
    if not root_key_id or not witness_key_id or root_key_id == witness_key_id:
        raise ValueError("recovery key identifiers must be nonempty and purpose-distinct")
    root = Ed25519PrivateKey.generate()
    witness = Ed25519PrivateKey.generate()
    if root.private_bytes_raw() == witness.private_bytes_raw():  # defensive, must never share power
        raise RuntimeError("generated recovery root and witness keys are unexpectedly identical")
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
    if os.name == "nt":
        raise OSError(
            "refusing recovery key generation on Windows: this tool cannot verify a private DACL"
        )
    try:
        resolved.relative_to(_RECOVERY_SECRET_ROOT)
    except ValueError as exc:
        raise ValueError(
            f"recovery identity output must remain beneath {_RECOVERY_SECRET_ROOT}"
        ) from exc
    _ensure_private_directory(_RECOVERY_SECRET_ROOT)
    parent = resolved.parent
    while parent != _RECOVERY_SECRET_ROOT:
        _ensure_private_directory(parent)
        parent = parent.parent
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(str(resolved), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
    except Exception:
        resolved.unlink(missing_ok=True)
        raise
    mode = stat.S_IMODE(resolved.stat().st_mode)
    if mode != 0o600:
        resolved.unlink(missing_ok=True)
        raise OSError("recovery identity file permission verification failed")


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise OSError(f"recovery identity directory is not private: {path}")
    getuid = getattr(os, "getuid", None)
    if getuid is None or path.stat().st_uid != getuid():
        raise OSError(f"recovery identity directory owner is invalid: {path}")


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
