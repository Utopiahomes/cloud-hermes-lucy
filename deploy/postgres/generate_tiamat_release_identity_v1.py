"""Create purpose-distinct offline staging RELEASE root and signing identities.

Run only from a native POSIX checkout. Private output is confined to the ignored
``secrets/generated/tiamat-release`` tree and is never printed.
"""

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
_SECRET_ROOT = _REPOSITORY_ROOT / "secrets" / "generated" / "tiamat-release"


def generate_identities(
    *, root_key_id: str, release_key_id: str
) -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, str]]:
    if not root_key_id or not release_key_id or root_key_id == release_key_id:
        raise ValueError("RELEASE root and signing key IDs must be nonempty and distinct")
    root = Ed25519PrivateKey.generate()
    release = Ed25519PrivateKey.generate()
    if root.private_bytes_raw() == release.private_bytes_raw():
        raise RuntimeError("RELEASE root and signing keys unexpectedly share material")
    return (
        {
            "format_version": "1",
            "root_key_id": root_key_id,
            "root_private_key_b64": base64.b64encode(root.private_bytes_raw()).decode("ascii"),
        },
        {
            "format_version": "1",
            "root_key_id": root_key_id,
            "root_public_key_b64": base64.b64encode(
                root.public_key().public_bytes_raw()
            ).decode("ascii"),
        },
        {
            "format_version": "1",
            "release_key_id": release_key_id,
            "release_private_key_b64": base64.b64encode(
                release.private_bytes_raw()
            ).decode("ascii"),
        },
        {
            "format_version": "1",
            "release_key_id": release_key_id,
            "release_public_key_b64": base64.b64encode(
                release.public_key().public_bytes_raw()
            ).decode("ascii"),
        },
    )


def _private_directory(path: Path) -> None:
    if path.is_symlink():
        raise OSError(f"offline RELEASE path is a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    getuid = getattr(os, "getuid", None)
    if getuid is None or stat.S_IMODE(info.st_mode) & 0o077 or info.st_uid != getuid():
        raise OSError(f"offline RELEASE directory is not private: {path}")


def _write_new(path: Path, value: dict[str, str]) -> None:
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        path.unlink(missing_ok=True)
        raise OSError("offline RELEASE identity file permissions are not private")


def write_identities(
    output_dir: Path,
    identities: tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, str]],
) -> None:
    if os.name == "nt":
        raise OSError("refusing RELEASE key generation on Windows: private DACL unverified")
    resolved = Path(os.path.abspath(output_dir))
    try:
        relative = resolved.relative_to(_SECRET_ROOT)
    except ValueError as exc:
        raise ValueError(f"output must be under {_SECRET_ROOT}") from exc
    if relative == Path("."):
        raise ValueError("use a new ceremony subdirectory under the RELEASE secret root")
    for parent in (_REPOSITORY_ROOT / "secrets", _REPOSITORY_ROOT / "secrets" / "generated"):
        if parent.is_symlink():
            raise OSError(f"offline RELEASE path is a symlink: {parent}")
    _private_directory(_SECRET_ROOT)
    current = _SECRET_ROOT
    for part in relative.parts:
        current = current / part
        _private_directory(current)
    filenames = (
        "root-private.json",
        "root-public.json",
        "release-private.json",
        "release-public.json",
    )
    if any((resolved / name).exists() for name in filenames):
        raise FileExistsError("RELEASE ceremony output already exists")
    written: list[Path] = []
    try:
        for name, identity in zip(filenames, identities, strict=True):
            path = resolved / name
            _write_new(path, identity)
            written.append(path)
    except Exception:
        for path in written:
            path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-key-id", required=True)
    parser.add_argument("--release-key-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    identities = generate_identities(
        root_key_id=args.root_key_id, release_key_id=args.release_key_id
    )
    write_identities(args.output_dir, identities)
    root_public = base64.b64decode(identities[1]["root_public_key_b64"], validate=True)
    release_public = base64.b64decode(identities[3]["release_public_key_b64"], validate=True)
    print(
        json.dumps(
            {
                "status": "created",
                "root_key_id": args.root_key_id,
                "root_public_key_sha256": hashlib.sha256(root_public).hexdigest(),
                "release_key_id": args.release_key_id,
                "release_public_key_sha256": hashlib.sha256(release_public).hexdigest(),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
