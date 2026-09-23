"""Verify a decrypted RELEASE custody archive from stdin without writing plaintext files."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import tarfile
from typing import BinaryIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_NAMES = (
    "root-private.json",
    "root-public.json",
    "release-private.json",
    "release-public.json",
)


def verify_archive(
    stream: BinaryIO,
    *,
    ceremony_dir: str,
    expected_root_id: str,
    expected_root_sha256: str,
    expected_release_id: str,
    expected_release_sha256: str,
) -> None:
    if not ceremony_dir or "/" in ceremony_dir or ceremony_dir in {".", ".."}:
        raise ValueError("invalid ceremony directory")
    expected_names = {f"{ceremony_dir}/{name}" for name in _NAMES}
    items: dict[str, dict[str, str]] = {}
    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for member in archive:
            if member.name == ceremony_dir and member.isdir():
                continue
            if member.name not in expected_names or not member.isfile() or member.size > 4096:
                raise ValueError("backup contains an unexpected member")
            if member.name in items:
                raise ValueError("backup contains a duplicate member")
            member_file = archive.extractfile(member)
            if member_file is None:
                raise ValueError("backup member cannot be read")
            value = json.loads(member_file.read(4097))
            if not isinstance(value, dict) or not all(
                isinstance(key, str) and isinstance(item, str) for key, item in value.items()
            ):
                raise ValueError("backup identity shape is invalid")
            items[member.name] = value
    if set(items) != expected_names:
        raise ValueError("backup is incomplete")

    for name, purpose, expected_id, expected_sha256 in (
        ("root", "root", expected_root_id, expected_root_sha256),
        ("release", "release", expected_release_id, expected_release_sha256),
    ):
        private = items[f"{ceremony_dir}/{name}-private.json"]
        public = items[f"{ceremony_dir}/{name}-public.json"]
        id_field = "root_key_id" if purpose == "root" else "release_key_id"
        private_field = "root_private_key_b64" if purpose == "root" else "release_private_key_b64"
        public_field = "root_public_key_b64" if purpose == "root" else "release_public_key_b64"
        if (
            set(private) != {"format_version", id_field, private_field}
            or set(public) != {"format_version", id_field, public_field}
            or private["format_version"] != "1"
            or public["format_version"] != "1"
            or private[id_field] != expected_id
            or public[id_field] != expected_id
        ):
            raise ValueError("backup identity metadata does not match")
        private_raw = base64.b64decode(private[private_field], validate=True)
        public_raw = base64.b64decode(public[public_field], validate=True)
        derived = Ed25519PrivateKey.from_private_bytes(private_raw).public_key().public_bytes_raw()
        if derived != public_raw or hashlib.sha256(derived).hexdigest() != expected_sha256:
            raise ValueError("backup key or approved fingerprint does not match")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ceremony-dir", required=True)
    parser.add_argument("--expected-root-id", required=True)
    parser.add_argument("--expected-root-sha256", required=True)
    parser.add_argument("--expected-release-id", required=True)
    parser.add_argument("--expected-release-sha256", required=True)
    args = parser.parse_args()
    verify_archive(
        sys.stdin.buffer,
        ceremony_dir=args.ceremony_dir,
        expected_root_id=args.expected_root_id,
        expected_root_sha256=args.expected_root_sha256,
        expected_release_id=args.expected_release_id,
        expected_release_sha256=args.expected_release_sha256,
    )
    print("USB restore test passed: both RELEASE identities and public fingerprints match")


if __name__ == "__main__":
    main()
