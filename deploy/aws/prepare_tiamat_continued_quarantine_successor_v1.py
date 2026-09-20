"""Offline-only builder for a 24-hour, quarantine-only Tiamat anchor successor.

This command intentionally has no AWS client and never creates a root key.  It consumes the
existing root signer plus a fresh witness signer offline, and emits a public package for separate
review and an explicitly confirmed conditional installation.
"""

from __future__ import annotations

import argparse
import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.recovery_anchor_commissioning import (
    RecoveryBootstrapArtifacts,
    build_continued_quarantine_successor,
    verify_bootstrap_package,
)
from lucy.shared_execution.recovery_checkpoint import construct_recovery_checkpoint


def _read_root_identity(value: dict[str, object]) -> tuple[str, Ed25519PrivateKey]:
    if set(value) != {"format_version", "root_key_id", "root_private_key_b64"}:
        raise ValueError("recovery root private identity shape is invalid")
    if value["format_version"] != "1":
        raise ValueError("recovery root private identity version is invalid")
    return (
        str(value["root_key_id"]),
        Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(str(value["root_private_key_b64"]), validate=True)
        ),
    )


def _read_witness_identity(value: dict[str, object]) -> tuple[str, Ed25519PrivateKey]:
    if set(value) != {"format_version", "witness_key_id", "witness_private_key_b64"}:
        raise ValueError("replacement witness private identity shape is invalid")
    if value["format_version"] != "1":
        raise ValueError("replacement witness private identity version is invalid")
    return (
        str(value["witness_key_id"]),
        Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(str(value["witness_private_key_b64"]), validate=True)
        ),
    )


def _parse_timestamp(value: str) -> datetime:
    try:
        if len(value) != 20 or not value.endswith("Z"):
            raise ValueError
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ValueError("predecessor verification timestamp is invalid") from exc


def build_package(
    *,
    predecessor_package: dict[str, object],
    root_private_identity: dict[str, object],
    replacement_witness_private_identity: dict[str, object],
    predecessor_verified_at: datetime,
    now: datetime,
    validity_hours: int = 24,
) -> dict[str, object]:
    """Construct a reviewable public candidate; private bytes cannot enter the result."""

    root_key_id, root = _read_root_identity(root_private_identity)
    predecessor_identity, _ = verify_bootstrap_package(
        predecessor_package,
        now=predecessor_verified_at,
        expected_root_public_sha256=str(predecessor_package["root_public_key_sha256"]),
    )
    if root_key_id != predecessor_package["root_key_id"]:
        raise ValueError("root signer does not match the pinned predecessor")
    checkpoint_raw = predecessor_package["checkpoint"]
    if not isinstance(checkpoint_raw, dict):
        raise ValueError("predecessor checkpoint is invalid")
    predecessor = RecoveryBootstrapArtifacts(
        root_key_id=root_key_id,
        root_public_key_b64=str(predecessor_package["root_public_key_b64"]),
        witness_key_id=str(predecessor_package["witness_key_id"]),
        inventory_jws=base64.b64decode(
            str(predecessor_package["inventory_jws_b64"]), validate=True
        ),
        witness_jws=base64.b64decode(str(predecessor_package["witness_jws_b64"]), validate=True),
        transition_jws=base64.b64decode(
            str(predecessor_package["transition_jws_b64"]), validate=True
        ),
        checkpoint=construct_recovery_checkpoint(checkpoint_raw, identity=predecessor_identity),
    )
    witness_key_id, witness = _read_witness_identity(replacement_witness_private_identity)
    artifacts, _ = build_continued_quarantine_successor(
        predecessor=predecessor,
        identity=predecessor_identity,
        root_private_key=root,
        witness_key_id=witness_key_id,
        witness_private_key=witness,
        predecessor_verified_at=predecessor_verified_at,
        now=now,
        validity=timedelta(hours=validity_hours),
    )
    package = artifacts.public_package(predecessor_identity)
    if "private" in json.dumps(package, sort_keys=True).lower():
        raise RuntimeError("private material entered continued quarantine package")
    return package


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predecessor-package", type=Path, required=True)
    parser.add_argument("--root-private-identity", type=Path, required=True)
    parser.add_argument("--replacement-witness-private-identity", type=Path, required=True)
    parser.add_argument("--predecessor-verified-at", required=True)
    parser.add_argument("--validity-hours", type=int, default=24)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve().exists():
        raise FileExistsError(f"refusing to overwrite successor package: {args.output.resolve()}")
    package = build_package(
        predecessor_package=json.loads(args.predecessor_package.read_text(encoding="utf-8")),
        root_private_identity=json.loads(args.root_private_identity.read_text(encoding="utf-8")),
        replacement_witness_private_identity=json.loads(
            args.replacement_witness_private_identity.read_text(encoding="utf-8")
        ),
        predecessor_verified_at=_parse_timestamp(args.predecessor_verified_at),
        now=datetime.now(UTC).replace(microsecond=0),
        validity_hours=args.validity_hours,
    )
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(
        json.dumps(package, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        json.dumps(
            {
                "status": "prepared_quarantine_successor",
                "transition_sha256": package["transition_sha256"],
                "predecessor_transition_sha256": package["predecessor_transition_sha256"],
                "continuity": "quarantined",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
