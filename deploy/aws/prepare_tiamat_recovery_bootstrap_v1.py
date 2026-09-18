"""Offline-only builder for a fail-closed Tiamat recovery-anchor bootstrap package."""

from __future__ import annotations

import argparse
import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.recovery_anchor import RecoveryAnchorIdentity
from lucy.shared_execution.recovery_anchor_commissioning import (
    build_quarantined_bootstrap,
    canonical_uuid4,
)


def build_package(
    *,
    root_private_identity: dict[str, object],
    witness_private_identity: dict[str, object],
    environment: str,
    ledger_id: str,
    storage_epoch: str,
    checkpoint: dict[str, object],
    now: datetime,
    validity_hours: int,
) -> dict[str, object]:
    if (
        set(root_private_identity)
        != {
            "format_version",
            "root_key_id",
            "root_private_key_b64",
        }
        or root_private_identity["format_version"] != "1"
    ):
        raise ValueError("recovery root private identity shape is invalid")
    if (
        set(witness_private_identity)
        != {
            "format_version",
            "witness_key_id",
            "witness_private_key_b64",
        }
        or witness_private_identity["format_version"] != "1"
    ):
        raise ValueError("recovery witness private identity shape is invalid")
    root = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(str(root_private_identity["root_private_key_b64"]), validate=True)
    )
    witness = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(str(witness_private_identity["witness_private_key_b64"]), validate=True)
    )
    if root.private_bytes_raw() == witness.private_bytes_raw():
        raise ValueError("recovery root and witness key material must be distinct")
    identity = RecoveryAnchorIdentity(
        environment,
        canonical_uuid4(ledger_id),
        canonical_uuid4(storage_epoch),
    )
    artifacts, _ = build_quarantined_bootstrap(
        identity=identity,
        root_key_id=str(root_private_identity["root_key_id"]),
        root_private_key=root,
        witness_key_id=str(witness_private_identity["witness_key_id"]),
        witness_private_key=witness,
        checkpoint=checkpoint,
        now=now,
        validity=timedelta(hours=validity_hours),
    )
    return artifacts.public_package(identity)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-private-identity", type=Path, required=True)
    parser.add_argument("--witness-private-identity", type=Path, required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--ledger-id", required=True)
    parser.add_argument("--storage-epoch", required=True)
    parser.add_argument(
        "--checkpoint",
        type=Path,
        required=True,
        help="full day-zero checkpoint JSON; hashes are computed and verified locally",
    )
    parser.add_argument("--validity-hours", type=int, default=12)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve().exists():
        raise FileExistsError(f"refusing to overwrite bootstrap package: {args.output.resolve()}")
    package = build_package(
        root_private_identity=json.loads(args.root_private_identity.read_text(encoding="utf-8")),
        witness_private_identity=json.loads(
            args.witness_private_identity.read_text(encoding="utf-8")
        ),
        environment=args.environment,
        ledger_id=args.ledger_id,
        storage_epoch=args.storage_epoch,
        checkpoint=json.loads(args.checkpoint.read_text(encoding="utf-8")),
        now=datetime.now(UTC).replace(microsecond=0),
        validity_hours=args.validity_hours,
    )
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(
        json.dumps(package, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps({"status": "prepared", "transition_sha256": package["transition_sha256"]}))


if __name__ == "__main__":
    main()
