"""Offline-only signer for the two reconciliation anchor steps (Draft 0.5 section 7, steps 5, 7).

``pending`` signs quarantined -> recovery_pending: a reconciled witness for the reviewed
checkpoint's generation, under a successor witness inventory for a fresh witness key.
``established`` signs recovery_pending -> continuity_established: the same witness, byte for
byte, plus the continuity beacon read from the ledger after the checkpoint was bound.

This command has no AWS or database client and never creates a root key. It emits a public
package for separate review and an explicitly confirmed install through the M4 writer, and, for
``established``, the launcher's anchor trust file. Private key material cannot enter either.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.recovery_anchor import PostgresContinuityBeacon, RecoveryAnchorIdentity
from lucy.shared_execution.recovery_anchor_commissioning import canonical_uuid4
from lucy.shared_execution.recovery_anchor_reconciliation import (
    AnchorHead,
    build_continuity_established,
    build_recovery_pending,
    verify_reconciliation_package,
)
from lucy.shared_execution.recovery_checkpoint import construct_recovery_checkpoint


def _read_identity(value: dict[str, object], kind: str) -> tuple[str, Ed25519PrivateKey]:
    fields = {"format_version", f"{kind}_key_id", f"{kind}_private_key_b64"}
    if set(value) != fields or value["format_version"] != "1":
        raise ValueError(f"{kind} private identity shape is invalid")
    return (
        str(value[f"{kind}_key_id"]),
        Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(str(value[f"{kind}_private_key_b64"]), validate=True)
        ),
    )


def _root_matches(root: Ed25519PrivateKey, expected_root_public_sha256: str) -> None:
    observed = hashlib.sha256(root.public_key().public_bytes_raw()).hexdigest()
    if observed != expected_root_public_sha256:
        raise ValueError("root signer does not match the pinned root")


def _no_private(document: dict[str, object]) -> dict[str, object]:
    if "private" in json.dumps(document, sort_keys=True).lower():
        raise RuntimeError("private material entered a public reconciliation document")
    return document


def build_pending_package(
    *,
    head_package: dict[str, object],
    checkpoint: dict[str, object],
    root_private_identity: dict[str, object],
    witness_private_identity: dict[str, object],
    expected_root_public_sha256: str,
    now: datetime,
    validity_hours: int = 12,
) -> dict[str, object]:
    """Sign the pending step from the published package of the current quarantined head.

    Any published package naming the head's ``transition_jws_b64``, ``witness_jws_b64``,
    ``inventory_jws_b64`` and ``witness_key_id`` serves: the bootstrap or a continued-quarantine
    successor. The head is re-verified against the pinned root before anything is signed.
    """

    root_key_id, root = _read_identity(root_private_identity, "root")
    _root_matches(root, expected_root_public_sha256)
    if root_key_id != head_package.get("root_key_id"):
        raise ValueError("root signer does not match the head package")
    witness_key_id, witness = _read_identity(witness_private_identity, "witness")
    identity = RecoveryAnchorIdentity(
        str(head_package["environment"]),
        canonical_uuid4(str(head_package["ledger_id"])),
        canonical_uuid4(str(head_package["storage_epoch"])),
    )
    head = AnchorHead(
        transition_jws=base64.b64decode(str(head_package["transition_jws_b64"]), validate=True),
        witness_jws=base64.b64decode(str(head_package["witness_jws_b64"]), validate=True),
        inventory_jws=base64.b64decode(str(head_package["inventory_jws_b64"]), validate=True),
        witness_key_id=str(head_package["witness_key_id"]),
    )
    step, _ = build_recovery_pending(
        head=head,
        identity=identity,
        root_key_id=root_key_id,
        root_private_key=root,
        witness_key_id=witness_key_id,
        witness_private_key=witness,
        checkpoint=construct_recovery_checkpoint(checkpoint, identity=identity),
        now=now,
        validity=timedelta(hours=validity_hours),
    )
    return _no_private(step.public_package())


def build_established_package(
    *,
    pending_package: dict[str, object],
    beacon: dict[str, object],
    root_private_identity: dict[str, object],
    expected_root_public_sha256: str,
    now: datetime,
) -> tuple[dict[str, object], dict[str, object]]:
    """Sign the established step; return its package and the launcher's anchor trust file."""

    root_key_id, root = _read_identity(root_private_identity, "root")
    _root_matches(root, expected_root_public_sha256)
    pending = verify_reconciliation_package(
        pending_package,
        now=now,
        expected_root_public_sha256=expected_root_public_sha256,
        expected_ceremony="recovery_pending",
    ).step
    if root_key_id != pending.root_key_id:
        raise ValueError("root signer does not match the pending package")
    if set(beacon) != {"system_identifier", "timeline_id", "flushed_wal_lsn", "checkpoint_digest"}:
        raise ValueError("continuity beacon shape is invalid")
    timeline = beacon["timeline_id"]
    if not isinstance(timeline, int) or isinstance(timeline, bool):
        raise ValueError("continuity beacon timeline is invalid")
    step, _ = build_continuity_established(
        pending=pending,
        root_private_key=root,
        beacon=PostgresContinuityBeacon(
            str(beacon["system_identifier"]),
            timeline,
            str(beacon["flushed_wal_lsn"]),
            str(beacon["checkpoint_digest"]),
        ),
        now=now,
    )
    return _no_private(step.public_package()), _no_private(step.trust_document())


def _write_new(path: Path, document: dict[str, object]) -> None:
    target = path.resolve()
    if target.exists():
        raise FileExistsError(f"refusing to overwrite: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="ceremony", required=True)
    pending = commands.add_parser("pending")
    pending.add_argument("--head-package", type=Path, required=True)
    pending.add_argument("--checkpoint", type=Path, required=True)
    pending.add_argument("--witness-private-identity", type=Path, required=True)
    pending.add_argument("--validity-hours", type=int, default=12)
    established = commands.add_parser("established")
    established.add_argument("--pending-package", type=Path, required=True)
    established.add_argument("--beacon", type=Path, required=True)
    established.add_argument("--trust-output", type=Path, required=True)
    for command in (pending, established):
        command.add_argument("--root-private-identity", type=Path, required=True)
        command.add_argument("--expected-root-public-sha256", required=True)
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    now = datetime.now(UTC).replace(microsecond=0)
    if args.ceremony == "pending":
        package = build_pending_package(
            head_package=_json(args.head_package),
            checkpoint=_json(args.checkpoint),
            root_private_identity=_json(args.root_private_identity),
            witness_private_identity=_json(args.witness_private_identity),
            expected_root_public_sha256=args.expected_root_public_sha256,
            now=now,
            validity_hours=args.validity_hours,
        )
        _write_new(args.output, package)
    else:
        package, trust = build_established_package(
            pending_package=_json(args.pending_package),
            beacon=_json(args.beacon),
            root_private_identity=_json(args.root_private_identity),
            expected_root_public_sha256=args.expected_root_public_sha256,
            now=now,
        )
        _write_new(args.output, package)
        _write_new(args.trust_output, trust)
    print(
        json.dumps(
            {
                "status": f"prepared_{package['ceremony']}",
                "head_transition_sha256": package["head_transition_sha256"],
                "transition_sha256": package["transition_sha256"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
