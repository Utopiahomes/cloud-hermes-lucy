"""Recovery-login operations on one Tiamat ledger for the reconciliation ceremony.

Reads ``TIAMAT_RECOVERY_DATABASE_URL``; it must never be given to a serving process.

- ``readback``: read-only and schema-tolerant: the migration revision, which tables and gate
  columns exist, this login's privileges, per-environment counts, inventories and the beacon.
  Safe on a ledger at any schema revision; run it first on any ledger not provisioned by this
  checklist.
- ``report``: read-only, content-free state (gate, identity, inventories, retained checkpoints,
  history counts, continuity beacon). With ``--checkpoint-generation`` it also emits the
  empty-ledger checkpoint for that generation, and refuses a ledger with any history.
- ``beacon``: read-only; the continuity beacon bound to the checkpoint retained for the gate's
  current, open generation, for signing ``continuity_established``.
- ``first-inventory``: the one-time install of the first RELEASE trust inventory while dispatch
  stays blocked. The release root is authenticated by ``--release-root-pin``, a committed,
  separately reviewed record of the fingerprint Control approved; a digest computed from the
  supplied key is never the authority. Previews by default; ``--execute`` needs
  ``--confirm-jws-sha256``.
- ``authorize``: Draft 0.5 section 7 step 6. Strong-reads the external anchor and requires its
  head to be exactly the verified pending step, then authorizes the generation jump. Previews by
  default; ``--execute`` needs the target generation and checkpoint digest confirmed.
- ``create-partition``: after authorization, one empty, blocked spending partition for a signed
  grant to be activated onto. Previews by default; ``--execute`` needs the partition confirmed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lucy.shared_execution.recovery import (
    authorize_recovery_generation,
    create_spending_partition,
    install_first_release_inventory,
)
from lucy.shared_execution.recovery_anchor import PostgresContinuityBeaconReader
from lucy.shared_execution.recovery_anchor_dynamodb import (
    dynamodb_recovery_anchor_from_environment,
)
from lucy.shared_execution.recovery_anchor_reconciliation import verify_reconciliation_package
from lucy.shared_execution.recovery_ledger_report import (
    empty_ledger_checkpoint,
    read_ledger_recovery_state,
    read_ledger_schema_readback,
)
from lucy.shared_execution.signed_releases import verify_trust_inventory


def _database_url() -> str:
    value = os.environ.get("TIAMAT_RECOVERY_DATABASE_URL", "")
    if not value:
        raise ValueError("TIAMAT_RECOVERY_DATABASE_URL is required")
    return value


def bound_checkpoint_beacon(database_url: str, *, environment: str) -> dict[str, object]:
    """The beacon for the checkpoint retained at the gate's current generation, once open."""

    with psycopg.connect(database_url) as connection, connection.transaction():
        connection.execute("SET TRANSACTION READ ONLY")
        row = connection.execute(
            """
            SELECT gate.dispatch_blocked, bound.checkpoint_sha256
            FROM tiamat.restore_gate AS gate
            LEFT JOIN tiamat.recovery_checkpoints AS bound
              ON bound.environment = gate.environment
             AND bound.recovery_generation = gate.recovery_generation
            WHERE gate.environment = %s
            """,
            (environment,),
        ).fetchone()
    if row is None or row[1] is None:
        raise ValueError("no checkpoint is bound at the gate's current generation")
    if bool(row[0]):
        raise ValueError("the gate is blocked: the checkpoint is not authorized")
    beacon = PostgresContinuityBeaconReader(database_url).read(checkpoint_digest=str(row[1]))
    return {
        "system_identifier": beacon.system_identifier,
        "timeline_id": beacon.timeline_id,
        "flushed_wal_lsn": beacon.flushed_wal_lsn,
        "checkpoint_digest": beacon.checkpoint_digest,
    }


def release_root_from_pin(
    pin: dict[str, object], *, environment: str, root_key_id: str, public_key_b64: str
) -> Ed25519PublicKey:
    """Authenticate the supplied release root key against the approved, committed pin.

    The pin names the environment, the root key ID and the SHA-256 fingerprint Control approved.
    The key's own digest is computed only to compare with that independent fingerprint.
    """

    if not isinstance(pin, dict) or set(pin) != {
        "format_version",
        "environment",
        "root_key_id",
        "root_public_key_sha256",
    }:
        raise ValueError("release root pin shape is invalid")
    if (
        pin["format_version"] != "1"
        or pin["environment"] != environment
        or pin["root_key_id"] != root_key_id
    ):
        raise ValueError("release root pin does not name this environment and root key")
    raw = base64.b64decode(public_key_b64, validate=True)
    if hashlib.sha256(raw).hexdigest() != pin["root_public_key_sha256"]:
        raise ValueError("release root public key does not match the approved pin")
    return Ed25519PublicKey.from_public_bytes(raw)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    readback = commands.add_parser("readback")
    report = commands.add_parser("report")
    report.add_argument("--checkpoint-generation", type=int)
    commands.add_parser("beacon")
    first = commands.add_parser("first-inventory")
    first.add_argument("--expected-ledger-id", type=UUID, required=True)
    first.add_argument("--expected-storage-epoch", type=UUID, required=True)
    first.add_argument("--expected-recovery-generation", type=int, required=True)
    first.add_argument("--inventory-jws-file", type=Path, required=True)
    first.add_argument("--release-root-key-id", required=True)
    first.add_argument("--release-root-public-key-b64", required=True)
    first.add_argument(
        "--release-root-pin",
        type=Path,
        required=True,
        help="committed, reviewed JSON naming the approved release root fingerprint",
    )
    first.add_argument("--execute", action="store_true")
    first.add_argument("--confirm-jws-sha256")
    authorize = commands.add_parser("authorize")
    authorize.add_argument("--pending-package", type=Path, required=True)
    authorize.add_argument("--expected-root-public-sha256", required=True)
    authorize.add_argument("--source-recovery-generation", type=int, required=True)
    authorize.add_argument("--execute", action="store_true")
    authorize.add_argument("--confirm-target-generation", type=int)
    authorize.add_argument("--confirm-checkpoint-sha256")
    partition = commands.add_parser("create-partition")
    partition.add_argument("--expected-ledger-id", type=UUID, required=True)
    partition.add_argument("--expected-storage-epoch", type=UUID, required=True)
    partition.add_argument("--expected-recovery-generation", type=int, required=True)
    partition.add_argument("--caller-id", required=True)
    partition.add_argument("--realm", required=True)
    partition.add_argument("--partition-id", required=True)
    partition.add_argument("--execute", action="store_true")
    partition.add_argument("--confirm-partition-id")
    for command in (readback, report, commands.choices["beacon"], first, authorize, partition):
        command.add_argument("--environment", required=True)
    args = parser.parse_args()
    url = _database_url()
    output: dict[str, object]

    if args.command == "readback":
        output = read_ledger_schema_readback(url, environment=args.environment)
    elif args.command == "report":
        state = read_ledger_recovery_state(url, environment=args.environment)
        output = state.as_dict()
        if args.checkpoint_generation is not None:
            checkpoint = empty_ledger_checkpoint(
                state, target_recovery_generation=args.checkpoint_generation
            )
            output["checkpoint"] = checkpoint.object
            output["checkpoint_sha256"] = checkpoint.checkpoint_sha256
    elif args.command == "beacon":
        output = bound_checkpoint_beacon(url, environment=args.environment)
    elif args.command == "first-inventory":
        exact = args.inventory_jws_file.read_bytes()
        root = release_root_from_pin(
            json.loads(args.release_root_pin.read_text(encoding="utf-8")),
            environment=args.environment,
            root_key_id=args.release_root_key_id,
            public_key_b64=args.release_root_public_key_b64,
        )
        inventory = verify_trust_inventory(
            exact,
            root_key_id=args.release_root_key_id,
            root_public_key=root,
            environment=args.environment,
        )
        digest = hashlib.sha256(exact).hexdigest()
        output = {
            "environment": args.environment,
            "inventory_generation": inventory.inventory_generation,
            "jws_sha256": digest,
            "release_root_pin": {
                "path": str(args.release_root_pin),
                "root_key_id": args.release_root_key_id,
                "root_public_key_sha256": hashlib.sha256(root.public_bytes_raw()).hexdigest(),
            },
            "status": "verified_not_written",
        }
        if args.execute:
            if args.confirm_jws_sha256 != digest:
                raise ValueError("--confirm-jws-sha256 must match the verified inventory")
            installed = install_first_release_inventory(
                url,
                environment=args.environment,
                expected_ledger_id=args.expected_ledger_id,
                expected_storage_epoch=args.expected_storage_epoch,
                expected_recovery_generation=args.expected_recovery_generation,
                exact_jws=exact,
                release_root_key_id=args.release_root_key_id,
                release_root_public_key=root,
            )
            output["status"] = "installed_dispatch_still_blocked"
            output["activation_recovery_generation"] = installed.activation_recovery_generation
    elif args.command == "create-partition":
        output = {
            "environment": args.environment,
            "caller_id": args.caller_id,
            "realm": args.realm,
            "partition_id": args.partition_id,
            "state": "blocked_no_active_grant",
            "status": "not_written",
        }
        if args.execute:
            if args.confirm_partition_id != args.partition_id:
                raise ValueError("--confirm-partition-id must repeat --partition-id")
            create_spending_partition(
                url,
                environment=args.environment,
                expected_ledger_id=args.expected_ledger_id,
                expected_storage_epoch=args.expected_storage_epoch,
                expected_recovery_generation=args.expected_recovery_generation,
                caller_id=args.caller_id,
                realm=args.realm,
                partition_id=args.partition_id,
            )
            output["status"] = "created"
    else:
        verified = verify_reconciliation_package(
            json.loads(args.pending_package.read_text(encoding="utf-8")),
            now=datetime.now(UTC).replace(microsecond=0),
            expected_root_public_sha256=args.expected_root_public_sha256,
            expected_ceremony="recovery_pending",
        )
        if verified.step.identity.environment != args.environment:
            raise ValueError("the pending package names another environment")
        target = verified.candidate.witness.recovery_generation
        output = {
            "environment": args.environment,
            "source_recovery_generation": args.source_recovery_generation,
            "target_recovery_generation": target,
            "checkpoint_sha256": verified.step.checkpoint.checkpoint_sha256,
            "pending_transition_sha256": verified.candidate.exact_sha256,
            "status": "verified_not_written",
        }
        if args.execute:
            if (
                args.confirm_target_generation != target
                or args.confirm_checkpoint_sha256 != verified.step.checkpoint.checkpoint_sha256
            ):
                raise ValueError("confirm the verified target generation and checkpoint digest")
            # The strong read of the anchor's head happens inside the authorization itself.
            authorized = authorize_recovery_generation(
                url,
                anchor=dynamodb_recovery_anchor_from_environment(verified.decoder()),
                authorized=verified.candidate,
                checkpoint=verified.step.checkpoint,
                source_recovery_generation=args.source_recovery_generation,
            )
            output["status"] = "authorized_gate_open_pending_continuity"
            output["anchor_floor_version"] = authorized.anchor_floor.transition_version
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    main()
