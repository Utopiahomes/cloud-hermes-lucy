"""Prepare the M4 writer's positive test on a disposable anchor key.

It mints a throwaway root and a disposable ledger ID in the given environment, signs a version-one
quarantined bootstrap for that key, and writes two files:

- ``probe-roots-entry.json``: the one entry to add to WriterRootsJson for the test, and to remove
  again afterwards;
- ``probe-event.json``: the writer invocation that installs the bootstrap.

The throwaway private keys exist only in this process and are never written. The disposable key
names no real ledger, so installing it touches no ledger's anchor; the item it leaves is inert.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.recovery_anchor import RecoveryAnchorIdentity
from lucy.shared_execution.recovery_anchor_commissioning import build_quarantined_bootstrap

ROOT_KEY_ID = "tiamat-recovery-root.writer-probe.1"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()

    identity = RecoveryAnchorIdentity(args.environment, uuid4(), uuid4())
    anchor_key = f"ENV#{identity.environment}#LEDGER#{identity.ledger_id}"
    root = Ed25519PrivateKey.generate()
    raw_root = root.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    artifacts, _ = build_quarantined_bootstrap(
        identity=identity,
        root_key_id=ROOT_KEY_ID,
        root_private_key=root,
        witness_key_id="tiamat-recovery-witness.writer-probe.1",
        witness_private_key=Ed25519PrivateKey.generate(),
        checkpoint={
            "environment": identity.environment,
            "ledger_id": str(identity.ledger_id),
            "storage_epoch": str(identity.storage_epoch),
            "recovery_generation": 1,
            "release_inventory": {"state": "not_installed"},
            "release_heads": [],
            "settlement_position": [],
        },
        now=datetime.now(UTC),
    )
    args.output_directory.mkdir(parents=True, exist_ok=True)
    (args.output_directory / "probe-roots-entry.json").write_text(
        json.dumps(
            {
                anchor_key: {
                    "root_key_id": ROOT_KEY_ID,
                    "root_public_key_b64": base64.b64encode(raw_root).decode(),
                    "root_public_key_sha256": hashlib.sha256(raw_root).hexdigest(),
                }
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (args.output_directory / "probe-event.json").write_text(
        json.dumps(
            {
                "anchor_key": anchor_key,
                "transition_jws_b64": base64.b64encode(artifacts.transition_jws).decode(),
                "witness_jws_b64": base64.b64encode(artifacts.witness_jws).decode(),
                "inventory_jws_b64": base64.b64encode(artifacts.inventory_jws).decode(),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "anchor_key": anchor_key,
                "expected_transition_sha256": artifacts.transition_sha256,
                "valid_for": "the bootstrap witness's validity window from now",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
