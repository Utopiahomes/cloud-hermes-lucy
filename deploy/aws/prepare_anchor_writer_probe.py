"""Prepare the M4 writer's positive tests on disposable anchor keys.

It mints two disposable ledger IDs in the given environment, each with its own throwaway root, and
signs a version-one quarantined bootstrap for each:

- ``before-boundary``: installed through the ``live`` alias before the table's writer-only policy
  exists, which shows the deployed version executes, assumes its role and loaded its roots;
- ``after-boundary``: installed after the policy is in place, which shows the writer still writes
  through it.

It writes ``writer-roots-with-probes.json``, the reviewed final roots with both probe entries
added, as the exact bytes to pass as ``WriterRootsJson``, and one invocation event per probe. It
prints the merged digest, each probe's expected transition digest and the witness expiry the tests
must beat.

The throwaway private keys exist only in this process and are never written. The disposable keys
name no real ledger, so installing them touches no ledger's anchor; the items they leave are inert.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.recovery_anchor import RecoveryAnchorIdentity
from lucy.shared_execution.recovery_anchor_commissioning import build_quarantined_bootstrap

PROBES = ("before-boundary", "after-boundary")


def prepare(
    environment: str,
    final_roots: bytes,
    output_directory: Path,
    *,
    final_roots_sha256: str,
    now: datetime,
) -> dict[str, Any]:
    if hashlib.sha256(final_roots).hexdigest() != final_roots_sha256:
        raise ValueError("the final roots are not the reviewed bytes")
    roots = json.loads(final_roots)
    if not isinstance(roots, dict) or not roots:
        raise ValueError("the final roots must be a non-empty JSON object")
    probes: dict[str, Any] = {}
    output_directory.mkdir(parents=True, exist_ok=True)
    for name in PROBES:
        identity = RecoveryAnchorIdentity(environment, uuid4(), uuid4())
        anchor_key = f"ENV#{identity.environment}#LEDGER#{identity.ledger_id}"
        root_key_id = f"tiamat-recovery-root.writer-probe-{name}.1"
        root = Ed25519PrivateKey.generate()
        raw_root = root.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        artifacts, transition = build_quarantined_bootstrap(
            identity=identity,
            root_key_id=root_key_id,
            root_private_key=root,
            witness_key_id=f"tiamat-recovery-witness.writer-probe-{name}.1",
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
            now=now,
        )
        roots[anchor_key] = {
            "root_key_id": root_key_id,
            "root_public_key_b64": base64.b64encode(raw_root).decode(),
            "root_public_key_sha256": hashlib.sha256(raw_root).hexdigest(),
        }
        (output_directory / f"probe-event-{name}.json").write_text(
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
        probes[name] = {
            "anchor_key": anchor_key,
            "expected_transition_sha256": artifacts.transition_sha256,
            # The test must run before this, or the writer refuses the witness.
            "witness_not_after": transition.witness.not_after.astimezone(UTC).isoformat(),
        }
    merged = json.dumps(roots, sort_keys=True, separators=(",", ":")).encode("utf-8")
    (output_directory / "writer-roots-with-probes.json").write_bytes(merged)
    return {"writer_roots_sha256": hashlib.sha256(merged).hexdigest(), "probes": probes}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", required=True)
    parser.add_argument(
        "--final-roots-file",
        type=Path,
        required=True,
        help="the reviewed final WriterRootsJson (tiamat-staging-anchor-writer-roots.json)",
    )
    parser.add_argument("--final-roots-sha256", required=True, help="the reviewed digest")
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    report = prepare(
        args.environment,
        args.final_roots_file.read_bytes(),
        args.output_directory,
        final_roots_sha256=args.final_roots_sha256,
        now=datetime.now(UTC),
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
