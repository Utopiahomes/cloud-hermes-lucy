"""Verify, preview, and explicitly install one signed Tiamat recovery bootstrap package.

Once the M4 anchor writer is deployed, no other principal may write the anchor table, so
``--writer-function`` sends the one write through the writer (which refuses unless the key is
empty, and treats an identical retry as installed); the tool then strong-reads it back. Without
it, the tool writes directly, which only a principal still holding PutItem can do.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from lucy.shared_execution.recovery_anchor_commissioning import verify_bootstrap_package
from lucy.shared_execution.recovery_anchor_dynamodb import dynamodb_recovery_anchor_from_environment
from lucy.shared_execution.recovery_witness_jws import RecoveryAnchorRecordDecoder


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--expected-root-public-sha256", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-empty-bootstrap")
    parser.add_argument("--writer-function", help="the M4 writer's live alias ARN")
    args = parser.parse_args()
    package = json.loads(args.package.read_text(encoding="utf-8"))
    now = datetime.now(UTC).replace(microsecond=0)
    identity, transition = verify_bootstrap_package(
        package,
        now=now,
        expected_root_public_sha256=args.expected_root_public_sha256,
    )
    preview = {
        "status": "verified_not_written" if not args.execute else "ready_to_install",
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "storage_epoch": str(identity.storage_epoch),
        "transition_sha256": transition.exact_sha256,
        "continuity": transition.continuity,
    }
    if not args.execute:
        print(json.dumps(preview, sort_keys=True))
        return
    expected_confirmation = f"bootstrap:{identity.environment}:{identity.ledger_id}"
    if args.confirm_empty_bootstrap != expected_confirmation:
        raise ValueError(f"--confirm-empty-bootstrap must equal {expected_confirmation}")
    # The strict package verification already joined the inventory, witness and transition. The
    # adapter reverifies exact bytes before its conditional attribute_not_exists write.
    from base64 import b64decode

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from lucy.shared_execution.recovery_witness_jws import verify_recovery_witness_inventory

    root_key_id = str(package["root_key_id"])
    witness_key_id = str(package["witness_key_id"])
    root_public_key = Ed25519PublicKey.from_public_bytes(
        b64decode(str(package["root_public_key_b64"]), validate=True)
    )
    inventory_jws = b64decode(str(package["inventory_jws_b64"]), validate=True)
    context = verify_recovery_witness_inventory(
        inventory_jws,
        root_key_id=root_key_id,
        root_public_key=root_public_key,
        identity=identity,
        witness_key_id=witness_key_id,
        now=now,
    )
    store = dynamodb_recovery_anchor_from_environment(
        RecoveryAnchorRecordDecoder(context, root_key_id, root_public_key)
    )
    if args.writer_function:
        import boto3  # type: ignore[import-untyped]

        from lucy.shared_execution.anchor_writer import AnchorWriteRequest
        from lucy.shared_execution.anchor_writer_lambda import LambdaAnchorWriterClient
        from lucy.shared_execution.recovery_anchor import RecoveryAnchorRejected

        writer = LambdaAnchorWriterClient(
            function_name=args.writer_function, client=boto3.client("lambda")
        )
        request = AnchorWriteRequest(
            anchor_key=f"ENV#{identity.environment}#LEDGER#{identity.ledger_id}",
            transition_jws=transition.exact_jws,
            witness_jws=transition.witness.exact_jws,
            inventory_jws=inventory_jws,
        )
        try:
            writer.write(request)
        except RecoveryAnchorRejected:
            # An unclear invocation might nevertheless have committed. Read once; do not retry.
            if store.read(identity.key).exact_sha256 != transition.exact_sha256:
                raise
        reread = store.read(identity.key)
        if reread.exact_sha256 != transition.exact_sha256:
            raise RuntimeError("recovery bootstrap strong-read verification failed")
        print(json.dumps({**preview, "status": "installed_and_verified"}, sort_keys=True))
        return
    installed = store.install(transition, expected_transition_sha256=None, now=now)
    reread = store.read(identity.key)
    if reread.exact_sha256 != installed.exact_sha256:
        raise RuntimeError("recovery bootstrap strong-read verification failed")
    print(json.dumps({**preview, "status": "installed_and_verified"}, sort_keys=True))


if __name__ == "__main__":
    main()
