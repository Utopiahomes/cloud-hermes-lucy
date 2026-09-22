"""Verify a signed quarantine successor; install only with an exact-digest confirmation.

This online tool has no signing capability. Its default mode performs no AWS calls. Once the M4
anchor writer is deployed the coordinator holds no PutItem, so ``--writer-function`` sends the one
write through the writer; the tool still strong-reads before and after it.
"""

from __future__ import annotations

import argparse
import base64
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import boto3  # type: ignore[import-untyped]

from lucy.shared_execution.anchor_writer import AnchorWriteRequest, AnchorWriteResult
from lucy.shared_execution.anchor_writer_lambda import LambdaAnchorWriterClient
from lucy.shared_execution.recovery_anchor import (
    RecoveryAnchorKey,
    RecoveryAnchorRejected,
    VerifiedAnchorTransition,
)
from lucy.shared_execution.recovery_anchor_commissioning import (
    verify_continued_quarantine_successor_package,
)
from lucy.shared_execution.recovery_anchor_dynamodb import (
    DynamoDbExternalRecoveryAnchor,
    dynamodb_recovery_anchor_from_environment,
)


def install_verified_successor(
    store: DynamoDbExternalRecoveryAnchor,
    *,
    predecessor_sha256: str,
    successor_sha256: str,
    key: RecoveryAnchorKey,
    successor: VerifiedAnchorTransition,
    now: datetime,
) -> str:
    """Strong-read before and after the one conditional write; never retry an unclear write."""

    current = store.read(key)
    if current.exact_sha256 != predecessor_sha256:
        raise RecoveryAnchorRejected("recovery_anchor_compare_failed")
    try:
        store.install(
            successor,
            expected_transition_sha256=predecessor_sha256,
            now=now,
        )
    except RecoveryAnchorRejected:
        # A failed/unclear request might nevertheless have committed. Read once; do not retry.
        observed = store.read(key)
        if observed.exact_sha256 != successor_sha256:
            raise
        return "already_installed_and_verified"
    observed = store.read(key)
    if observed.exact_sha256 != successor_sha256 or observed.continuity != "quarantined":
        raise RuntimeError("recovery successor strong-read verification failed")
    return "installed_and_verified"


def install_through_writer(
    store: DynamoDbExternalRecoveryAnchor,
    write: Callable[[AnchorWriteRequest], AnchorWriteResult],
    request: AnchorWriteRequest,
    *,
    predecessor_sha256: str,
    successor_sha256: str,
    key: RecoveryAnchorKey,
) -> str:
    """The same exact-digest discipline, with the write made by the M4 writer."""

    current = store.read(key)
    if current.exact_sha256 != predecessor_sha256:
        raise RecoveryAnchorRejected("recovery_anchor_compare_failed")
    try:
        result = write(request)
    except RecoveryAnchorRejected:
        # An unclear invocation might nevertheless have committed. Read once; do not retry.
        observed = store.read(key)
        if observed.exact_sha256 != successor_sha256:
            raise
        return "already_installed_and_verified"
    observed = store.read(key)
    if (
        result.transition_sha256 != successor_sha256
        or observed.exact_sha256 != successor_sha256
        or observed.continuity != "quarantined"
    ):
        raise RuntimeError("recovery successor strong-read verification failed")
    return "installed_and_verified"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--expected-root-public-sha256", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-successor-sha256")
    parser.add_argument(
        "--writer-function",
        help="M4 anchor writer function or alias ARN; required once coordinator PutItem is gone",
    )
    args = parser.parse_args()
    package = json.loads(args.package.read_text(encoding="utf-8"))
    now = datetime.now(UTC).replace(microsecond=0)
    identity, predecessor, successor, decoder = verify_continued_quarantine_successor_package(
        package,
        now=now,
        expected_root_public_sha256=args.expected_root_public_sha256,
    )
    preview = {
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "predecessor_sha256": predecessor.exact_sha256,
        "successor_sha256": successor.exact_sha256,
        "continuity": successor.continuity,
        "status": "verified_not_written",
    }
    if not args.execute:
        print(json.dumps(preview, sort_keys=True))
        return
    if args.confirm_successor_sha256 != successor.exact_sha256:
        raise ValueError("--confirm-successor-sha256 must match the verified successor")
    store = dynamodb_recovery_anchor_from_environment(decoder)
    if args.writer_function:
        writer = LambdaAnchorWriterClient(
            function_name=args.writer_function, client=boto3.client("lambda")
        )
        preview["status"] = install_through_writer(
            store,
            writer.write,
            AnchorWriteRequest(
                anchor_key=f"ENV#{identity.environment}#LEDGER#{identity.ledger_id}",
                transition_jws=successor.exact_jws,
                witness_jws=successor.witness.exact_jws,
                inventory_jws=base64.b64decode(str(package["inventory_jws_b64"])),
                head_inventory_jws=base64.b64decode(
                    str(package["predecessor_inventory_jws_b64"])
                ),
            ),
            predecessor_sha256=predecessor.exact_sha256,
            successor_sha256=successor.exact_sha256,
            key=identity.key,
        )
    else:
        preview["status"] = install_verified_successor(
            store,
            predecessor_sha256=predecessor.exact_sha256,
            successor_sha256=successor.exact_sha256,
            key=identity.key,
            successor=successor,
            now=now,
        )
    print(json.dumps(preview, sort_keys=True))


if __name__ == "__main__":
    main()
