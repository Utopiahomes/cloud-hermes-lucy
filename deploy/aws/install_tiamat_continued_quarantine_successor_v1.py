"""Verify a signed quarantine successor; install only with an exact-digest confirmation.

This online tool has no signing capability. Its default mode performs no AWS calls.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--expected-root-public-sha256", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-successor-sha256")
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
