"""Verify a signed reconciliation step; install it through the M4 writer only when confirmed.

The default mode verifies the package's exact bytes, offline, and prints what it would install.
``--execute`` additionally requires ``--confirm-transition-sha256`` equal to the verified
candidate and ``--writer-function``: it strong-reads the anchor (the head must be exactly the
package's head, or already the candidate), invokes the writer once, and strong-reads again. An
unclear invocation is resolved by that readback, never by a blind retry.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import boto3  # type: ignore[import-untyped]

from lucy.shared_execution.anchor_writer_lambda import LambdaAnchorWriterClient
from lucy.shared_execution.recovery_anchor_dynamodb import (
    dynamodb_recovery_anchor_from_environment,
)
from lucy.shared_execution.recovery_anchor_reconciliation import (
    install_through_writer,
    verify_reconciliation_package,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument(
        "--ceremony", choices=("recovery_pending", "continuity_established"), required=True
    )
    parser.add_argument("--expected-root-public-sha256", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-transition-sha256")
    parser.add_argument("--writer-function", help="the M4 writer's live alias ARN")
    args = parser.parse_args()
    verified = verify_reconciliation_package(
        json.loads(args.package.read_text(encoding="utf-8")),
        now=datetime.now(UTC).replace(microsecond=0),
        expected_root_public_sha256=args.expected_root_public_sha256,
        expected_ceremony=args.ceremony,
    )
    report: dict[str, object] = {
        "environment": verified.step.identity.environment,
        "ledger_id": str(verified.step.identity.ledger_id),
        "head_transition_sha256": verified.head.exact_sha256,
        "head_continuity": verified.head.continuity,
        "transition_sha256": verified.candidate.exact_sha256,
        "transition_version": verified.candidate.transition_version,
        "continuity": verified.candidate.continuity,
        "recovery_generation": verified.candidate.witness.recovery_generation,
        "checkpoint_sha256": verified.step.checkpoint.checkpoint_sha256,
        "status": "verified_not_written",
    }
    if args.execute:
        if args.confirm_transition_sha256 != verified.candidate.exact_sha256:
            raise ValueError("--confirm-transition-sha256 must match the verified candidate")
        if not args.writer_function:
            raise ValueError("--writer-function is required: only the M4 writer writes the anchor")
        writer = LambdaAnchorWriterClient(
            function_name=args.writer_function, client=boto3.client("lambda")
        )
        report["status"] = install_through_writer(
            dynamodb_recovery_anchor_from_environment(verified.decoder()),
            writer.write,
            verified,
        )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
