"""Issue one D1 startup claimant from the deployed signed anchor.

This is the recovery launcher's startup gate. It strong-reads the external anchor, verifies it
under pinned trust, reads the live continuity beacon with the recovery login, and issues one
short-lived claimant. It never signs, installs or mutates an anchor record, never accepts a
checkpoint digest from its caller, and prints only content-free evidence.

Credentials are never application arguments: the recovery database URL comes from the environment
and the AWS identity is the ambient one this process already runs as.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from lucy.shared_execution.recovery_anchor_trust import (
    AnchorTrustRejected,
    load_anchor_trust,
    verified_anchor_reader,
)
from lucy.shared_execution.startup_attestation import (
    LedgerRecoveryCheckpointSource,
    StartupAttestationIssuer,
    StartupAttestationRejected,
)


class StartupGateRejected(RuntimeError):
    """The launcher refused to issue a claimant, so no process may start."""


def run_startup_gate(
    *,
    trust_document: dict[str, object],
    recovery_database_url: str,
    expected_ledger_id: UUID,
    now: datetime,
    environment_values: dict[str, str] | None = None,
) -> dict[str, object]:
    """Verify external authority and issue exactly one claimant, or refuse."""

    try:
        trust = load_anchor_trust(trust_document)
    except AnchorTrustRejected as exc:
        raise StartupGateRejected(str(exc)) from exc
    if trust.identity.ledger_id != expected_ledger_id:
        raise StartupGateRejected("startup_gate_ledger_mismatch")
    try:
        anchor = verified_anchor_reader(trust, now=now, environment=environment_values)
    except AnchorTrustRejected as exc:
        raise StartupGateRejected(str(exc)) from exc
    issuer = StartupAttestationIssuer(
        anchor=anchor,
        identity=trust.identity,
        recovery_database_url=recovery_database_url,
        checkpoint_source=LedgerRecoveryCheckpointSource(recovery_database_url),
    )
    try:
        receipt = issuer.issue(now=now)
    except StartupAttestationRejected as exc:
        # Every refusal is fail-closed: no claimant exists, so no executor can start.
        raise StartupGateRejected(str(exc)) from exc
    return {
        "status": "claimant_issued",
        "environment": trust.identity.environment,
        "ledger_id": str(trust.identity.ledger_id),
        "attestation_id": str(receipt.attestation_id),
        "anchor_transition_sha256": receipt.anchor_transition_sha256,
        "anchor_transition_version": receipt.anchor_transition_version,
        "expires_at": receipt.expires_at.astimezone(UTC).isoformat(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trust-package", required=True, type=Path)
    parser.add_argument("--expected-ledger-id", required=True, type=UUID)
    args = parser.parse_args()
    recovery_database_url = os.environ.get("TIAMAT_RECOVERY_DATABASE_URL")
    if not recovery_database_url:
        raise ValueError("TIAMAT_RECOVERY_DATABASE_URL is required")
    document: Any = json.loads(args.trust_package.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("trust package must be a JSON object")
    try:
        result = run_startup_gate(
            trust_document=document,
            recovery_database_url=recovery_database_url,
            expected_ledger_id=args.expected_ledger_id,
            now=datetime.now(UTC),
        )
    except StartupGateRejected as exc:
        print(json.dumps({"status": "refused", "reason": str(exc)}, sort_keys=True))
        raise SystemExit(1) from exc
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
