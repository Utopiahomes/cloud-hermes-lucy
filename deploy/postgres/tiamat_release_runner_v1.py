"""Control's one-off release runner for a disposable Tiamat ledger (Gate 2 Proof 2, D4).

Reads only ``TIAMAT_RELEASE_MANAGER_DATABASE_URL``: the TLS-required release-manager login. It
holds no recovery, owner, serving, signing or AWS credential. It is fed exact pre-signed release
bytes and the committed, approved RELEASE-root pin.

``stage`` and ``activate`` each verify first and write nothing without ``--execute`` and the
release's exact ``--confirm-jws-sha256``. ``activate`` re-verifies the current inventory and the
release immediately before activation, requires the staged bytes, succession, an open gate and
(for a grant) active profile and policy heads, then reads the head back. Activate nothing until
the anchor's continuity is established; that ordering is the operator's, since this runner holds
no anchor credential.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from lucy.shared_execution.postgres_authority import AuthorityScope
from lucy.shared_execution.release_runner import (
    RunnerContext,
    preview_or_activate,
    preview_or_stage,
    release_root_from_pin,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("stage", "activate"))
    parser.add_argument("--environment", required=True)
    parser.add_argument("--expected-ledger-id", type=UUID, required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--caller-id", required=True)
    parser.add_argument("--realm", required=True)
    parser.add_argument("--release-root-pin", type=Path, required=True)
    parser.add_argument("--release-root-key-id", required=True)
    parser.add_argument("--release-root-public-key-b64", required=True)
    parser.add_argument("--release-jws-file", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-jws-sha256")
    args = parser.parse_args()
    database_url = os.environ.get("TIAMAT_RELEASE_MANAGER_DATABASE_URL", "")
    if not database_url:
        raise ValueError("TIAMAT_RELEASE_MANAGER_DATABASE_URL is required")
    if args.execute and not args.confirm_jws_sha256:
        raise ValueError("--execute requires --confirm-jws-sha256")
    context = RunnerContext(
        database_url=database_url,
        expected_ledger_id=args.expected_ledger_id,
        scope=AuthorityScope(args.environment, args.issuer, args.caller_id, args.realm),
        root_key_id=args.release_root_key_id,
        root_public_key=release_root_from_pin(
            json.loads(args.release_root_pin.read_text(encoding="utf-8")),
            environment=args.environment,
            root_key_id=args.release_root_key_id,
            public_key_b64=args.release_root_public_key_b64,
        ),
    )
    operation = preview_or_stage if args.command == "stage" else preview_or_activate
    report = operation(
        context,
        args.release_jws_file.read_bytes(),
        now=datetime.now(UTC),
        confirm_jws_sha256=args.confirm_jws_sha256 if args.execute else None,
    )
    report["release_root_pin"] = str(args.release_root_pin)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
