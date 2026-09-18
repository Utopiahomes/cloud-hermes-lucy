"""Initialize one migrated Tiamat ledger in its non-serving day-zero state.

This operator tool writes only the isolated Tiamat PostgreSQL database. It does not generate a
signing key, contact AWS, install a recovery anchor, or enable provider/model dispatch.
"""

from __future__ import annotations

import argparse
import json
import os
from uuid import UUID

from lucy.shared_execution.recovery import initialize_environment


def initialize_day_zero(
    *, database_url: str, environment: str, storage_epoch: UUID, recovery_generation: int
) -> dict[str, object]:
    """Return the full untrusted-yet-deterministic checkpoint after writing the blocked gate."""

    identity = initialize_environment(
        database_url,
        environment=environment,
        storage_epoch=storage_epoch,
        recovery_generation=recovery_generation,
    )
    return {
        "environment": identity.environment,
        "ledger_id": str(identity.ledger_id),
        "storage_epoch": str(identity.storage_epoch),
        "recovery_generation": identity.recovery_generation,
        "release_inventory": {"state": "not_installed"},
        "release_heads": [],
        "settlement_position": [],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default=os.environ.get("TIAMAT_RECOVERY_DATABASE_URL"))
    parser.add_argument("--environment", default=os.environ.get("TIAMAT_ENVIRONMENT"))
    parser.add_argument("--storage-epoch", default=os.environ.get("TIAMAT_STORAGE_EPOCH"))
    parser.add_argument(
        "--recovery-generation", type=int, default=os.environ.get("TIAMAT_RECOVERY_GENERATION")
    )
    parser.add_argument(
        "--confirm-initialize",
        help="Required exact acknowledgement: initialize:<environment>:<storage-epoch>",
    )
    args = parser.parse_args()
    if not args.database_url or not args.environment or not args.storage_epoch:
        raise ValueError("Tiamat database URL, environment, and storage epoch are required")
    if args.recovery_generation is None:
        raise ValueError("Tiamat recovery generation is required")
    storage_epoch = UUID(args.storage_epoch)
    expected_confirmation = f"initialize:{args.environment}:{storage_epoch}"
    if args.confirm_initialize != expected_confirmation:
        raise ValueError(f"confirmation must equal {expected_confirmation!r}")
    checkpoint = initialize_day_zero(
        database_url=args.database_url,
        environment=args.environment,
        storage_epoch=storage_epoch,
        recovery_generation=int(args.recovery_generation),
    )
    print(json.dumps(checkpoint, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
