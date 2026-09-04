"""Fail-closed Lucy container startup."""

import os
from pathlib import Path

import uvicorn
from sqlalchemy.exc import SQLAlchemyError

from lucy.db import create_session_factory
from lucy.deletion_journal import DeletionJournalError, deletion_journal_from_environment
from lucy.readiness import (
    ReadinessError,
    ServiceReadiness,
    expected_storage_epoch,
    service_mode_from_environment,
)


def _expected_commit() -> str:
    values = dict(
        line.split("=", 1)
        for line in Path("/app/hermes.lock").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#") and "=" in line
    )
    return values["commit"]


def main() -> None:
    database_url = os.environ["LUCY_DATABASE_URL"]
    observed = os.environ["LUCY_OBSERVED_HERMES_COMMIT"]
    sessions = create_session_factory(database_url)
    if observed != _expected_commit():
        raise SystemExit("Lucy startup gate failed: Hermes pin mismatch")
    mode = service_mode_from_environment()
    print(f"Lucy startup admission check beginning for isolated {mode} identity")
    try:
        # V1.2 evidence/deletion callers have no DynamoDB credentials. Only the
        # routine/archive boundary reads the bounded journal head at admission.
        journal = deletion_journal_from_environment() if mode == "routine" else None
        ServiceReadiness(
            sessions,
            mode=mode,
            storage_epoch=expected_storage_epoch(mode),
            journal=journal,
        ).check()
    except (ReadinessError, DeletionJournalError) as exc:
        raise SystemExit(f"Lucy startup gate failed: {exc}") from exc
    except SQLAlchemyError:
        raise SystemExit(
            "Lucy startup gate failed: storage or permission check unavailable"
        ) from None
    print("Lucy startup admission check passed")
    # No lifecycle writes, pending-operation scans, KMS calls, registry scans,
    # migrations, or recovery occur when any HTTP service starts/restarts.
    # Import the application only after admission and pass the object directly.
    # This keeps Uvicorn from resolving an import string after the fail-closed
    # gate and guarantees that the admitted process is the serving process.
    from lucy.api import app

    print("Lucy admitted ASGI listener starting")
    uvicorn.run(app, host="0.0.0.0", port=8080, access_log=False)


if __name__ == "__main__":
    main()
