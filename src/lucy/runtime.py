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
    expected_database_login_from_environment,
    expected_storage_epoch,
    security_baseline_from_environment,
    service_mode_from_environment,
)


def _expected_commit() -> str:
    values = dict(
        line.split("=", 1)
        for line in Path("/app/hermes.lock").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#") and "=" in line
    )
    return values["commit"]


def _listener_port() -> int:
    try:
        port = int(os.getenv("PORT", "8080"))
    except ValueError:
        raise SystemExit("Lucy startup gate failed: invalid listener port") from None
    if not 1 <= port <= 65_535:
        raise SystemExit("Lucy startup gate failed: invalid listener port")
    return port


def main() -> None:
    database_url = os.environ["LUCY_DATABASE_URL"]
    observed = os.environ["LUCY_OBSERVED_HERMES_COMMIT"]
    sessions = create_session_factory(database_url)
    if observed != _expected_commit():
        raise SystemExit("Lucy startup gate failed: Hermes pin mismatch")
    mode = service_mode_from_environment()
    baseline = security_baseline_from_environment()
    print(f"Lucy startup admission check beginning for isolated {mode} identity")
    try:
        # V1.2 evidence/deletion callers have no DynamoDB credentials. Only the
        # routine/archive boundary reads the bounded journal head at admission.
        journal = (
            deletion_journal_from_environment()
            if baseline == "v1.2" and mode == "routine"
            else None
        )
        ServiceReadiness(
            sessions,
            mode=mode,
            storage_epoch=expected_storage_epoch(mode),
            journal=journal,
            baseline=baseline,
            expected_database_login=expected_database_login_from_environment(baseline),
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
    uvicorn.run(app, host="0.0.0.0", port=_listener_port(), access_log=False)


if __name__ == "__main__":
    main()
