"""Fail-closed Lucy container startup."""

import os
import time
from pathlib import Path

import uvicorn
from sqlalchemy.exc import OperationalError, SQLAlchemyError

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


def _retryable_connection_failure(error: OperationalError) -> bool:
    category = _database_failure_category(error)
    if category in {"authentication", "tls"}:
        return False
    original = error.orig
    sqlstate = getattr(original, "sqlstate", None)
    if isinstance(sqlstate, str):
        return sqlstate.startswith("08")
    return (
        type(original).__module__.startswith("psycopg")
        and type(original).__name__ == "OperationalError"
    )


def _database_failure_category(error: SQLAlchemyError) -> str:
    original = getattr(error, "orig", None)
    sqlstate = getattr(original, "sqlstate", None)
    if isinstance(sqlstate, str) and sqlstate.startswith("08"):
        return "connection"
    if isinstance(sqlstate, str) and sqlstate.startswith("28"):
        return "authentication"
    message = str(original).casefold()
    if "resolve host" in message or "translate host name" in message:
        return "dns"
    if "password authentication failed" in message or "no password supplied" in message:
        return "authentication"
    if "ssl" in message or "certificate" in message:
        return "tls"
    if any(term in message for term in ("timed out", "timeout", "connection refused")):
        return "connection"
    return "database"


def _check_with_connection_retries(readiness: ServiceReadiness) -> None:
    """Keep the listener closed while Render's private DNS/network becomes ready."""

    delays = (1, 2, 4, 8, 8)
    for attempt, delay in enumerate(delays, start=1):
        try:
            readiness.check()
            return
        except OperationalError as exc:
            if not _retryable_connection_failure(exc):
                raise
            print(
                f"Lucy startup storage connection unavailable; retrying ({attempt}/{len(delays)})",
                flush=True,
            )
            time.sleep(delay)
    readiness.check()


def _initialize_stage2_archive_boundary(*, mode: str, baseline: str) -> None:
    """Refuse the listener unless this process can build its Stage 2 archive boundary."""

    stage = os.getenv("LUCY_TELEGRAM_STAGE")
    capture = os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED")
    if baseline != "v1.3" or mode != "routine" or (stage != "2" and capture != "true"):
        return
    if stage != "2" or capture != "true":
        raise SystemExit("Lucy startup gate failed: Stage 2 configuration mismatch")
    try:
        from lucy.api import _archive_service
        from lucy.realm_archive_commit import RealmConversationArchiveService

        service = _archive_service()
        if not isinstance(service, RealmConversationArchiveService):
            raise RuntimeError("unexpected archive service")
    except Exception:
        raise SystemExit(
            "Lucy startup gate failed: Stage 2 archive boundary unavailable"
        ) from None
    print("Lucy startup Stage 2 archive boundary passed", flush=True)


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
        readiness = ServiceReadiness(
            sessions,
            mode=mode,
            storage_epoch=expected_storage_epoch(mode),
            journal=journal,
            baseline=baseline,
            expected_database_login=expected_database_login_from_environment(baseline),
        )
        _check_with_connection_retries(readiness)
    except (ReadinessError, DeletionJournalError) as exc:
        raise SystemExit(f"Lucy startup gate failed: {exc}") from exc
    except SQLAlchemyError as exc:
        category = _database_failure_category(exc)
        print(f"Lucy startup storage failure category: {category}", flush=True)
        raise SystemExit(
            "Lucy startup gate failed: storage or permission check unavailable"
        ) from None
    print("Lucy startup admission check passed")
    _initialize_stage2_archive_boundary(mode=mode, baseline=baseline)
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
