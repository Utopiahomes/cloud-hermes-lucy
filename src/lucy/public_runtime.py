"""Fail-closed startup for the isolated Public Lucy HTTP service."""

from __future__ import annotations

import os

import uvicorn
from sqlalchemy.exc import SQLAlchemyError

from lucy.db import create_session_factory
from lucy.public_api import PublicApiConfigurationError, _configuration
from lucy.readiness import (
    ReadinessError,
    ServiceReadiness,
    expected_database_login_from_environment,
    expected_storage_epoch,
    security_baseline_from_environment,
    service_mode_from_environment,
)
from lucy.runtime import _expected_commit, _listener_port


def main() -> None:
    if os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
        raise SystemExit("Public Lucy startup gate failed: transcript capture must be disabled")
    if os.getenv("LUCY_OBSERVED_HERMES_COMMIT") != _expected_commit():
        raise SystemExit("Public Lucy startup gate failed: Hermes pin mismatch")
    try:
        config = _configuration()
        mode = service_mode_from_environment()
        baseline = security_baseline_from_environment()
        if mode != "public" or baseline != "v1.3":
            raise ReadinessError("isolated public service identity required")
        ServiceReadiness(
            create_session_factory(config.database_url),
            mode=mode,
            storage_epoch=expected_storage_epoch(mode),
            journal=None,
            baseline=baseline,
            expected_database_login=expected_database_login_from_environment(baseline),
        ).check()
    except (PublicApiConfigurationError, ReadinessError) as exc:
        raise SystemExit(f"Public Lucy startup gate failed: {exc}") from exc
    except SQLAlchemyError:
        raise SystemExit(
            "Public Lucy startup gate failed: storage or permission check unavailable"
        ) from None

    from lucy.public_api import app

    print("Public Lucy admitted ASGI listener starting")
    uvicorn.run(app, host="0.0.0.0", port=_listener_port(), access_log=False)


if __name__ == "__main__":
    main()
