"""Fail-closed startup for the isolated Public Lucy model service."""

from __future__ import annotations

import os

import uvicorn
from sqlalchemy.exc import SQLAlchemyError

from lucy.public_model_api import (
    PublicModelApiConfigurationError,
    _dependencies,
    app,
    check_cost_identity,
)
from lucy.public_model_service import PublicModelServiceUnavailable
from lucy.runtime import _expected_commit, _listener_port


def main() -> None:
    if (
        os.getenv("LUCY_ENVIRONMENT") != "production"
        or os.getenv("LUCY_SECURITY_BASELINE") != "v1.3"
        or os.getenv("LUCY_SERVICE_MODE") != "public-model"
        or os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false"
        or os.getenv("LUCY_OBSERVED_HERMES_COMMIT") != _expected_commit()
    ):
        raise SystemExit("Public Lucy model startup gate failed")
    try:
        check_cost_identity(_dependencies())
    except (
        PublicModelApiConfigurationError,
        PublicModelServiceUnavailable,
        SQLAlchemyError,
        ValueError,
    ):
        raise SystemExit("Public Lucy model startup dependency unavailable") from None
    print("Public Lucy model admitted ASGI listener starting")
    uvicorn.run(app, host="0.0.0.0", port=_listener_port(), access_log=False)


if __name__ == "__main__":
    main()
