"""Fail-closed startup for one isolated recovery-journal writer service."""

import os

import uvicorn

from lucy.recovery_writer_api import _dependencies, app
from lucy.runtime import _expected_commit, _listener_port


def main() -> None:
    if (
        os.getenv("LUCY_ENVIRONMENT") != "production"
        or os.getenv("LUCY_SECURITY_BASELINE") != "v1.3"
        or os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false"
        or os.getenv("LUCY_OBSERVED_HERMES_COMMIT") != _expected_commit()
    ):
        raise SystemExit("Lucy recovery-writer startup gate failed")
    try:
        dependencies = _dependencies()
        dependencies.journal.head()
    except Exception:
        raise SystemExit("Lucy recovery-writer dependency unavailable") from None
    uvicorn.run(app, host="0.0.0.0", port=_listener_port(), access_log=False)


if __name__ == "__main__":
    main()
