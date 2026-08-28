"""Fail-closed Lucy container startup."""

import os
from pathlib import Path

import uvicorn

from lucy.contracts import RejoiningState
from lucy.db import create_session_factory
from lucy.rejoining import RejoiningService


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
    result = RejoiningService(
        create_session_factory(database_url), expected_hermes_commit=_expected_commit()
    ).run(observed_hermes_commit=observed)
    if result.state != RejoiningState.READY:
        raise SystemExit(f"Lucy startup gate failed: {result.checks}")
    uvicorn.run("lucy.api:app", host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
