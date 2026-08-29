"""Fail-closed Lucy container startup."""

import os
from pathlib import Path

import uvicorn

from lucy.archive_crypto import (
    archive_dependencies_from_environment,
    verify_archive_dependencies,
)
from lucy.contracts import RejoiningState
from lucy.db import create_session_factory
from lucy.evidence import EvidenceService
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
    sessions = create_session_factory(database_url)
    archive_backend = os.environ.get("LUCY_ARCHIVE_BACKEND", "").strip()
    if archive_backend:
        cipher, key_store = archive_dependencies_from_environment()
        verify_archive_dependencies(cipher, key_store)
        EvidenceService(
            sessions,
            cipher,
            key_store,
        ).reconcile_missing_keys()
    result = RejoiningService(
        sessions, expected_hermes_commit=_expected_commit()
    ).run(observed_hermes_commit=observed)
    if result.state != RejoiningState.READY:
        raise SystemExit(f"Lucy startup gate failed: {result.checks}")
    uvicorn.run("lucy.api:app", host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
