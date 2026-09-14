"""Execute-only PostgreSQL adapter for encrypted memory provider outcomes."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_outcome import MemoryOutcomeEnvelopeV1, MemoryOutcomeUnavailable


class PostgresMemoryOutcomeStore:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def load(self, extraction_job_id: UUID) -> MemoryOutcomeEnvelopeV1 | None:
        try:
            with self._sessions.begin() as session:
                value = session.execute(
                    text("SELECT lucy.load_memory_import_provider_outcome_v1(:job)"),
                    {"job": extraction_job_id},
                ).scalar_one()
        except DBAPIError as exc:
            raise MemoryOutcomeUnavailable("provider outcome lookup unavailable") from exc
        return None if value is None else MemoryOutcomeEnvelopeV1.model_validate(value)

    def put(self, envelope: MemoryOutcomeEnvelopeV1) -> MemoryOutcomeEnvelopeV1:
        try:
            with self._sessions.begin() as session:
                value = session.execute(
                    text(
                        "SELECT lucy.record_memory_import_provider_outcome_v1("
                        "CAST(:envelope AS jsonb))"
                    ),
                    {"envelope": canonical_json_bytes(envelope).decode("utf-8")},
                ).scalar_one()
        except DBAPIError as exc:
            raise MemoryOutcomeUnavailable("provider outcome write unavailable") from exc
        return MemoryOutcomeEnvelopeV1.model_validate(value)
