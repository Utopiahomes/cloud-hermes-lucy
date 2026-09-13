"""Execute-only PostgreSQL adapter for encrypted memory provider outcomes."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from lucy.chatgpt_manifest import AuthorizedPilotManifestV1
from lucy.contracts.canonical import canonical_json_bytes
from lucy.contracts.memory_outcome_recovery_v1 import (
    MemoryOutcomeEnvelopeV1,
    MemoryOutcomeRecoveryPackageV1,
)
from lucy.memory_outcome import MemoryOutcomeUnavailable


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

    def require_recoverable(
        self,
        *,
        authorization: AuthorizedPilotManifestV1,
        package: MemoryOutcomeRecoveryPackageV1,
        checked_at: datetime,
        phase: str,
    ) -> None:
        """Re-run the DB's exact-job/source gate immediately around recovery."""

        if phase not in {"pre_grant", "pre_completion"}:
            raise ValueError("memory outcome recovery eligibility phase is invalid")
        if checked_at.tzinfo is None or checked_at.utcoffset() is None:
            raise ValueError("memory outcome recovery eligibility time must be aware")
        manifest = authorization.bundle.manifest
        if (
            manifest.expires_at <= checked_at
            or manifest.campaign_id != package.envelope.binding.campaign_id
            or manifest.digest != package.envelope.binding.manifest_digest
        ):
            raise MemoryOutcomeUnavailable("memory outcome authorization is no longer current")
        current = self.load(package.envelope.binding.extraction_job_id)
        if current != package.envelope:
            raise MemoryOutcomeUnavailable("memory outcome is not currently recoverable")
