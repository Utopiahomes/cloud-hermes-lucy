"""Execute-only client for new-realm scoped semantic memory."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from lucy.secret_filter import MemorySecretDetected, detect_memory_secrets


class ScopedMemoryUnavailable(PermissionError):
    pass


class ScopedMemoryWrite(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    idempotency_key: str = Field(min_length=1, max_length=200)
    subject: str = Field(min_length=1, max_length=200)
    predicate: str = Field(min_length=1, max_length=200)
    object: str = Field(min_length=1, max_length=2000)
    confidence_millionths: int = Field(ge=0, le=1_000_000)


class ScopedMemoryWriteResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    claim_id: UUID
    replayed: bool


class ScopedMemoryClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    claim_id: UUID
    subject: str
    predicate: str
    object: str
    confidence_millionths: int
    status: str


class ScopedMemoryService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def write(self, candidate: ScopedMemoryWrite) -> ScopedMemoryWriteResult:
        findings = detect_memory_secrets(candidate.subject, candidate.predicate, candidate.object)
        if findings:
            raise MemorySecretDetected(tuple(item.category for item in findings))
        try:
            with self._sessions.begin() as session:
                result = session.execute(
                    text(
                        "SELECT lucy.write_scoped_memory_claim_v1("
                        ":key,:subject,:predicate,:object,:confidence)"
                    ),
                    {
                        "key": candidate.idempotency_key,
                        "subject": candidate.subject,
                        "predicate": candidate.predicate,
                        "object": candidate.object,
                        "confidence": candidate.confidence_millionths,
                    },
                ).scalar_one()
        except DBAPIError as exc:
            raise ScopedMemoryUnavailable("scoped memory operation is unavailable") from exc
        return ScopedMemoryWriteResult.model_validate(result)

    def search(self, query: str, *, limit: int = 10) -> tuple[ScopedMemoryClaim, ...]:
        if not query.strip() or len(query) > 200 or not 1 <= limit <= 50:
            raise ValueError("scoped memory query is invalid")
        try:
            with self._sessions() as session:
                result = session.execute(
                    text("SELECT lucy.search_scoped_memory_v1(:query,:limit)"),
                    {"query": query, "limit": limit},
                ).scalar_one()
        except DBAPIError as exc:
            raise ScopedMemoryUnavailable("scoped memory operation is unavailable") from exc
        return tuple(ScopedMemoryClaim.model_validate(item) for item in result)
