"""Private, content-free API for one isolated recovery-journal writer."""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass
from functools import lru_cache
from typing import Protocol
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from lucy.authority_recovery import AuthorityJournalWriter, AuthorityTransitionService
from lucy.cost_recovery import CostJournalPreparationService, CostJournalWriter
from lucy.db import create_session_factory
from lucy.readiness import RECOVERY_SCHEMA_REVISIONS
from lucy.recovery_journal import (
    RecoveryAppendAcknowledgementV1,
    RecoveryJournalError,
    RecoveryStreamKind,
)
from lucy.recovery_journal_aws import AwsDynamoRecoveryJournal

_LOGIN = re.compile(r"[a-z][a-z0-9_]{2,62}\Z")

app = FastAPI(title="Lucy Recovery Journal Writer API", version="1.0.0")


class JournalWriter(Protocol):
    def append_pending(self, event_id: UUID) -> RecoveryAppendAcknowledgementV1: ...


class WriterResponseV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID
    stream_kind: RecoveryStreamKind
    sequence: int
    event_digest: str


@dataclass(frozen=True)
class RecoveryWriterDependencies:
    stream_kind: RecoveryStreamKind
    writer: JournalWriter
    journal: AwsDynamoRecoveryJournal


@app.exception_handler(RecoveryJournalError)
@app.exception_handler(SQLAlchemyError)
@app.exception_handler(LookupError)
def unavailable(_request: Request, _error: Exception) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": "journal write unavailable"})


def _stream_kind() -> RecoveryStreamKind:
    try:
        return RecoveryStreamKind(os.environ["LUCY_RECOVERY_WRITER_STREAM"])
    except (KeyError, ValueError):
        raise RecoveryJournalError("journal writer stream is invalid") from None


def _authorize(authorization: str | None) -> None:
    token = os.getenv("LUCY_RECOVERY_WRITER_TOKEN")
    if (
        not token
        or authorization is None
        or not secrets.compare_digest(authorization, f"Bearer {token}")
    ):
        raise HTTPException(status_code=401, detail="invalid journal writer credential")


def _verified_sessions(kind: RecoveryStreamKind) -> sessionmaker[Session]:
    try:
        expected_login = os.environ["LUCY_RECOVERY_WRITER_DATABASE_LOGIN"]
        database_url = os.environ["LUCY_RECOVERY_WRITER_DATABASE_URL"]
    except KeyError:
        raise RecoveryJournalError("journal writer database is incomplete") from None
    if _LOGIN.fullmatch(expected_login) is None:
        raise RecoveryJournalError("journal writer database identity is invalid")
    sessions = create_session_factory(database_url)
    with sessions() as session:
        identity = session.execute(
            text(
                "SELECT current_user,r.rolcanlogin,r.rolsuper,r.rolinherit,"
                "r.rolcreaterole,r.rolcreatedb,r.rolreplication,r.rolbypassrls "
                "FROM pg_catalog.pg_roles r WHERE r.rolname=current_user"
            )
        ).one()
        revision = session.execute(
            text("SELECT version_num FROM public.alembic_version")
        ).scalar_one()
    if tuple(identity) != (expected_login, True, False, False, False, False, False, False):
        raise RecoveryJournalError("journal writer database identity is elevated or differs")
    if revision not in RECOVERY_SCHEMA_REVISIONS:
        raise RecoveryJournalError("journal writer schema revision differs")
    required_suffix = f"_{kind.value}_writer"
    if not expected_login.endswith(required_suffix):
        raise RecoveryJournalError("journal writer database identity is cross-stream")
    return sessions


@lru_cache
def _dependencies() -> RecoveryWriterDependencies:
    kind = _stream_kind()
    sessions = _verified_sessions(kind)
    journal = AwsDynamoRecoveryJournal.from_environment()
    if journal.head().stream_kind is not kind:
        raise RecoveryJournalError("journal writer AWS stream differs")
    writer: JournalWriter
    if kind is RecoveryStreamKind.AUTHORITY:
        writer = AuthorityJournalWriter(AuthorityTransitionService(sessions), journal)
    else:
        writer = CostJournalWriter(CostJournalPreparationService(sessions), journal)
    return RecoveryWriterDependencies(kind, writer, journal)


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready", tags=["operations"])
def ready() -> dict[str, str]:
    dependencies = _dependencies()
    dependencies.journal.head()
    return {"status": "ready", "stream_kind": dependencies.stream_kind.value}


@app.post("/v1/recovery/events/{event_id}", response_model=WriterResponseV1)
async def append_event(
    event_id: UUID,
    request: Request,
    authorization: str | None = Header(default=None),
) -> WriterResponseV1:
    _authorize(authorization)
    if await request.body():
        raise HTTPException(status_code=400, detail="journal writer body is prohibited")
    dependencies = _dependencies()
    acknowledgement = dependencies.writer.append_pending(event_id)
    if acknowledgement.event_id != event_id:
        raise RecoveryJournalError("journal writer acknowledgement differs")
    return WriterResponseV1(
        event_id=event_id,
        stream_kind=dependencies.stream_kind,
        sequence=acknowledgement.resulting_head.sequence,
        event_digest=acknowledgement.event_digest,
    )
