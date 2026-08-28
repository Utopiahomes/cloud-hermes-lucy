"""Narrow companion API exposed to the pinned Hermes runtime."""

import os
import secrets

from fastapi import FastAPI, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from lucy.contracts import RejoiningState
from lucy.db import create_session_factory
from lucy.db.models import LifecycleRow
from lucy.memory import MemoryService
from lucy.model_execution import (
    ModelExecutionBegin,
    ModelExecutionBeginResult,
    ModelExecutionService,
    ModelExecutionSettlement,
    ModelExecutionSettlementResult,
)
from lucy.proposals import MemoryProposalInput, MemoryProposalService

app = FastAPI(title="Lucy Companion API", version="0.1.0")


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready", tags=["operations"])
def ready() -> dict[str, str]:
    database_url = os.getenv("LUCY_DATABASE_URL")
    if database_url is None:
        raise HTTPException(status_code=503, detail="memory store unavailable")
    with create_session_factory(database_url)() as session:
        lifecycle = session.scalar(select(LifecycleRow).where(LifecycleRow.singleton))
        if lifecycle is None or lifecycle.state != RejoiningState.READY:
            raise HTTPException(status_code=503, detail="Lucy is not ready")
    return {"status": "ready"}


def _authorize(authorization: str | None) -> None:
    token = os.getenv("LUCY_ADAPTER_TOKEN")
    if token is None or authorization is None or not secrets.compare_digest(
        authorization, f"Bearer {token}"
    ):
        raise HTTPException(status_code=401, detail="invalid adapter credential")


def _ready_sessions() -> sessionmaker[Session]:
    database_url = os.getenv("LUCY_DATABASE_URL")
    if database_url is None:
        raise HTTPException(status_code=503, detail="memory store unavailable")
    sessions = create_session_factory(database_url)
    with sessions() as session:
        lifecycle = session.scalar(select(LifecycleRow).where(LifecycleRow.singleton))
        if lifecycle is None or lifecycle.state != RejoiningState.READY:
            raise HTTPException(status_code=503, detail="Lucy is not ready")
    return sessions


@app.get("/v1/memory/lookup", tags=["memory"])
def read_only_memory_lookup(
    query: str, authorization: str | None = Header(default=None)
) -> dict[str, object]:
    """Return a bounded projection; never expose or mutate archive evidence."""

    _authorize(authorization)
    sessions = _ready_sessions()
    context = MemoryService(sessions).build_context(query)
    return {"query": query, "claims": context.claims, "read_only": True}


@app.post("/v1/memory/proposals", tags=["memory"], status_code=202)
def propose_memory(
    candidate: MemoryProposalInput,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, object]:
    """Create a gated candidate; this endpoint can never apply a memory write."""
    _authorize(authorization)
    if idempotency_key is None:
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    sessions = _ready_sessions()
    result = MemoryProposalService(sessions).submit(idempotency_key, candidate)
    return result.model_dump(mode="json")


@app.post(
    "/internal/v1/model-executions/begin",
    tags=["internal"],
    response_model=ModelExecutionBeginResult,
)
def begin_model_execution(
    request: ModelExecutionBegin,
    authorization: str | None = Header(default=None),
) -> ModelExecutionBeginResult:
    """Reserve once immediately before the Hermes provider call."""
    _authorize(authorization)
    return ModelExecutionService(_ready_sessions()).begin(request)


@app.post(
    "/internal/v1/model-executions/settle",
    tags=["internal"],
    response_model=ModelExecutionSettlementResult,
)
def settle_model_execution(
    request: ModelExecutionSettlement,
    authorization: str | None = Header(default=None),
) -> ModelExecutionSettlementResult:
    """Settle usage after the wrapped provider call completes."""
    _authorize(authorization)
    return ModelExecutionService(_ready_sessions()).settle(request)
