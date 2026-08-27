"""Narrow companion API exposed to the pinned Hermes runtime."""

import os
import secrets

from fastapi import FastAPI, Header, HTTPException
from sqlalchemy import select

from lucy.contracts import RejoiningState
from lucy.db import create_session_factory
from lucy.db.models import LifecycleRow
from lucy.memory import MemoryService

app = FastAPI(title="Lucy Companion API", version="0.1.0")


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/memory/lookup", tags=["memory"])
def read_only_memory_lookup(
    query: str, authorization: str | None = Header(default=None)
) -> dict[str, object]:
    """Return a bounded projection; never expose or mutate archive evidence."""

    database_url = os.getenv("LUCY_DATABASE_URL")
    token = os.getenv("LUCY_ADAPTER_TOKEN")
    if token is None or authorization is None or not secrets.compare_digest(
        authorization, f"Bearer {token}"
    ):
        raise HTTPException(status_code=401, detail="invalid adapter credential")
    if database_url is None:
        raise HTTPException(status_code=503, detail="memory store unavailable")
    sessions = create_session_factory(database_url)
    with sessions() as session:
        lifecycle = session.scalar(select(LifecycleRow).where(LifecycleRow.singleton))
        if lifecycle is None or lifecycle.state != RejoiningState.READY:
            raise HTTPException(status_code=503, detail="Lucy is not ready")
    context = MemoryService(sessions).build_context(query)
    return {"query": query, "claims": context.claims, "read_only": True}
