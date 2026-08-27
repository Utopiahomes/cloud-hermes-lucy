"""Narrow companion API exposed to the pinned Hermes runtime."""

import os

from fastapi import FastAPI

from lucy.db import create_session_factory
from lucy.memory import MemoryService

app = FastAPI(title="Lucy Companion API", version="0.1.0")


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/memory/lookup", tags=["memory"])
def read_only_memory_lookup(query: str) -> dict[str, object]:
    """Return a bounded projection; never expose or mutate archive evidence."""

    database_url = os.getenv("LUCY_DATABASE_URL")
    if database_url is None:
        return {"query": query, "claims": [], "read_only": True}
    context = MemoryService(create_session_factory(database_url)).build_context(query)
    return {"query": query, "claims": context.claims, "read_only": True}
