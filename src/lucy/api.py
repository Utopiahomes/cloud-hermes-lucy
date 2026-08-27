"""Minimal companion API; domain operations will be added by the vertical slice."""

from fastapi import FastAPI

app = FastAPI(title="Lucy Companion API", version="0.1.0")


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/memory/lookup", tags=["memory"])
def read_only_memory_lookup(query: str) -> dict[str, object]:
    """Compatibility-spike endpoint; it intentionally performs no mutation."""

    return {"query": query, "claims": [], "read_only": True}

