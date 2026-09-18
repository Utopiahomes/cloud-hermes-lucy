"""Inert staging identity workload used before Tiamat activation.

This service exposes no inference or recovery mutation endpoint. It exists only so Render assigns
an exact OIDC workload subject before AWS trust policies are provisioned.
"""

from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(title="Tiamat staging identity", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"status": "disabled", "provider_dispatch": False},
        headers={"Cache-Control": "no-store"},
    )
