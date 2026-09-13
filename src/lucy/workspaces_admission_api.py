"""Private HTTP boundary for content-free Workspaces admission."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from typing import Protocol

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from lucy.internal_admission import InternalAdmissionDenied
from lucy.workspaces_admission import (
    WorkspacesRoomAdmissionReceiptV1,
    WorkspacesRoomAdmissionRequestV1,
)


class WorkspacesAdmissionGateway(Protocol):
    def preflight(
        self,
        *,
        lucy_authority_credential: SecretStr,
        request: WorkspacesRoomAdmissionRequestV1,
        checked_at: datetime,
    ) -> WorkspacesRoomAdmissionReceiptV1: ...


class WorkspacesAdmissionAPISettingsV1(BaseModel):
    """Secrets stay in the private Cloud Lucy service configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    transport_token: SecretStr = Field(min_length=32)
    lucy_authority_credential: SecretStr = Field(min_length=1)


def create_workspaces_admission_app(
    *,
    settings: WorkspacesAdmissionAPISettingsV1,
    gateway: WorkspacesAdmissionGateway,
) -> FastAPI:
    app = FastAPI(
        title="Cloud Lucy Workspaces Admission API",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.exception_handler(InternalAdmissionDenied)
    def admission_denied(_request: Request, _error: Exception) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": "request not authorized"})

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(
        "/v1/workspaces/rooms/admit",
        response_model=WorkspacesRoomAdmissionReceiptV1,
    )
    async def admit_room(
        http_request: Request,
        authorization: str | None = Header(default=None),
    ) -> WorkspacesRoomAdmissionReceiptV1:
        expected = f"Bearer {settings.transport_token.get_secret_value()}"
        if authorization is None or not secrets.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="invalid Workspaces credential")
        body = await http_request.body()
        if len(body) > 4096:
            raise HTTPException(status_code=413, detail="Workspaces request is too large")
        try:
            request = WorkspacesRoomAdmissionRequestV1.model_validate(json.loads(body))
        except (json.JSONDecodeError, ValidationError):
            raise HTTPException(status_code=422, detail="invalid Workspaces request") from None
        return gateway.preflight(
            lucy_authority_credential=settings.lucy_authority_credential,
            request=request,
            checked_at=datetime.now(UTC),
        )

    return app
