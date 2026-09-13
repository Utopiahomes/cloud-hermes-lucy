"""Private HTTP boundary for Workspaces admission and bounded operations."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from typing import Literal, Protocol
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from lucy.contracts.security_v1_3 import ResolvedExecutionContextV1
from lucy.internal_admission import InternalAdmissionDenied
from lucy.workspaces_admission import (
    WorkspacesExperienceGateway,
    WorkspacesRoomAdmissionReceiptV1,
    WorkspacesRoomAdmissionRequestV1,
)
from lucy.workspaces_operations import WorkspacesOperationUnavailable


class WorkspacesKnowledgeQueryV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    question: str = Field(min_length=2, max_length=500)


class WorkspacesKnowledgeAnswerV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    room_id: UUID
    answer: str
    source: str
    version: int = Field(ge=1)
    snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class WorkspacesTaskRequestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    instruction: str = Field(min_length=2, max_length=2000)


class WorkspacesTaskReceiptV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    room_id: UUID
    task_id: UUID
    status: Literal["accepted"] = "accepted"


class WorkspacesOperationService(Protocol):
    def query_knowledge(
        self,
        *,
        context: ResolvedExecutionContextV1,
        question: str,
    ) -> tuple[str, str, int, str]: ...

    def delegate_task(
        self,
        *,
        context: ResolvedExecutionContextV1,
        request_id: UUID,
        instruction: str,
    ) -> UUID: ...


class WorkspacesAdmissionAPISettingsV1(BaseModel):
    """Secrets stay in the private Cloud Lucy service configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    transport_token: SecretStr = Field(min_length=32)
    lucy_authority_credential: SecretStr = Field(min_length=1)


def create_workspaces_admission_app(
    *,
    settings: WorkspacesAdmissionAPISettingsV1,
    gateway: WorkspacesExperienceGateway,
    operations: WorkspacesOperationService | None = None,
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

    @app.exception_handler(WorkspacesOperationUnavailable)
    def operation_unavailable(_request: Request, _error: Exception) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": "operation unavailable"})

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

    @app.post(
        "/v1/workspaces/rooms/{room_id}/knowledge/query",
        response_model=WorkspacesKnowledgeAnswerV1,
    )
    async def query_knowledge(
        room_id: UUID,
        http_request: Request,
        authorization: str | None = Header(default=None),
    ) -> WorkspacesKnowledgeAnswerV1:
        _authorize(settings, authorization)
        try:
            request = WorkspacesKnowledgeQueryV1.model_validate(
                _bounded_json(await http_request.body())
            )
        except ValidationError:
            raise HTTPException(status_code=422, detail="invalid Workspaces request") from None
        if operations is None:
            raise HTTPException(status_code=503, detail="Workspaces operation unavailable")
        answer, source, version, digest = gateway.execute(
            lucy_authority_credential=settings.lucy_authority_credential,
            request_id=request.request_id,
            room_id=room_id,
            capability="memory.read",
            checked_at=datetime.now(UTC),
            effect=lambda context: operations.query_knowledge(
                context=context, question=request.question
            ),
        )
        return WorkspacesKnowledgeAnswerV1(
            request_id=request.request_id,
            room_id=room_id,
            answer=answer,
            source=source,
            version=version,
            snapshot_digest=digest,
        )

    @app.post(
        "/v1/workspaces/rooms/{room_id}/tasks",
        response_model=WorkspacesTaskReceiptV1,
        status_code=202,
    )
    async def delegate_task(
        room_id: UUID,
        http_request: Request,
        authorization: str | None = Header(default=None),
    ) -> WorkspacesTaskReceiptV1:
        _authorize(settings, authorization)
        try:
            request = WorkspacesTaskRequestV1.model_validate(
                _bounded_json(await http_request.body())
            )
        except ValidationError:
            raise HTTPException(status_code=422, detail="invalid Workspaces request") from None
        if operations is None:
            raise HTTPException(status_code=503, detail="Workspaces operation unavailable")
        task_id = gateway.execute(
            lucy_authority_credential=settings.lucy_authority_credential,
            request_id=request.request_id,
            room_id=room_id,
            capability="task.delegate",
            checked_at=datetime.now(UTC),
            effect=lambda context: operations.delegate_task(
                context=context,
                request_id=request.request_id,
                instruction=request.instruction,
            ),
        )
        return WorkspacesTaskReceiptV1(
            request_id=request.request_id,
            room_id=room_id,
            task_id=task_id,
        )

    return app


def _authorize(
    settings: WorkspacesAdmissionAPISettingsV1, authorization: str | None
) -> None:
    expected = f"Bearer {settings.transport_token.get_secret_value()}"
    if authorization is None or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="invalid Workspaces credential")


def _bounded_json(body: bytes) -> object:
    if len(body) > 4096:
        raise HTTPException(status_code=413, detail="Workspaces request is too large")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="invalid Workspaces request") from None
