"""Minimal synchronous HTTP admission surface for exact private-memory pilot batches."""

from __future__ import annotations

import base64
import binascii
import secrets
from collections.abc import Callable
from typing import Annotated, Protocol
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError
from starlette.middleware.base import RequestResponseEndpoint

from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_candidate_review import CandidateReviewBundleArtifactV1
from lucy.memory_pilot_transport import (
    MemoryPilotTransportAdmissionReceiptV1,
    MemoryPilotTransportBatchV1,
    MemoryPilotTransportUnavailable,
)
from lucy.memory_pilot_transport_runner import (
    MemoryPilotTransportExecutionReceiptV1,
    MemoryPilotTransportExecutionResult,
)


class MemoryPilotBatchAdmission(Protocol):
    def admit(
        self, batch: MemoryPilotTransportBatchV1, *, capability_token: bytes
    ) -> MemoryPilotTransportAdmissionReceiptV1: ...


class MemoryPilotBatchExecutor(Protocol):
    def execute(
        self, batch: MemoryPilotTransportBatchV1, *, capability_token: bytes
    ) -> MemoryPilotTransportExecutionResult: ...


class MemoryPilotExecutionResponseV1(BaseModel):
    """Sensitive synchronous response intended only for protected local intake."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    receipt: MemoryPilotTransportExecutionReceiptV1
    review_artifact: CandidateReviewBundleArtifactV1 | None


class MemoryPilotIntakeConfigurationV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    maximum_request_bytes: int = Field(default=2_000_000, ge=1, le=10_000_000)
    gateway_bearer_token: SecretStr | None = Field(default=None, exclude=True)


def create_memory_pilot_intake_app(
    admission: MemoryPilotBatchAdmission,
    *,
    configuration: MemoryPilotIntakeConfigurationV1 | None = None,
) -> FastAPI:
    """Build a docs-free intake app that admits one synchronous batch request."""

    settings = configuration or MemoryPilotIntakeConfigurationV1()
    app = FastAPI(
        title="Private Lucy memory pilot intake",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    _install_common_intake_routes(app)

    @app.post(
        "/v1/private-memory/pilot/batches/{batch_id}",
        response_model=MemoryPilotTransportAdmissionReceiptV1,
    )
    async def admit_batch(
        batch_id: UUID,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> MemoryPilotTransportAdmissionReceiptV1:
        _validate_wire_headers(request)
        capability = _bearer_capability(authorization)
        body = await _bounded_body(request, maximum_bytes=settings.maximum_request_bytes)
        try:
            batch = MemoryPilotTransportBatchV1.model_validate_json(body)
            if body != canonical_json_bytes(batch):
                raise ValueError("request body is not exact canonical JSON")
            if batch.batch_id != batch_id:
                raise ValueError("path and payload batch IDs differ")
            return admission.admit(batch, capability_token=capability)
        except (MemoryPilotTransportUnavailable, ValidationError, ValueError) as exc:
            raise HTTPException(status_code=403, detail="pilot batch unavailable") from exc

    return app


def create_memory_pilot_execution_app(
    executor: MemoryPilotBatchExecutor,
    *,
    configuration: MemoryPilotIntakeConfigurationV1 | None = None,
) -> FastAPI:
    """Build the commissioned intake that executes and returns protected review data."""

    settings = configuration or MemoryPilotIntakeConfigurationV1()
    app = FastAPI(
        title="Private Lucy memory pilot execution intake",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    _install_common_intake_routes(app)

    @app.post(
        "/v1/private-memory/pilot/batches/{batch_id}",
        response_model=MemoryPilotExecutionResponseV1,
    )
    async def execute_batch(
        batch_id: UUID,
        request: Request,
        response: Response,
        authorization: Annotated[str | None, Header()] = None,
        x_lucy_pilot_capability: Annotated[str | None, Header()] = None,
    ) -> MemoryPilotExecutionResponseV1:
        _validate_wire_headers(request)
        capability_authorization = authorization
        if settings.gateway_bearer_token is not None:
            gateway_token = settings.gateway_bearer_token.get_secret_value()
            if not 32 <= len(gateway_token) <= 512:
                raise HTTPException(status_code=503, detail="gateway configuration invalid")
            if authorization is None or not secrets.compare_digest(
                authorization, f"Bearer {gateway_token}"
            ):
                raise HTTPException(status_code=401, detail="gateway credential invalid")
            capability_authorization = x_lucy_pilot_capability
        capability = _bearer_capability(capability_authorization)
        body = await _bounded_body(request, maximum_bytes=settings.maximum_request_bytes)
        try:
            batch = MemoryPilotTransportBatchV1.model_validate_json(body)
            if body != canonical_json_bytes(batch):
                raise ValueError("request body is not exact canonical JSON")
            if batch.batch_id != batch_id:
                raise ValueError("path and payload batch IDs differ")
            result = executor.execute(batch, capability_token=capability)
            return MemoryPilotExecutionResponseV1(
                receipt=result.receipt,
                review_artifact=result.review_artifact,
            )
        except (MemoryPilotTransportUnavailable, ValidationError, ValueError) as exc:
            raise HTTPException(status_code=403, detail="pilot batch unavailable") from exc
        except (PermissionError, RuntimeError) as exc:
            raise HTTPException(status_code=503, detail="pilot execution unavailable") from exc

    return app


def _install_common_intake_routes(app: FastAPI) -> None:
    @app.middleware("http")
    async def no_store(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}


def _validate_wire_headers(request: Request) -> None:
    content_type = request.headers.get("content-type", "")
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(status_code=415, detail="application/json required")
    content_encoding = request.headers.get("content-encoding")
    if content_encoding is not None and content_encoding.strip().lower() != "identity":
        raise HTTPException(status_code=415, detail="content encoding unsupported")


async def _bounded_body(request: Request, *, maximum_bytes: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > maximum_bytes:
                raise HTTPException(status_code=413, detail="request too large")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid content length") from exc
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > maximum_bytes:
            raise HTTPException(status_code=413, detail="request too large")
    if not body:
        raise HTTPException(status_code=400, detail="request body required")
    return bytes(body)


def _bearer_capability(value: str | None) -> bytes:
    if value is None or not value.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="bearer capability required")
    encoded = value.removeprefix("Bearer ")
    if not encoded or "=" in encoded:
        raise HTTPException(status_code=401, detail="bearer capability invalid")
    try:
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=401, detail="bearer capability invalid") from exc
    if len(decoded) != 32:
        raise HTTPException(status_code=401, detail="bearer capability invalid")
    return decoded


MemoryPilotIntakeFactory = Callable[[], FastAPI]
