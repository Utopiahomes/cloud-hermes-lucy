"""Minimal synchronous HTTP admission surface for exact private-memory pilot batches."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
from typing import Annotated, Protocol
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

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

    @app.post(
        "/v1/private-memory/pilot/batches/{batch_id}",
        response_model=MemoryPilotTransportAdmissionReceiptV1,
    )
    async def admit_batch(
        batch_id: UUID,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> MemoryPilotTransportAdmissionReceiptV1:
        capability = _bearer_capability(authorization)
        body = await _bounded_body(request, maximum_bytes=settings.maximum_request_bytes)
        try:
            batch = MemoryPilotTransportBatchV1.model_validate_json(body)
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

    @app.post(
        "/v1/private-memory/pilot/batches/{batch_id}",
        response_model=MemoryPilotExecutionResponseV1,
    )
    async def execute_batch(
        batch_id: UUID,
        request: Request,
        response: Response,
        authorization: Annotated[str | None, Header()] = None,
    ) -> MemoryPilotExecutionResponseV1:
        response.headers["Cache-Control"] = "no-store"
        capability = _bearer_capability(authorization)
        body = await _bounded_body(request, maximum_bytes=settings.maximum_request_bytes)
        try:
            batch = MemoryPilotTransportBatchV1.model_validate_json(body)
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
