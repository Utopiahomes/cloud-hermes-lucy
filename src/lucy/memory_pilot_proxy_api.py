"""Public, database-free proxy for one commissioned private-memory pilot intake."""

from __future__ import annotations

import re
from typing import Annotated, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException
from fastapi import Request as FastAPIRequest
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError
from starlette.concurrency import run_in_threadpool

from lucy.contracts.canonical import canonical_json_bytes
from lucy.memory_pilot_intake_api import (
    MemoryPilotExecutionResponseV1,
    _bounded_body,
    _install_common_intake_routes,
    _validate_wire_headers,
)
from lucy.memory_pilot_transport import MemoryPilotTransportBatchV1

_PRIVATE_HOSTPORT = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?:[1-9][0-9]{1,4}\Z")


class MemoryPilotProxyUnavailable(RuntimeError):
    """The private execution result could not be established safely."""


class MemoryPilotPrivateTransport(Protocol):
    def __call__(
        self,
        url: str,
        body: bytes,
        gateway_authorization: str,
        capability_authorization: str,
        timeout_seconds: int,
    ) -> bytes: ...


class MemoryPilotProxyConfigurationV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    private_executor_hostport: str = Field(min_length=3, max_length=100)
    gateway_bearer_token: SecretStr = Field(exclude=True)
    maximum_request_bytes: int = Field(default=2_000_000, ge=1, le=10_000_000)
    maximum_response_bytes: int = Field(default=10_000_000, ge=1, le=10_000_000)
    private_timeout_seconds: int = Field(default=180, ge=1, le=600)

    def private_url(self, batch_id: UUID) -> str:
        if _PRIVATE_HOSTPORT.fullmatch(self.private_executor_hostport) is None:
            raise ValueError("private executor host binding is invalid")
        return f"http://{self.private_executor_hostport}/v1/private-memory/pilot/batches/{batch_id}"


def create_memory_pilot_proxy_app(
    configuration: MemoryPilotProxyConfigurationV1,
    *,
    transport: MemoryPilotPrivateTransport | None = None,
) -> FastAPI:
    """Build a fixed-realm proxy with no database, AWS, provider, or tenant selector."""

    private_transport = transport or _private_post
    app = FastAPI(
        title="Private Lucy pilot transfer gateway",
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
    async def forward_batch(
        batch_id: UUID,
        request: FastAPIRequest,
        authorization: Annotated[str | None, Header()] = None,
    ) -> MemoryPilotExecutionResponseV1:
        _validate_wire_headers(request)
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="bearer capability required")
        body = await _bounded_body(request, maximum_bytes=configuration.maximum_request_bytes)
        try:
            gateway_token = configuration.gateway_bearer_token.get_secret_value()
            if not 32 <= len(gateway_token) <= 512:
                raise ValueError("gateway credential length is invalid")
            batch = MemoryPilotTransportBatchV1.model_validate_json(body)
            if batch.batch_id != batch_id or body != canonical_json_bytes(batch):
                raise ValueError("pilot wire identity differs")
            raw = await run_in_threadpool(
                private_transport,
                configuration.private_url(batch_id),
                body,
                f"Bearer {gateway_token}",
                authorization,
                configuration.private_timeout_seconds,
            )
            if not raw or len(raw) > configuration.maximum_response_bytes:
                raise ValueError("private response is outside its byte ceiling")
            response = MemoryPilotExecutionResponseV1.model_validate_json(raw)
            if (
                response.receipt.campaign_id != batch.campaign_id
                or response.receipt.batch_id != batch.batch_id
                or response.receipt.extraction_job_id != batch.dispatch.extraction_job_id
            ):
                raise ValueError("private response identity differs")
            return response
        except (MemoryPilotProxyUnavailable, ValidationError, ValueError) as exc:
            raise HTTPException(status_code=503, detail="pilot execution unavailable") from exc

    return app


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _private_post(
    url: str,
    body: bytes,
    gateway_authorization: str,
    capability_authorization: str,
    timeout_seconds: int,
) -> bytes:
    request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": gateway_authorization,
            "X-Lucy-Pilot-Capability": capability_authorization,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Cache-Control": "no-store",
        },
    )
    try:
        with build_opener(_RejectRedirects()).open(request, timeout=timeout_seconds) as response:
            return bytes(response.read(10_000_001))
    except (HTTPError, URLError, TimeoutError) as exc:
        raise MemoryPilotProxyUnavailable("private pilot request failed") from exc
