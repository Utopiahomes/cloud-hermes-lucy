"""Private FastAPI transport for the local Tiamat RC1 executor slice."""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.middleware.base import RequestResponseEndpoint
from starlette.requests import ClientDisconnect
from starlette.responses import Response

from lucy.shared_execution.auth import (
    AuthenticationFailed,
    AuthenticationStateUnavailable,
    WorkloadJwtVerifier,
    content_sha256,
)
from lucy.shared_execution.service import (
    ExecutionFailure,
    ExecutionInProgress,
    IdempotencyConflict,
    SharedExecutionService,
)
from lucy.shared_execution.wire import CostReceipt, ExecutionRequest

PATH = "/execution/v1/inference"
UUID4 = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
BODY_HASH = re.compile(r"^[A-Za-z0-9_-]{43}$")
ERRORS: dict[str, tuple[int, str, bool]] = {
    "invalid_request": (400, "The execution request is invalid.", False),
    "authentication_failed": (401, "Service authentication failed.", False),
    "capability_forbidden": (403, "This execution capability is not permitted.", False),
    "route_not_found": (404, "The requested execution route was not found.", False),
    "method_not_allowed": (405, "The execution method is not allowed.", False),
    "request_in_progress": (409, "The execution request is already in progress.", True),
    "idempotency_conflict": (409, "The idempotency key conflicts with an earlier request.", False),
    "request_too_large": (413, "The execution request is too large.", False),
    "unsupported_media_type": (415, "The execution request media type is not supported.", False),
    "response_media_not_acceptable": (
        406,
        "The requested response media type is not supported.",
        False,
    ),
    "execution_aborted": (409, "The execution ended before model dispatch.", False),
    "output_contract_unsupported": (422, "The requested output contract is not supported.", False),
    "cost_ceiling_insufficient": (422, "The execution cost ceiling is insufficient.", False),
    "idempotency_recovery_unavailable": (
        409,
        "The earlier execution result is no longer available.",
        False,
    ),
    "execution_outcome_unknown": (
        409,
        "The execution outcome could not be determined.",
        False,
    ),
    "execution_invalidated": (
        409,
        "The earlier execution result is no longer eligible.",
        False,
    ),
    "rate_limited": (429, "Execution capacity is temporarily limited.", True),
    "provider_execution_failed": (502, "The model execution failed.", False),
    "provider_response_invalid": (502, "The model returned an unusable result.", False),
    "provider_response_too_large": (502, "The model response is too large.", False),
    "output_limit_reached": (502, "The model reached its output limit.", False),
    "content_filtered": (502, "The model response was filtered.", False),
    "cost_settlement_violation": (
        502,
        "The provider charge exceeded its reservation.",
        False,
    ),
    "authentication_state_unavailable": (
        503,
        "Service authentication state is temporarily unavailable.",
        True,
    ),
    "privacy_route_unavailable": (
        503,
        "No approved private execution route is available.",
        False,
    ),
    "state_store_unavailable": (
        503,
        "Execution state is temporarily unavailable.",
        True,
    ),
    "spending_authority_exhausted": (
        503,
        "Execution spending authority is unavailable.",
        False,
    ),
    "temporarily_unavailable": (
        503,
        "Model execution is temporarily unavailable.",
        True,
    ),
    "deadline_exceeded": (504, "Model execution exceeded its deadline.", False),
}


@dataclass(frozen=True)
class ApiRelease:
    execution: str
    policy: str


def create_shared_execution_app(
    service: SharedExecutionService,
    verifier: WorkloadJwtVerifier,
    release: ApiRelease,
    *,
    authentication_failure_delay: Callable[[float], Awaitable[None]] | None = None,
) -> FastAPI:
    app = FastAPI(title="Tiamat Shared Model Execution", docs_url=None, redoc_url=None)
    delay_authentication_failure = (
        authentication_failure_delay or _default_authentication_failure_delay
    )

    @app.middleware("http")
    async def route_method_gate(
        http_request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if http_request.url.path != PATH:
            return _error("route_not_found", request_id=None)
        if http_request.method != "POST":
            return _error("method_not_allowed", request_id=None)
        return await call_next(http_request)

    @app.post(PATH)
    async def inference(http_request: Request) -> JSONResponse:
        framing = _content_length(http_request)
        if framing is None:
            return _transport_rejection(400)
        if framing > 1_048_576:
            return _transport_rejection(413)
        try:
            body = await _bounded_body(http_request, 1_048_576)
        except (ClientDisconnect, ValueError):
            return _transport_rejection(400)
        if body is None:
            return _transport_rejection(413)
        if framing >= 0 and framing != len(body):
            return _transport_rejection(400)

        authentication_started = time.perf_counter()
        request_id_text = _single(http_request, "X-Request-ID")
        idempotency_key = _single(http_request, "Idempotency-Key")
        declared_hash = _single(http_request, "X-Content-SHA256")
        authorization = _single(http_request, "Authorization")
        if (
            idempotency_key is None
            or UUID4.fullmatch(idempotency_key) is None
            or declared_hash is None
            or BODY_HASH.fullmatch(declared_hash) is None
            or authorization is None
        ):
            await delay_authentication_failure(authentication_started)
            return _error("authentication_failed", request_id=None)
        try:
            verifier.verify(
                authorization,
                method="POST",
                path=PATH,
                idempotency_key=idempotency_key,
                declared_body_hash=declared_hash,
            )
        except AuthenticationStateUnavailable:
            await delay_authentication_failure(authentication_started)
            return _error("authentication_state_unavailable", request_id=None)
        except AuthenticationFailed:
            await delay_authentication_failure(authentication_started)
            return _error("authentication_failed", request_id=None)

        request_id = _valid_uuid4(request_id_text)
        timeout = _timeout(_single(http_request, "X-Execution-Timeout-Ms"))
        if request_id is None or timeout is None:
            return _error("invalid_request", request_id=request_id_text, release=release)
        if _single(http_request, "Content-Type") != "application/json":
            return _error("unsupported_media_type", request_id=request_id_text, release=release)
        if _single(http_request, "Accept") != "application/json":
            return _error(
                "response_media_not_acceptable", request_id=request_id_text, release=release
            )
        if len(body) > 262_144:
            return _error("request_too_large", request_id=request_id_text, release=release)
        if content_sha256(body) != declared_hash:
            return _error("authentication_failed", request_id=None)

        try:
            payload = json.loads(body, parse_constant=_reject_non_json_number)
            request = ExecutionRequest.model_validate(payload)
        except (json.JSONDecodeError, UnicodeError, ValidationError, ValueError):
            return _error("invalid_request", request_id=request_id_text, release=release)
        if request.execution_profile_id not in verifier.identity.execution_profiles:
            return _error("capability_forbidden", request_id=request_id_text, release=release)

        try:
            response = service.execute(
                caller=verifier.identity.subject,
                idempotency_key=idempotency_key,
                request_id=request_id,
                request=request,
            )
        except IdempotencyConflict:
            return _error("idempotency_conflict", request_id=request_id_text, release=release)
        except ExecutionInProgress:
            return _error(
                "request_in_progress",
                request_id=request_id_text,
                release=release,
                retry_after=1,
            )
        except PermissionError:
            return _error("capability_forbidden", request_id=request_id_text, release=release)
        except ValueError as exc:
            code = (
                "cost_ceiling_insufficient"
                if "cost ceiling" in str(exc)
                else "output_contract_unsupported"
            )
            return _error(code, request_id=request_id_text, release=release)
        except ExecutionFailure as exc:
            return _error(
                exc.code,
                request_id=request_id_text,
                release=release,
                execution=(exc.execution_id, exc.execution_state),
                cost=exc.cost,
            )
        except RuntimeError:
            return _error("provider_execution_failed", request_id=request_id_text, release=release)

        assert request_id_text is not None
        response_content = response.model_dump(mode="json", by_alias=True)
        # RC1 echoes the valid inbound spelling exactly, including accepted UUID hex case.
        response_content["request_id"] = request_id_text
        return JSONResponse(
            status_code=200,
            content=response_content,
            headers=_authenticated_headers(request_id_text, release),
        )

    return app


async def _default_authentication_failure_delay(started_at: float) -> None:
    """Place every step-3 rejection in one fixed-minimum, bounded-jitter timing class."""

    jitter = secrets.randbelow(10_001) / 1_000_000
    remaining = 0.05 + jitter - (time.perf_counter() - started_at)
    if remaining > 0:
        await asyncio.sleep(remaining)


def _single(request: Request, name: str) -> str | None:
    values = request.headers.getlist(name)
    return values[0] if len(values) == 1 else None


def _content_length(request: Request) -> int | None:
    lengths = request.headers.getlist("content-length")
    transfer_encodings = request.headers.getlist("transfer-encoding")
    if len(lengths) > 1 or len(transfer_encodings) > 1 or (lengths and transfer_encodings):
        return None
    if transfer_encodings:
        return -1 if transfer_encodings[0].strip().lower() == "chunked" else None
    if not lengths:
        return -1
    if not lengths[0].isascii() or not lengths[0].isdigit():
        return None
    return int(lengths[0])


async def _bounded_body(request: Request, maximum: int) -> bytes | None:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > maximum:
            return None
    return bytes(body)


def _transport_rejection(status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"detail": "request rejected"},
        headers={"Cache-Control": "no-store"},
    )


def _valid_uuid4(value: str | None) -> UUID | None:
    if value is None or UUID4.fullmatch(value) is None:
        return None
    return UUID(value)


def _timeout(value: str | None) -> int | None:
    try:
        parsed = int(value or "")
    except ValueError:
        return None
    return parsed if 1000 <= parsed <= 18_000 else None


def _reject_non_json_number(value: str) -> None:
    raise ValueError(f"non-JSON number is prohibited: {value}")


def _authenticated_headers(request_id: str, release: ApiRelease) -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "X-Request-ID": request_id,
        "X-Stoin-Execution-Release": release.execution,
        "X-Stoin-Execution-Policy-Release": release.policy,
    }


def _error(
    code: str,
    *,
    request_id: str | None,
    release: ApiRelease | None = None,
    retry_after: int | None = None,
    execution: tuple[UUID, str] | None = None,
    cost: CostReceipt | None = None,
) -> JSONResponse:
    status, message, retryable = ERRORS[code]
    correlation_id = str(uuid4())
    content: dict[str, object] = {
        "contract": "stoin.inference.execute.error.v1",
        "correlation_id": correlation_id,
        "error": {"code": code, "message": message, "retryable": retryable},
    }
    headers = {"Cache-Control": "no-store", "X-Correlation-ID": correlation_id}
    if request_id is not None and UUID4.fullmatch(request_id):
        content["request_id"] = request_id
        headers["X-Request-ID"] = request_id
    if execution is not None:
        content["execution"] = {
            "execution_id": str(execution[0]),
            "state": execution[1],
        }
    if cost is not None:
        content["cost"] = cost.model_dump(mode="json")
    if release is not None:
        headers.update(
            {
                "X-Stoin-Execution-Release": release.execution,
                "X-Stoin-Execution-Policy-Release": release.policy,
            }
        )
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return JSONResponse(status_code=status, content=content, headers=headers)
