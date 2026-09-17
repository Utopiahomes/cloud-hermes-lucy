"""Private FastAPI transport for the local Tiamat RC1 executor slice."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

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
from lucy.shared_execution.wire import ExecutionRequest

PATH = "/execution/v1/inference"
UUID4 = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
BODY_HASH = re.compile(r"^[A-Za-z0-9_-]{43}$")
ERRORS: dict[str, tuple[int, str, bool]] = {
    "invalid_request": (400, "The execution request is invalid.", False),
    "authentication_failed": (401, "Service authentication failed.", False),
    "capability_forbidden": (403, "This execution capability is not permitted.", False),
    "request_in_progress": (409, "The execution request is already in progress.", True),
    "idempotency_conflict": (409, "The idempotency key conflicts with an earlier request.", False),
    "request_too_large": (413, "The execution request is too large.", False),
    "unsupported_media_type": (415, "The execution request media type is not supported.", False),
    "response_media_not_acceptable": (
        406,
        "The requested response media type is not supported.",
        False,
    ),
    "output_contract_unsupported": (422, "The requested output contract is not supported.", False),
    "cost_ceiling_insufficient": (422, "The execution cost ceiling is insufficient.", False),
    "provider_execution_failed": (502, "The model execution failed.", False),
    "provider_response_invalid": (502, "The model returned an unusable result.", False),
    "provider_response_too_large": (502, "The model response is too large.", False),
    "output_limit_reached": (502, "The model reached its output limit.", False),
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
}


@dataclass(frozen=True)
class ApiRelease:
    execution: str
    policy: str


def create_shared_execution_app(
    service: SharedExecutionService,
    verifier: WorkloadJwtVerifier,
    release: ApiRelease,
) -> FastAPI:
    app = FastAPI(title="Tiamat Shared Model Execution", docs_url=None, redoc_url=None)

    @app.post(PATH)
    async def inference(http_request: Request) -> JSONResponse:
        body = await http_request.body()
        if len(body) > 1_048_576:
            return JSONResponse(status_code=413, content={"detail": "request rejected"})

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
            return _error("authentication_state_unavailable", request_id=None)
        except AuthenticationFailed:
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
            payload = json.loads(body)
            request = ExecutionRequest.model_validate(payload)
        except (json.JSONDecodeError, UnicodeError, ValidationError):
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
            return _error(exc.code, request_id=request_id_text, release=release)
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


def _single(request: Request, name: str) -> str | None:
    values = request.headers.getlist(name)
    return values[0] if len(values) == 1 else None


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
