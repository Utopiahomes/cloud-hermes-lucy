"""Authenticated, read-only HTTP surface for approved public projections."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

from lucy.public_contracts import PublicHistoryTurn, PublicPageContext
from lucy.public_diagnostics import (
    PublicDiagnosticReceipt,
    PublicDiagnosticStore,
    receipt_now,
)
from lucy.public_model_service import (
    HttpPublicModelClient,
    PublicModelServiceRequest,
    PublicModelServiceUnavailable,
)
from lucy.public_retrieval import PublicKnowledgeRetriever
from lucy.publication import PublicProjectionReader
from lucy.readiness import ReadinessError, admitted_session_factory
from lucy.tenancy import ScopeNotFound

_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_PUBLIC_LOGIN = re.compile(r"lucy_[a-z][a-z0-9]{0,30}_public\Z")
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LUCY_DATABASE = re.compile(r"lucy(?:_[a-z0-9]+)*\Z")
_RELEASE_ID = re.compile(r"[0-9a-f]{40}\Z")


class PublicApiConfigurationError(ValueError):
    """Content-free startup/configuration failure."""


class PublicQuestion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    question: str = Field(min_length=2, max_length=500)
    page_context: PublicPageContext | None = None
    history: tuple[PublicHistoryTurn, ...] = Field(default=(), max_length=6)

    @field_validator("question")
    @classmethod
    def normalize_question(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if len(normalized) < 2:
            raise ValueError("question is blank")
        return normalized

    @field_validator("history")
    @classmethod
    def bound_history(cls, value: tuple[PublicHistoryTurn, ...]) -> tuple[PublicHistoryTurn, ...]:
        if sum(len(turn.content) for turn in value) > 4_000:
            raise ValueError("conversation context is too large")
        return value


@dataclass(frozen=True)
class PublicApiConfiguration:
    database_url: str
    api_token: str
    allowed_origin: str
    site_hostname: str
    snapshot_digest: str
    storage_epoch: UUID
    max_request_bytes: int
    requests_per_ip_per_minute: int
    requests_per_session_per_minute: int
    session_ttl_seconds: int
    conversation_enabled: bool
    model_enabled: bool
    model_hostport: str | None
    model_token: str | None
    cost_commitment_key: bytes | None
    diagnostics_enabled: bool
    diagnostic_token: str | None
    release_id: str | None
    deployment_tier: str | None
    diagnostic_ttl_seconds: int
    diagnostic_maximum_receipts: int
    exercise_mode: bool
    exercise_concurrency_limit: int
    exercise_session_request_limit: int
    exercise_total_request_limit: int

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> PublicApiConfiguration:
        values = os.environ if environment is None else environment
        database_url = _required(values, "LUCY_DATABASE_URL")
        expected_login = _required(values, "LUCY_EXPECTED_DATABASE_LOGIN")
        try:
            parsed = make_url(database_url)
        except Exception as exc:
            raise PublicApiConfigurationError("public database URL is invalid") from exc
        if (
            parsed.drivername not in {"postgresql", "postgresql+psycopg"}
            or parsed.username != expected_login
            or _PUBLIC_LOGIN.fullmatch(expected_login) is None
            or not parsed.password
            or not parsed.host
            or not parsed.database
        ):
            raise PublicApiConfigurationError("public database identity is invalid")
        if values.get("LUCY_ENVIRONMENT") == "production" and (
            _PRIVATE_RENDER_HOST.fullmatch(parsed.host) is None
            or parsed.database is None
            or _LUCY_DATABASE.fullmatch(parsed.database) is None
            or parsed.port not in (None, 5432)
        ):
            raise PublicApiConfigurationError("public database boundary is invalid")

        api_token = _required(values, "LUCY_PUBLIC_API_TOKEN")
        if not 32 <= len(api_token) <= 512:
            raise PublicApiConfigurationError("public API credential is invalid")

        site_hostname = _required(values, "LUCY_PUBLIC_SITE_HOSTNAME").lower()
        allowed_origin = _required(values, "LUCY_PUBLIC_ALLOWED_ORIGIN")
        origin = urlsplit(allowed_origin)
        if (
            _HOSTNAME.fullmatch(site_hostname) is None
            or origin.scheme != "https"
            or origin.hostname != site_hostname
            or origin.port not in (None, 443)
            or origin.username is not None
            or origin.password is not None
            or origin.path not in ("", "/")
            or origin.query
            or origin.fragment
            or allowed_origin.rstrip("/") != f"https://{site_hostname}"
        ):
            raise PublicApiConfigurationError("public origin binding is invalid")

        snapshot_digest = _required(values, "LUCY_PUBLIC_SNAPSHOT_DIGEST")
        if _DIGEST.fullmatch(snapshot_digest) is None:
            raise PublicApiConfigurationError("public snapshot digest is invalid")
        try:
            storage_epoch = UUID(_required(values, "LUCY_STORAGE_EPOCH"))
        except ValueError as exc:
            raise PublicApiConfigurationError("public storage epoch is invalid") from exc

        conversation_enabled = _strict_bool(
            values.get("LUCY_PUBLIC_CONVERSATION_ENABLED", "false"),
            "LUCY_PUBLIC_CONVERSATION_ENABLED",
        )
        model_enabled = _strict_bool(
            values.get("LUCY_PUBLIC_MODEL_ENABLED", "false"),
            "LUCY_PUBLIC_MODEL_ENABLED",
        )
        model_hostport: str | None = None
        model_token: str | None = None
        cost_commitment_key: bytes | None = None
        if model_enabled:
            if not conversation_enabled:
                raise PublicApiConfigurationError(
                    "public model requires the conversation contract"
                )
            model_hostport = _required(values, "LUCY_PUBLIC_MODEL_HOSTPORT")
            model_token = _required(values, "LUCY_PUBLIC_MODEL_TOKEN")
            if not 32 <= len(model_token) <= 512:
                raise PublicApiConfigurationError("public model credential is invalid")
            try:
                # Validate the private destination during configuration so a malformed
                # host cannot escape the normal fail-closed API error path at first use.
                HttpPublicModelClient(model_hostport, model_token)
            except ValueError:
                raise PublicApiConfigurationError(
                    "public model destination is invalid"
                ) from None
            cost_commitment_key = _base64_key(
                values, "LUCY_PUBLIC_COST_COMMITMENT_KEY_B64"
            )

        diagnostics_enabled = _strict_bool(
            values.get("LUCY_PUBLIC_DIAGNOSTICS_ENABLED", "false"),
            "LUCY_PUBLIC_DIAGNOSTICS_ENABLED",
        )
        diagnostic_token = values.get("LUCY_PUBLIC_DIAGNOSTIC_TOKEN", "").strip() or None
        release_id = values.get("LUCY_PUBLIC_RELEASE_ID", "").strip() or None
        deployment_tier = values.get("LUCY_PUBLIC_DEPLOYMENT_TIER", "").strip() or None
        if diagnostics_enabled and (
            not model_enabled
            or diagnostic_token is None
            or not 32 <= len(diagnostic_token) <= 512
            or release_id is None
            or _RELEASE_ID.fullmatch(release_id) is None
            or deployment_tier not in {"staging", "production"}
        ):
            raise PublicApiConfigurationError("public diagnostic boundary is invalid")
        exercise_mode = _strict_bool(
            values.get("LUCY_PUBLIC_EXERCISE_MODE", "false"),
            "LUCY_PUBLIC_EXERCISE_MODE",
        )
        if exercise_mode and (not diagnostics_enabled or deployment_tier != "staging"):
            raise PublicApiConfigurationError("public exercise boundary is invalid")

        return cls(
            database_url=database_url,
            api_token=api_token,
            allowed_origin=allowed_origin.rstrip("/"),
            site_hostname=site_hostname,
            snapshot_digest=snapshot_digest,
            storage_epoch=storage_epoch,
            max_request_bytes=_bounded_int(
                values, "LUCY_PUBLIC_MAX_REQUEST_BYTES", 1024, 1_048_576
            ),
            requests_per_ip_per_minute=_bounded_int(
                values, "LUCY_PUBLIC_REQUESTS_PER_IP_PER_MINUTE", 1, 600
            ),
            requests_per_session_per_minute=_bounded_int(
                values, "LUCY_PUBLIC_REQUESTS_PER_SESSION_PER_MINUTE", 1, 600
            ),
            session_ttl_seconds=_bounded_int(
                values, "LUCY_PUBLIC_SESSION_TTL_SECONDS", 300, 86_400
            ),
            conversation_enabled=conversation_enabled,
            model_enabled=model_enabled,
            model_hostport=model_hostport,
            model_token=model_token,
            cost_commitment_key=cost_commitment_key,
            diagnostics_enabled=diagnostics_enabled,
            diagnostic_token=diagnostic_token,
            release_id=release_id,
            deployment_tier=deployment_tier,
            diagnostic_ttl_seconds=_bounded_int_default(
                values, "LUCY_PUBLIC_DIAGNOSTIC_TTL_SECONDS", 3_600, 60, 86_400
            ),
            diagnostic_maximum_receipts=_bounded_int_default(
                values, "LUCY_PUBLIC_DIAGNOSTIC_MAX_RECEIPTS", 200, 10, 10_000
            ),
            exercise_mode=exercise_mode,
            exercise_concurrency_limit=_bounded_int_default(
                values, "LUCY_PUBLIC_EXERCISE_CONCURRENCY_LIMIT", 2, 1, 20
            ),
            exercise_session_request_limit=_bounded_int_default(
                values, "LUCY_PUBLIC_EXERCISE_SESSION_REQUEST_LIMIT", 20, 1, 100
            ),
            exercise_total_request_limit=_bounded_int_default(
                values, "LUCY_PUBLIC_EXERCISE_TOTAL_REQUEST_LIMIT", 40, 1, 1_000
            ),
        )


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise PublicApiConfigurationError(f"required public configuration is missing: {name}")
    return value


def _bounded_int(values: Mapping[str, str], name: str, minimum: int, maximum: int) -> int:
    try:
        value = int(_required(values, name))
    except ValueError as exc:
        raise PublicApiConfigurationError(f"public limit is invalid: {name}") from exc
    if not minimum <= value <= maximum:
        raise PublicApiConfigurationError(f"public limit is invalid: {name}")
    return value


def _bounded_int_default(
    values: Mapping[str, str],
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = values.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise PublicApiConfigurationError(f"public limit is invalid: {name}") from exc
    if not minimum <= value <= maximum:
        raise PublicApiConfigurationError(f"public limit is invalid: {name}")
    return value


def _strict_bool(value: str, name: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise PublicApiConfigurationError(f"public flag is invalid: {name}")


def _base64_key(values: Mapping[str, str], name: str) -> bytes:
    try:
        decoded = base64.b64decode(_required(values, name), validate=True)
    except ValueError:
        raise PublicApiConfigurationError(f"public key is invalid: {name}") from None
    if len(decoded) < 32:
        raise PublicApiConfigurationError(f"public key is invalid: {name}")
    return decoded


@dataclass
class _Window:
    minute: int
    count: int


class _OpaqueRateLimiter:
    """One-instance limiter that retains only keyed commitments, never raw identifiers."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        commitment_key: bytes | None = None,
    ) -> None:
        self._clock = clock
        self._key = commitment_key or secrets.token_bytes(32)
        self._windows: dict[str, _Window] = {}
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()

    def allow(self, ip_address: str, session_id: UUID, config: PublicApiConfiguration) -> bool:
        now = self._clock()
        minute = int(now // 60)
        ip_key = self._commitment("ip", ip_address)
        session_key = self._commitment("session", str(session_id))
        with self._lock:
            first_seen = self._sessions.setdefault(session_key, now)
            if now - first_seen > config.session_ttl_seconds:
                return False
            if not self._increment(ip_key, minute, config.requests_per_ip_per_minute):
                return False
            if not self._increment(session_key, minute, config.requests_per_session_per_minute):
                return False
            self._prune(minute, now, config.session_ttl_seconds)
            return True

    def _commitment(self, kind: str, value: str) -> str:
        return hmac.new(self._key, f"{kind}\0{value}".encode(), hashlib.sha256).hexdigest()

    def _increment(self, key: str, minute: int, ceiling: int) -> bool:
        current = self._windows.get(key)
        if current is None or current.minute != minute:
            self._windows[key] = _Window(minute=minute, count=1)
            return True
        if current.count >= ceiling:
            return False
        current.count += 1
        return True

    def _prune(self, minute: int, now: float, session_ttl: int) -> None:
        self._windows = {
            key: value for key, value in self._windows.items() if value.minute >= minute - 1
        }
        self._sessions = {
            key: value for key, value in self._sessions.items() if now - value <= session_ttl * 2
        }


@dataclass
class _ExerciseSession:
    last_seen: float
    requests: int


class _ExerciseLimiter:
    """Bound a staging exercise independently of ordinary production rate limits."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._sessions: dict[UUID, _ExerciseSession] = {}
        self._active_requests = 0
        self._total_requests = 0
        self._lock = threading.Lock()

    def acquire(self, session_id: UUID, config: PublicApiConfiguration) -> bool:
        now = self._clock()
        with self._lock:
            self._sessions = {
                key: value
                for key, value in self._sessions.items()
                if now - value.last_seen <= config.session_ttl_seconds
            }
            current = self._sessions.get(session_id)
            if (
                self._active_requests >= config.exercise_concurrency_limit
                or self._total_requests >= config.exercise_total_request_limit
                or (
                    current is not None
                    and current.requests >= config.exercise_session_request_limit
                )
            ):
                return False
            if current is None:
                current = _ExerciseSession(last_seen=now, requests=0)
                self._sessions[session_id] = current
            current.last_seen = now
            current.requests += 1
            self._total_requests += 1
            self._active_requests += 1
            return True

    def release(self) -> None:
        with self._lock:
            if self._active_requests <= 0:
                raise RuntimeError("public exercise request accounting is unbalanced")
            self._active_requests -= 1


app = FastAPI(
    title="Lucy Public Projection API",
    version="1.0.0",
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
)
_limiter = _OpaqueRateLimiter()
_exercise_limiter = _ExerciseLimiter()
_retriever = PublicKnowledgeRetriever()


@lru_cache(maxsize=1)
def _configuration() -> PublicApiConfiguration:
    return PublicApiConfiguration.from_environment()


@lru_cache(maxsize=1)
def _reader() -> PublicProjectionReader:
    config = _configuration()
    sessions = admitted_session_factory(
        config.database_url,
        config.storage_epoch,
        journal=None,
        journal_required=False,
    )
    return PublicProjectionReader(sessions)


@lru_cache(maxsize=1)
def _model_client() -> HttpPublicModelClient:
    config = _configuration()
    if (
        not config.model_enabled
        or config.model_hostport is None
        or config.model_token is None
    ):
        raise PublicModelServiceUnavailable("public model service is disabled")
    return HttpPublicModelClient(config.model_hostport, config.model_token)


@lru_cache(maxsize=1)
def _diagnostic_store() -> PublicDiagnosticStore:
    config = _configuration()
    return PublicDiagnosticStore(
        ttl_seconds=config.diagnostic_ttl_seconds,
        maximum_receipts=config.diagnostic_maximum_receipts,
    )


def _cost_commitment(key: bytes, kind: str, value: str) -> str:
    return hmac.new(key, f"{kind}\0{value}".encode(), hashlib.sha256).hexdigest()


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/operations/public-diagnostic/{trace_id}", tags=["operations"])
def public_diagnostic(trace_id: str, request: Request) -> JSONResponse:
    try:
        config = _configuration()
    except PublicApiConfigurationError:
        return _response(404, "Diagnostic receipt is unavailable")
    if not config.diagnostics_enabled or config.diagnostic_token is None:
        return _response(404, "Diagnostic receipt is unavailable")
    authorization = request.headers.get("authorization")
    if authorization is None or not secrets.compare_digest(
        authorization, f"Bearer {config.diagnostic_token}"
    ):
        return _response(401, "Invalid diagnostic credential")
    try:
        identifier = UUID(trace_id)
    except ValueError:
        return _response(404, "Diagnostic receipt is unavailable")
    if identifier.version != 4 or str(identifier) != trace_id:
        return _response(404, "Diagnostic receipt is unavailable")
    receipt = _diagnostic_store().get(identifier)
    if receipt is None:
        return _response(404, "Diagnostic receipt is unavailable")
    return JSONResponse(
        status_code=200,
        content=receipt.model_dump(mode="json"),
        headers={"Cache-Control": "no-store"},
    )


@app.post("/v1/public/answer", tags=["public"])
async def public_answer(request: Request) -> JSONResponse:
    try:
        config = _configuration()
    except PublicApiConfigurationError:
        return _response(503, "Public Lucy is unavailable")

    authorization = request.headers.get("authorization")
    if authorization is None or not secrets.compare_digest(
        authorization, f"Bearer {config.api_token}"
    ):
        return _response(401, "Invalid public credential")
    origin = request.headers.get("origin")
    if origin is None or not secrets.compare_digest(origin, config.allowed_origin):
        return _response(403, "Origin is not allowed")
    site_hostname = request.headers.get("x-lucy-public-host", "").lower()
    if not secrets.compare_digest(site_hostname, config.site_hostname):
        return _response(403, "Hostname is not allowed")

    session_value = request.headers.get("x-lucy-public-session", "")
    try:
        session_id = UUID(session_value)
    except ValueError:
        return _response(400, "Invalid public session")
    if session_id.version != 4 or str(session_id) != session_value:
        return _response(400, "Invalid public session")
    if request.client is None or not _limiter.allow(request.client.host, session_id, config):
        return _response(429, "Public request limit reached")
    client_ip = request.client.host

    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return _response(415, "JSON request required")
    declared_length = request.headers.get("content-length")
    if declared_length is not None:
        try:
            if int(declared_length) > config.max_request_bytes:
                return _response(413, "Public request is too large")
        except ValueError:
            return _response(400, "Invalid public request")

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > config.max_request_bytes:
            return _response(413, "Public request is too large")
    try:
        payload = json.loads(body)
        question = PublicQuestion.model_validate(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, TypeError):
        return _response(400, "Invalid public request")

    try:
        if config.conversation_enabled:
            projection = _reader().knowledge_admitted(
                hostname=config.site_hostname,
                storage_epoch=config.storage_epoch,
            )
            if not secrets.compare_digest(projection.snapshot_digest, config.snapshot_digest):
                return _response(503, "Public Lucy is unavailable")
            if config.model_enabled:
                if config.cost_commitment_key is None:
                    return _response(503, "Public Lucy is unavailable")
                trace_id = uuid4()
                started = time.perf_counter()
                exercise_acquired = False
                if config.exercise_mode:
                    exercise_acquired = _exercise_limiter.acquire(session_id, config)
                    if not exercise_acquired:
                        return _response(429, "Public exercise limit reached")
                try:
                    try:
                        model_response = _model_client().answer(
                            PublicModelServiceRequest(
                                contract="lucy.public-model-request.v1",
                                request_id=trace_id,
                                snapshot_digest=projection.snapshot_digest,
                                session_commitment=_cost_commitment(
                                    config.cost_commitment_key, "session", str(session_id)
                                ),
                                ip_commitment=_cost_commitment(
                                    config.cost_commitment_key, "ip", client_ip
                                ),
                                question=question.question,
                                entries=projection.entries,
                                page_context=question.page_context,
                                history=question.history,
                            )
                        )
                    except PublicModelServiceUnavailable:
                        if (
                            config.diagnostics_enabled
                            and config.release_id is not None
                            and config.deployment_tier in {"staging", "production"}
                        ):
                            _diagnostic_store().put(
                                PublicDiagnosticReceipt(
                                    contract="lucy.public-diagnostic-receipt.v1",
                                    trace_id=trace_id,
                                    recorded_at=receipt_now(),
                                    environment=cast(
                                        Literal["staging", "production"],
                                        config.deployment_tier,
                                    ),
                                    cloud_release_id=config.release_id,
                                    snapshot_version=projection.version,
                                    snapshot_digest=projection.snapshot_digest,
                                    request_latency_ms=max(
                                        0,
                                        round(
                                            (time.perf_counter() - started) * 1_000
                                        ),
                                    ),
                                    outcome="unavailable",
                                )
                            )
                            return _response(
                                503,
                                "Public Lucy is unavailable",
                                extra_headers={
                                    "X-Lucy-Trace-Id": str(trace_id),
                                    "X-Lucy-Cloud-Release": config.release_id,
                                    "X-Lucy-Snapshot-Version": str(projection.version),
                                    "X-Lucy-Snapshot-Digest": projection.snapshot_digest,
                                },
                            )
                        raise
                finally:
                    if exercise_acquired:
                        _exercise_limiter.release()
                response_headers = {"Cache-Control": "no-store"}
                if config.diagnostics_enabled:
                    if (
                        model_response.diagnostic is None
                        or model_response.diagnostic.request_id != trace_id
                        or config.release_id is None
                        or config.deployment_tier not in {"staging", "production"}
                    ):
                        return _response(503, "Public Lucy is unavailable")
                    receipt = PublicDiagnosticReceipt(
                        contract="lucy.public-diagnostic-receipt.v1",
                        trace_id=trace_id,
                        recorded_at=receipt_now(),
                        environment=cast(
                            Literal["staging", "production"], config.deployment_tier
                        ),
                        cloud_release_id=config.release_id,
                        snapshot_version=projection.version,
                        snapshot_digest=projection.snapshot_digest,
                        request_latency_ms=max(
                            0, round((time.perf_counter() - started) * 1_000)
                        ),
                        outcome="completed",
                        model=model_response.diagnostic,
                    )
                    _diagnostic_store().put(receipt)
                    response_headers.update(
                        {
                            "X-Lucy-Trace-Id": str(trace_id),
                            "X-Lucy-Cloud-Release": config.release_id,
                            "X-Lucy-Snapshot-Version": str(projection.version),
                            "X-Lucy-Snapshot-Digest": projection.snapshot_digest,
                        }
                    )
                result = model_response.answer
            else:
                response_headers = {"Cache-Control": "no-store"}
                result = _retriever.retrieve(
                    question=question.question,
                    entries=projection.entries,
                    page_context=question.page_context,
                    history=question.history,
                )
            return JSONResponse(
                status_code=200,
                content={
                    "contract": "lucy.public-answer.v2",
                    "outcome": result.outcome,
                    "answer": result.answer,
                    **(
                        {"clarification": result.clarification}
                        if result.clarification is not None
                        else {}
                    ),
                    "sources": [item.model_dump(mode="json") for item in result.sources],
                    "links": [item.model_dump(mode="json") for item in result.links],
                    "version": projection.version,
                    "snapshot_digest": projection.snapshot_digest,
                },
                headers=response_headers,
            )
        answer = _reader().answer_admitted(
            hostname=config.site_hostname,
            question=question.question,
            storage_epoch=config.storage_epoch,
        )
    except ScopeNotFound:
        return _response(404, "Public answer is unavailable")
    except (ReadinessError, SQLAlchemyError, PublicModelServiceUnavailable):
        return _response(503, "Public Lucy is unavailable")
    if not secrets.compare_digest(answer.snapshot_digest, config.snapshot_digest):
        return _response(503, "Public Lucy is unavailable")
    return JSONResponse(
        status_code=200,
        content={
            "answer": answer.answer,
            "source": answer.source,
            "version": answer.version,
            "snapshot_digest": answer.snapshot_digest,
        },
        headers={"Cache-Control": "no-store"},
    )


def _response(
    status_code: int,
    detail: str,
    *,
    extra_headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    headers = {"Cache-Control": "no-store"}
    if extra_headers is not None:
        headers.update(extra_headers)
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail},
        headers=headers,
    )
