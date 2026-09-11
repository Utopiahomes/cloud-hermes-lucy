"""Authenticated, read-only HTTP surface for approved public projections."""

from __future__ import annotations

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
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

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


class PublicApiConfigurationError(ValueError):
    """Content-free startup/configuration failure."""


class PublicQuestion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    question: str = Field(min_length=2, max_length=500)

    @field_validator("question")
    @classmethod
    def normalize_question(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if len(normalized) < 2:
            raise ValueError("question is blank")
        return normalized


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
            if not self._increment(
                session_key, minute, config.requests_per_session_per_minute
            ):
                return False
            self._prune(minute, now, config.session_ttl_seconds)
            return True

    def _commitment(self, kind: str, value: str) -> str:
        return hmac.new(
            self._key, f"{kind}\0{value}".encode(), hashlib.sha256
        ).hexdigest()

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


app = FastAPI(
    title="Lucy Public Projection API",
    version="1.0.0",
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
)
_limiter = _OpaqueRateLimiter()


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


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok"}


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
        answer = _reader().answer_admitted(
            hostname=config.site_hostname,
            question=question.question,
            storage_epoch=config.storage_epoch,
        )
    except ScopeNotFound:
        return _response(404, "Public answer is unavailable")
    except (ReadinessError, SQLAlchemyError):
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


def _response(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail},
        headers={"Cache-Control": "no-store"},
    )
