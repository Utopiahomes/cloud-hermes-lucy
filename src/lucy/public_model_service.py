"""Content-bounded private service contract for Public Lucy model execution."""

from __future__ import annotations

import http.client
import json
import re
from collections.abc import Callable
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from lucy.public_contracts import (
    PublicHistoryTurn,
    PublicKnowledgeEntry,
    PublicPageContext,
    PublicRetrievalResult,
)
from lucy.public_model import PublicConversationEngine, PublicModelRejected
from lucy.publication import knowledge_snapshot, snapshot_digest

_HOSTPORT = re.compile(r"([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?):([0-9]{2,5})\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class PublicModelServiceUnavailable(RuntimeError):
    """The private model service cannot safely return a response."""


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PublicModelServiceRequest(StrictModel):
    contract: Literal["lucy.public-model-request.v1"]
    request_id: UUID
    snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    session_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    ip_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    question: str = Field(min_length=2, max_length=500)
    entries: tuple[PublicKnowledgeEntry, ...] = Field(min_length=1, max_length=500)
    page_context: PublicPageContext | None = None
    history: tuple[PublicHistoryTurn, ...] = Field(default=(), max_length=6)

    @model_validator(mode="after")
    def request_is_bounded(self) -> PublicModelServiceRequest:
        if self.request_id.version != 4:
            raise ValueError("public model request identifier must be random")
        if sum(len(item.content) for item in self.history) > 4_000:
            raise ValueError("public model history exceeds its bound")
        return self


class PublicModelServiceResponse(StrictModel):
    contract: Literal["lucy.public-model-response.v1"]
    request_id: UUID
    snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    answer: PublicRetrievalResult


class PublicModelServiceHandler:
    """Revalidate approved bytes before any body-bearing model execution."""

    def __init__(
        self,
        allowed_snapshot_digests: tuple[str, ...],
        engine_factory: Callable[[PublicModelServiceRequest], PublicConversationEngine],
    ) -> None:
        if not allowed_snapshot_digests or any(
            _DIGEST.fullmatch(item) is None for item in allowed_snapshot_digests
        ):
            raise ValueError("public model snapshot allowlist is invalid")
        self._allowed_digests = frozenset(allowed_snapshot_digests)
        self._engine_factory = engine_factory

    def answer(self, request: PublicModelServiceRequest) -> PublicModelServiceResponse:
        canonical = knowledge_snapshot(
            [item.model_dump(mode="json") for item in request.entries]
        )
        actual_digest = snapshot_digest(canonical)
        if (
            actual_digest != request.snapshot_digest
            or actual_digest not in self._allowed_digests
        ):
            raise PublicModelServiceUnavailable("public model snapshot is not admitted")
        try:
            result = self._engine_factory(request).answer(
                question=request.question,
                entries=request.entries,
                page_context=request.page_context,
                history=request.history,
            )
        except PublicModelRejected:
            raise PublicModelServiceUnavailable("public model answer was rejected") from None
        return PublicModelServiceResponse(
            contract="lucy.public-model-response.v1",
            request_id=request.request_id,
            snapshot_digest=request.snapshot_digest,
            answer=result.answer,
        )


class HttpPublicModelClient:
    """Bounded private-network client; response and error bodies are never logged."""

    def __init__(
        self,
        hostport: str,
        token: str,
        *,
        timeout_seconds: int = 15,
        maximum_request_bytes: int = 200_000,
        maximum_response_bytes: int = 65_536,
    ) -> None:
        match = _HOSTPORT.fullmatch(hostport)
        if match is None or not 32 <= len(token) <= 512:
            raise ValueError("private public-model client configuration is invalid")
        port = int(match.group(2))
        if port > 65_535 or timeout_seconds not in range(1, 31):
            raise ValueError("private public-model client configuration is invalid")
        if maximum_request_bytes not in range(1_024, 1_000_001):
            raise ValueError("private public-model request bound is invalid")
        if maximum_response_bytes not in range(1_024, 1_000_001):
            raise ValueError("private public-model response bound is invalid")
        self._host = match.group(1)
        self._port = port
        self._token = token
        self._timeout = timeout_seconds
        self._maximum_request_bytes = maximum_request_bytes
        self._maximum_response_bytes = maximum_response_bytes

    def answer(self, request: PublicModelServiceRequest) -> PublicModelServiceResponse:
        body = request.model_dump_json().encode("utf-8")
        if len(body) > self._maximum_request_bytes:
            raise PublicModelServiceUnavailable("public model request is too large")
        connection = http.client.HTTPConnection(
            self._host, self._port, timeout=self._timeout
        )
        try:
            connection.request(
                "POST",
                "/v1/public-model/answer",
                body=body,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                },
            )
            response = connection.getresponse()
            raw = response.read(self._maximum_response_bytes + 1)
        except (OSError, http.client.HTTPException):
            raise PublicModelServiceUnavailable("public model service is unavailable") from None
        finally:
            connection.close()
        if response.status != 200 or len(raw) > self._maximum_response_bytes:
            raise PublicModelServiceUnavailable("public model service rejected the request")
        try:
            result = PublicModelServiceResponse.model_validate(json.loads(raw))
        except (json.JSONDecodeError, UnicodeError, ValidationError):
            raise PublicModelServiceUnavailable("public model response is invalid") from None
        if (
            result.request_id != request.request_id
            or result.snapshot_digest != request.snapshot_digest
        ):
            raise PublicModelServiceUnavailable("public model response binding differs")
        return result
