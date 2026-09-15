"""Content-bounded private service contract for Public Lucy model execution."""

from __future__ import annotations

import http.client
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from lucy.public_contracts import (
    PublicHistoryTurn,
    PublicKnowledgeEntry,
    PublicPageContext,
    PublicRetrievalResult,
)
from lucy.public_model import (
    PUBLIC_ANSWER_POLICY_DIGEST,
    PUBLIC_VERIFY_POLICY_DIGEST,
    PublicConversationEngine,
    PublicModelRejected,
    PublicModelResult,
)
from lucy.public_model_admission import public_model_attempt_id
from lucy.publication import knowledge_snapshot, snapshot_digest

_HOSTPORT = re.compile(r"([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?):([0-9]{2,5})\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class PublicModelServiceUnavailable(RuntimeError):
    """The private model service cannot safely return a response."""


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PublicModelCallDiagnostic(StrictModel):
    purpose: Literal["answer", "verify"]
    attempt_id: UUID
    configured_model: str = Field(min_length=1, max_length=200)
    observed_model: str = Field(min_length=1, max_length=200)
    configured_providers: tuple[str, ...] = Field(min_length=1, max_length=20)
    observed_provider: str = Field(min_length=1, max_length=200)
    rate_version: str = Field(min_length=1, max_length=80)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    maximum_microusd: int = Field(ge=0)
    incurred_microusd: int = Field(ge=0)


class PublicModelDiagnostic(StrictModel):
    contract: Literal["lucy.public-model-diagnostic.v1"]
    request_id: UUID
    model_release_id: str = Field(pattern=r"^[0-9a-f]{40}$")
    answer_policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    verifier_policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    validation_outcome: Literal["supported"]
    model_latency_ms: int = Field(ge=0)
    calls: tuple[PublicModelCallDiagnostic, PublicModelCallDiagnostic]

    @model_validator(mode="after")
    def calls_are_exact(self) -> PublicModelDiagnostic:
        if tuple(call.purpose for call in self.calls) != ("answer", "verify"):
            raise ValueError("public model diagnostic calls are invalid")
        if len({call.attempt_id for call in self.calls}) != 2:
            raise ValueError("public model diagnostic attempt identities differ")
        return self


@dataclass(frozen=True)
class PublicModelDiagnosticConfiguration:
    model_release_id: str
    configured_model: str
    configured_providers: tuple[str, ...]
    rate_version: str
    generator_maximum_microusd: int
    verifier_maximum_microusd: int

    def __post_init__(self) -> None:
        if (
            re.fullmatch(r"[0-9a-f]{40}", self.model_release_id) is None
            or not self.configured_model
            or not self.configured_providers
            or not self.rate_version
            or self.generator_maximum_microusd < 0
            or self.verifier_maximum_microusd < 0
        ):
            raise ValueError("public model diagnostic configuration is invalid")


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
    diagnostic: PublicModelDiagnostic | None = None


class PublicModelServiceHandler:
    """Revalidate approved bytes before any body-bearing model execution."""

    def __init__(
        self,
        allowed_snapshot_digests: tuple[str, ...],
        engine_factory: Callable[[PublicModelServiceRequest], PublicConversationEngine],
        diagnostic_configuration: PublicModelDiagnosticConfiguration | None = None,
    ) -> None:
        if not allowed_snapshot_digests or any(
            _DIGEST.fullmatch(item) is None for item in allowed_snapshot_digests
        ):
            raise ValueError("public model snapshot allowlist is invalid")
        self._allowed_digests = frozenset(allowed_snapshot_digests)
        self._engine_factory = engine_factory
        self._diagnostic_configuration = diagnostic_configuration

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
        started = time.perf_counter()
        try:
            result = self._engine_factory(request).answer(
                question=request.question,
                entries=request.entries,
                page_context=request.page_context,
                history=request.history,
            )
        except PublicModelRejected:
            raise PublicModelServiceUnavailable("public model answer was rejected") from None
        diagnostic = self._diagnostic(request, result, started)
        return PublicModelServiceResponse(
            contract="lucy.public-model-response.v1",
            request_id=request.request_id,
            snapshot_digest=request.snapshot_digest,
            answer=result.answer,
            diagnostic=diagnostic,
        )

    def _diagnostic(
        self,
        request: PublicModelServiceRequest,
        result: PublicModelResult,
        started: float,
    ) -> PublicModelDiagnostic | None:
        config = self._diagnostic_configuration
        if config is None:
            return None
        # No prompt, answer, question, or provider reference is copied into this receipt.
        usage = result.usage
        calls = (
            PublicModelCallDiagnostic(
                purpose="answer",
                attempt_id=public_model_attempt_id(request.request_id, "answer"),
                configured_model=config.configured_model,
                observed_model=usage.generator.model,
                configured_providers=config.configured_providers,
                observed_provider=usage.generator.provider,
                rate_version=config.rate_version,
                prompt_tokens=usage.generator.prompt_tokens,
                completion_tokens=usage.generator.completion_tokens,
                maximum_microusd=config.generator_maximum_microusd,
                incurred_microusd=usage.generator.incurred_microusd,
            ),
            PublicModelCallDiagnostic(
                purpose="verify",
                attempt_id=public_model_attempt_id(request.request_id, "verify"),
                configured_model=config.configured_model,
                observed_model=usage.verifier.model,
                configured_providers=config.configured_providers,
                observed_provider=usage.verifier.provider,
                rate_version=config.rate_version,
                prompt_tokens=usage.verifier.prompt_tokens,
                completion_tokens=usage.verifier.completion_tokens,
                maximum_microusd=config.verifier_maximum_microusd,
                incurred_microusd=usage.verifier.incurred_microusd,
            ),
        )
        return PublicModelDiagnostic(
            contract="lucy.public-model-diagnostic.v1",
            request_id=request.request_id,
            model_release_id=config.model_release_id,
            answer_policy_digest=PUBLIC_ANSWER_POLICY_DIGEST,
            verifier_policy_digest=PUBLIC_VERIFY_POLICY_DIGEST,
            validation_outcome="supported",
            model_latency_ms=max(0, round((time.perf_counter() - started) * 1_000)),
            calls=calls,
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
