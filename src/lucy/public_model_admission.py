"""Bridge strict model JSON calls through durable public cost admission."""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid5

from pydantic import ValidationError

from lucy.cost_admission import ProviderAttemptRequestV1
from lucy.public_inference import (
    ProviderInferenceOutcome,
    PublicInferenceRequest,
    PublicInferenceResult,
    PublicInferenceUnavailable,
)
from lucy.public_model import (
    PublicJsonModel,
    PublicModelCall,
    PublicModelCompletion,
    approximate_tokens,
)

_ATTEMPT_NAMESPACE = UUID("a58b25e3-7379-43da-8125-42808d933bf0")


class PublicInferenceExecutor(Protocol):
    def execute(
        self,
        *,
        attempt: ProviderAttemptRequestV1,
        inference: PublicInferenceRequest,
    ) -> PublicInferenceResult: ...


class OpenRouterInferenceProvider:
    """Adapt a structured OpenRouter client to the admitted provider interface."""

    def __init__(self, model: PublicJsonModel) -> None:
        self._model = model

    def infer(self, request: PublicInferenceRequest) -> ProviderInferenceOutcome:
        try:
            call = PublicModelCall.model_validate_json(request.prompt)
        except (ValidationError, ValueError):
            raise PublicInferenceUnavailable("admitted model request is invalid") from None
        encoded = request.prompt.encode("utf-8")
        if (
            len(encoded) != request.request_bytes
            or approximate_tokens(call.messages) != request.input_tokens
            or call.max_output_tokens != request.output_tokens
            or call.timeout_seconds != request.timeout_seconds
            or call.maximum_microusd != request.maximum_microusd
        ):
            raise PublicInferenceUnavailable("admitted model request bounds differ")
        completion = self._model.complete(call)
        return ProviderInferenceOutcome(
            output=completion.model_dump_json(),
            incurred_microusd=completion.incurred_microusd,
            provider_reference=completion.provider_reference,
        )


class AdmittedPublicJsonModel:
    """Make one idempotent, content-committed, cost-admitted model call."""

    def __init__(
        self,
        executor: PublicInferenceExecutor,
        *,
        request_id: UUID,
        model: str,
        rate_version: str,
        node_id: UUID,
        channel_binding_id: UUID,
        session_commitment: str,
        ip_commitment: str,
        request_commitment_key: bytes,
    ) -> None:
        if request_id.version != 4 or len(request_commitment_key) < 32:
            raise ValueError("admitted public model identity is invalid")
        self._executor = executor
        self._request_id = request_id
        self._model = model
        self._rate_version = rate_version
        self._node_id = node_id
        self._channel_binding_id = channel_binding_id
        self._session_commitment = session_commitment
        self._ip_commitment = ip_commitment
        self._commitment_key = request_commitment_key

    def complete(self, call: PublicModelCall) -> PublicModelCompletion:
        encoded = call.model_dump_json().encode("utf-8")
        input_tokens = approximate_tokens(call.messages)
        attempt_id = uuid5(
            _ATTEMPT_NAMESPACE, f"{self._request_id}:{call.purpose}"
        )
        attempt = ProviderAttemptRequestV1(
            attempt_id=attempt_id,
            idempotency_key=f"public-model:{self._request_id}:{call.purpose}",
            node_id=self._node_id,
            channel_binding_id=self._channel_binding_id,
            provider="openrouter",
            model=self._model,
            rate_version=self._rate_version,
            request_commitment=hmac.new(
                self._commitment_key, encoded, hashlib.sha256
            ).hexdigest(),
            session_commitment=self._session_commitment,
            ip_commitment=self._ip_commitment,
            maximum_microusd=call.maximum_microusd,
            input_tokens=input_tokens,
            output_tokens=call.max_output_tokens,
            request_bytes=len(encoded),
            timeout_seconds=call.timeout_seconds,
            requested_at=datetime.now(UTC),
        )
        inference = PublicInferenceRequest(
            prompt=encoded.decode("utf-8"),
            maximum_microusd=call.maximum_microusd,
            input_tokens=input_tokens,
            output_tokens=call.max_output_tokens,
            request_bytes=len(encoded),
            timeout_seconds=call.timeout_seconds,
        )
        result = self._executor.execute(attempt=attempt, inference=inference)
        if result.state != "SETTLED" or result.output is None or result.replayed:
            raise PublicInferenceUnavailable("admitted model output is unavailable")
        try:
            completion = PublicModelCompletion.model_validate_json(result.output)
        except (ValidationError, ValueError):
            raise PublicInferenceUnavailable("admitted model output is invalid") from None
        if (
            completion.model != self._model
            or completion.incurred_microusd > call.maximum_microusd
        ):
            raise PublicInferenceUnavailable("admitted model output binding differs")
        return completion
