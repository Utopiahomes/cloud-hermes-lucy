from __future__ import annotations

import json
from uuid import UUID

import pytest

from lucy.public_inference import PublicInferenceRequest, PublicInferenceResult
from lucy.public_model import (
    PublicModelCall,
    PublicModelCompletion,
    PublicModelMessage,
)
from lucy.public_model_admission import (
    AdmittedPublicJsonModel,
    OpenRouterInferenceProvider,
)

REQUEST_ID = UUID("24512180-a368-4ad0-a167-44082ae66c66")
NODE_ID = UUID("eb181c78-1314-456b-b5c9-675495ddc896")
CHANNEL_ID = UUID("be91f214-c314-4d05-88dc-3d541922f72f")


def _call() -> PublicModelCall:
    return PublicModelCall(
        purpose="answer",
        messages=(PublicModelMessage(role="user", content="Synthetic question"),),
        response_schema_name="synthetic_response",
        response_schema={"type": "object"},
        max_output_tokens=200,
        timeout_seconds=20,
        maximum_microusd=5_000,
    )


def _completion() -> PublicModelCompletion:
    return PublicModelCompletion(
        content=json.dumps({"answer": "Synthetic answer"}),
        model="google/gemini-3.1-flash-lite",
        provider="Google",
        provider_reference="generation-test-1",
        prompt_tokens=20,
        completion_tokens=10,
        incurred_microusd=100,
    )


class FakeExecutor:
    def __init__(self, output: str | None = None, *, replayed: bool = False) -> None:
        self.output = output or _completion().model_dump_json()
        self.replayed = replayed
        self.calls: list[tuple[object, PublicInferenceRequest]] = []

    def execute(self, *, attempt, inference):
        self.calls.append((attempt, inference))
        return PublicInferenceResult(
            attempt_id=attempt.attempt_id,
            state="SETTLED",
            output=self.output,
            replayed=self.replayed,
        )


def _model(executor: FakeExecutor) -> AdmittedPublicJsonModel:
    return AdmittedPublicJsonModel(
        executor,
        request_id=REQUEST_ID,
        model="google/gemini-3.1-flash-lite",
        rate_version="openrouter-2026-09-13",
        node_id=NODE_ID,
        channel_binding_id=CHANNEL_ID,
        session_commitment="a" * 64,
        ip_commitment="b" * 64,
        request_commitment_key=b"r" * 32,
    )


def test_model_call_is_idempotent_committed_and_exactly_bound_to_admission() -> None:
    first = FakeExecutor()
    second = FakeExecutor()

    result = _model(first).complete(_call())
    _model(second).complete(_call())

    attempt, inference = first.calls[0]
    repeated, _ = second.calls[0]
    assert attempt.attempt_id == repeated.attempt_id
    assert attempt.idempotency_key == repeated.idempotency_key
    assert attempt.request_commitment not in inference.prompt
    assert attempt.session_commitment == "a" * 64
    assert attempt.ip_commitment == "b" * 64
    assert attempt.request_bytes == len(inference.prompt.encode())
    assert attempt.maximum_microusd == inference.maximum_microusd == 5_000
    assert result == _completion()


def test_replayed_call_without_retained_body_fails_closed() -> None:
    with pytest.raises(Exception, match="output is unavailable"):
        _model(FakeExecutor(replayed=True)).complete(_call())


class FakeJsonModel:
    def __init__(self) -> None:
        self.calls: list[PublicModelCall] = []

    def complete(self, call: PublicModelCall) -> PublicModelCompletion:
        self.calls.append(call)
        return _completion()


def test_provider_adapter_revalidates_serialized_call_bounds() -> None:
    model = FakeJsonModel()
    provider = OpenRouterInferenceProvider(model)
    call = _call()
    prompt = call.model_dump_json()
    request = PublicInferenceRequest(
        prompt=prompt,
        maximum_microusd=call.maximum_microusd,
        input_tokens=49,
        output_tokens=call.max_output_tokens,
        request_bytes=len(prompt.encode()),
        timeout_seconds=call.timeout_seconds,
    )
    # The admission adapter computes the exact provider-independent estimate.
    from lucy.public_model import approximate_tokens

    request = request.model_copy(update={"input_tokens": approximate_tokens(call.messages)})
    outcome = provider.infer(request)

    assert outcome.incurred_microusd == 100
    assert outcome.provider_reference == "generation-test-1"
    assert model.calls == [call]

    with pytest.raises(Exception, match="bounds differ"):
        provider.infer(request.model_copy(update={"output_tokens": 201}))
