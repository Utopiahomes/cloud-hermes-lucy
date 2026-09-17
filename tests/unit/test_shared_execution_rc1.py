from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from lucy.shared_execution.output_validation import validate_output
from lucy.shared_execution.service import (
    ExecutionFailure,
    ExecutionInProgress,
    ExecutionProfile,
    IdempotencyConflict,
    InMemoryExecutionStore,
    ProviderResult,
    SharedExecutionService,
)
from lucy.shared_execution.wire import (
    BUNDLE_DIGEST,
    ExecutionRequest,
    restricted_schema_is_valid,
)


class FakeProvider:
    def __init__(self) -> None:
        self.calls = 0
        self._lock = Lock()

    def execute(self, request: ExecutionRequest, profile: ExecutionProfile) -> ProviderResult:
        with self._lock:
            self.calls += 1
        content: str | dict[str, Any] = "Candidate answer"
        if request.output.mode == "json_schema":
            content = {"answer": "Candidate answer"}
        return ProviderResult(
            content=content,
            input_tokens=50,
            generated_tokens=12,
            output_tokens=10,
            reasoning_tokens=2,
            cost_microusd=40,
        )


def request(question: str = "Tell me about Buttercup.") -> ExecutionRequest:
    return ExecutionRequest.model_validate(
        {
            "contract": "stoin.inference.execute.request.v1",
            "execution_profile_id": "utopia-homes.public-answer.generate.v1",
            "messages": [
                {"role": "system", "content": "Use approved context."},
                {"role": "user", "content": question},
            ],
            "output": {"mode": "text"},
            "limits": {"max_output_tokens": 900, "max_cost_microusd": 2000},
        }
    )


def service() -> tuple[SharedExecutionService, FakeProvider]:
    provider = FakeProvider()
    profile = ExecutionProfile(
        profile_id="utopia-homes.public-answer.generate.v1",
        release_id="profiles-local.1",
        allowed_modes=frozenset({"text", "json_schema"}),
        maximum_output_tokens=900,
        maximum_cost_microusd=2000,
    )
    return (
        SharedExecutionService(InMemoryExecutionStore(), provider, {profile.profile_id: profile}),
        provider,
    )


def test_bundle_digest_is_pinned() -> None:
    assert BUNDLE_DIGEST == "5185680e2cb9ac9aff6006c9abc6a582b67933db077d5c7bd5dcc596f574cb85"


def test_message_roles_are_enforced_before_execution() -> None:
    payload = request().model_dump(mode="json", by_alias=True)
    payload["messages"].append({"role": "user", "content": "Adjacent user"})
    with pytest.raises(ValidationError):
        ExecutionRequest.model_validate(payload)


def test_success_is_settled_and_same_key_replays_without_second_dispatch() -> None:
    executor, provider = service()
    first = executor.execute(
        caller="stoin:synth:utopia-homes-prime",
        idempotency_key=str(uuid4()),
        request_id=uuid4(),
        request=request(),
    )
    key = str(uuid4())
    original = executor.execute(
        caller="stoin:synth:utopia-homes-prime",
        idempotency_key=key,
        request_id=uuid4(),
        request=request(),
    )
    replay_request_id = uuid4()
    replay = executor.execute(
        caller="stoin:synth:utopia-homes-prime",
        idempotency_key=key,
        request_id=replay_request_id,
        request=request(),
    )
    assert first.cost.settlement_status == "settled"
    assert replay.execution_id == original.execution_id
    assert replay.request_id == replay_request_id
    assert replay.replayed is True
    assert provider.calls == 2


def test_same_scoped_key_with_different_identity_conflicts() -> None:
    executor, _ = service()
    key = str(uuid4())
    executor.execute(
        caller="stoin:synth:utopia-homes-prime",
        idempotency_key=key,
        request_id=uuid4(),
        request=request(),
    )
    with pytest.raises(IdempotencyConflict):
        executor.execute(
            caller="stoin:synth:utopia-homes-prime",
            idempotency_key=key,
            request_id=uuid4(),
            request=request("Different operation"),
        )


def test_concurrent_same_key_dispatches_at_most_once() -> None:
    executor, provider = service()
    key = str(uuid4())

    def call() -> str:
        try:
            result = executor.execute(
                caller="stoin:synth:utopia-homes-prime",
                idempotency_key=key,
                request_id=uuid4(),
                request=request(),
            )
            return str(result.execution_id)
        except ExecutionInProgress:
            return "in-progress"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: call(), range(8)))
    assert provider.calls == 1
    assert len({value for value in outcomes if value != "in-progress"}) == 1


def test_profile_requires_complete_worst_case_reservation() -> None:
    executor, provider = service()
    payload = request().model_dump(mode="json", by_alias=True)
    payload["limits"]["max_cost_microusd"] = 1999
    with pytest.raises(ValueError, match="complete profile maximum"):
        executor.execute(
            caller="stoin:synth:utopia-homes-prime",
            idempotency_key=str(uuid4()),
            request_id=uuid4(),
            request=ExecutionRequest.model_validate(payload),
        )
    assert provider.calls == 0


def test_json_schema_provider_output_is_validated_by_executor() -> None:
    class InvalidJsonProvider:
        def execute(
            self, request: ExecutionRequest, profile: ExecutionProfile
        ) -> ProviderResult:
            return ProviderResult(
                content={"answer": ""},
                input_tokens=10,
                generated_tokens=1,
                output_tokens=1,
                reasoning_tokens=0,
                cost_microusd=1,
            )

    profile = ExecutionProfile(
        profile_id="utopia-homes.public-answer.generate.v1",
        release_id="profiles-local.1",
        allowed_modes=frozenset({"json_schema"}),
        maximum_output_tokens=900,
        maximum_cost_microusd=2000,
    )
    executor = SharedExecutionService(
        InMemoryExecutionStore(), InvalidJsonProvider(), {profile.profile_id: profile}
    )
    payload = request().model_dump(mode="json", by_alias=True)
    payload["output"] = {
        "mode": "json_schema",
        "name": "guest-answer-candidate",
        "schema": {
            "type": "object",
            "properties": {"answer": {"type": "string", "minLength": 1}},
            "required": ["answer"],
            "additionalProperties": False,
        },
    }
    with pytest.raises(ExecutionFailure) as failure:
        executor.execute(
            caller="stoin:synth:utopia-homes-prime",
            idempotency_key=str(uuid4()),
            request_id=uuid4(),
            request=ExecutionRequest.model_validate(payload),
        )
    assert failure.value.code == "provider_response_invalid"


def test_output_validator_distinguishes_json_boolean_from_integer() -> None:
    assert validate_output({"type": "integer", "minimum": 0}, 1)
    assert not validate_output({"type": "integer", "minimum": 0}, True)


def test_output_token_limit_is_checked_against_combined_generated_tokens() -> None:
    class OverLimitProvider:
        def execute(
            self, request: ExecutionRequest, profile: ExecutionProfile
        ) -> ProviderResult:
            return ProviderResult(
                content="candidate",
                input_tokens=1,
                generated_tokens=901,
                output_tokens=600,
                reasoning_tokens=301,
                cost_microusd=1,
            )

    profile = ExecutionProfile(
        profile_id="utopia-homes.public-answer.generate.v1",
        release_id="profiles-local.1",
        allowed_modes=frozenset({"text"}),
        maximum_output_tokens=900,
        maximum_cost_microusd=2000,
    )
    executor = SharedExecutionService(
        InMemoryExecutionStore(), OverLimitProvider(), {profile.profile_id: profile}
    )
    with pytest.raises(ExecutionFailure) as failure:
        executor.execute(
            caller="stoin:synth:utopia-homes-prime",
            idempotency_key=str(uuid4()),
            request_id=uuid4(),
            request=request(),
        )
    assert failure.value.code == "output_limit_reached"


@pytest.mark.parametrize(
    "schema",
    [
        {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
            "$ref": "x",
        },
        {
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": [],
            "additionalProperties": False,
        },
        {"type": ["string", "null"], "const": "answer"},
        {"type": ["string", "null"], "enum": ["answer"]},
        {"type": "integer", "minimum": -(2**53)},
        {"type": "string", "enum": ["same", "same"]},
    ],
)
def test_restricted_schema_rejects_unsupported_or_ambiguous_shapes(
    schema: dict[str, Any],
) -> None:
    assert not restricted_schema_is_valid(schema)
