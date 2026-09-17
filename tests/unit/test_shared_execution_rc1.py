from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from lucy.shared_execution.service import (
    ExecutionInProgress,
    ExecutionProfile,
    IdempotencyConflict,
    InMemoryExecutionStore,
    ProviderResult,
    SharedExecutionService,
)
from lucy.shared_execution.wire import BUNDLE_DIGEST, ExecutionRequest


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
