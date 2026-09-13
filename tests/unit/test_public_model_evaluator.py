from __future__ import annotations

import pytest

from deploy.render.evaluate_public_model import RecordingModel
from lucy.public_model import PublicModelCall, PublicModelMessage
from lucy.public_openrouter import OpenRouterPublicError


class FailingModel:
    def complete(self, _call: PublicModelCall):
        raise OpenRouterPublicError("synthetic failure")


def test_recording_model_retains_attempt_when_no_billable_response_is_parseable() -> None:
    recorder = RecordingModel(FailingModel())  # type: ignore[arg-type]
    call = PublicModelCall(
        purpose="answer",
        messages=(PublicModelMessage(role="user", content="Synthetic"),),
        response_schema_name="synthetic",
        response_schema={"type": "object"},
        max_output_tokens=100,
        timeout_seconds=10,
        maximum_microusd=30_000,
    )

    with pytest.raises(OpenRouterPublicError):
        recorder.complete(call)

    assert recorder.calls == [call]
    assert recorder.completions == []
