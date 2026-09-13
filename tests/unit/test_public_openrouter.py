from __future__ import annotations

import json

from lucy.public_model import PublicModelCall, PublicModelMessage
from lucy.public_openrouter import OpenRouterPublicJsonModel


class Response:
    def __init__(self, model: str = "openai/gpt-5-mini") -> None:
        self._model = model

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, _: int) -> bytes:
        return json.dumps(
            {
                "id": "generation-test-1",
                "model": self._model,
                "provider": "ExampleZDR",
                "choices": [{"message": {"content": '{"ok":true}'}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 2, "cost": 0.00001},
            }
        ).encode()


def test_openrouter_request_enforces_privacy_routing_and_price_caps(monkeypatch) -> None:
    observed: dict[str, object] = {}

    def fake_urlopen(request, timeout: int):
        observed["body"] = json.loads(request.data)
        observed["headers"] = dict(request.header_items())
        observed["timeout"] = timeout
        return Response()

    monkeypatch.setattr("lucy.public_openrouter.urlopen", fake_urlopen)
    model = OpenRouterPublicJsonModel(
        api_key="k" * 32,
        model="openai/gpt-5-mini",
        allowed_providers=("azure",),
        maximum_prompt_usd_per_million=0.5,
        maximum_completion_usd_per_million=3.0,
    )
    result = model.complete(
        PublicModelCall(
            purpose="answer",
            messages=(PublicModelMessage(role="user", content="Synthetic question"),),
            response_schema_name="synthetic_result",
            response_schema={"type": "object"},
            max_output_tokens=100,
            timeout_seconds=20,
            maximum_microusd=100,
        )
    )

    body = observed["body"]
    assert isinstance(body, dict)
    assert body["model"] == "openai/gpt-5-mini"
    assert body["provider"] == {
        "zdr": True,
        "data_collection": "deny",
        "allow_fallbacks": False,
        "max_price": {"prompt": 0.5, "completion": 3.0},
        "only": ["azure"],
    }
    assert body["response_format"]["type"] == "json_schema"
    assert body["max_completion_tokens"] == 100
    assert body["reasoning"] == {"effort": "low", "exclude": True}
    assert "max_tokens" not in body
    assert observed["timeout"] == 20
    assert result.incurred_microusd == 10
    assert result.provider == "ExampleZDR"
    assert result.provider_reference == "generation-test-1"
    assert "Authorization" not in str(observed["body"])


def test_non_reasoning_model_uses_standard_output_token_parameter(monkeypatch) -> None:
    observed: dict[str, object] = {}

    def fake_urlopen(request, timeout: int):
        del timeout
        observed["body"] = json.loads(request.data)
        return Response("google/gemini-3.1-flash-lite")

    monkeypatch.setattr("lucy.public_openrouter.urlopen", fake_urlopen)
    model = OpenRouterPublicJsonModel(
        api_key="k" * 32,
        model="google/gemini-3.1-flash-lite",
        maximum_prompt_usd_per_million=0.5,
        maximum_completion_usd_per_million=3.0,
    )
    model.complete(
        PublicModelCall(
            purpose="answer",
            messages=(PublicModelMessage(role="user", content="Synthetic question"),),
            response_schema_name="synthetic_result",
            response_schema={"type": "object"},
            max_output_tokens=100,
            timeout_seconds=20,
            maximum_microusd=100,
        )
    )

    body = observed["body"]
    assert isinstance(body, dict)
    assert body["max_tokens"] == 100
    assert "max_completion_tokens" not in body
    assert "reasoning" not in body
