import json

import pytest
from fastapi.testclient import TestClient

from lucy.api import app
from lucy.hindsight_model_proxy import (
    HindsightModelProxyError,
    _bounded_request,
    _cost,
    complete,
)


def _request(**changes: object) -> bytes:
    return json.dumps({
        "model": "openai/gpt-oss-20b",
        "messages": [{"role": "user", "content": "synthetic test"}],
        **changes,
    }).encode()


def test_bounded_request_enforces_provider_route_and_output_cap() -> None:
    body = _bounded_request(_request())
    assert body["max_tokens"] == 4096
    assert body["provider"]["zdr"] is True
    assert body["provider"]["allow_fallbacks"] is False
    with pytest.raises(HindsightModelProxyError):
        _bounded_request(_request(model="other/model"))
    assert _bounded_request(_request(max_tokens=16384))["max_tokens"] == 4096
    with pytest.raises(HindsightModelProxyError):
        _bounded_request(_request(stream=True))
    with pytest.raises(HindsightModelProxyError):
        _bounded_request(_request(provider={"zdr": False}))


def test_provider_cost_must_fit_reservation() -> None:
    assert _cost({"cost": 0.0001171}) == 118
    with pytest.raises(HindsightModelProxyError):
        _cost({"cost": 0.006})
    with pytest.raises(HindsightModelProxyError):
        _cost({"prompt_tokens": 10})


def test_private_model_route_rejects_missing_hindsight_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_HINDSIGHT_MODEL_PROXY_TOKEN", "synthetic-secret")
    monkeypatch.setenv("LUCY_SERVICE_MODE", "routine")
    response = TestClient(app).post(
        "/internal/v1/hindsight/openai/v1/chat/completions", content=_request()
    )
    assert response.status_code == 401


def test_model_call_reserves_then_settles(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []

    class FakeResult:
        def __init__(self, value: object) -> None:
            self.value = value

        def scalar_one(self) -> object:
            return self.value

    class FakeSession:
        def execute(self, query: object, params: dict[str, object]) -> FakeResult:
            operation = "begin" if "begin_hindsight" in str(query) else "settle"
            calls.append((operation, params))
            return FakeResult({"execute": True})

    class FakeTransaction:
        def __enter__(self) -> FakeSession:
            return FakeSession()

        def __exit__(self, *_args: object) -> None:
            pass

    class FakeSessions:
        def begin(self) -> FakeTransaction:
            return FakeTransaction()

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def read(self, _limit: int) -> bytes:
            return json.dumps({
                "model": "openai/gpt-oss-20b",
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"cost": 0.00012, "prompt_tokens": 10, "completion_tokens": 5},
            }).encode()

    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        calls.append(("upstream", request, timeout))
        return FakeResponse()

    monkeypatch.setenv("OPENROUTER_API_KEY", "synthetic-key")
    monkeypatch.setattr("lucy.hindsight_model_proxy.urlopen", fake_urlopen)
    result = complete(_request(), FakeSessions())  # type: ignore[arg-type]
    assert result["choices"][0]["message"]["content"] == "ok"
    assert [call[0] for call in calls] == ["begin", "upstream", "settle"]
    assert calls[2][1]["actual"] == 120
    assert calls[2][1]["succeeded"] is True
