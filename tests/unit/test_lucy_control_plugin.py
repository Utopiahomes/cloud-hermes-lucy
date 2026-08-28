from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

REPOSITORY_ROOT = Path(__file__).parents[2]
PLUGIN_PATH = (
    REPOSITORY_ROOT / "profiles" / "lucy" / "plugins" / "lucy_control" / "__init__.py"
)


def _load_plugin() -> ModuleType:
    spec = importlib.util.spec_from_file_location("lucy_control_plugin", PLUGIN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _response() -> SimpleNamespace:
    return SimpleNamespace(
        usage=SimpleNamespace(
            prompt_tokens=100,
            completion_tokens=20,
            completion_tokens_details=SimpleNamespace(reasoning_tokens=5),
            model_extra={"cost": 0.00001},
        )
    )


def _middleware_kwargs() -> dict[str, str]:
    return {
        "api_request_id": "request-1",
        "session_id": "session-1",
        "model": "openai/gpt-oss-20b",
        "provider": "custom",
        "base_url": "https://openrouter.ai/api/v1",
    }


def _request() -> dict[str, Any]:
    return {
        "messages": [],
        "max_tokens": 1024,
        "extra_body": {
            "provider": {
                "zdr": True,
                "data_collection": "deny",
                "sort": "price",
                "require_parameters": True,
                "max_price": {"prompt": 0.10, "completion": 0.50},
            }
        },
    }


def test_middleware_reserves_calls_once_and_settles(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _load_plugin()
    posts: list[tuple[str, dict[str, Any]]] = []

    def post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
        posts.append((path, payload))
        if path.endswith("/begin"):
            return {"action_id": "action-1", "status": "executing", "execute": True}
        return {"action_id": "action-1", "status": "succeeded", "replayed": False}

    monkeypatch.setattr(plugin, "_post_json", post)
    calls = 0

    def next_call(request: dict[str, Any]) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        assert request == _request()
        return _response()

    response = plugin._execution_middleware(
        _request(), next_call, **_middleware_kwargs()
    )
    assert response is not None and calls == 1
    assert posts[0][0].endswith("/begin")
    assert posts[1][0].endswith("/settle")
    assert posts[1][1]["actual_microusd"] == 10
    assert posts[1][1]["usage"] == {
        "input_tokens": 100,
        "output_tokens": 20,
        "reasoning_tokens": 5,
        "provider_cost_microusd": 10,
    }


def test_middleware_fails_closed_without_reservation(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _load_plugin()

    def unavailable(_path: str, _payload: dict[str, Any]) -> dict[str, Any]:
        raise OSError("companion unavailable")

    monkeypatch.setattr(plugin, "_post_json", unavailable)
    calls = 0

    def next_call(_request: dict[str, Any]) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        return _response()

    response = plugin._execution_middleware(_request(), next_call, **_middleware_kwargs())
    assert calls == 0
    assert response.choices[0].message.content.startswith("Lucy blocked")


def test_middleware_conservatively_settles_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    posts: list[tuple[str, dict[str, Any]]] = []

    def post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
        posts.append((path, payload))
        if path.endswith("/begin"):
            return {"action_id": "action-1", "status": "executing", "execute": True}
        return {"action_id": "action-1", "status": "failed", "replayed": False}

    monkeypatch.setattr(plugin, "_post_json", post)

    def fail(_request: dict[str, Any]) -> SimpleNamespace:
        raise TimeoutError("ambiguous provider failure")

    with pytest.raises(TimeoutError, match="ambiguous provider failure"):
        plugin._execution_middleware(_request(), fail, **_middleware_kwargs())

    assert posts[-1][0].endswith("/settle")
    assert posts[-1][1]["actual_microusd"] == 5_000
    assert posts[-1][1]["succeeded"] is False


def test_middleware_blocks_duplicate_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _load_plugin()
    monkeypatch.setattr(
        plugin,
        "_post_json",
        lambda _path, _payload: {
            "action_id": "action-1",
            "status": "executing",
            "execute": False,
            "replayed": True,
        },
    )
    response = plugin._execution_middleware(
        _request(), lambda _request: pytest.fail("provider call must not run"),
        **_middleware_kwargs()
    )
    assert "duplicate" in response.choices[0].message.content


def test_plugin_registers_execution_middleware() -> None:
    plugin = _load_plugin()
    registrations: list[tuple[str, Any]] = []
    ctx = SimpleNamespace(
        register_middleware=lambda kind, callback: registrations.append((kind, callback))
    )
    plugin.register(ctx)
    assert registrations == [
        ("llm_request", plugin._request_middleware),
        ("llm_execution", plugin._execution_middleware),
    ]


def test_request_middleware_injects_and_clamps_output_cap() -> None:
    plugin = _load_plugin()
    missing = plugin._request_middleware({"messages": []})["request"]
    oversized = plugin._request_middleware(
        {"messages": [], "max_tokens": 9000}
    )["request"]
    smaller = plugin._request_middleware(
        {"messages": [], "max_completion_tokens": 200}
    )["request"]
    assert missing["max_tokens"] == 1024
    assert oversized["max_tokens"] == 1024
    assert smaller["max_completion_tokens"] == 200


def test_middleware_blocks_request_without_price_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    monkeypatch.setattr(
        plugin,
        "_post_json",
        lambda _path, _payload: pytest.fail("reservation must not be attempted"),
    )
    request = _request()
    request["extra_body"] = {}
    response = plugin._execution_middleware(
        request, lambda _request: pytest.fail("provider call must not run"),
        **_middleware_kwargs()
    )
    assert "unapproved model route" in response.choices[0].message.content
