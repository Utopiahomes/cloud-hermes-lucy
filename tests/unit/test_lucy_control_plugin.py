from __future__ import annotations

import importlib.util
import io
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from contextvars import Context
from pathlib import Path
from threading import Barrier
from types import ModuleType, SimpleNamespace
from typing import Any
from urllib.error import HTTPError

import pytest

REPOSITORY_ROOT = Path(__file__).parents[2]
PLUGIN_PATH = REPOSITORY_ROOT / "profiles" / "lucy" / "plugins" / "lucy_control" / "__init__.py"


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


def _active_turn(plugin: ModuleType, session: str = "session-1", turn: str = "turn-1") -> None:
    plugin._SESSION_TURN[session] = {
        "turn_id": turn, "capture_enabled": True, "active": True, "proposal_keys": {},
    }


def _middleware_kwargs() -> dict[str, str]:
    return {
        "api_request_id": "request-1",
        "session_id": "session-1",
        "model": "openai/gpt-oss-20b",
        "provider": "custom",
        "base_url": "https://openrouter.ai/api/v1",
    }


def test_lookup_binds_all_observed_sources_before_proposing_or_archiving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    a = "11111111-1111-4111-8111-111111111111"
    b = "22222222-2222-4222-8222-222222222222"
    forged = "33333333-3333-4333-8333-333333333333"
    _active_turn(plugin)
    _active_turn(plugin, "session-2", "turn-2")
    calls: list[dict[str, Any]] = []

    def request(path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs.get("payload", {}))
        if path.endswith("lookup"):
            return {"read_only": True, "claims": [{"object": "synthetic fact",
                                                   "source_evidence_ids": [a, b]}]}
        if path.endswith("proposals"):
            return {"status": "pending", "proposal_id": a, "approval_id": b}
        return {"archived": True, "evidence_id": a, "keyed_commitment": "a" * 64,
                "turn_committed": True}

    monkeypatch.setattr(plugin, "_request_json", request)
    result = plugin._tool_execution_middleware(
        {"query": "tea", "source_evidence_ids": [forged]},
        lambda args: plugin._memory_lookup(args, session_id="session-1"),
        tool_name="lucy_memory_lookup", session_id="session-1", turn_id="turn-1",
    )
    assert json.loads(result)["ok"]
    assert plugin._SESSION_TURN["session-1"]["source_evidence_ids"] == {a, b}
    assert not plugin._SESSION_TURN["session-2"].get("source_evidence_ids")
    proposed = plugin._memory_propose(
        {"evidence_id": a, "subject": "owner", "predicate": "likes", "object": "tea",
         "confidence": 0.9, "source_evidence_ids": [forged]},
        session_id="session-1", turn_id="turn-1",
    )
    assert json.loads(proposed)["ok"]
    assert calls[-1]["source_evidence_ids"] == [a, b]
    plugin._archive_conversation_message(
        role="assistant", content="Synthetic reply", session_id="session-1",
        turn_id="turn-1", platform="telegram",
    )
    assert calls[-1]["source_evidence_ids"] == [a, b]


def test_untracked_lookup_content_is_never_returned_to_an_active_retained_turn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    _active_turn(plugin)
    monkeypatch.setattr(plugin, "_request_json", lambda *_a, **_k: {
        "read_only": True, "claims": [{"object": "synthetic hidden text"}],
    })
    result = json.loads(plugin._memory_lookup({"query": "tea"}, session_id="session-1",
                                              turn_id="turn-1"))
    assert result == {"ok": False, "error": "invalid_companion_provenance"}
    assert "synthetic hidden text" not in json.dumps(result)


def test_cold_gateway_cannot_resume_retention_with_missing_tool_exposure_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    monkeypatch.setattr(plugin, "_request_json", lambda *_a, **_k: {
        "capture_enabled": True, "replayed": True, "version": 0,
    })
    assert plugin._accept_turn("session-1", "turn-1") is None
    _active_turn(plugin)
    assert plugin._accept_turn("session-1", "turn-1") is True


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


def test_archive_commit_uses_bounded_private_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    monkeypatch.setenv("LUCY_COMPANION_URL", "http://lucy.invalid")
    monkeypatch.setenv("LUCY_ADAPTER_TOKEN", "synthetic-token")
    deadlines: list[int] = []

    def open_request(_request: Any, *, timeout: int) -> io.BytesIO:
        deadlines.append(timeout)
        return io.BytesIO(b'{"ok":true}')

    monkeypatch.setattr(plugin, "urlopen", open_request)
    plugin._request_json("/internal/v1/conversations/messages", method="POST", payload={})
    plugin._request_json("/internal/v1/conversations/accept-turn", method="POST", payload={})
    assert deadlines == [
        plugin.PRIVATE_API_TIMEOUT_SECONDS,
        plugin.PRIVATE_API_TIMEOUT_SECONDS,
    ]
    assert deadlines == [20, 20]


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

    response = plugin._execution_middleware(_request(), next_call, **_middleware_kwargs())
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


def test_stage1_budget_identity_is_bound_to_the_claimed_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    bridge = ModuleType("sitecustomize")
    bridge.next_model_operation = lambda: (  # type: ignore[attr-defined]
        "11111111-1111-4111-8111-111111111111",
        1,
    )
    monkeypatch.setitem(sys.modules, "sitecustomize", bridge)
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", "1")
    monkeypatch.setenv("LUCY_TELEGRAM_GATEWAY_HOLDER_ID", "22222222-2222-4222-8222-222222222222")
    monkeypatch.setenv("LUCY_TELEGRAM_GATEWAY_FENCE", "7")
    posts: list[tuple[str, dict[str, Any]]] = []

    def post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
        posts.append((path, payload))
        if path.endswith("/begin"):
            return {"action_id": "action-1", "status": "executing", "execute": True}
        return {"action_id": "action-1", "status": "succeeded", "replayed": False}

    monkeypatch.setattr(plugin, "_post_json", post)
    response = plugin._execution_middleware(
        _request(),
        lambda _request: _response(),
        **_middleware_kwargs(),
        platform="telegram",
        turn_id="transient-turn",
    )
    assert response is not None
    assert posts[0][1]["idempotency_key"] == (
        "hermes-model:telegram-event:11111111-1111-4111-8111-111111111111:model-step:1"
    )
    assert posts[0][1]["session_id"].startswith("telegram-event:")
    assert posts[0][1]["api_request_id"] == "model-step:1"
    assert posts[0][1]["telegram_event_id"] == "11111111-1111-4111-8111-111111111111"
    assert posts[0][1]["telegram_model_step"] == 1
    assert posts[1][1]["telegram_lease_fence"] == 7


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
        _request(),
        lambda _request: pytest.fail("provider call must not run"),
        **_middleware_kwargs(),
    )
    assert "duplicate" in response.choices[0].message.content


def test_plugin_registers_memory_tools_and_execution_middleware() -> None:
    plugin = _load_plugin()
    registrations: list[tuple[str, Any]] = []
    hooks: list[tuple[str, Any]] = []
    tools: list[dict[str, Any]] = []
    ctx = SimpleNamespace(
        register_middleware=lambda kind, callback: registrations.append((kind, callback)),
        register_hook=lambda kind, callback: hooks.append((kind, callback)),
        register_tool=lambda **kwargs: tools.append(kwargs),
    )
    plugin.register(ctx)
    assert [tool["name"] for tool in tools] == [
        "lucy_memory_lookup",
        "lucy_memory_propose",
        "lucy_evidence_retrieve",
    ]
    assert {tool["toolset"] for tool in tools} == {"lucy_memory"}
    assert all(
        tool["requires_env"] == ["LUCY_COMPANION_URL", "LUCY_ADAPTER_TOKEN"] for tool in tools
    )
    assert registrations == [
        ("llm_request", plugin._request_middleware),
        ("llm_execution", plugin._execution_middleware),
        ("tool_execution", plugin._tool_execution_middleware),
    ]
    assert hooks == [
        ("pre_llm_call", plugin._pre_llm_call),
        ("transform_llm_output", plugin._transform_llm_output),
        ("post_llm_call", plugin._post_llm_call),
        ("on_session_end", plugin._on_session_end),
    ]


def test_stage1_registers_only_read_only_memory_and_budget_middleware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", "1")
    plugin = _load_plugin()
    registrations: list[tuple[str, Any]] = []
    hooks: list[tuple[str, Any]] = []
    tools: list[dict[str, Any]] = []
    ctx = SimpleNamespace(
        register_middleware=lambda kind, callback: registrations.append((kind, callback)),
        register_hook=lambda kind, callback: hooks.append((kind, callback)),
        register_tool=lambda **kwargs: tools.append(kwargs),
    )
    plugin.register(ctx)
    assert [tool["name"] for tool in tools] == ["lucy_memory_lookup"]
    assert [kind for kind, _callback in registrations] == [
        "llm_request",
        "llm_execution",
        "tool_execution",
    ]
    assert hooks == []


def test_stage2_registers_capture_hooks_but_no_sensitive_tools_or_fallback_writer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", "2")
    plugin = _load_plugin()
    registrations: list[tuple[str, Any]] = []
    hooks: list[tuple[str, Any]] = []
    tools: list[dict[str, Any]] = []
    ctx = SimpleNamespace(
        register_middleware=lambda kind, callback: registrations.append((kind, callback)),
        register_hook=lambda kind, callback: hooks.append((kind, callback)),
        register_tool=lambda **kwargs: tools.append(kwargs),
    )
    plugin.register(ctx)
    assert [tool["name"] for tool in tools] == ["lucy_memory_lookup"]
    assert [kind for kind, _callback in registrations] == [
        "llm_request",
        "llm_execution",
        "tool_execution",
    ]
    assert [kind for kind, _callback in hooks] == [
        "pre_llm_call",
        "transform_llm_output",
        "on_session_end",
    ]


def test_stage2_hindsight_hides_old_lookup_but_keeps_capture_hooks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", "2")
    monkeypatch.setenv("LUCY_HINDSIGHT_ENABLED", "true")
    plugin = _load_plugin()
    tools: list[dict[str, Any]] = []
    hooks: list[str] = []
    ctx = SimpleNamespace(
        register_middleware=lambda _kind, _callback: None,
        register_hook=lambda kind, _callback: hooks.append(kind),
        register_tool=lambda **kwargs: tools.append(kwargs),
    )
    plugin.register(ctx)
    assert tools == []
    assert hooks == ["pre_llm_call", "transform_llm_output", "on_session_end"]


def test_stage2_forget_phrase_never_calls_sensitive_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", "2")
    plugin = _load_plugin()
    calls: list[str] = []

    def request(path: str, **_kwargs: Any) -> dict[str, Any]:
        calls.append(path)
        if path.endswith("/accept-turn"):
            return {"capture_enabled": True, "version": 0}
        raise AssertionError("sensitive boundary must not be called")

    monkeypatch.setattr(plugin, "_request_json", request)
    context = plugin._pre_llm_call(
        user_message="Lucy, forget the last message.",
        session_id="session-stage2",
        turn_id="turn-stage2",
        platform="telegram",
    )
    assert context is not None and "not confirmed" in context["context"]
    assert calls == ["/internal/v1/conversations/accept-turn"]


def test_stage2_off_record_transition_and_receipt_are_one_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", "2")
    plugin = _load_plugin()
    calls: list[tuple[str, dict[str, Any]]] = []

    def request(path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((path, kwargs))
        return {"capture_enabled": False, "version": 1, "replayed": False}

    monkeypatch.setattr(plugin, "_request_json", request)
    context = plugin._pre_llm_call(
        user_message="Lucy, off the record.",
        session_id="stage2-conversation",
        turn_id="stage2-control-turn",
        platform="telegram",
    )
    assert context is not None and "not archiving" in context["context"]
    assert [path for path, _kwargs in calls] == [
        "/internal/v1/conversations/capture-mode-and-accept"
    ]
    assert calls[0][1]["payload"]["source_turn_id"] == "stage2-control-turn"


def test_telegram_transcript_hooks_archive_both_roles_idempotently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    calls: list[tuple[str, dict[str, Any]]] = []

    def request(path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((path, kwargs))
        if "capture-mode" in path or path.endswith("/accept-turn"):
            return {"capture_enabled": True, "version": 0}
        return {
            "archived": True,
            "evidence_id": "evidence-1",
            "keyed_commitment": "a" * 64,
            "turn_committed": kwargs["payload"]["role"] == "assistant",
        }

    monkeypatch.setattr(plugin, "_request_json", request)
    hook_context = {
        "user_message": "Please remember our whole conversation.",
        "session_id": "session-1",
        "turn_id": "turn-1",
        "platform": "telegram",
    }
    context = plugin._pre_llm_call(**hook_context)
    assert context is not None
    assert "evidence_id evidence-1" in context["context"]
    assert (
        plugin._transform_llm_output(
            response_text="I will retain our conversations by default.",
            session_id="session-1",
            turn_id="turn-1",
            platform="telegram",
        )
        is None
    )
    plugin._post_llm_call(
        **hook_context,
        assistant_response="I will retain our conversations by default.",
    )

    message_calls = [call for call in calls if call[0].endswith("/messages")]
    assert len(message_calls) == 4
    assert [call[1]["payload"]["role"] for call in message_calls] == [
        "user",
        "assistant",
        "user",
        "assistant",
    ]
    assert message_calls[0][1]["extra_headers"] == message_calls[2][1]["extra_headers"]
    assert message_calls[1][1]["extra_headers"] == message_calls[3][1]["extra_headers"]
    assert message_calls[1][1]["payload"]["current_input_evidence_id"] == "evidence-1"


def test_archive_recovers_one_ambiguous_private_response_with_exact_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    calls: list[tuple[str, dict[str, Any]]] = []

    def request(path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((path, kwargs))
        if len(calls) == 1:
            raise TimeoutError("synthetic lost response")
        return {
            "archived": True,
            "evidence_id": "evidence-1",
            "operation_id": "operation-1",
            "turn_committed": False,
        }

    monkeypatch.setattr(plugin, "_request_json", request)
    result = plugin._archive_conversation_message(
        role="user",
        content="Synthetic retry-safe message.",
        session_id="session-1",
        turn_id="turn-1",
        platform="telegram",
    )

    assert result is not None and result["archived"] is True
    assert len(calls) == 2
    assert calls[0] == calls[1]


def test_archive_does_not_retry_definitive_http_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    plugin = _load_plugin()
    calls = 0

    def request(_path: str, **_kwargs: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        raise HTTPError(
            "http://lucy-routine",
            409,
            "Conflict",
            {},
            io.BytesIO(b'{"detail":"realm archive boundary unavailable"}'),
        )

    monkeypatch.setattr(plugin, "_request_json", request)
    result = plugin._archive_conversation_message(
        role="assistant",
        content="Synthetic definitive failure.",
        session_id="session-1",
        turn_id="turn-1",
        platform="telegram",
    )

    assert result is None
    assert calls == 1
    output = capsys.readouterr().out
    assert '"code":"archive_http_error"' in output
    assert '"http_status":409' in output
    assert '"attempt":1' in output
    assert '"reason":"archive_boundary_unavailable"' in output
    assert "Synthetic definitive failure" not in output


def test_capture_transition_recovers_one_ambiguous_response_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", "2")
    calls: list[tuple[str, dict[str, Any]]] = []

    def request(path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((path, kwargs))
        if len(calls) == 1:
            raise TimeoutError("synthetic lost transition response")
        return {"capture_enabled": False, "version": 1, "replayed": True}

    monkeypatch.setattr(plugin, "_request_json", request)
    assert plugin._set_capture_mode(
        session_id="session-2", turn_id="turn-2", capture_enabled=False
    )
    assert len(calls) == 2
    assert calls[0] == calls[1]


def test_blocked_delivery_notice_is_not_archived_as_the_assistant_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    calls: list[str] = []

    def archive(**kwargs: Any) -> dict[str, Any] | None:
        calls.append(kwargs["content"])
        return None

    monkeypatch.setattr(plugin, "_archive_conversation_message", archive)
    plugin._SESSION_TURN["session-1"] = {
        "turn_id": "turn-1",
        "capture_enabled": True,
        "active": True,
        "proposal_keys": {},
    }
    notice = plugin._transform_llm_output(
        response_text="Synthetic substantive response.",
        session_id="session-1",
        turn_id="turn-1",
        platform="telegram",
    )
    assert notice is not None and "could not durably retain" in notice
    plugin._post_llm_call(
        user_message="Synthetic owner message.",
        assistant_response=notice,
        session_id="session-1",
        turn_id="turn-1",
        platform="telegram",
    )
    assert calls == ["Synthetic substantive response."]


def test_failed_inbound_retention_does_not_attempt_outbound_archive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    calls: list[str] = []

    def archive(**kwargs: Any) -> dict[str, Any] | None:
        calls.append(kwargs["role"])
        return None

    monkeypatch.setattr(plugin, "_archive_conversation_message", archive)
    plugin._SESSION_TURN["session-1"] = {
        "turn_id": "turn-1",
        "capture_enabled": True,
        "active": False,
        "proposal_keys": {},
        "source_evidence_ids": set(),
        "current_input_evidence_id": None,
    }

    transformed = plugin._transform_llm_output(
        response_text="Lucy blocked this model call because retention was unavailable.",
        session_id="session-1",
        turn_id="turn-1",
        platform="telegram",
    )

    assert transformed is None
    assert calls == []


def test_off_record_is_visible_and_skips_archive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    calls: list[str] = []

    def request(path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append(path)
        assert path.endswith(("/capture-mode", "/accept-turn"))
        if path.endswith("/capture-mode"):
            assert kwargs["payload"]["capture_enabled"] is False
        else:
            assert "content" not in kwargs["payload"]
        return {"capture_enabled": False, "version": 1}

    monkeypatch.setattr(plugin, "_request_json", request)
    context = plugin._pre_llm_call(
        user_message="Lucy, off the record.",
        session_id="session-2",
        turn_id="turn-2",
        platform="telegram",
    )
    transformed = plugin._transform_llm_output(
        response_text="Understood.",
        session_id="session-2",
        turn_id="turn-2",
        platform="telegram",
    )
    assert context is not None and "not archiving" in context["context"]
    assert transformed is not None and transformed.startswith("🔒 Off the record")
    assert calls == ["/internal/v1/conversations/capture-mode",
                     "/internal/v1/conversations/accept-turn"]


def test_back_on_record_archives_the_control_turn_before_delivery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    calls: list[tuple[str, dict[str, Any]]] = []

    def request(path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((path, kwargs))
        if path.endswith(("/capture-mode", "/accept-turn")):
            return {"capture_enabled": True, "version": 2}
        role = kwargs["payload"]["role"]
        return {
            "archived": True,
            "evidence_id": f"evidence-{role}",
            "keyed_commitment": "a" * 64,
            "turn_committed": role == "assistant",
        }

    monkeypatch.setattr(plugin, "_request_json", request)
    context = plugin._pre_llm_call(
        user_message="Back on the record.",
        session_id="session-3",
        turn_id="turn-3",
        platform="telegram",
    )
    transformed = plugin._transform_llm_output(
        response_text="Capture is back on.",
        session_id="session-3",
        turn_id="turn-3",
        platform="telegram",
    )

    assert context is not None and "evidence-user" in context["context"]
    assert transformed is None
    assert [path for path, _kwargs in calls] == [
        "/internal/v1/conversations/capture-mode",
        "/internal/v1/conversations/accept-turn",
        "/internal/v1/conversations/messages",
        "/internal/v1/conversations/messages",
    ]
    assert [kwargs["payload"]["role"] for path, kwargs in calls if path.endswith("/messages")] == [
        "user",
        "assistant",
    ]


def test_forget_last_deletes_before_archiving_the_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    # This isolated protocol test stubs the policy issuer. The actual gateway
    # permit endpoint remains quarantined and has its own negative API test.
    monkeypatch.setenv("LUCY_ALLOW_LOCAL_BOUNDARY_FALLBACK", "true")
    calls: list[tuple[str, dict[str, Any]]] = []

    def request(path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((path, kwargs))
        if "latest-retained-evidence" in path:
            return {"evidence_id": "12345678-1234-5678-1234-567812345678"}
        if path.endswith("/sensitive-action-permits"):
            return {"signed": "permit"}
        if path.endswith("/forget-last"):
            return {"deleted": True, "key_destroyed": True}
        if "capture-mode" in path or path.endswith("/accept-turn"):
            return {"capture_enabled": True, "version": 2}
        role = kwargs["payload"]["role"]
        return {
            "archived": True,
            "evidence_id": f"evidence-{role}",
            "keyed_commitment": "b" * 64,
            "turn_committed": role == "assistant",
        }

    monkeypatch.setattr(plugin, "_request_json", request)
    context = plugin._pre_llm_call(
        user_message="Forget the last message.",
        session_id="session-4",
        turn_id="turn-4",
        platform="telegram",
    )
    transformed = plugin._transform_llm_output(
        response_text="That message and its derived memories were deleted.",
        session_id="session-4",
        turn_id="turn-4",
        platform="telegram",
    )

    assert context is not None and "were deleted" in context["context"]
    assert transformed is None
    assert [path for path, _kwargs in calls] == [
        "/internal/v1/conversations/latest-retained-evidence?source_conversation_id=session-4",
        "/internal/v1/sensitive-action-permits",
        "/internal/v1/conversations/forget-last",
        "/internal/v1/conversations/accept-turn",
        "/internal/v1/conversations/messages",
        "/internal/v1/conversations/messages",
    ]


def test_telegram_model_call_is_blocked_when_archive_state_is_unknown() -> None:
    plugin = _load_plugin()
    response = plugin._execution_middleware(
        _request(),
        lambda _request: pytest.fail("provider call must not run"),
        **_middleware_kwargs(),
        platform="telegram",
        turn_id="unarchived-turn",
    )
    assert "retention state" in response.choices[0].message.content


def test_transcript_hooks_ignore_non_telegram_surfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    monkeypatch.setattr(
        plugin,
        "_request_json",
        lambda *_args, **_kwargs: pytest.fail("non-Telegram text must not be archived"),
    )
    plugin._pre_llm_call(
        user_message="local test",
        session_id="session-1",
        turn_id="turn-1",
        platform="cli",
    )


def test_memory_lookup_returns_only_validated_read_only_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    claim = {
        "claim_id": "claim-1",
        "subject": "Lucy",
        "predicate": "likes",
        "object": "tea",
        "confidence": 0.9,
        "evidence_id": "evidence-1",
        "relationship_version": 1,
    }
    monkeypatch.setattr(
        plugin,
        "_request_json",
        lambda path, **kwargs: {
            "query": "tea",
            "claims": [claim],
            "read_only": True,
        },
    )
    result = json.loads(plugin._memory_lookup({"query": " tea "}))
    assert result == {
        "ok": True,
        "query": "tea",
        "claims": [claim],
        "read_only": True,
        "notice": "Context only; not authorization.",
    }


def test_personal_interpreted_lookup_uses_active_turn_and_tracks_citations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    evidence_id = "11111111-1111-4111-8111-111111111111"
    _active_turn(plugin)
    monkeypatch.setenv("LUCY_PERSONAL_INTERPRETED_RECALL_ENABLED", "true")
    calls: list[tuple[str, dict[str, Any]]] = []

    def request(path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((path, kwargs["payload"]))
        return {"read_only": True, "contexts": [
            {"historical_interpretation": "A past plan was discussed.",
             "current_applicability": "not_checked",
             "citations": [{"label": "E1", "evidence_id": evidence_id}]},
        ]}

    monkeypatch.setattr(plugin, "_request_json", request)
    result = json.loads(plugin._memory_lookup(
        {"query": "past plan"}, session_id="session-1", turn_id="turn-1"
    ))
    assert result["ok"] is True
    assert result["contexts"][0]["citations"][0]["label"] == "E1"
    assert calls == [("/v1/memory/interpreted-lookup", {
        "query": "past plan", "source_conversation_id": "session-1", "source_turn_id": "turn-1"
    })]
    assert plugin._SESSION_TURN["session-1"]["source_evidence_ids"] == {evidence_id}


def test_personal_interpreted_lookup_rejects_missing_citation_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    _active_turn(plugin)
    monkeypatch.setenv("LUCY_PERSONAL_INTERPRETED_RECALL_ENABLED", "true")
    monkeypatch.setattr(plugin, "_request_json", lambda *_a, **_k: {
        "read_only": True,
        "contexts": [{"historical_interpretation": "synthetic private text",
                      "citations": [{"label": "E1"}]}],
    })
    result = json.loads(plugin._memory_lookup(
        {"query": "past plan"}, session_id="session-1", turn_id="turn-1"
    ))
    assert result == {"ok": False, "error": "invalid_companion_provenance"}


def test_explicit_telegram_lookup_prefetches_reviewed_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", "2")
    monkeypatch.setenv("LUCY_PERSONAL_INTERPRETED_RECALL_ENABLED", "true")
    monkeypatch.setattr(plugin, "_accept_turn", lambda *_args: True)
    monkeypatch.setattr(plugin, "_archive_conversation_message", lambda **_kwargs: {
        "archived": True, "evidence_id": "11111111-1111-4111-8111-111111111111"
    })
    calls: list[tuple[dict[str, Any], str, str]] = []

    def lookup(args: dict[str, Any], *, session_id: str, turn_id: str) -> str:
        calls.append((args, session_id, turn_id))
        return json.dumps({"ok": True, "contexts": [{
            "historical_interpretation": "Synthetic dated interpretation.",
            "citations": [{"label": "E1", "evidence_id": "22222222-2222-4222-8222-222222222222"}],
        }]})

    monkeypatch.setattr(plugin, "_memory_lookup", lookup)
    result = plugin._pre_llm_call(
        user_message='Look up “Gate” in your memory. What changed?',
        session_id="session-prefetch", turn_id="turn-prefetch", platform="telegram",
    )
    assert calls == [({"query": "Gate"}, "session-prefetch", "turn-prefetch")]
    assert result is not None
    assert "already complete" in result["context"]
    assert "Synthetic dated interpretation." in result["context"]
    assert '"label":"E1"' in result["context"]
    bounded = plugin._request_middleware({
        "messages": [], "tools": [{"type": "function"}],
        "tool_choice": "auto", "parallel_tool_calls": True,
    })["request"]
    assert "tools" not in bounded
    assert "tool_choice" not in bounded
    assert "parallel_tool_calls" not in bounded


def test_hindsight_recall_preserves_reviewed_nuance_and_source_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    monkeypatch.setenv("HINDSIGHT_API_URL", "http://raymond-hindsight-api:8888")
    monkeypatch.setenv("HINDSIGHT_API_KEY", "synthetic-key")
    seen: list[str] = []
    rows = [
        {"text": "An assistant proposed a second tag as confirmed.",
         "document_id": "raw-1", "metadata": {"source": "approved_chatgpt_export",
                                                 "source_record_id": "raw-source"}},
        {"text": "Ray confirmed Trial Gate only as the minimum tag.",
         "document_id": "review-1", "metadata": {
             "source": "lucy_governed_reviewed_interpretation",
             "source_record_ids": '["review-source-1"]'}},
        {"text": "Guardian Locked was proposed; Ray's confirmation was ambiguous.",
         "document_id": "review-2", "metadata": {
             "source": "lucy_governed_reviewed_interpretation",
             "source_record_ids": '["review-source-2"]'}},
        {"text": "Uncited derived thought", "metadata": {}},
    ]

    def open_recall(request: Any, *, timeout: int) -> io.BytesIO:
        seen.append(request.full_url)
        assert timeout == 30
        assert request.get_header("Authorization") == "Bearer synthetic-key"
        return io.BytesIO(json.dumps({"results": rows}).encode())

    monkeypatch.setattr(plugin, "urlopen", open_recall)
    context = plugin._hindsight_recall_context(
        "What did Ray confirm about Gate?"
    )
    assert context is not None
    assert context.index("review-source-1") < context.index("raw-source")
    assert "Guardian Locked was proposed" in context
    assert "review-source-2" in context
    assert "Uncited derived thought" not in context
    assert seen == ["http://raymond-hindsight-api:8888/v1/default/banks/"
                    "ray-personal/memories/recall"]


def test_hindsight_telegram_prefetch_injects_citations_and_skips_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", "2")
    monkeypatch.setenv("LUCY_HINDSIGHT_ENABLED", "true")
    monkeypatch.setattr(plugin, "_accept_turn", lambda *_args: True)
    monkeypatch.setattr(plugin, "_archive_conversation_message", lambda **_kwargs: {
        "archived": True, "evidence_id": "11111111-1111-4111-8111-111111111111"
    })
    monkeypatch.setattr(plugin, "_hindsight_recall_context", lambda _query: (
        '{"kind":"reviewed","text":"A proposal remained ambiguous",'
        '"source_record_ids":["source-1"]}'
    ))
    result = plugin._pre_llm_call(
        user_message="What did I confirm?", session_id="hindsight-session",
        turn_id="hindsight-turn", platform="telegram",
    )
    assert result is not None
    assert "source-1" in result["context"]
    assert "what was only proposed or ambiguous" in result["context"]
    bounded = plugin._request_middleware({
        "messages": [], "tools": [{"type": "function"}], "tool_choice": "auto",
    })["request"]
    assert "tools" not in bounded


def test_hindsight_gateway_strips_tools_without_turn_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", "2")
    monkeypatch.setenv("LUCY_HINDSIGHT_ENABLED", "true")
    request = {"messages": [], "tools": [{"type": "function"}],
               "tool_choice": "auto", "parallel_tool_calls": True}
    bounded = Context().run(plugin._request_middleware, request)["request"]
    assert "tools" not in bounded
    assert "tool_choice" not in bounded
    assert "parallel_tool_calls" not in bounded


def test_raw_tool_markup_is_replaced_before_archive_and_delivery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    archived: list[str] = []

    def archive(**kwargs: Any) -> dict[str, Any]:
        archived.append(kwargs["content"])
        return {"archived": True, "turn_committed": True}

    monkeypatch.setattr(plugin, "_archive_conversation_message", archive)
    plugin._SESSION_TURN["session-markup"] = {
        "turn_id": "turn-markup", "capture_enabled": True,
        "active": True, "proposal_keys": {},
    }
    for raw_markup in (
        '<|channel|>commentary to=functions.tool_call {"name":"lucy_memory_lookup"}',
        '<|start|>assistant<|channel|>commentary to=hermes-recall code'
        '<|message|>{"query":"Gate"}<|call|>',
    ):
        plugin._SESSION_TURN["session-markup"]["active"] = True
        delivered = plugin._transform_llm_output(
            response_text=raw_markup,
            session_id="session-markup", turn_id="turn-markup", platform="telegram",
        )
        assert delivered is not None and "could not complete" in delivered
        assert "<|" not in delivered
    assert archived == [delivered, delivered]


def test_memory_lookup_fails_closed_on_invalid_companion_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    monkeypatch.setattr(
        plugin,
        "_request_json",
        lambda path, **kwargs: {"claims": [], "read_only": False},
    )
    result = json.loads(plugin._memory_lookup({"query": "tea"}))
    assert result == {"ok": False, "error": "invalid_companion_response"}


def test_memory_proposal_is_pending_idempotent_and_never_applied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    _active_turn(plugin)
    calls: list[tuple[str, dict[str, Any]]] = []

    def request(path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((path, kwargs))
        return {
            "proposal_id": "proposal-1",
            "approval_id": "approval-1",
            "status": "pending",
            "claim_id": None,
            "replayed": False,
        }

    monkeypatch.setattr(plugin, "_request_json", request)
    args = {
        "evidence_id": "12345678-1234-5678-1234-567812345678",
        "subject": "Lucy",
        "predicate": "likes",
        "object": "tea",
        "confidence": 0.9,
    }
    first = json.loads(plugin._memory_propose(args, session_id="session-1", turn_id="turn-1"))
    json.loads(plugin._memory_propose(args, session_id="session-1", turn_id="turn-1"))
    assert first["status"] == "pending"
    assert first["applied"] is False
    assert first["notice"].startswith("Pending human approval")
    assert calls[0][1]["extra_headers"]["Idempotency-Key"].startswith("hermes-memory-proposal:")
    assert calls[0][1]["extra_headers"] == calls[1][1]["extra_headers"]


def test_memory_proposal_rejects_applied_companion_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    _active_turn(plugin)
    monkeypatch.setattr(
        plugin,
        "_request_json",
        lambda path, **kwargs: {
            "proposal_id": "proposal-1",
            "approval_id": "approval-1",
            "status": "applied",
            "claim_id": "claim-1",
        },
    )
    result = json.loads(
        plugin._memory_propose(
            {
                "evidence_id": "12345678-1234-5678-1234-567812345678",
                "subject": "Lucy",
                "predicate": "likes",
                "object": "tea",
                "confidence": 0.9,
            }, session_id="session-1", turn_id="turn-1",
        )
    )
    assert result == {"ok": False, "error": "invalid_companion_response"}


def test_evidence_retrieval_is_provenance_bounded_and_audited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    monkeypatch.setenv("LUCY_ALLOW_LOCAL_BOUNDARY_FALLBACK", "true")
    calls: list[dict[str, Any]] = []

    def request(path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        if path.endswith("/sensitive-action-permits"):
            return {"signed": "permit"}
        return {
            "evidence_id": "12345678-1234-5678-1234-567812345678",
            "message": {
                "message_id": "turn-1:user",
                "role": "user",
                "content": "Exact wording",
                "occurred_at": "2026-08-28T12:00:00Z",
            },
            "reason": "verify_exact_wording",
            "autonomous": True,
            "audited": True,
        }

    monkeypatch.setattr(plugin, "_request_json", request)
    _active_turn(plugin)
    result = json.loads(
        plugin._evidence_retrieve(
            {
                "evidence_id": "12345678-1234-5678-1234-567812345678",
                "claim_id": "87654321-4321-6789-4321-678943216789",
                "reason": "verify_exact_wording",
            }, session_id="session-1", turn_id="turn-1",
        )
    )
    assert result["ok"] is True
    assert result["audited"] is True
    assert result["message"]["content"] == "Exact wording"
    assert calls[1]["extra_headers"]["Idempotency-Key"].startswith("hermes-evidence-read:")


def test_evidence_retrieval_requires_an_active_owner_interaction() -> None:
    plugin = _load_plugin()
    result = json.loads(
        plugin._evidence_retrieve(
            {
                "evidence_id": "12345678-1234-5678-1234-567812345678",
                "claim_id": "87654321-4321-6789-4321-678943216789",
                "reason": "verify_exact_wording",
            }
        )
    )
    assert result == {"ok": False, "error": "owner_interaction_required"}


@pytest.mark.parametrize("context", [{}, {"session_id": "session-1", "turn_id": "stale"},
                                    {"session_id": "unknown", "turn_id": "turn-1"}])
def test_model_arguments_cannot_supply_trusted_invocation_context(
    monkeypatch: pytest.MonkeyPatch, context: dict[str, str],
) -> None:
    plugin = _load_plugin()
    _active_turn(plugin)
    monkeypatch.setattr(plugin, "_request_json", lambda *_a, **_k: pytest.fail("no HTTP allowed"))
    args = {"evidence_id": "12345678-1234-5678-1234-567812345678",
            "claim_id": "87654321-4321-6789-4321-678943216789",
            "subject": "owner", "predicate": "likes", "object": "tea", "confidence": 0.9,
            "reason": "resolve_ambiguity", "session_id": "session-1", "turn_id": "turn-1"}
    assert not json.loads(plugin._memory_propose(args, **context))["ok"]
    assert not json.loads(plugin._evidence_retrieve(args, **context))["ok"]


def test_off_record_memory_proposal_never_calls_companion(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _load_plugin()
    _active_turn(plugin)
    plugin._SESSION_TURN["session-1"]["capture_enabled"] = False
    monkeypatch.setattr(plugin, "_request_json", lambda *_a, **_k: pytest.fail("no HTTP allowed"))
    result = json.loads(plugin._memory_propose(
        {"evidence_id": "12345678-1234-5678-1234-567812345678", "subject": "private"},
        session_id="session-1", turn_id="turn-1",
    ))
    assert result == {"ok": False, "error": "retained_turn_required"}


def test_parallel_sessions_keep_evidence_authority_invocation_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    _active_turn(plugin, "session-A", "turn-A")
    _active_turn(plugin, "session-B", "turn-B")
    captured: list[dict[str, Any]] = []

    def issue(**kwargs: Any) -> Any:
        captured.append(kwargs)
        raise RuntimeError("synthetic stop before disclosure")

    monkeypatch.setattr(plugin, "_issue_sensitive_permit", issue)
    plugin._evidence_retrieve(
        {"evidence_id": "12345678-1234-5678-1234-567812345678",
         "claim_id": "87654321-4321-6789-4321-678943216789", "reason": "resolve_ambiguity"},
        session_id="session-A", turn_id="turn-A",
    )
    assert captured[0]["session_id"] == "session-A"
    assert captured[0]["turn_id"] == "turn-A"


def test_pinned_handler_signature_gets_turn_from_execution_middleware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    _active_turn(plugin, "A", "turn-A")
    _active_turn(plugin, "B", "turn-B")
    barrier = Barrier(2)

    def issue(**kwargs: Any) -> Any:
        assert kwargs["turn_id"] == f"turn-{kwargs['session_id']}"
        raise RuntimeError("synthetic stop before disclosure")

    monkeypatch.setattr(plugin, "_issue_sensitive_permit", issue)

    def invoke(session: str) -> None:
        args = {"evidence_id": "12345678-1234-5678-1234-567812345678",
                "claim_id": "87654321-4321-6789-4321-678943216789",
                "reason": "resolve_ambiguity", "session_id": "FORGED", "turn_id": "FORGED"}

        def dispatch(arguments: dict[str, Any]) -> str:
            barrier.wait(timeout=5)
            assert plugin._TOOL_CONTEXT.get() == (session, f"turn-{session}")
            # Matches model_tools.py: the handler receives session_id, no turn_id.
            return plugin._evidence_retrieve(arguments, session_id=session)

        plugin._tool_execution_middleware(
            args, dispatch, tool_name="lucy_evidence_retrieve",
            session_id=session, turn_id=f"turn-{session}",
        )
        assert plugin._TOOL_CONTEXT.get() is None

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(invoke, ("A", "B")))


def test_pinned_output_hook_uses_execution_local_lifecycle_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _load_plugin()
    monkeypatch.setattr(plugin, "_accept_turn", lambda *_: False)
    contexts = {session: Context() for session in ("A", "B")}
    for session, context in contexts.items():
        context.run(plugin._pre_llm_call, user_message="Synthetic off-record turn",
                    session_id=session, turn_id=f"turn-{session}", platform="telegram")
    # The pinned finalizer sends no turn_id. Session B's later start must not
    # change A's context, and a context with no pre-call hook must fail closed.
    for session, context in contexts.items():
        result = context.run(plugin._transform_llm_output, response_text="Synthetic reply",
                             session_id=session, platform="telegram")
        assert result.startswith(plugin.OFF_RECORD_NOTICE)
        assert context.run(plugin._TURN_CONTEXT.get) is None
    result = Context().run(plugin._transform_llm_output, response_text="Synthetic reply",
                           session_id="A", platform="telegram")
    assert "could not verify" in result


def test_evidence_retrieval_rejects_broad_model_reason() -> None:
    plugin = _load_plugin()
    result = json.loads(
        plugin._evidence_retrieve(
            {
                "evidence_id": "12345678-1234-5678-1234-567812345678",
                "claim_id": "87654321-4321-6789-4321-678943216789",
                "reason": "owner_export",
            }
        )
    )
    assert result == {"ok": False, "error": "invalid_retrieval_reason"}


def test_request_middleware_injects_and_clamps_output_cap() -> None:
    plugin = _load_plugin()
    missing = plugin._request_middleware({"messages": []})["request"]
    oversized = plugin._request_middleware({"messages": [], "max_tokens": 9000})["request"]
    smaller = plugin._request_middleware({"messages": [], "max_completion_tokens": 200})["request"]
    assert missing["max_tokens"] == 1024
    assert oversized["max_tokens"] == 1024
    assert smaller["max_completion_tokens"] == 200
    expected_policy = _request()["extra_body"]["provider"]
    assert missing["extra_body"]["provider"] == expected_policy
    assert oversized["extra_body"]["provider"] == expected_policy
    assert smaller["extra_body"]["provider"] == expected_policy


def test_request_middleware_replaces_unapproved_provider_policy() -> None:
    plugin = _load_plugin()
    request = {
        "messages": [],
        "extra_body": {
            "provider": {"zdr": False, "max_price": {"completion": 999}},
            "unrelated": "preserved",
        },
    }
    bounded = plugin._request_middleware(request)["request"]
    assert bounded["extra_body"]["provider"] == _request()["extra_body"]["provider"]
    assert bounded["extra_body"]["unrelated"] == "preserved"
    assert request["extra_body"]["provider"]["zdr"] is False


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
        request, lambda _request: pytest.fail("provider call must not run"), **_middleware_kwargs()
    )
    assert "unapproved model route" in response.choices[0].message.content
def test_hindsight_retain_is_import_only(monkeypatch: Any) -> None:
    plugin = _load_plugin()
    monkeypatch.setenv("LUCY_HINDSIGHT_ENABLED", "true")
    calls: list[dict[str, Any]] = []
    result = plugin._tool_execution_middleware(
        {"content": "synthetic"}, lambda args: calls.append(args),
        tool_name="hindsight_retain", session_id="session-1", turn_id="turn-1",
    )
    assert json.loads(result) == {"ok": False, "error": "hindsight_import_only"}
    assert calls == []
