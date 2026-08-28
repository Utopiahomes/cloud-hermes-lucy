"""Fail-closed Hermes middleware backed by Lucy's durable model budget."""

from __future__ import annotations

import json
import math
import os
import time
from collections.abc import Callable
from contextlib import suppress
from types import SimpleNamespace
from typing import Any
from urllib.request import Request, urlopen

MODEL = "openai/gpt-oss-20b"
BASE_URL = "https://openrouter.ai/api/v1"
RESERVATION_MICROUSD = 5_000
BLOCKED_MESSAGE = "Lucy blocked this model call because its budget gate is unavailable."
MAX_OUTPUT_TOKENS = 1_024
MAX_PROMPT_USD_PER_MILLION = 0.10
MAX_COMPLETION_USD_PER_MILLION = 0.50


def _approved_provider_policy() -> dict[str, Any]:
    return {
        "zdr": True,
        "data_collection": "deny",
        "sort": "price",
        "require_parameters": True,
        "max_price": {
            "prompt": MAX_PROMPT_USD_PER_MILLION,
            "completion": MAX_COMPLETION_USD_PER_MILLION,
        },
    }


def _blocked_response(model: str, message: str = BLOCKED_MESSAGE) -> SimpleNamespace:
    return SimpleNamespace(
        id="lucy-budget-blocked",
        object="chat.completion",
        created=int(time.time()),
        model=model or MODEL,
        choices=[
            SimpleNamespace(
                index=0,
                finish_reason="stop",
                message=SimpleNamespace(
                    role="assistant", content=message, tool_calls=None
                ),
            )
        ],
        usage=SimpleNamespace(
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
            model_extra={},
        ),
    )


def _post_json(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    base_url = os.environ.get("LUCY_COMPANION_URL", "").rstrip("/")
    token = os.environ.get("LUCY_ADAPTER_TOKEN", "")
    if not base_url or not token:
        raise RuntimeError("Lucy companion configuration is missing")
    request = Request(
        f"{base_url}{path}",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urlopen(request, timeout=5) as response:  # noqa: S310 - configured private URL
        result: dict[str, Any] = json.load(response)
        return result


def _usage_value(usage: Any, *names: str) -> int | None:
    for name in names:
        value = getattr(usage, name, None)
        if isinstance(value, int) and value >= 0:
            return value
    return None


def _provider_cost_microusd(response: Any) -> int | None:
    usage = getattr(response, "usage", None)
    cost = getattr(usage, "cost", None)
    if cost is None:
        extra = getattr(usage, "model_extra", None)
        if isinstance(extra, dict):
            cost = extra.get("cost")
    if not isinstance(cost, (int, float)) or isinstance(cost, bool) or cost < 0:
        return None
    return math.ceil(float(cost) * 1_000_000)


def _usage_payload(response: Any) -> dict[str, int | None]:
    usage = getattr(response, "usage", None)
    output_tokens = _usage_value(usage, "completion_tokens", "output_tokens")
    details = getattr(usage, "completion_tokens_details", None)
    reasoning_tokens = _usage_value(details, "reasoning_tokens")
    return {
        "input_tokens": _usage_value(usage, "prompt_tokens", "input_tokens"),
        "output_tokens": output_tokens,
        "reasoning_tokens": reasoning_tokens,
        "provider_cost_microusd": _provider_cost_microusd(response),
    }


def _request_policy_failure(request: dict[str, Any]) -> str | None:
    output_cap = request.get("max_tokens", request.get("max_completion_tokens"))
    if (
        not isinstance(output_cap, int)
        or isinstance(output_cap, bool)
        or output_cap < 1
        or output_cap > MAX_OUTPUT_TOKENS
    ):
        return "output_cap"
    extra_body = request.get("extra_body")
    routing = extra_body.get("provider") if isinstance(extra_body, dict) else None
    if not isinstance(routing, dict):
        return "provider_policy_missing"
    max_price = routing.get("max_price")
    valid = (
        routing.get("zdr") is True
        and routing.get("data_collection") == "deny"
        and routing.get("sort") == "price"
        and routing.get("require_parameters") is True
        and isinstance(max_price, dict)
        and max_price.get("prompt") == MAX_PROMPT_USD_PER_MILLION
        and max_price.get("completion") == MAX_COMPLETION_USD_PER_MILLION
    )
    return None if valid else "provider_policy_mismatch"


def _request_middleware(
    request: dict[str, Any], **_: Any
) -> dict[str, Any]:
    bounded = dict(request)
    if "max_completion_tokens" in bounded:
        raw = bounded.get("max_completion_tokens")
        bounded["max_completion_tokens"] = (
            min(raw, MAX_OUTPUT_TOKENS)
            if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0
            else MAX_OUTPUT_TOKENS
        )
    else:
        raw = bounded.get("max_tokens")
        bounded["max_tokens"] = (
            min(raw, MAX_OUTPUT_TOKENS)
            if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0
            else MAX_OUTPUT_TOKENS
        )
    raw_extra_body = bounded.get("extra_body")
    extra_body = dict(raw_extra_body) if isinstance(raw_extra_body, dict) else {}
    # The pinned Hermes gateway path can omit the custom provider's extra_body
    # even though the same profile includes it for one-shot calls. Inject the
    # canonical policy into the effective wire request, then independently
    # revalidate it in execution middleware immediately before next_call().
    extra_body["provider"] = _approved_provider_policy()
    bounded["extra_body"] = extra_body
    return {
        "request": bounded,
        "source": "lucy_control",
        "reason": "output_cap_and_provider_policy",
    }


def _settle(action_id: str, response: Any, *, succeeded: bool) -> None:
    usage = _usage_payload(response)
    provider_cost = usage["provider_cost_microusd"]
    actual = (
        provider_cost
        if isinstance(provider_cost, int) and provider_cost <= RESERVATION_MICROUSD
        else RESERVATION_MICROUSD
    )
    _post_json(
        "/internal/v1/model-executions/settle",
        {
            "action_id": action_id,
            "actual_microusd": actual,
            "succeeded": succeeded,
            "usage": usage,
        },
    )


def _execution_middleware(
    request: dict[str, Any],
    next_call: Callable[[dict[str, Any]], Any],
    *,
    api_request_id: str = "",
    session_id: str = "",
    model: str = "",
    provider: str = "",
    base_url: str = "",
    **_: Any,
) -> Any:
    route_invalid = (
        model != MODEL
        or provider != "custom"
        or base_url.rstrip("/") != BASE_URL
        or not api_request_id
    )
    policy_failure = _request_policy_failure(request)
    if route_invalid or policy_failure:
        reason = "route_identity" if route_invalid else policy_failure
        return _blocked_response(
            model, f"Lucy blocked an unapproved model route ({reason})."
        )
    try:
        begun = _post_json(
            "/internal/v1/model-executions/begin",
            {
                "idempotency_key": f"hermes-model:{session_id}:{api_request_id}",
                "model": model,
                "reservation_microusd": RESERVATION_MICROUSD,
                "session_id": session_id,
                "api_request_id": api_request_id,
            },
        )
    except Exception:
        return _blocked_response(model)
    if begun.get("status") != "executing" or begun.get("execute") is not True:
        return _blocked_response(model, "Lucy blocked a duplicate or unreserved model call.")
    action_id = str(begun.get("action_id") or "")
    if not action_id:
        return _blocked_response(model)
    try:
        response = next_call(request)
    except Exception:
        with suppress(Exception):
            _settle(action_id, SimpleNamespace(usage=None), succeeded=False)
        raise
    # If settlement fails, the executing reservation remains durable. Rejoining
    # will mark the outcome ambiguous and conservatively charge it in full.
    with suppress(Exception):
        _settle(action_id, response, succeeded=True)
    return response


def register(ctx: Any) -> None:
    ctx.register_middleware("llm_request", _request_middleware)
    ctx.register_middleware("llm_execution", _execution_middleware)
