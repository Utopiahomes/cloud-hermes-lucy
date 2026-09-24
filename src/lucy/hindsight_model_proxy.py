"""Bounded OpenAI-compatible model route for the private Hindsight service."""

from __future__ import annotations

import json
import os
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from lucy.model_execution import MODEL, RESERVATION_MICROUSD

_UPSTREAM = "https://openrouter.ai/api/v1/chat/completions"
_MAX_REQUEST_BYTES = 80_000
_MAX_RESPONSE_BYTES = 400_000
_MAX_OUTPUT_TOKENS = 4096
_ALLOWED_KEYS = {
    "model", "messages", "temperature", "top_p", "max_tokens",
    "max_completion_tokens", "response_format", "seed", "stop",
    "frequency_penalty", "presence_penalty", "reasoning_effort",
    "tools", "tool_choice", "parallel_tool_calls", "stream",
}


class HindsightModelProxyError(RuntimeError):
    pass


def _upstream_failure(error: HTTPError) -> str:
    """Return only bounded, non-content diagnostics from an upstream HTTP error."""
    status = error.code
    if status != 429:
        return f"upstream_http_{status}"
    try:
        body = json.loads(error.read(2_001))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        body = None
    message = ""
    provider = "unknown"
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        detail = body["error"]
        if isinstance(detail.get("message"), str):
            message = detail["message"].lower()
        metadata = detail.get("metadata")
        if isinstance(metadata, dict) and isinstance(metadata.get("provider_name"), str):
            candidate = metadata["provider_name"]
            if (candidate.isascii() and candidate.replace("-", "").isalnum()
                    and len(candidate) <= 40):
                provider = candidate
    reason = "rate_limit"
    if "credit" in message or "balance" in message:
        reason = "credits"
    elif "quota" in message or "daily" in message:
        reason = "quota"
    elif "provider" in message and "available" in message:
        reason = "provider_unavailable"
    retry = error.headers.get("Retry-After", "") if error.headers else ""
    retry_seconds = retry if retry.isdecimal() and len(retry) <= 4 else "unspecified"
    return f"upstream_http_429_{reason}_{provider}_retry_{retry_seconds}"


def _bounded_request(body: bytes) -> dict[str, Any]:
    if len(body) > _MAX_REQUEST_BYTES:
        raise HindsightModelProxyError("request_size")
    try:
        parsed = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HindsightModelProxyError("request_json") from exc
    if not isinstance(parsed, dict) or set(parsed) - _ALLOWED_KEYS:
        raise HindsightModelProxyError("request_shape")
    if parsed.get("model") != MODEL or parsed.get("stream", False):
        raise HindsightModelProxyError("model_route")
    messages = parsed.get("messages")
    if not isinstance(messages, list) or not 1 <= len(messages) <= 40:
        raise HindsightModelProxyError("messages")
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in {
            "system", "developer", "user", "assistant", "tool"
        }:
            raise HindsightModelProxyError("messages")
    output_cap = parsed.get("max_completion_tokens", parsed.get("max_tokens", _MAX_OUTPUT_TOKENS))
    if (not isinstance(output_cap, int) or isinstance(output_cap, bool)
            or output_cap < 1):
        raise HindsightModelProxyError("output_cap")
    if "max_completion_tokens" in parsed:
        parsed["max_completion_tokens"] = min(output_cap, _MAX_OUTPUT_TOKENS)
    elif "max_tokens" in parsed:
        parsed["max_tokens"] = min(output_cap, _MAX_OUTPUT_TOKENS)
    else:
        parsed["max_tokens"] = _MAX_OUTPUT_TOKENS
    if parsed.get("stream") is False:
        parsed.pop("stream")
    parsed["provider"] = {
        "zdr": True,
        "data_collection": "deny",
        "sort": "price",
        "require_parameters": True,
        "allow_fallbacks": False,
        "max_price": {"prompt": 0.10, "completion": 0.50},
    }
    return parsed


def _cost(usage: object) -> int:
    if not isinstance(usage, dict):
        raise HindsightModelProxyError("usage_missing")
    try:
        value = Decimal(str(usage["cost"]))
    except (KeyError, InvalidOperation, ValueError) as exc:
        raise HindsightModelProxyError("cost_missing") from exc
    if not value.is_finite() or value < 0:
        raise HindsightModelProxyError("cost_invalid")
    amount = int((value * 1_000_000).to_integral_value(rounding=ROUND_CEILING))
    if amount > RESERVATION_MICROUSD:
        raise HindsightModelProxyError("cost_over_reservation")
    return amount


def complete(body: bytes, sessions: sessionmaker[Session]) -> dict[str, Any]:
    """Reserve first, then call the pinned model with fail-closed routing."""
    request_body = _bounded_request(body)
    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key:
        raise HindsightModelProxyError("provider_key_missing")
    action_id = uuid4()
    with sessions.begin() as session:
        begin = session.execute(
            text("SELECT lucy.begin_hindsight_model_operation_v1(:action_id)"),
            {"action_id": action_id},
        ).scalar_one()
    if not begin.get("execute"):
        raise HindsightModelProxyError("budget_unavailable")
    succeeded = False
    actual = RESERVATION_MICROUSD
    try:
        wire = json.dumps(request_body, separators=(",", ":")).encode()
        upstream = Request(
            _UPSTREAM,
            data=wire,
            method="POST",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://localhost/cloud-hermes-lucy",
                "X-Title": "Lucy governed Hindsight inference",
            },
        )
        try:
            with urlopen(upstream, timeout=90) as response:  # noqa: S310 - fixed upstream URL
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            raise HindsightModelProxyError(_upstream_failure(exc)) from exc
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise HindsightModelProxyError("response_size")
        result = json.loads(raw)
        if not isinstance(result, dict) or result.get("model") != MODEL:
            raise HindsightModelProxyError("response_model")
        provider_usage = result.get("usage")
        actual = _cost(provider_usage)
        assert isinstance(provider_usage, dict)
        succeeded = True
        return result
    finally:
        with sessions.begin() as session:
            session.execute(
                text("SELECT lucy.settle_hindsight_model_operation_v1("
                     ":action_id,:actual,:succeeded)"),
                {"action_id": action_id, "actual": actual, "succeeded": succeeded},
            ).scalar_one()
