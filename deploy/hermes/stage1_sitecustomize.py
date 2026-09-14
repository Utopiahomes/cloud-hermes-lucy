"""Fail-closed Stage 1 Telegram lifecycle overlay for pinned Hermes v0.20.5.

Imported as ``sitecustomize`` by the gateway Python interpreter.  The overlay
persists only numeric transport identifiers and closed lifecycle states through
Lucy's private companion API.  Message and response content never cross it.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import re
from contextlib import suppress
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any
from urllib.request import Request, urlopen
from uuid import NAMESPACE_URL, UUID, uuid5


@dataclass
class _Event:
    event_id: UUID
    model_step: int = 0


_CURRENT: ContextVar[_Event | None] = ContextVar("lucy_stage1_event", default=None)


def next_model_operation() -> tuple[str, int]:
    """Return one content-free, event-bound identity for the next provider call."""

    current = _CURRENT.get()
    if current is None:
        raise RuntimeError("stage1_event_context_missing")
    current.model_step += 1
    return str(current.event_id), current.model_step


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError("stage1_configuration_missing")
    return value


def _post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    base = _required("LUCY_COMPANION_URL").rstrip("/")
    token = _required("LUCY_ADAPTER_TOKEN")
    request = Request(
        f"{base}{path}",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urlopen(request, timeout=8) as response:  # noqa: S310 - fixed private service URL
        result: dict[str, Any] = json.load(response)
    return result


def _identity(event: Any) -> tuple[int, int, int, int]:
    source = getattr(event, "source", None)
    if source is None or str(getattr(getattr(source, "platform", None), "value", "")) != "telegram":
        raise RuntimeError("stage1_platform_denied")
    user_id = int(str(getattr(source, "user_id", "")))
    chat_id = int(str(getattr(source, "chat_id", "")))
    message_id = int(str(getattr(event, "message_id", "")))
    update_id = int(getattr(event, "platform_update_id", -1))
    if update_id < 0 or message_id <= 0:
        raise RuntimeError("stage1_transport_identity_missing")
    return user_id, chat_id, message_id, update_id


def _lease_payload() -> dict[str, Any]:
    return {
        "holder_id": _required("LUCY_TELEGRAM_GATEWAY_HOLDER_ID"),
        "fence": int(_required("LUCY_TELEGRAM_GATEWAY_FENCE")),
    }


def _is_back_on_record(event: Any) -> bool:
    text = getattr(event, "text", None)
    if not isinstance(text, str):
        return False
    normalized = re.sub(r"[.!?]+$", "", text.strip().casefold())
    normalized = re.sub(r"^lucy[, :]\s*", "", normalized)
    return normalized == "back on the record"


async def _reset_history_boundary(adapter: Any, event: Any) -> None:
    """Rotate Hermes history before capture resumes after an off-record interval."""

    handler = getattr(adapter, "_message_handler", None)
    gateway = getattr(handler, "__self__", None)
    reset = getattr(gateway, "_handle_reset_command", None)
    if reset is None:
        raise RuntimeError("stage2_history_boundary_unavailable")
    reset_event = copy.copy(event)
    reset_event.text = "/reset"
    await reset(reset_event)


def _transition(event_id: UUID, state: str, outbound_message_id: int | None = None) -> None:
    payload = {
        **_lease_payload(),
        "event_id": str(event_id),
        "state": state,
        "outbound_message_id": outbound_message_id,
    }
    _post("/internal/v1/telegram-stage1/events/transition", payload)


def _install() -> None:
    stage = os.getenv("LUCY_TELEGRAM_STAGE")
    if stage not in {"1", "2"}:
        return
    capture = os.getenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED")
    if (stage, capture) not in {("1", "false"), ("2", "true")}:
        raise RuntimeError("telegram_stage_capture_mismatch")

    from gateway.platforms.base import BasePlatformAdapter  # type: ignore[import-not-found]

    original_process = BasePlatformAdapter._process_message_background
    original_send = BasePlatformAdapter._send_with_retry
    conversation_locks: dict[int, asyncio.Lock] = {}

    async def stage1_process(self: Any, event: Any, session_key: str) -> None:
        try:
            user_id, chat_id, message_id, update_id = _identity(event)
        except (TypeError, ValueError, RuntimeError):
            return
        owner_id = int(_required("TELEGRAM_ALLOWED_USERS"))
        home_id = int(_required("TELEGRAM_HOME_CHANNEL"))
        chat_type = str(getattr(event.source, "chat_type", ""))
        if user_id != owner_id or chat_id != home_id or chat_type != "dm":
            return
        async with conversation_locks.setdefault(chat_id, asyncio.Lock()):
            bot_id = int(_required("LUCY_TELEGRAM_BOT_ID"))
            event_id = uuid5(NAMESPACE_URL, f"lucy-stage1:{bot_id}:{update_id}")
            claim = await asyncio.to_thread(
                _post,
                "/internal/v1/telegram-stage1/events/claim",
                {
                    **_lease_payload(),
                    "event_id": str(event_id),
                    "update_id": update_id,
                    "chat_id": chat_id,
                    "message_id": message_id,
                },
            )
            if claim.get("admitted") is not True:
                return
            context_token = _CURRENT.set(_Event(event_id))
            try:
                if stage == "2" and _is_back_on_record(event):
                    await _reset_history_boundary(self, event)
                await asyncio.to_thread(_transition, event_id, "INFERENCE_STARTED")
                await original_process(self, event, session_key)
                current = _CURRENT.get()
                if current is not None:
                    await asyncio.to_thread(_transition, event_id, "INFERENCE_SETTLED")
                    await asyncio.to_thread(_transition, event_id, "COMPLETED_NO_REPLY")
            except BaseException:
                with suppress(Exception):
                    await asyncio.to_thread(_transition, event_id, "INTERRUPTED")
                raise
            finally:
                _CURRENT.reset(context_token)

    async def stage1_send(self: Any, *args: Any, **kwargs: Any) -> Any:
        current = _CURRENT.get()
        if current is None:
            return await original_send(self, *args, **kwargs)
        event_id = current.event_id
        await asyncio.to_thread(_transition, event_id, "INFERENCE_SETTLED")
        await asyncio.to_thread(_transition, event_id, "SEND_STARTED")
        try:
            result = await original_send(self, *args, **kwargs)
        except BaseException:
            try:
                await asyncio.to_thread(_transition, event_id, "DELIVERY_UNCERTAIN")
            finally:
                _CURRENT.set(None)
            raise
        message_id = getattr(result, "message_id", None)
        if getattr(result, "success", False) and message_id is not None:
            await asyncio.to_thread(_transition, event_id, "SENT", int(message_id))
        else:
            await asyncio.to_thread(_transition, event_id, "DELIVERY_UNCERTAIN")
        _CURRENT.set(None)
        return result

    BasePlatformAdapter._process_message_background = stage1_process
    BasePlatformAdapter._send_with_retry = stage1_send


_install()
