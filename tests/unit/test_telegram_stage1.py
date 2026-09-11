from __future__ import annotations

import asyncio
import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from lucy.telegram_stage1 import (
    TelegramEventTransitionRequest,
    TelegramGatewayBinding,
    TelegramStage1Unavailable,
)

ROOT = Path(__file__).parents[2]


def test_stage1_binding_requires_four_exact_environment_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "LUCY_TELEGRAM_NODE_ID",
        "LUCY_TELEGRAM_REALM_ID",
        "LUCY_TELEGRAM_CHANNEL_BINDING_ID",
        "LUCY_TELEGRAM_BOT_ID",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(TelegramStage1Unavailable):
        TelegramGatewayBinding.from_environment()


def test_sent_transition_requires_only_a_numeric_outbound_id() -> None:
    base = {
        "holder_id": uuid4(),
        "fence": 1,
        "event_id": uuid4(),
    }
    with pytest.raises(ValidationError):
        TelegramEventTransitionRequest(**base, state="SENT")
    with pytest.raises(ValidationError):
        TelegramEventTransitionRequest(
            **base, state="INFERENCE_SETTLED", outbound_message_id=123
        )


def _load_overlay(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[ModuleType, type[Any]]:
    class FakeBasePlatformAdapter:
        async def _process_message_background(self, event: Any, session_key: str) -> None:
            del event, session_key
            await self._send_with_retry()

        async def _send_with_retry(self, *_args: Any, **_kwargs: Any) -> Any:
            return SimpleNamespace(success=True, message_id="901")

    gateway = ModuleType("gateway")
    platforms = ModuleType("gateway.platforms")
    base = ModuleType("gateway.platforms.base")
    base.BasePlatformAdapter = FakeBasePlatformAdapter
    monkeypatch.setitem(sys.modules, "gateway", gateway)
    monkeypatch.setitem(sys.modules, "gateway.platforms", platforms)
    monkeypatch.setitem(sys.modules, "gateway.platforms.base", base)
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", "1")
    monkeypatch.setenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "false")
    monkeypatch.setenv("LUCY_COMPANION_URL", "http://lucy.invalid")
    monkeypatch.setenv("LUCY_ADAPTER_TOKEN", "synthetic-token")
    monkeypatch.setenv("LUCY_TELEGRAM_GATEWAY_HOLDER_ID", str(uuid4()))
    monkeypatch.setenv("LUCY_TELEGRAM_GATEWAY_FENCE", "7")
    monkeypatch.setenv("LUCY_TELEGRAM_BOT_ID", "555")
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "123")
    monkeypatch.setenv("TELEGRAM_HOME_CHANNEL", "123")
    path = ROOT / "deploy" / "hermes" / "stage1_sitecustomize.py"
    spec = importlib.util.spec_from_file_location("test_stage1_sitecustomize", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module, FakeBasePlatformAdapter


def _event(*, user_id: str = "123", chat_id: str = "123") -> Any:
    return SimpleNamespace(
        source=SimpleNamespace(
            platform=SimpleNamespace(value="telegram"),
            user_id=user_id,
            chat_id=chat_id,
            chat_type="dm",
        ),
        message_id="41",
        platform_update_id=81,
        timestamp=datetime.now(UTC),
    )


def test_overlay_claims_before_inference_and_records_one_delivery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay, adapter_type = _load_overlay(monkeypatch)
    calls: list[tuple[str, dict[str, Any]]] = []

    def post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
        calls.append((path, payload))
        if path.endswith("/claim"):
            return {"admitted": True}
        return {"replayed": False}

    monkeypatch.setattr(overlay, "_post", post)
    asyncio.run(adapter_type()._process_message_background(_event(), "session"))
    assert [payload.get("state", "CLAIM") for _, payload in calls] == [
        "CLAIM",
        "INFERENCE_STARTED",
        "INFERENCE_SETTLED",
        "SEND_STARTED",
        "SENT",
    ]
    assert calls[-1][1]["outbound_message_id"] == 901
    serialized = str(calls)
    assert "message text" not in serialized and "response" not in serialized


def test_overlay_assigns_monotonic_model_steps_inside_one_claimed_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay, _adapter_type = _load_overlay(monkeypatch)
    event_id = uuid4()
    token = overlay._CURRENT.set(overlay._Event(event_id))
    try:
        assert overlay.next_model_operation() == (
            str(event_id),
            1,
        )
        assert overlay.next_model_operation() == (
            str(event_id),
            2,
        )
    finally:
        overlay._CURRENT.reset(token)


def test_overlay_drops_duplicate_and_wrong_owner_before_inference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay, adapter_type = _load_overlay(monkeypatch)
    calls: list[str] = []

    def post(path: str, _payload: dict[str, Any]) -> dict[str, Any]:
        calls.append(path)
        return {"admitted": False}

    monkeypatch.setattr(overlay, "_post", post)
    asyncio.run(adapter_type()._process_message_background(_event(), "session"))
    asyncio.run(
        adapter_type()._process_message_background(_event(user_id="999"), "session")
    )
    assert calls == ["/internal/v1/telegram-stage1/events/claim"]


def test_gateway_image_is_exactly_pinned_and_has_no_persistent_volume_contract() -> None:
    dockerfile = (ROOT / "Dockerfile.hermes-telegram-stage1").read_text(encoding="utf-8")
    lock = (ROOT / "hermes.lock").read_text(encoding="utf-8")
    assert "v2026.8.19@sha256:3811ed13" in dockerfile
    assert "commit=fcbd1076a93841fa88855acce810e342a5b78101" in lock
    assert "VOLUME" not in dockerfile
    launcher = (ROOT / "deploy" / "hermes" / "stage1_launcher.py").read_text(
        encoding="utf-8"
    )
    assert 'parts[2] == "tmpfs"' in launcher
    assert "stdout=subprocess.DEVNULL" in launcher
    assert "stderr=subprocess.DEVNULL" in launcher
    for event in (
        "configuration_validated",
        "ram_boundary_validated",
        "profile_staged",
        "preflight_passed",
        "lease_acquired",
        "gateway_started",
    ):
        assert event in launcher
    assert '("hermes_config",' in launcher
    assert '"lucy_plugin",' in launcher
    assert 'f"{label}_failed"' in launcher
    assert 'f"{label}_passed"' in launcher
