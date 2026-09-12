from __future__ import annotations

import asyncio
import importlib.util
import io
import os
import stat
import sys
import threading
import time
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


def _load_launcher() -> ModuleType:
    path = ROOT / "deploy" / "hermes" / "stage1_launcher.py"
    spec = importlib.util.spec_from_file_location("test_stage1_launcher", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_managed_home_prepares_only_ephemeral_hermes_runtime_directories(
    tmp_path: Path,
) -> None:
    launcher = _load_launcher()
    launcher._prepare_managed_home(tmp_path)
    assert {path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")} == {
        "cron",
        "logs",
        "memories",
        "sessions",
    }
    if os.name != "nt":
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
        for name in ("cron", "sessions", "logs", "memories"):
            assert stat.S_IMODE((tmp_path / name).stat().st_mode) == 0o700


@pytest.mark.parametrize("stage,capture", [("1", "false"), ("2", "true")])
def test_launcher_binds_capture_authority_to_release_stage(
    monkeypatch: pytest.MonkeyPatch, stage: str, capture: str
) -> None:
    launcher = _load_launcher()
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", stage)
    monkeypatch.setenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", capture)
    assert launcher._validate_stage_mode() == stage


@pytest.mark.parametrize("stage,capture", [("1", "true"), ("2", "false"), ("3", "false")])
def test_launcher_rejects_stage_capture_mismatch(
    monkeypatch: pytest.MonkeyPatch, stage: str, capture: str
) -> None:
    launcher = _load_launcher()
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", stage)
    monkeypatch.setenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", capture)
    with pytest.raises(RuntimeError, match="stage_capture_mismatch"):
        launcher._validate_stage_mode()


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
    *,
    stage: str = "1",
    capture: str = "false",
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
    monkeypatch.setenv("LUCY_TELEGRAM_STAGE", stage)
    monkeypatch.setenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", capture)
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


def test_stage2_overlay_preserves_owner_filter_and_delivery_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay, adapter_type = _load_overlay(monkeypatch, stage="2", capture="true")
    calls: list[str] = []

    def post(path: str, _payload: dict[str, Any]) -> dict[str, Any]:
        calls.append(path)
        return {"admitted": True} if path.endswith("/claim") else {"replayed": False}

    monkeypatch.setattr(overlay, "_post", post)
    asyncio.run(adapter_type()._process_message_background(_event(), "session"))
    assert calls[0].endswith("/claim")
    assert calls[-1].endswith("/transition")


def _event(
    *, user_id: str = "123", chat_id: str = "123", update_id: int = 81
) -> Any:
    return SimpleNamespace(
        text="hello",
        source=SimpleNamespace(
            platform=SimpleNamespace(value="telegram"),
            user_id=user_id,
            chat_id=chat_id,
            chat_type="dm",
        ),
        message_id="41",
        platform_update_id=update_id,
        timestamp=datetime.now(UTC),
    )


def test_stage2_rotates_hermes_history_before_capture_resumes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay, adapter_type = _load_overlay(monkeypatch, stage="2", capture="true")
    sequence: list[str] = []

    class Gateway:
        async def handle(self, _event: Any) -> str:
            sequence.append("inference")
            return "ok"

        async def _handle_reset_command(self, _event: Any) -> str:
            sequence.append("reset")
            return "reset"

    gateway = Gateway()
    adapter = adapter_type()
    adapter._message_handler = gateway.handle

    def post(path: str, _payload: dict[str, Any]) -> dict[str, Any]:
        return {"admitted": True} if path.endswith("/claim") else {"replayed": False}

    monkeypatch.setattr(overlay, "_post", post)
    event = _event()
    event.text = "Lucy, back on the record."
    asyncio.run(adapter._process_message_background(event, "session"))
    assert sequence == ["reset"]


def test_stage2_serializes_same_chat_claim_and_processing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay, adapter_type = _load_overlay(monkeypatch, stage="2", capture="true")
    guard = threading.Lock()
    active_claims = 0
    maximum_claims = 0

    def post(path: str, _payload: dict[str, Any]) -> dict[str, Any]:
        nonlocal active_claims, maximum_claims
        if not path.endswith("/claim"):
            return {"replayed": False}
        with guard:
            active_claims += 1
            maximum_claims = max(maximum_claims, active_claims)
        time.sleep(0.05)
        with guard:
            active_claims -= 1
        return {"admitted": True}

    monkeypatch.setattr(overlay, "_post", post)

    async def run_both() -> None:
        adapter = adapter_type()
        await asyncio.gather(
            adapter._process_message_background(_event(update_id=81), "session"),
            adapter._process_message_background(_event(update_id=82), "session"),
        )

    asyncio.run(run_both())
    assert maximum_claims == 1


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
    assert "stdout=subprocess.PIPE" in launcher
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


def test_launcher_forwards_only_allowlisted_content_free_retention_events(
    capsys: pytest.CaptureFixture[str],
) -> None:
    launcher = _load_launcher()
    stream = io.BytesIO(
        b'{"component":"lucy-retention","code":"archive_request_failed",'
        b'"role":"assistant","error_type":"TimeoutError"}\n'
        b'{"component":"lucy-retention","code":"archive_http_error",'
        b'"role":"assistant","http_status":409,"attempt":1,'
        b'"reason":"archive_boundary_unavailable","content":"secret"}\n'
        b'{"component":"lucy-retention","code":"unexpected","content":"secret"}\n'
        b'{"component":"other","code":"archive_request_failed","content":"secret"}\n'
        b'ordinary child output containing private conversation text\n'
    )
    launcher._forward_content_free_child_events(stream)
    output = capsys.readouterr().out
    assert "archive_request_failed" in output
    assert "TimeoutError" in output
    assert "archive_http_error" in output
    assert '"http_status":409' in output
    assert '"attempt":1' in output
    assert '"reason":"archive_boundary_unavailable"' in output
    assert "secret" not in output
    assert "private conversation" not in output


def test_stage2_gateway_uses_same_pin_with_capture_only_plugin_contract() -> None:
    dockerfile = (ROOT / "Dockerfile.hermes-telegram-stage2").read_text(encoding="utf-8")
    plugin = (ROOT / "deploy" / "hermes" / "stage2_plugin.yaml").read_text(
        encoding="utf-8"
    )
    assert "v2026.8.19@sha256:3811ed13" in dockerfile
    assert "stage2_plugin.yaml" in dockerfile
    assert "lucy_memory_lookup" in plugin
    assert "lucy_memory_propose" not in plugin
    assert "lucy_evidence_retrieve" not in plugin
    assert "pre_llm_call" in plugin
    assert "transform_llm_output" in plugin
    assert "post_llm_call" not in plugin
