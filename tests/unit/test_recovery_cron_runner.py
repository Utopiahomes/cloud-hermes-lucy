from __future__ import annotations

import io
import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from deploy.render import recovery_cron_runner as runner


class _Response(io.StringIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


@contextmanager
def _environment(monkeypatch: pytest.MonkeyPatch, values: dict[str, str]) -> Iterator[None]:
    for key in tuple(runner.os.environ):
        if key.startswith("LUCY_RECOVERY_") or key.endswith("_EVENT_ID") or key.endswith("_TOKEN"):
            monkeypatch.delenv(key, raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    yield


def test_readiness_requires_each_exact_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = iter(
        [
            {"status": "ready", "stream_kind": "authority"},
            {"status": "ready", "stream_kind": "cost"},
            {"status": "ready"},
        ]
    )
    monkeypatch.setattr(runner, "_json_request", lambda *_a, **_k: next(responses))
    nonce = "0b233d55-aa9d-4f17-8a09-d98e86dad247"
    assert runner.readiness(nonce) == {
        "authority": "ready",
        "cost": "ready",
        "coordinator": "ready",
    }


def test_invoke_uses_exact_paths_and_terminal_states(monkeypatch: pytest.MonkeyPatch) -> None:
    authority_event = "9c72056b-bde8-4b71-b9ef-13537a2e91ad"
    cost_event = "f636f732-f4b5-4648-9710-1a411f8a9f66"
    calls: list[tuple[str, str | None]] = []
    responses = iter(
        [
            {"stream_kind": "authority", "sequence": 1},
            {"stream_kind": "cost", "sequence": 1},
            {"stream_kind": "authority", "state": "DURABLY_RECORDED"},
            {"stream_kind": "cost", "state": "ADMITTED"},
        ]
    )

    def request(url: str, *, token: str | None = None) -> dict[str, Any]:
        calls.append((url, token))
        return next(responses)

    monkeypatch.setattr(runner, "_json_request", request)
    with _environment(
        monkeypatch,
        {
            "AUTHORITY_EVENT_ID": authority_event,
            "COST_EVENT_ID": cost_event,
            "AUTHORITY_WRITER_TOKEN": "aw",
            "COST_WRITER_TOKEN": "cw",
            "AUTHORITY_ACK_TOKEN": "aa",
            "COST_ACK_TOKEN": "ca",
        },
    ):
        assert runner.invoke() == {
            "authority_writer": 1,
            "cost_writer": 1,
            "authority_ack": "DURABLY_RECORDED",
            "cost_ack": "ADMITTED",
        }
    assert calls == [
        (f"http://lucy-authority-writer:10000/v1/recovery/events/{authority_event}", "aw"),
        (f"http://lucy-cost-writer:10000/v1/recovery/events/{cost_event}", "cw"),
        (
            "http://lucy-recovery-coordinator:10000/v1/recovery/authority/"
            f"acknowledgements/{authority_event}",
            "aa",
        ),
        (
            "http://lucy-recovery-coordinator:10000/v1/recovery/cost/"
            f"acknowledgements/{cost_event}",
            "ca",
        ),
    ]


def test_json_request_does_not_send_body_or_auth_for_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def urlopen(request: Any, *, timeout: int) -> _Response:
        captured.update(
            method=request.method,
            data=request.data,
            authorization=request.get_header("Authorization"),
            timeout=timeout,
        )
        return _Response(json.dumps({"status": "ready"}))

    monkeypatch.setattr(runner.urllib.request, "urlopen", urlopen)
    assert runner._json_request("http://example.test/ready") == {"status": "ready"}
    assert captured == {
        "method": "GET",
        "data": None,
        "authorization": None,
        "timeout": 30,
    }
