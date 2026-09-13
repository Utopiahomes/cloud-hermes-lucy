from __future__ import annotations

from types import SimpleNamespace

import pytest

import lucy.public_model_runtime as runtime


def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "LUCY_ENVIRONMENT": "production",
        "LUCY_SECURITY_BASELINE": "v1.3",
        "LUCY_SERVICE_MODE": "public-model",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_OBSERVED_HERMES_COMMIT": "a" * 40,
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_model_runtime_checks_cost_identity_before_starting_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _environment(monkeypatch)
    dependencies = SimpleNamespace()
    checks: list[object] = []
    listeners: list[bool] = []
    monkeypatch.setattr(runtime, "_expected_commit", lambda: "a" * 40)
    monkeypatch.setattr(runtime, "_dependencies", lambda: dependencies)
    monkeypatch.setattr(
        runtime, "check_cost_identity", lambda item: checks.append(item)
    )
    monkeypatch.setattr(
        runtime.uvicorn,
        "run",
        lambda *_args, **kwargs: listeners.append(kwargs["access_log"]),
    )

    runtime.main()

    assert checks == [dependencies]
    assert listeners == [False]


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("LUCY_ENVIRONMENT", "development"),
        ("LUCY_SERVICE_MODE", "public"),
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_OBSERVED_HERMES_COMMIT", "b" * 40),
    ),
)
def test_model_runtime_fails_before_dependencies_or_listener(
    monkeypatch: pytest.MonkeyPatch, key: str, value: str
) -> None:
    _environment(monkeypatch)
    monkeypatch.setenv(key, value)
    monkeypatch.setattr(runtime, "_expected_commit", lambda: "a" * 40)
    called: list[str] = []
    monkeypatch.setattr(runtime, "_dependencies", lambda: called.append("dependencies"))
    monkeypatch.setattr(runtime.uvicorn, "run", lambda *_args, **_kwargs: called.append("run"))

    with pytest.raises(SystemExit, match="startup gate failed"):
        runtime.main()

    assert called == []
