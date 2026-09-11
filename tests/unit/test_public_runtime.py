from __future__ import annotations

from types import SimpleNamespace

import pytest

import lucy.public_api as api
import lucy.public_runtime as runtime


def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "LUCY_DATABASE_URL": "postgresql://lucy_utopia_public:test@dpg-example-a/lucy_example",
        "LUCY_EXPECTED_DATABASE_LOGIN": "lucy_utopia_public",
        "LUCY_PUBLIC_API_TOKEN": "public-runtime-test-token-that-is-long-enough",
        "LUCY_PUBLIC_ALLOWED_ORIGIN": "https://www.utopiahomes.com",
        "LUCY_PUBLIC_SITE_HOSTNAME": "www.utopiahomes.com",
        "LUCY_PUBLIC_SNAPSHOT_DIGEST": "6" * 64,
        "LUCY_STORAGE_EPOCH": "4f1d7615-6d73-4dc8-9d87-e17113e0a56c",
        "LUCY_PUBLIC_MAX_REQUEST_BYTES": "8192",
        "LUCY_PUBLIC_REQUESTS_PER_IP_PER_MINUTE": "20",
        "LUCY_PUBLIC_REQUESTS_PER_SESSION_PER_MINUTE": "30",
        "LUCY_PUBLIC_SESSION_TTL_SECONDS": "3600",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_OBSERVED_HERMES_COMMIT": "a" * 40,
        "LUCY_SERVICE_MODE": "public",
        "LUCY_SECURITY_BASELINE": "v1.3",
        "LUCY_ENVIRONMENT": "production",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    api._configuration.cache_clear()


def test_public_runtime_starts_only_after_exact_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _environment(monkeypatch)
    monkeypatch.setattr(runtime, "_expected_commit", lambda: "a" * 40)
    monkeypatch.setattr(runtime, "create_session_factory", lambda _url: object())
    checks: list[str] = []
    monkeypatch.setattr(
        runtime,
        "ServiceReadiness",
        lambda *_args, **kwargs: SimpleNamespace(
            check=lambda: checks.append(f"{kwargs['mode']}:{kwargs['baseline']}")
        ),
    )
    listeners: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        runtime.uvicorn,
        "run",
        lambda app, **kwargs: listeners.append((app.title, kwargs["access_log"])),
    )
    runtime.main()
    assert checks == ["public:v1.3"]
    assert listeners == [("Lucy Public Projection API", False)]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_SERVICE_MODE", "routine"),
        ("LUCY_SECURITY_BASELINE", "v1.2"),
        ("LUCY_OBSERVED_HERMES_COMMIT", "b" * 40),
    ],
)
def test_public_runtime_fails_closed_before_listener(
    monkeypatch: pytest.MonkeyPatch, key: str, value: str
) -> None:
    _environment(monkeypatch)
    monkeypatch.setenv(key, value)
    monkeypatch.setattr(runtime, "_expected_commit", lambda: "a" * 40)
    monkeypatch.setattr(runtime, "create_session_factory", lambda _url: object())
    monkeypatch.setattr(
        runtime,
        "ServiceReadiness",
        lambda *_args, **_kwargs: SimpleNamespace(check=lambda: None),
    )
    listener_called = False

    def listener(*_args: object, **_kwargs: object) -> None:
        nonlocal listener_called
        listener_called = True

    monkeypatch.setattr(runtime.uvicorn, "run", listener)
    with pytest.raises(SystemExit, match="startup gate failed"):
        runtime.main()
    assert listener_called is False
