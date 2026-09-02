from __future__ import annotations

import pytest

from lucy.provisioning_hold import _validate_environment


def _valid_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LUCY_RESOURCE_ID_BOOTSTRAP_HOLD", "resource-id-only")
    monkeypatch.setenv("LUCY_ENVIRONMENT", "production")
    monkeypatch.setenv("LUCY_SERVICE_MODE", "routine")
    monkeypatch.setenv("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "false")
    monkeypatch.setenv("PORT", "8080")


def test_provisioning_hold_accepts_only_explicit_safe_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _valid_environment(monkeypatch)
    assert _validate_environment() == ("0.0.0.0", 8080)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("LUCY_RESOURCE_ID_BOOTSTRAP_HOLD", ""),
        ("LUCY_ENVIRONMENT", "development"),
        ("LUCY_SERVICE_MODE", "all-local"),
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("AWS_ACCESS_KEY_ID", "static-key-forbidden"),
        ("AWS_SECRET_ACCESS_KEY", "static-secret-forbidden"),
        ("AWS_SESSION_TOKEN", "static-session-forbidden"),
        ("PORT", "not-a-port"),
        ("PORT", "70000"),
    ],
)
def test_provisioning_hold_rejects_unsafe_configuration(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    _valid_environment(monkeypatch)
    monkeypatch.setenv(name, value)
    with pytest.raises(SystemExit):
        _validate_environment()
