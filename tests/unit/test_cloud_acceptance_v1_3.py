from __future__ import annotations

from pathlib import Path

import pytest

import lucy.cloud_acceptance_v1_3 as acceptance


def _environment() -> dict[str, str]:
    return {
        "LUCY_CLOUD_ACCEPTANCE_AUTHORIZED": "synthetic-only-v1.3",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_SECURITY_ENVIRONMENT": "production",
        "LUCY_SECURITY_BASELINE": "v1.3",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_SERVICE_MODE": "routine",
    }


def test_acceptance_preflight_keeps_live_capture_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in _environment().items():
        monkeypatch.setenv(name, value)
    checked: list[bool] = []
    monkeypatch.setattr(acceptance, "_ready_sessions", lambda: checked.append(True))
    acceptance._preflight("routine")
    assert checked == [True]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("LUCY_CLOUD_ACCEPTANCE_AUTHORIZED", "wrong"),
        ("LUCY_ENVIRONMENT", "development"),
        ("LUCY_SECURITY_BASELINE", "v1.2"),
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_SERVICE_MODE", "policy"),
    ],
)
def test_acceptance_preflight_fails_closed(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    for key, content in _environment().items():
        monkeypatch.setenv(key, content)
    monkeypatch.setenv(name, value)
    monkeypatch.setattr(acceptance, "_ready_sessions", lambda: object())
    with pytest.raises(acceptance.CloudAcceptanceV13Error):
        acceptance._preflight("routine")


def test_acceptance_handoff_is_exact_and_outputs_no_signed_contract() -> None:
    source = (
        Path(__file__).parents[2] / "src" / "lucy" / "cloud_acceptance_v1_3.py"
    ).read_text(encoding="utf-8")
    assert "workflow.load_permit(permit_id" in source
    assert "read_sensitive_action_permit_v3" not in source
    assert '"permit_id": str(permit.permit_id)' in source
    assert "permit.model_dump" not in source
    assert "plaintext_b64" not in source.split("def _report", 1)[0]
    assert "LUCY_TRANSCRIPT_CAPTURE_ENABLED" in source
