from __future__ import annotations

import json
from typing import Any

import pytest

import deploy.render.protected_recovery_service as service
from deploy.postgres.run_protected_recovery_v1_3 import ProtectedRecoveryError


def test_service_listens_only_after_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    marker = object()
    monkeypatch.setattr(service.ProtectedRecoveryConfig, "from_environment", lambda: marker)
    monkeypatch.setattr(
        service,
        "run",
        lambda config: {
            "contract": "lucy.protected-recovery-handoff.v1.3",
            "config": config is marker,
        },
    )

    class Served(RuntimeError):
        pass

    monkeypatch.setattr(service, "_serve", lambda: (_ for _ in ()).throw(Served()))
    with pytest.raises(Served):
        service.main()
    assert json.loads(capsys.readouterr().out) == {
        "config": True,
        "contract": "lucy.protected-recovery-handoff.v1.3",
    }


def test_service_fails_closed_before_listening(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        service.ProtectedRecoveryConfig,
        "from_environment",
        lambda: (_ for _ in ()).throw(ProtectedRecoveryError("boundary differs")),
    )
    served: list[Any] = []
    monkeypatch.setattr(service, "_serve", lambda: served.append(True))
    with pytest.raises(SystemExit) as failure:
        service.main()
    assert failure.value.code == 1
    assert served == []
    assert json.loads(capsys.readouterr().out) == {
        "error": "boundary differs",
        "status": "failed",
    }
