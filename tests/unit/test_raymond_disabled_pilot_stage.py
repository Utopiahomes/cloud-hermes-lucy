from __future__ import annotations

import json
from pathlib import Path

import pytest

import deploy.render.stage_raymond_disabled_pilot as stage


def test_preparation_requires_disabled_flags_and_unchanged_base(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    prior = {role: {
        "LUCY_SERVICE_MODE": role,
        "LUCY_DATABASE_URL": f"postgresql://{role}@raymond/lucy_raymond",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_PRODUCT_INGRESS_ENABLED": "false",
        "LUCY_MEMORY_PILOT_EXECUTOR_ENABLED": "false",
        "LUCY_MEMORY_PILOT_INTAKE_ENABLED": "false",
    } for role in stage.render.SERVICES}
    desired = {role: dict(values) for role, values in prior.items()}
    desired["routine"]["OPENROUTER_API_KEY"] = "synthetic-key"
    base = tmp_path / "base.json"
    base.write_text(json.dumps({"environments": prior}))
    prepared = tmp_path / "prepared.json"
    prepared.write_text(json.dumps({
        "status": "prepared_not_applied", "environments": desired,
    }))
    monkeypatch.setattr(stage.render, "STATE", base)
    monkeypatch.setattr(stage, "DESIRED", prepared)
    assert stage.prepare() == desired
    desired["routine"]["LUCY_MEMORY_PILOT_EXECUTOR_ENABLED"] = "true"
    prepared.write_text(json.dumps({
        "status": "prepared_not_applied", "environments": desired,
    }))
    with pytest.raises(ValueError, match="disabled boundary"):
        stage.prepare()


def test_uncertain_second_write_restores_both_services(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(stage, "ROLLBACK", tmp_path / "rollback.json")
    monkeypatch.setattr(stage, "RECEIPT", tmp_path / "receipt.json")
    base = tmp_path / "base.json"
    prior = {role: {"old": role} for role in stage.render.SERVICES}
    base.write_text(json.dumps({"environments": prior}))
    monkeypatch.setattr(stage.render, "STATE", base)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    (tmp_path / ".render").mkdir()
    (tmp_path / ".render/cli.yaml").write_text("api:\n  key: synthetic\n")
    current = {role: dict(values) for role, values in prior.items()}
    monkeypatch.setattr(stage.render, "_suspended", lambda *_: None)
    monkeypatch.setattr(stage.render, "_environment", lambda _, sid: dict(
        current[next(role for role, value in stage.render.SERVICES.items() if value == sid)]
    ))
    writes = 0

    def request(_token: str, _method: str, path: str, body: object) -> None:
        nonlocal writes
        assert isinstance(body, list)
        writes += 1
        sid = path.split("/")[2]
        role = next(role for role, value in stage.render.SERVICES.items() if value == sid)
        current[role] = {row["key"]: row["value"] for row in body}
        if writes == 2:
            raise TimeoutError("uncertain second write")

    monkeypatch.setattr(stage.render, "_request", request)
    desired = {role: {"new": role} for role in stage.render.SERVICES}
    with pytest.raises(TimeoutError):
        stage.apply(desired, stage.AUTHORIZATION)
    assert current == prior
    assert writes == 4
    assert not stage.RECEIPT.exists()


def test_authorization_gate_precedes_cloud_access(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stage.render, "_request", lambda *_: pytest.fail("cloud access"))
    with pytest.raises(PermissionError):
        stage.apply({}, "")
