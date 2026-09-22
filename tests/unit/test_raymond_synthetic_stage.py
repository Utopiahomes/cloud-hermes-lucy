from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

import deploy.render.stage_raymond_synthetic as stage
from lucy.realm_provisioning import RealmSecurityStampV1
from tests.unit.test_realm_cloud_bootstrap_v1_3 import _stamp


def test_local_preparation_has_no_provider_pilot_or_network_dependency(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    stamp = RealmSecurityStampV1.model_validate_json(
        _stamp().model_dump_json().replace("utopia", "raymond")
    )
    documents = {
        "raymond-realm-security-stamp-v1.3.json": {
            "realm_security_stamp": stamp.model_dump(mode="json"),
            "realm_security_stamp_sha256": stamp.digest_hex(),
        },
        "raymond-v13-runtime-secret-bundle.json": {"urls": {
            role: f"postgresql+psycopg://lucy_raymond_{role}:synthetic@"
            f"{stage.DATABASE_HOST}/lucy_raymond?sslmode=require"
            for role in stage.SERVICES
        }},
        "raymond-policy-private-v1.3.json": {
            "private_key_b64": base64.b64encode(b"p" * 32).decode(), "key_id": "synthetic",
        },
        "raymond-policy-trust-store-v1.3.json": [{"key_id": "synthetic"}],
    }
    monkeypatch.setattr(stage, "_read", documents.__getitem__)
    monkeypatch.setattr(stage, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(stage, "_request", lambda *_: pytest.fail("Preparation used network"))
    desired = stage.prepare()
    for role, env in desired.items():
        assert env["LUCY_MEMORY_PILOT_EXECUTOR_ENABLED"] == "false"
        assert env["LUCY_TRANSCRIPT_CAPTURE_ENABLED"] == "false"
        assert env["LUCY_PRODUCT_INGRESS_ENABLED"] == "false"
        assert env["LUCY_EXPECTED_DATABASE_LOGIN"] == f"lucy_raymond_{role}"
        assert not ({"OPENROUTER_API_KEY", "TELEGRAM_BOT_TOKEN"} & env.keys())
    assert "LUCY_V13_POLICY_SIGNING_PRIVATE_KEY_B64" not in desired["routine"]
    assert not stage.STATE.exists()


def test_apply_requires_authorization_before_any_cloud_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(stage, "_request", lambda *_: pytest.fail("Unauthorized cloud request"))
    with pytest.raises(PermissionError):
        stage.apply({}, "")


def test_uncertain_second_write_restores_both_suspended_environments(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(stage, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(stage, "ROLLBACK", tmp_path / "rollback.json")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    (tmp_path / ".render").mkdir()
    (tmp_path / ".render/cli.yaml").write_text("api:\n  key: synthetic\n")
    environments = {service: {"old": role} for role, service in stage.SERVICES.items()}
    prior = {key: dict(value) for key, value in environments.items()}
    written: list[str] = []
    failed = False

    def request(token: str, method: str, path: str, body: object = None) -> object:
        nonlocal failed
        assert token == "synthetic"
        service = path.split("/")[2]
        if method == "PUT":
            assert isinstance(body, list)
            environments[service] = {row["key"]: row["value"] for row in body}
            written.append(service)
            if service == stage.SERVICES["routine"] and not failed:
                failed = True
                raise TimeoutError("synthetic uncertain acknowledgement")
            return None
        assert method == "GET"
        if "/env-vars" in path:
            return [{"envVar": {"key": k, "value": v}} for k, v in environments[service].items()]
        role = next(role for role, value in stage.SERVICES.items() if value == service)
        return {
            "id": service, "name": f"raymond-lucy-{role}", "environmentId": stage.ENVIRONMENT,
            "type": "private_service", "suspended": "suspended", "autoDeploy": "no",
        }

    monkeypatch.setattr(stage, "_request", request)
    desired = {role: {
        "LUCY_POLICY_GATEWAY_TOKEN": "synthetic-token",
        "LUCY_STORAGE_EPOCH": "synthetic-epoch",
    } for role in stage.SERVICES}
    with pytest.raises(TimeoutError):
        stage.apply(desired, stage.AUTHORIZATION)
    assert environments == prior
    assert written == [stage.SERVICES[r] for r in ("policy", "routine", "routine", "policy")]
    assert json.loads(stage.ROLLBACK.read_text())["policy"] == {"old": "policy"}
