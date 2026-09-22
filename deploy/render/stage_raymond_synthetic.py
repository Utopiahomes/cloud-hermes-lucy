"""Prepare or stage credentials on exactly two suspended Raymond services.

No deploy, resume, schema change, provider credential, or pilot data operation is
implemented here. Preparation is local; --apply requires explicit authorization.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from uuid import uuid4

import yaml  # type: ignore[import-untyped]
from sqlalchemy.engine import make_url

from lucy.realm_provisioning import RealmSecurityStampV1

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "secrets/generated/raymond-synthetic-stage-v1.json"
ROLLBACK = ROOT / "secrets/generated/raymond-synthetic-stage-rollback-v1.json"
AUTHORIZATION = "stage-raymond-synthetic-suspended-v1"
ENVIRONMENT = "evm-dak5bboae00c73fnvu4g"
DATABASE_HOST = "dpg-dak5bqad0e5s73b2e3d0-a"
SERVICES = {
    "policy": "srv-dak5bd5g1s2s7389ml7g",
    "routine": "srv-dak5bc2d0e5s73b2c8vg",
}


def _read(name: str) -> Any:
    return json.loads((ROOT / "secrets/generated" / name).read_text(encoding="utf-8"))


def prepare() -> dict[str, dict[str, str]]:
    wrapped = _read("raymond-realm-security-stamp-v1.3.json")
    stamp = RealmSecurityStampV1.model_validate(wrapped["realm_security_stamp"])
    if (
        stamp.realm_slug != "raymond"
        or stamp.digest_hex() != wrapped["realm_security_stamp_sha256"]
    ):
        raise ValueError("Raymond stamp mismatch")
    urls = _read("raymond-v13-runtime-secret-bundle.json")["urls"]
    for role, login in (("policy", stamp.policy_login), ("routine", stamp.routine_login)):
        url = make_url(urls[role])
        if (
            url.host != DATABASE_HOST or url.database != "lucy_raymond"
            or url.username != login or not url.password
            or url.port not in (None, 5432) or url.query.get("sslmode") != "require"
        ):
            raise ValueError("Raymond database destination mismatch")
    private = _read("raymond-policy-private-v1.3.json")
    trust = _read("raymond-policy-trust-store-v1.3.json")
    if (
        len(base64.b64decode(private["private_key_b64"], validate=True)) != 32
        or len(trust) != 1 or trust[0]["key_id"] != private["key_id"]
    ):
        raise ValueError("Raymond policy material mismatch")
    # Preparation is repeatable after a saved apply; it never rotates existing credentials.
    generated = (
        json.loads(STATE.read_text(encoding="utf-8"))["generated"]
        if STATE.exists() else
        {"gateway_token": secrets.token_urlsafe(36), "storage_epoch": str(uuid4())}
    )
    hermes = dict(
        line.split("=", 1) for line in (ROOT / "hermes.lock").read_text().splitlines()
        if line and not line.startswith("#") and "=" in line
    )["commit"]
    common = {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_SECURITY_ENVIRONMENT": "production",
        "LUCY_SECURITY_BASELINE": "v1.3",
        "LUCY_COMMISSIONING_STATE": "synthetic_staged_suspended",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_PRODUCT_INGRESS_ENABLED": "false",
        "LUCY_MEMORY_PILOT_EXECUTOR_ENABLED": "false",
        "LUCY_MEMORY_PILOT_INTAKE_ENABLED": "false",
        "LUCY_STORAGE_EPOCH": generated["storage_epoch"],
        "LUCY_OBSERVED_HERMES_COMMIT": hermes,
        "LUCY_POLICY_GATEWAY_TOKEN": generated["gateway_token"],
    }
    return {
        "policy": {
            **common,
            "LUCY_SERVICE_MODE": "policy",
            "LUCY_EXPECTED_DATABASE_LOGIN": stamp.policy_login,
            "LUCY_DATABASE_URL": urls["policy"],
            "LUCY_V13_POLICY_SIGNING_PRIVATE_KEY_B64": private["private_key_b64"],
            "LUCY_V13_POLICY_KEY_ID": private["key_id"],
            "LUCY_V13_POLICY_TRUST_STORE_JSON": json.dumps(trust, separators=(",", ":")),
            "LUCY_POLICY_ISSUER": "lucy-raymond-policy",
        },
        "routine": {
            **common,
            "LUCY_SERVICE_MODE": "routine",
            "LUCY_EXPECTED_DATABASE_LOGIN": stamp.routine_login,
            "LUCY_DATABASE_URL": urls["routine"],
            "LUCY_POLICY_HOSTPORT": "raymond-lucy-policy:10000",
        },
    }


def _request(token: str, method: str, path: str, body: object | None = None) -> Any:
    request = Request(
        "https://api.render.com/v1" + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        method=method,
    )
    with urlopen(request, timeout=30) as response:
        raw = response.read()
    return json.loads(raw) if raw else None


def _environment(token: str, service: str) -> dict[str, str]:
    rows = _request(token, "GET", f"/services/{service}/env-vars?limit=100")
    if not isinstance(rows, list) or len(rows) >= 100:
        raise ValueError("Cannot safely snapshot service environment")
    return {row["envVar"]["key"]: row["envVar"]["value"] for row in rows}


def _suspended(token: str, role: str) -> None:
    value = _request(token, "GET", f"/services/{SERVICES[role]}")
    if (
        value.get("id") != SERVICES[role] or value.get("name") != f"raymond-lucy-{role}"
        or value.get("environmentId") != ENVIRONMENT
        or value.get("type") != "private_service"
        or value.get("suspended") != "suspended" or value.get("autoDeploy") != "no"
    ):
        raise ValueError("Service is outside the approved suspended boundary")


def apply(desired: dict[str, dict[str, str]], authorization: str) -> None:
    if authorization != AUTHORIZATION:
        raise PermissionError("Explicit suspended credential staging authorization required")
    if ROLLBACK.exists() or STATE.exists():
        raise ValueError("Saved staging state exists; inspect it before retrying")
    config = yaml.safe_load((Path.home() / ".render/cli.yaml").read_text(encoding="utf-8"))
    token = config["api"]["key"]
    for role in SERVICES:
        _suspended(token, role)
    rollback = {role: _environment(token, service) for role, service in SERVICES.items()}
    ROLLBACK.write_text(json.dumps(rollback, indent=2), encoding="utf-8")
    STATE.write_text(json.dumps({
        "generated": {
            "gateway_token": desired["policy"]["LUCY_POLICY_GATEWAY_TOKEN"],
            "storage_epoch": desired["policy"]["LUCY_STORAGE_EPOCH"],
        },
        "environments": desired,
    }, indent=2), encoding="utf-8")
    attempted: list[str] = []
    try:
        for role, service in SERVICES.items():
            _suspended(token, role)
            attempted.append(role)  # Include an uncertain or partially acknowledged write.
            _request(token, "PUT", f"/services/{service}/env-vars", [
                {"key": key, "value": value} for key, value in desired[role].items()
            ])
            if _environment(token, service) != desired[role]:
                raise ValueError("Environment readback differs")
            _suspended(token, role)
    except Exception:
        for role in reversed(attempted):
            _request(token, "PUT", f"/services/{SERVICES[role]}/env-vars", [
                {"key": key, "value": value} for key, value in rollback[role].items()
            ])
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--authorization", default="")
    args = parser.parse_args()
    try:
        desired = prepare()
        if args.apply:
            apply(desired, args.authorization)
        print(json.dumps({
            "status": "staged_suspended" if args.apply else "prepared_locally",
            "services": SERVICES,
            "environment_keys": {role: sorted(values) for role, values in desired.items()},
            "provider_credential_installed": False,
            "pilot_authorization_used": False,
            "activation_performed": False,
        }, sort_keys=True))
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
