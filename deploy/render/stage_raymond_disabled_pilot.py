"""Install the prepared pilot config only on two suspended Raymond services."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml  # type: ignore[import-untyped]

from deploy.render import stage_raymond_synthetic as render

ROOT = Path(__file__).resolve().parents[2]
DESIRED = ROOT / "secrets/generated/raymond-disabled-pilot-desired-20260922.json"
ROLLBACK = ROOT / "secrets/generated/raymond-disabled-pilot-rollback-20260922.json"
RECEIPT = ROOT / "secrets/generated/raymond-disabled-pilot-stage-20260922.json"
AUTHORIZATION = "stage-raymond-disabled-pilot-suspended-v1"
FORBIDDEN = {"TELEGRAM_BOT_TOKEN", "TELEGRAM_ALLOWED_USERS", "LUCY_OWNER_TOKEN",
             "LUCY_MIGRATION_DATABASE_URL", "LUCY_MAINTENANCE_DATABASE_URL"}


def prepare() -> dict[str, dict[str, str]]:
    document = json.loads(DESIRED.read_text(encoding="utf-8"))
    if document.get("status") != "prepared_not_applied":
        raise ValueError("Prepared Raymond config is not a disabled proposal")
    raw = document.get("environments")
    if not isinstance(raw, dict) or set(raw) != set(render.SERVICES):
        raise ValueError("Prepared Raymond service set differs")
    values: dict[str, dict[str, str]] = {}
    for role in render.SERVICES:
        environment = raw[role]
        if (not isinstance(environment, dict)
            or any(not isinstance(key, str) or not isinstance(value, str)
                   for key, value in environment.items())
            or FORBIDDEN & set(environment)
            or environment.get("LUCY_SERVICE_MODE") != role
            or any(environment.get(key) != "false" for key in (
                "LUCY_TRANSCRIPT_CAPTURE_ENABLED", "LUCY_PRODUCT_INGRESS_ENABLED",
                "LUCY_MEMORY_PILOT_EXECUTOR_ENABLED", "LUCY_MEMORY_PILOT_INTAKE_ENABLED",
            ))):
            raise ValueError("Prepared Raymond service would cross disabled boundary")
        values[role] = {str(key): str(value) for key, value in environment.items()}
    prior = json.loads(render.STATE.read_text(encoding="utf-8"))["environments"]
    for role in render.SERVICES:
        if any(values[role].get(key) != value for key, value in prior[role].items()):
            raise ValueError("Prepared config changed the staged Raymond base")
    if values["policy"]["LUCY_DATABASE_URL"] == values["routine"]["LUCY_DATABASE_URL"]:
        raise ValueError("Policy and routine database credentials must differ")
    if not values["routine"].get("OPENROUTER_API_KEY"):
        raise ValueError("Prepared provider credential is missing")
    return values


def apply(desired: dict[str, dict[str, str]], authorization: str) -> None:
    if authorization != AUTHORIZATION:
        raise PermissionError("Exact disabled Raymond staging authorization required")
    if ROLLBACK.exists() or RECEIPT.exists():
        raise ValueError("Saved staging state exists; inspect before retrying")
    api_token = yaml.safe_load(
        (Path.home() / ".render/cli.yaml").read_text(encoding="utf-8")
    )["api"]["key"]
    stage = json.loads(render.STATE.read_text(encoding="utf-8"))["environments"]
    for role, service_id in render.SERVICES.items():
        render._suspended(api_token, role)
        if render._environment(api_token, service_id) != stage[role]:
            raise ValueError("Raymond service differs from approved credential stage")
    ROLLBACK.write_text(json.dumps(stage, indent=2) + "\n", encoding="utf-8")
    attempted: list[str] = []
    try:
        for role, service_id in render.SERVICES.items():
            render._suspended(api_token, role)
            attempted.append(role)
            render._request(api_token, "PUT", f"/services/{service_id}/env-vars", [
                {"key": key, "value": value} for key, value in desired[role].items()
            ])
            if render._environment(api_token, service_id) != desired[role]:
                raise ValueError("Raymond service readback differs")
            render._suspended(api_token, role)
    except Exception:
        for role in reversed(attempted):
            render._request(api_token, "PUT", f"/services/{render.SERVICES[role]}/env-vars", [
                {"key": key, "value": value} for key, value in stage[role].items()
            ])
        raise
    RECEIPT.write_text(json.dumps({
        "contract": "lucy.raymond-disabled-pilot-stage.v1", "status": "staged_suspended",
        "services": render.SERVICES, "pilot_executor_enabled": False,
        "product_ingress_enabled": False, "personal_records_uploaded": False,
    }, indent=2) + "\n", encoding="utf-8")


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
            "service_keys": {role: sorted(values) for role, values in desired.items()},
            "personal_records_uploaded": False, "services_activated": False,
        }, sort_keys=True))
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
