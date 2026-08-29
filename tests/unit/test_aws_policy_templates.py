from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
AWS_DEPLOY = ROOT / "deploy" / "aws"


def _load(name: str) -> dict[str, Any]:
    return json.loads((AWS_DEPLOY / name).read_text(encoding="utf-8"))


def test_render_trust_is_bound_to_one_workspace_environment_and_service() -> None:
    statement = _load("render-oidc-trust-policy.json.example")["Statement"][0]
    assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"
    equals = statement["Condition"]["StringEquals"]
    assert set(equals.values()) == {
        "sts.amazonaws.com",
        "workspace:${RENDER_WORKSPACE_ID}:environment:${RENDER_ENVIRONMENT_ID}:"
        "service:${RENDER_SERVICE_ID}",
    }
    assert statement["Principal"]["Federated"].endswith(
        "oidc.render.com/${RENDER_WORKSPACE_ID}"
    )


def test_runtime_policy_has_only_required_kms_and_item_operations() -> None:
    statements = _load("lucy-runtime-policy.json.example")["Statement"]
    kms, dynamo = statements
    assert set(kms["Action"]) == {"kms:GenerateDataKey", "kms:Decrypt"}
    assert kms["Resource"] == "${LUCY_KMS_KEY_ARN}"
    assert kms["Condition"]["StringEquals"] == {
        "kms:EncryptionContext:application": "cloud-hermes-lucy"
    }
    assert set(dynamo["Action"]) == {
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem",
    }
    assert dynamo["Resource"].endswith("table/${LUCY_DYNAMODB_TABLE}")


def test_kms_key_statement_grants_use_but_not_administration() -> None:
    statement = _load("kms-key-policy-statement.json.example")
    assert set(statement["Action"]) == {"kms:GenerateDataKey", "kms:Decrypt"}
    assert all(
        fragment not in json.dumps(statement)
        for fragment in ("kms:*", "CreateGrant", "ScheduleKeyDeletion", "PutKeyPolicy")
    )


def test_render_example_has_no_active_static_aws_credentials() -> None:
    active_lines = [
        line.strip()
        for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert not any(
        line.startswith(
            ("AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=", "AWS_WEB_IDENTITY_TOKEN_FILE=")
        )
        for line in active_lines
    )
