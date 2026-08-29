from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

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


def _actions(name: str) -> set[str]:
    actions: set[str] = set()
    for statement in _load(name)["Statement"]:
        value = statement["Action"]
        actions.update([value] if isinstance(value, str) else value)
    return actions


def test_execution_policies_are_capability_separated() -> None:
    assert _actions("lucy-archive-policy.json.example") == {
        "kms:GenerateDataKey",
        "dynamodb:PutItem",
    }
    assert _actions("lucy-evidence-policy.json.example") == {
        "kms:Decrypt",
        "dynamodb:GetItem",
    }
    assert _actions("lucy-deletion-policy.json.example") == {
        "dynamodb:GetItem",
        "dynamodb:DeleteItem",
    }
    assert "kms:Decrypt" not in _actions("lucy-archive-policy.json.example")
    assert not any(
        action.startswith("kms:")
        for action in _actions("lucy-deletion-policy.json.example")
    )


def test_kms_key_statements_separate_generation_from_decryption() -> None:
    statements = _load("kms-key-policy-statements.json.example")
    assert [statement["Action"] for statement in statements] == [
        "kms:GenerateDataKey",
        "kms:Decrypt",
    ]
    assert statements[0]["Principal"] != statements[1]["Principal"]
    assert all(
        fragment not in json.dumps(statements)
        for fragment in ("kms:*", "CreateGrant", "ScheduleKeyDeletion", "PutKeyPolicy")
    )


def test_cloudformation_keeps_master_key_administration_out_of_runtime_roles() -> None:
    template = (AWS_DEPLOY / "security-baseline-v1.1.yaml").read_text(encoding="utf-8")
    deletion_section = template.split("  DeletionRole:", 1)[1].split(
        "  SecurityAlertTopic:", 1
    )[0]
    assert "kms:" not in deletion_section
    assert "dynamodb:DeleteItem" in deletion_section
    assert "DeletionProtectionEnabled: true" in template
    assert "PendingWindowInDays: 30" in template
    assert "EnableKeyRotation: true" in template
    assert "KeyAdministratorPrincipalArnPattern" in template
    assert "AWSReservedSSO_LucySecurityAdministrator_*" in template
    assert "KmsRecoveryAdministratorRole" in template
    administrator_section = template.split(
        "          - Sid: IdentityCenterHumanKeyAdministrator", 1
    )[1].split("          - Sid: ArchiveGenerateOnly", 1)[0]
    assert "kms:Decrypt" not in administrator_section
    assert "kms:GenerateDataKey" not in administrator_section


def test_cloudformation_template_is_well_formed_yaml_with_expected_boundaries() -> None:
    class CloudFormationLoader(yaml.SafeLoader):
        pass

    def construct_tag(loader: CloudFormationLoader, _suffix: str, node: Any) -> Any:
        if isinstance(node, ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, SequenceNode):
            return loader.construct_sequence(node)
        if isinstance(node, MappingNode):
            return loader.construct_mapping(node)
        raise TypeError("unsupported YAML node")

    CloudFormationLoader.add_multi_constructor("!", construct_tag)
    template = yaml.load(
        (AWS_DEPLOY / "security-baseline-v1.1.yaml").read_text(encoding="utf-8"),
        Loader=CloudFormationLoader,
    )
    resources = template["Resources"]
    assert {
        "EvidenceKey",
        "WrappedKeyRegistry",
        "ArchiveRole",
        "EvidenceRole",
        "DeletionRole",
        "AuditTrail",
        "KeyAdministrationAlert",
    } <= resources.keys()


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
