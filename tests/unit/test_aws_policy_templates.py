from __future__ import annotations

import json
import re
from graphlib import TopologicalSorter
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
    assert statement["Principal"]["Federated"].endswith("oidc.render.com/${RENDER_WORKSPACE_ID}")


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
        "dynamodb:GetItem",
    }
    assert _actions("lucy-evidence-policy.json.example") == {
        "kms:Decrypt",
        "dynamodb:GetItem",
    }
    assert _actions("lucy-deletion-policy.json.example") == {
        "dynamodb:GetItem",
        "dynamodb:DeleteItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
    }
    assert "kms:Decrypt" not in _actions("lucy-archive-policy.json.example")
    assert not any(
        action.startswith("kms:") for action in _actions("lucy-deletion-policy.json.example")
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
    deletion_section = template.split("  DeletionRole:", 1)[1].split("  SecurityAlertTopic:", 1)[0]
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


def _cloudformation() -> dict[str, Any]:
    class CloudFormationLoader(yaml.SafeLoader):
        pass

    def construct_tag(loader: CloudFormationLoader, suffix: str, node: Any) -> Any:
        if isinstance(node, ScalarNode):
            value = loader.construct_scalar(node)
        elif isinstance(node, SequenceNode):
            value = loader.construct_sequence(node)
        elif isinstance(node, MappingNode):
            value = loader.construct_mapping(node)
        else:
            raise TypeError("unsupported YAML node")
        return {suffix if suffix == "Ref" else f"Fn::{suffix}": value}

    CloudFormationLoader.add_multi_constructor("!", construct_tag)
    return yaml.load(
        (AWS_DEPLOY / "security-baseline-v1.1.yaml").read_text(encoding="utf-8"),
        Loader=CloudFormationLoader,
    )


def test_cloudformation_template_is_well_formed_yaml_with_expected_boundaries() -> None:
    resources = _cloudformation()["Resources"]
    assert {
        "EvidenceKey",
        "WrappedKeyRegistry",
        "ArchiveRole",
        "ArchivePolicy",
        "EvidenceRole",
        "EvidencePolicy",
        "DeletionRole",
        "AuditTrail",
        "KeyAdministrationAlert",
        "DeletionJournalHead",
        "DeletionJournalIntents",
    } <= resources.keys()


def test_journal_tables_are_retained_protected_and_backed_up() -> None:
    resources = _cloudformation()["Resources"]
    for name in ("DeletionJournalHead", "DeletionJournalIntents"):
        resource = resources[name]
        assert resource["DeletionPolicy"] == "Retain"
        assert resource["UpdateReplacePolicy"] == "Retain"
        assert resource["Properties"]["DeletionProtectionEnabled"] is True
        assert resource["Properties"]["PointInTimeRecoverySpecification"] == {
            "PointInTimeRecoveryEnabled": True
        }
    # Wrapped-key backup resurrection would defeat crypto-shredding.
    assert resources["WrappedKeyRegistry"]["Properties"]["PointInTimeRecoverySpecification"] == {
        "PointInTimeRecoveryEnabled": False
    }


def test_cloudformation_creates_kms_principals_before_key_without_cycles() -> None:
    resources = _cloudformation()["Resources"]

    def references(value: Any) -> set[str]:
        if isinstance(value, list):
            return set().union(*(references(item) for item in value))
        if not isinstance(value, dict):
            return set()
        result: set[str] = set()
        if "Ref" in value:
            result.add(value["Ref"])
        if "Fn::GetAtt" in value:
            target = value["Fn::GetAtt"]
            result.add(target.split(".")[0] if isinstance(target, str) else target[0])
        if "Fn::Sub" in value:
            sub = value["Fn::Sub"]
            template = sub if isinstance(sub, str) else sub[0]
            overrides = set() if isinstance(sub, str) else set(sub[1])
            result.update(
                token.split(".")[0]
                for token in re.findall(r"\$\{([^}]+)\}", template)
                if token not in overrides
            )
        for child in value.values():
            result.update(references(child))
        return result & resources.keys()

    dependencies = {name: references(resource) for name, resource in resources.items()}
    for name, resource in resources.items():
        explicit = resource.get("DependsOn", [])
        dependencies[name].update([explicit] if isinstance(explicit, str) else explicit)
    order = list(TopologicalSorter(dependencies).static_order())
    for role, policy, sid, action in (
        ("ArchiveRole", "ArchivePolicy", "ArchiveGenerateOnly", "kms:GenerateDataKey"),
        ("EvidenceRole", "EvidencePolicy", "EvidenceDecryptOnly", "kms:Decrypt"),
    ):
        assert order.index(role) < order.index("EvidenceKey") < order.index(policy)
        assert "Policies" not in resources[role]["Properties"]
        assert resources[policy]["Properties"]["Roles"] == [{"Ref": role}]
        statements = resources["EvidenceKey"]["Properties"]["KeyPolicy"]["Statement"]
        statement = next(item for item in statements if item["Sid"] == sid)
        assert statement["Principal"]["AWS"] == {"Fn::GetAtt": f"{role}.Arn"}
        assert statement["Action"] == action
        policy_actions = {
            item["Action"]
            for item in resources[policy]["Properties"]["PolicyDocument"]["Statement"]
        }
        expected = {
            action,
            "dynamodb:PutItem" if role == "ArchiveRole" else "dynamodb:GetItem",
        }
        if role == "ArchiveRole":
            expected.add("dynamodb:GetItem")
        assert policy_actions == expected


def test_journal_iam_separates_head_readers_from_intent_writer() -> None:
    resources = _cloudformation()["Resources"]
    archive = json.dumps(resources["ArchivePolicy"])
    evidence = json.dumps(resources["EvidencePolicy"])
    deletion = json.dumps(resources["DeletionRole"])
    assert "DeletionJournalHead" in archive and "DeletionJournalIntents" not in archive
    assert "DeletionJournalHead" in evidence and "DeletionJournalIntents" not in evidence
    assert "DeletionJournalHead" in deletion and "DeletionJournalIntents" in deletion
    assert "dynamodb:UpdateItem" in deletion and "dynamodb:PutItem" in deletion
    assert "TransactWriteItems" in deletion
    assert not any(token in deletion for token in ("dynamodb:Scan", "dynamodb:Query", "kms:"))


def test_head_readers_can_request_only_identity_and_chain_metadata() -> None:
    resources = _cloudformation()["Resources"]
    for policy_name in ("ArchivePolicy", "EvidencePolicy"):
        statements = resources[policy_name]["Properties"]["PolicyDocument"]["Statement"]
        statement = next(
            item
            for item in statements
            if item["Action"] == "dynamodb:GetItem"
            and item["Resource"] == {"Fn::GetAtt": "DeletionJournalHead.Arn"}
        )
        assert statement["Condition"] == {
            "ForAllValues:StringEquals": {
                "dynamodb:Attributes": ["journal_id", "registry_id", "sequence", "digest"]
            }
        }


def test_cloudtrail_records_all_security_table_data_events() -> None:
    resources = _cloudformation()["Resources"]
    selectors = resources["AuditTrail"]["Properties"]["EventSelectors"]
    assert len(selectors) == 1
    assert selectors[0]["ReadWriteType"] == "All"
    assert selectors[0]["IncludeManagementEvents"] is True
    assert selectors[0]["DataResources"] == [
        {
            "Type": "AWS::DynamoDB::Table",
            "Values": [
                {"Fn::GetAtt": "WrappedKeyRegistry.Arn"},
                {"Fn::GetAtt": "DeletionJournalHead.Arn"},
                {"Fn::GetAtt": "DeletionJournalIntents.Arn"},
            ],
        }
    ]


def test_policy_render_service_keeps_no_aws_role_or_journal_access() -> None:
    render = yaml.safe_load(
        (ROOT / "deploy" / "render" / "security-baseline-v1.1.yaml.example").read_text()
    )
    services = render["projects"][0]["environments"][0]["services"]
    policy = next(service for service in services if service["name"] == "lucy-policy")
    keys = {item["key"] for item in policy["envVars"]}
    assert "AWS_ROLE_ARN" not in keys
    assert not any("JOURNAL" in key or "DYNAMODB" in key for key in keys)


def test_render_oidc_and_journal_configuration_is_exactly_service_scoped() -> None:
    render = yaml.safe_load(
        (ROOT / "deploy" / "render" / "security-baseline-v1.1.yaml.example").read_text()
    )
    configured = render["projects"][0]["environments"][0]["services"]
    services = {service["name"]: service for service in configured}
    journal_keys = {
        "LUCY_ARCHIVE_REGISTRY_ID",
        "LUCY_DELETION_JOURNAL_ID",
        "LUCY_AWS_DELETION_HEAD_TABLE",
        "LUCY_AWS_DELETION_INTENT_TABLE",
    }
    forbidden = {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
    }
    for name, service in services.items():
        keys = [item["key"] for item in service["envVars"]]
        assert forbidden.isdisjoint(keys)
        if name == "lucy-policy":
            assert "AWS_ROLE_ARN" not in keys
            assert journal_keys.isdisjoint(keys)
        else:
            assert keys.count("AWS_ROLE_ARN") == 1
            assert journal_keys <= set(keys)


def test_initializer_is_create_only_and_never_rewinds_head() -> None:
    script = (AWS_DEPLOY / "initialize-deletion-journal.ps1").read_text()
    assert "attribute_not_exists(journal_key)" in script
    assert "put-item" in script
    assert not any(action in script for action in ("update-item", "delete-item", "transact-write"))


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
