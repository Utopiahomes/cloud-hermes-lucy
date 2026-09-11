from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from deploy.aws.render_security_v1_3_template import V12_SHA256, derive_v1_3

ROOT = Path(__file__).parents[2]
AWS_DEPLOY = ROOT / "deploy" / "aws"


def _load_cloudformation(text: str) -> dict[str, Any]:
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
    value = yaml.load(text, Loader=CloudFormationLoader)
    assert isinstance(value, dict)
    return value


def _template() -> tuple[str, dict[str, Any]]:
    text = (AWS_DEPLOY / "security-baseline-v1.3.yaml").read_text(encoding="utf-8")
    return text, _load_cloudformation(text)


def test_v13_template_is_reproducibly_derived_from_frozen_v12() -> None:
    source = (AWS_DEPLOY / "security-baseline-v1.2.yaml").read_bytes()
    rendered = (AWS_DEPLOY / "security-baseline-v1.3.yaml").read_text(encoding="utf-8")
    assert hashlib.sha256(source).hexdigest() == V12_SHA256
    assert derive_v1_3(source) == rendered

    with pytest.raises(ValueError, match="digest mismatch"):
        derive_v1_3(source + b"\n")


def test_v13_stamp_requires_one_explicit_realm_identity() -> None:
    _, template = _template()
    parameters = template["Parameters"]
    required = {
        "ResourceNamespace",
        "RealmSlug",
        "TenantAccountUuid",
        "NodeId",
        "NodeTenureId",
        "TenureEpoch",
        "SecurityRealmId",
        "RealmWorkspaceUuid",
        "DeploymentId",
        "RealmBindingGeneration",
        "NodeAuthzEpoch",
        "AuthorityRecoveryJournalTableArn",
        "CostRecoveryJournalTableArn",
    }
    assert required <= parameters.keys()
    assert all("Default" not in parameters[name] for name in required)
    assert "RetrievalFunctionName" not in parameters
    assert "DeletionFunctionName" not in parameters
    assert template["Outputs"]["SecurityRealmId"] == {"Value": {"Ref": "SecurityRealmId"}}


def test_v13_existing_trail_covers_both_independent_recovery_journals() -> None:
    _, template = _template()
    selectors = template["Resources"]["AuditTrail"]["Properties"]["EventSelectors"]
    dynamodb = next(
        resource
        for resource in selectors[0]["DataResources"]
        if resource["Type"] == "AWS::DynamoDB::Table"
    )
    assert {"Ref": "AuthorityRecoveryJournalTableArn"} in dynamodb["Values"]
    assert {"Ref": "CostRecoveryJournalTableArn"} in dynamodb["Values"]
    for name in (
        "AuthorityRecoveryJournalTableArn",
        "CostRecoveryJournalTableArn",
    ):
        parameter = template["Parameters"][name]
        assert "Default" not in parameter
        assert parameter["AllowedPattern"].startswith(
            "arn:aws:dynamodb:us-east-1:"
        )


def test_v13_executors_are_environment_pinned_to_the_realm() -> None:
    text, template = _template()
    resources = template["Resources"]
    retrieval = resources["RetrievalExecutorFunction"]["Properties"]
    deletion = resources["DeletionExecutorFunction"]["Properties"]

    assert retrieval["Handler"] == (
        "lucy.executors.handlers_v1_3.realm_retrieval_lambda_handler"
    )
    assert deletion["Handler"] == (
        "lucy.executors.handlers_v1_3.realm_deletion_lambda_handler"
    )
    assert retrieval["FunctionName"] == {
        "Fn::Sub": "${ResourceNamespace}-evidence-executor-v13"
    }
    assert deletion["FunctionName"] == {
        "Fn::Sub": "${ResourceNamespace}-deletion-executor-v13"
    }

    retrieval_env = retrieval["Environment"]["Variables"]
    deletion_env = deletion["Environment"]["Variables"]
    for environment in (retrieval_env, deletion_env):
        assert {
            "LUCY_V13_TARGET_SCOPE_JSON",
            "LUCY_V13_EXECUTION_BINDING_JSON",
            "LUCY_V13_WORKSPACE_ID",
            "LUCY_V13_CALLER_IDENTITY",
        } <= environment.keys()
        assert environment["LUCY_EXECUTOR_ALIAS_NAME"] == "realm-v13"
        assert "LUCY_SECURITY_REGISTRY_EPOCH" not in environment
        assert "LUCY_EXPECTED_DATABASE_SESSION_USER" not in environment
    assert retrieval_env["LUCY_V13_CALLER_IDENTITY"] == {
        "Fn::GetAtt": "EvidenceRole.Arn"
    }
    assert deletion_env["LUCY_V13_CALLER_IDENTITY"] == {
        "Fn::GetAtt": "DeletionRole.Arn"
    }
    assert "SecurityV1_2" not in text
    assert "handlers.retrieval_lambda_handler" not in text
    assert "handlers.deletion_lambda_handler" not in text


def test_v13_kms_boundary_requires_the_complete_realm_context() -> None:
    text, _ = _template()
    expected_keys = {
        "contract_version",
        "tenant_account_id",
        "node_id",
        "node_tenure_id",
        "tenure_epoch",
        "security_realm_id",
        "storage_epoch",
        "evidence_id",
        "purpose",
    }
    assert text.count("kms:EncryptionContext:contract_version: KmsEncryptionContextV2") == 4
    for key in expected_keys:
        assert text.count(f"                  - {key}") == 4
    assert text.count("kms:EncryptionContext:security_realm_id: !Ref SecurityRealmId") == 4
    assert text.count("kms:EncryptionContext:tenant_account_id: !Ref TenantAccountUuid") == 4
    assert text.count("kms:EncryptionContext:purpose: EVIDENCE_DEK") == 4
    assert "kms:EncryptionContext:application" not in text
    assert "kms:EncryptionContext:evidence-id" not in text


def test_v13_each_stack_owns_separate_physical_security_resources() -> None:
    _, template = _template()
    resources = template["Resources"]
    for logical_id in (
        "EvidenceKey",
        "RetrievalReceiptKey",
        "DeletionReceiptKey",
        "WrappedKeyRegistry",
        "RetrievalReceiptLedger",
        "DeletionReceiptLedger",
        "RetrievalExecutorFunction",
        "DeletionExecutorFunction",
        "EvidenceRole",
        "DeletionRole",
        "KmsRecoveryAdministratorRole",
    ):
        assert logical_id in resources

    assert resources["EvidenceCallerPolicy"]["Properties"]["PolicyDocument"]["Statement"] == [
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": {"Ref": "RetrievalExecutorAlias"},
        }
    ]
    assert resources["DeletionCallerPolicy"]["Properties"]["PolicyDocument"]["Statement"] == [
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": {"Ref": "DeletionExecutorAlias"},
        }
    ]


def test_v13_archive_role_can_reconcile_only_exact_wrapped_key_records() -> None:
    _, template = _template()
    statements = template["Resources"]["ArchivePolicy"]["Properties"][
        "PolicyDocument"
    ]["Statement"]
    registry_statement = next(
        statement
        for statement in statements
        if statement.get("Resource") == {"Fn::GetAtt": "WrappedKeyRegistry.Arn"}
    )
    assert registry_statement["Action"] == ["dynamodb:GetItem", "dynamodb:PutItem"]
    serialized = str(registry_statement)
    assert "Scan" not in serialized
    assert "Query" not in serialized
    assert "BatchGetItem" not in serialized
    assert "DeleteItem" not in serialized


def test_r1_recovery_journals_have_separate_tables_and_pause_only_recovery() -> None:
    text = (AWS_DEPLOY / "r1-recovery-journals-v1.3.yaml").read_text(encoding="utf-8")
    template = _load_cloudformation(text)
    resources = template["Resources"]
    for name in ("AuthorityJournal", "CostJournal"):
        table = resources[name]
        assert table["DeletionPolicy"] == "Retain"
        properties = table["Properties"]
        assert properties["DeletionProtectionEnabled"] is True
        assert properties["BillingMode"] == "PAY_PER_REQUEST"
        assert properties["PointInTimeRecoverySpecification"] == {
            "PointInTimeRecoveryEnabled": True,
            "RecoveryPeriodInDays": 30,
        }
        assert "TimeToLiveSpecification" not in properties

    policies = {
        name: resources[name]["Properties"]["PolicyDocument"]["Statement"]
        for name in (
            "AuthorityWriterPolicy",
            "CostWriterPolicy",
            "RecoveryCoordinatorPolicy",
        )
    }
    authority = str(policies["AuthorityWriterPolicy"])
    cost = str(policies["CostWriterPolicy"])
    recovery = str(policies["RecoveryCoordinatorPolicy"])
    assert "CostJournal" not in authority and "STREAM#cost#" not in authority
    assert "AuthorityJournal" not in cost and "STREAM#authority#" not in cost
    assert "PAUSE#authority#" in recovery and "PAUSE#cost#" in recovery
    assert "EVENT#*" in recovery
    assert "UpdateItem" not in recovery
    for statement in policies["RecoveryCoordinatorPolicy"]:
        if statement["Action"] != "dynamodb:GetItem":
            assert "EVENT#*" not in str(statement)
    for serialized in (authority, cost, recovery):
        assert "TransactWriteItems" in serialized
        assert not any(action in serialized for action in ("Scan", "Query", "DeleteItem"))
    for statements in policies.values():
        for statement in statements:
            assert statement["Condition"]["Null"] == {
                "dynamodb:LeadingKeys": "false"
            }
            if statement["Action"] == "dynamodb:ConditionCheckItem":
                assert "StringEquals" not in statement["Condition"]
                assert set(
                    statement["Condition"]["ForAllValues:StringEquals"]
                ) == {"dynamodb:LeadingKeys"}

    trusts = [
        str(resources[name]["Properties"]["AssumeRolePolicyDocument"])
        for name in ("AuthorityWriterRole", "CostWriterRole", "RecoveryCoordinatorRole")
    ]
    assert len(set(trusts)) == 3
    assert all("sts.amazonaws.com" in trust and ":service:" in trust for trust in trusts)
