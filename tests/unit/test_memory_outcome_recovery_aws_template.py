from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

ROOT = Path(__file__).parents[2]
TEMPLATE = ROOT / "deploy" / "aws" / "memory-outcome-recovery-v1.yaml"


def _load_cloudformation() -> tuple[str, dict[str, Any]]:
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
    text = TEMPLATE.read_text(encoding="utf-8")
    parsed = yaml.load(text, Loader=CloudFormationLoader)
    assert isinstance(parsed, dict)
    return text, parsed


def test_outcome_writer_cannot_read_or_decrypt() -> None:
    _, template = _load_cloudformation()
    statements = template["Resources"]["ArchiveOutcomePolicy"]["Properties"][
        "PolicyDocument"
    ]["Statement"]
    serialized = str(statements)
    assert "kms:GenerateDataKey" in serialized
    assert "dynamodb:PutItem" in serialized
    assert "lambda:InvokeFunction" in serialized
    for forbidden in (
        "kms:Decrypt",
        "dynamodb:GetItem",
        "dynamodb:Scan",
        "dynamodb:Query",
        "dynamodb:DeleteItem",
    ):
        assert forbidden not in serialized


def test_recovery_runtime_has_only_exact_key_read_decrypt_and_receipt_write() -> None:
    _, template = _load_cloudformation()
    statements = template["Resources"]["OutcomeRecoveryRuntimePolicy"]["Properties"][
        "PolicyDocument"
    ]["Statement"]
    serialized = str(statements)
    for required in (
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "kms:Decrypt",
    ):
        assert required in serialized
    for forbidden in (
        "kms:GenerateDataKey",
        "dynamodb:Scan",
        "dynamodb:Query",
        "dynamodb:DeleteItem",
        "dynamodb:UpdateItem",
        "lambda:InvokeFunction",
    ):
        assert forbidden not in serialized


def test_outcome_key_policy_and_runtime_pin_complete_context() -> None:
    _, template = _load_cloudformation()
    expected = {
        "contract_version",
        "tenant_account_id",
        "node_id",
        "node_tenure_id",
        "tenure_epoch",
        "security_realm_id",
        "storage_epoch",
        "encryption_id",
        "purpose",
    }
    resources = template["Resources"]
    key_statements = resources["OutcomeKey"]["Properties"]["KeyPolicy"]["Statement"]
    conditions = [key_statements[1]["Condition"], key_statements[2]["Condition"]]
    archive_condition = resources["ArchiveOutcomePolicy"]["Properties"][
        "PolicyDocument"
    ]["Statement"][0]["Condition"]
    conditions.append(archive_condition)
    for condition in conditions:
        equals = condition["StringEquals"]
        assert equals["kms:EncryptionContext:purpose"] == "MEMORY_OUTCOME_DEK"
        assert (
            equals["kms:EncryptionContext:contract_version"]
            == "MemoryOutcomeKmsContextV1"
        )
        assert set(condition["ForAllValues:StringEquals"]["kms:EncryptionContextKeys"]) == expected

    function = template["Resources"]["OutcomeRecoveryFunction"]["Properties"]
    assert function["Handler"] == (
        "lucy.executors.outcome_recovery_v1.memory_outcome_recovery_lambda_handler"
    )
    assert function["ReservedConcurrentExecutions"] == 1
    assert function["Environment"]["Variables"]["LUCY_OUTCOME_REGISTRY_ID"] == {
        "Ref": "OutcomeRegistryId"
    }


def test_outcome_state_is_protected_and_retained() -> None:
    _, template = _load_cloudformation()
    for name in ("OutcomeKeyRegistry", "OutcomeRecoveryReceiptLedger"):
        table = template["Resources"][name]
        assert table["DeletionPolicy"] == "Retain"
        assert table["UpdateReplacePolicy"] == "Retain"
        assert table["Properties"]["DeletionProtectionEnabled"] is True
        assert table["Properties"]["BillingMode"] == "PAY_PER_REQUEST"
        assert table["Properties"]["PointInTimeRecoverySpecification"] == {
            "PointInTimeRecoveryEnabled": True,
            "RecoveryPeriodInDays": 30,
        }
    key = template["Resources"]["OutcomeKey"]
    assert key["DeletionPolicy"] == "Retain"
    assert key["Properties"]["EnableKeyRotation"] is True
