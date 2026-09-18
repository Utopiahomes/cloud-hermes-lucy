from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "deploy" / "aws" / "tiamat-recovery-anchor-v1.yaml"


class CloudFormationLoader(yaml.SafeLoader):
    pass


def _tag(loader: CloudFormationLoader, suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.ScalarNode):
        return {suffix: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {suffix: loader.construct_sequence(node)}
    return {suffix: loader.construct_mapping(node)}


CloudFormationLoader.add_multi_constructor("!", _tag)


def load_template() -> dict[str, object]:
    value = yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=CloudFormationLoader)
    assert isinstance(value, dict)
    return value


def test_anchor_table_is_independent_retained_and_recoverable() -> None:
    template = load_template()
    resources = template["Resources"]
    assert isinstance(resources, dict)
    table = resources["RecoveryAnchorTable"]
    assert table["Type"] == "AWS::DynamoDB::Table"
    assert table["DeletionPolicy"] == "Retain"
    assert table["UpdateReplacePolicy"] == "Retain"
    properties = table["Properties"]
    assert properties["BillingMode"] == "PAY_PER_REQUEST"
    assert properties["DeletionProtectionEnabled"] is True
    assert properties["SSESpecification"] == {"SSEEnabled": True, "SSEType": "KMS"}
    assert properties["PointInTimeRecoverySpecification"] == {
        "PointInTimeRecoveryEnabled": True,
        "RecoveryPeriodInDays": 35,
    }
    assert properties["KeySchema"] == [{"AttributeName": "anchor_key", "KeyType": "HASH"}]


def test_reader_and_updater_credentials_are_separate_and_narrow() -> None:
    resources = load_template()["Resources"]
    assert isinstance(resources, dict)
    read_statements = resources["RecoveryAnchorReadPolicy"]["Properties"]["PolicyDocument"][
        "Statement"
    ]
    update_statements = resources["RecoveryAnchorUpdatePolicy"]["Properties"][
        "PolicyDocument"
    ]["Statement"]
    read_actions = {action for statement in read_statements for action in _actions(statement)}
    update_actions = {action for statement in update_statements for action in _actions(statement)}
    assert read_actions == {"dynamodb:GetItem", "dynamodb:DescribeTable"}
    assert update_actions == {
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DescribeTable",
    }
    forbidden = {
        "dynamodb:DeleteItem",
        "dynamodb:UpdateItem",
        "dynamodb:Scan",
        "dynamodb:Query",
    }
    assert not (read_actions | update_actions) & forbidden


def _actions(statement: dict[str, object]) -> list[str]:
    value = statement["Action"]
    return [value] if isinstance(value, str) else value
