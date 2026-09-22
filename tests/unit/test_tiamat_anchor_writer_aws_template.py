"""The M4 writer stack gives PutItem to the writer alone and reports any other writer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from tests.unit.test_tiamat_recovery_anchor_aws_template import CloudFormationLoader

ROOT = Path(__file__).resolve().parents[2]
WRITER = ROOT / "deploy" / "aws" / "tiamat-anchor-writer-v1.yaml"
ANCHOR = ROOT / "deploy" / "aws" / "tiamat-recovery-anchor-v1.yaml"


def _resources(path: Path) -> dict[str, Any]:
    template = yaml.load(path.read_text(encoding="utf-8"), Loader=CloudFormationLoader)
    resources = template["Resources"]
    assert isinstance(resources, dict)
    return resources


def _actions(statement: dict[str, Any]) -> list[str]:
    value = statement["Action"]
    return [value] if isinstance(value, str) else list(value)


def _granted(resources: dict[str, Any], action: str) -> set[str]:
    """Every policy resource, across both stacks' templates, that grants ``action``."""

    return {
        name
        for name, resource in resources.items()
        if resource["Type"] == "AWS::IAM::Policy"
        for statement in resource["Properties"]["PolicyDocument"]["Statement"]
        if statement["Effect"] == "Allow" and action in _actions(statement)
    }


def test_only_the_writer_role_may_put_an_anchor_item() -> None:
    writer, anchor = _resources(WRITER), _resources(ANCHOR)

    assert _granted(writer, "dynamodb:PutItem") == {"WriterPolicy"}
    assert _granted(anchor, "dynamodb:PutItem") == set()
    assert writer["WriterPolicy"]["Properties"]["Roles"] == [{"Ref": "WriterRole"}]
    for resources in (writer, anchor):
        for forbidden in ("dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"):
            assert _granted(resources, forbidden) == set()


def test_the_writer_writes_only_this_environments_keys() -> None:
    statement = _resources(WRITER)["WriterPolicy"]["Properties"]["PolicyDocument"]["Statement"][0]
    assert set(_actions(statement)) == {"dynamodb:GetItem", "dynamodb:PutItem"}
    assert statement["Condition"]["ForAllValues:StringLike"]["dynamodb:LeadingKeys"] == [
        {"Sub": "ENV#${EnvironmentName}#LEDGER#*"}
    ]


def test_the_coordinator_may_only_invoke_the_writer() -> None:
    resources = _resources(WRITER)
    permission = resources["CoordinatorInvokePermission"]["Properties"]
    assert permission["Action"] == "lambda:InvokeFunction"
    assert permission["FunctionName"] == {"Ref": "WriterAlias"}
    assert permission["Principal"] == {
        "Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/${CoordinatorRoleName}"
    }
    statements = resources["CoordinatorInvokePolicy"]["Properties"]["PolicyDocument"]["Statement"]
    assert [(_actions(item), item["Resource"]) for item in statements] == [
        (["lambda:InvokeFunction"], {"Ref": "WriterAlias"})
    ]


def test_the_writer_runs_one_install_at_a_time_from_a_pinned_artifact() -> None:
    resources = _resources(WRITER)
    function = resources["WriterFunction"]["Properties"]
    assert function["Handler"] == "lucy.shared_execution.anchor_writer_lambda.handler"
    assert function["ReservedConcurrentExecutions"] == 1
    assert function["Code"]["S3ObjectVersion"] == {"Ref": "WriterArtifactObjectVersion"}
    assert resources["WriterVersion"]["Properties"]["CodeSha256"] == {
        "Ref": "WriterArtifactCodeSha256"
    }
    assert set(function["Environment"]["Variables"]) == {
        "TIAMAT_RECOVERY_ANCHOR_TABLE",
        "TIAMAT_ANCHOR_WRITER_ROOTS",
    }


def test_every_anchor_table_write_is_trailed_and_a_foreign_writer_alarms() -> None:
    resources = _resources(WRITER)
    selectors = resources["AnchorWriteTrail"]["Properties"]["AdvancedEventSelectors"][0][
        "FieldSelectors"
    ]
    fields = {item["Field"]: item["Equals"] for item in selectors}
    assert fields["eventCategory"] == ["Data"]
    assert fields["resources.type"] == ["AWS::DynamoDB::Table"]
    assert fields["readOnly"] == ["false"]

    rule = resources["ForeignAnchorWriteRule"]["Properties"]
    detail = rule["EventPattern"]["detail"]
    assert "PutItem" in detail["eventName"]
    assert detail["$or"] == [
        {"userIdentity": {"type": [{"anything-but": ["AssumedRole"]}]}},
        {
            "userIdentity": {
                "sessionContext": {
                    "sessionIssuer": {"arn": [{"anything-but": [{"GetAtt": "WriterRole.Arn"}]}]}
                }
            }
        },
    ]
    assert rule["Targets"] == [
        {"Id": "foreign-anchor-write-alarm", "Arn": {"Ref": "AlarmTopicArn"}}
    ]
