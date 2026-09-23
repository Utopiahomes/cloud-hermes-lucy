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


def test_the_table_itself_denies_item_writes_to_everyone_but_the_writer() -> None:
    table = _resources(ANCHOR)["RecoveryAnchorTable"]["Properties"]
    [statement] = table["ResourcePolicy"]["PolicyDocument"]["Statement"]
    assert statement["Effect"] == "Deny" and statement["Principal"] == "*"
    assert set(statement["Action"]) == {
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:BatchWriteItem",
        "dynamodb:PartiQLInsert",
        "dynamodb:PartiQLUpdate",
        "dynamodb:PartiQLDelete",
    }
    assert statement["Condition"] == {
        "ArnNotEquals": {
            "aws:PrincipalArn": {
                "Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/${AnchorWriterRoleName}"
            }
        }
    }


def test_the_writer_role_is_assumable_only_by_its_own_function() -> None:
    [statement] = _resources(WRITER)["WriterRole"]["Properties"]["AssumeRolePolicyDocument"][
        "Statement"
    ]
    assert statement["Principal"] == {"Service": "lambda.amazonaws.com"}
    assert statement["Condition"]["ArnLike"]["aws:SourceArn"]["Sub"].endswith(
        ":function:${ResourceNamespace}-${EnvironmentName}-tiamat-anchor-writer-v1*"
    )


def test_foreign_writes_and_boundary_changes_reach_an_alarm() -> None:
    """Through CloudWatch Logs: EventBridge does not carry DynamoDB item-level data events."""

    resources = _resources(WRITER)
    assert not [name for name, item in resources.items() if item["Type"] == "AWS::Events::Rule"]

    trail = resources["AnchorWriteTrail"]["Properties"]
    assert trail["CloudWatchLogsLogGroupArn"] == {"GetAtt": "AnchorTrailLogGroup.Arn"}
    assert trail["IncludeGlobalServiceEvents"] is True
    categories = [
        {item["Field"]: item["Equals"] for item in selector["FieldSelectors"]}["eventCategory"]
        for selector in trail["AdvancedEventSelectors"]
    ]
    assert categories == [["Data"], ["Management"]]

    patterns = {
        name: resources[name]["Properties"]["FilterPattern"]["Sub"]
        for name in (
            "ForeignItemWriteByRoleFilter",
            "ForeignItemWriteByNonRoleFilter",
            "BoundaryChangeFilter",
        )
    }
    assert '$.userIdentity.sessionContext.sessionIssuer.arn != "${WriterRole.Arn}"' in patterns[
        "ForeignItemWriteByRoleFilter"
    ]
    assert '$.userIdentity.type != "AssumedRole"' in patterns["ForeignItemWriteByNonRoleFilter"]
    for name in ("ForeignItemWriteByRoleFilter", "ForeignItemWriteByNonRoleFilter"):
        assert "$.readOnly IS FALSE" in patterns[name]
    boundary = patterns["BoundaryChangeFilter"]
    for source in ("dynamodb.amazonaws.com", "lambda.amazonaws.com", "iam.amazonaws.com"):
        assert source in boundary

    metrics = {
        resources[name]["Properties"]["MetricTransformations"][0]["MetricName"]
        for name in patterns
    }
    alarms = {
        resources[name]["Properties"]["MetricName"]: resources[name]["Properties"]
        for name in ("ForeignAnchorWriteAlarm", "AnchorBoundaryChangeAlarm")
    }
    assert metrics == set(alarms) == {"ForeignAnchorWrites", "AnchorBoundaryChanges"}
    for alarm in alarms.values():
        assert alarm["Threshold"] == 1
        assert alarm["ComparisonOperator"] == "GreaterThanOrEqualToThreshold"
        assert alarm["AlarmActions"] == [{"Ref": "AlarmTopicArn"}]
