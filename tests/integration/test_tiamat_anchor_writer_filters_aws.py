"""The anchor-writer stack's CloudWatch metric filters, tested by AWS against CloudTrail events.

The patterns are taken from the template itself, rendered as the stack would render them, and
evaluated by CloudWatch Logs' TestMetricFilter, so what is tested is AWS's own matching, not a
local imitation of it. TestMetricFilter reads and writes nothing in the account. It needs AWS
credentials and runs only when TIAMAT_AWS_FILTER_TEST=1.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.unit.test_tiamat_recovery_anchor_aws_template import CloudFormationLoader

TEMPLATE = Path(__file__).resolve().parents[2] / "deploy" / "aws" / "tiamat-anchor-writer-v1.yaml"
ACCOUNT, REGION = "123456789012", "us-east-1"
NAMESPACE, ENVIRONMENT = "stoin", "staging"
TABLE = "stoin-staging-tiamat-recovery-anchor-v1"
TABLE_ARN = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{TABLE}"
OTHER_TABLE_ARN = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/unrelated"
WRITER_ROLE = f"{NAMESPACE}-{ENVIRONMENT}-tiamat-anchor-writer-v1"
WRITER_ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/{WRITER_ROLE}"
COORDINATOR_ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/stoin-staging-tiamat-recovery-coordinator"
FUNCTION = f"{NAMESPACE}-{ENVIRONMENT}-tiamat-anchor-writer-v1"

pytestmark = pytest.mark.skipif(
    os.environ.get("TIAMAT_AWS_FILTER_TEST") != "1",
    reason="evaluates the filters with AWS TestMetricFilter; set TIAMAT_AWS_FILTER_TEST=1",
)


def _patterns() -> dict[str, str]:
    resources = yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=CloudFormationLoader)[
        "Resources"
    ]
    values = {
        "AWS::Partition": "aws",
        "AWS::Region": REGION,
        "AWS::AccountId": ACCOUNT,
        "AnchorTableName": TABLE,
        "ResourceNamespace": NAMESPACE,
        "EnvironmentName": ENVIRONMENT,
        "WriterRole": WRITER_ROLE,
        "WriterRole.Arn": WRITER_ROLE_ARN,
    }
    return {
        name: re.sub(
            r"\$\{([^}]+)\}",
            lambda match: values[match.group(1)],
            resource["Properties"]["FilterPattern"]["Sub"],
        )
        for name, resource in resources.items()
        if resource["Type"] == "AWS::Logs::MetricFilter"
    }


def _role(arn: str) -> dict[str, Any]:
    return {
        "type": "AssumedRole",
        "arn": arn.replace(":iam::", ":sts::").replace(":role/", ":assumed-role/") + "/session",
        "sessionContext": {"sessionIssuer": {"type": "Role", "arn": arn}},
    }


def _data(name: str, identity: dict[str, Any], *arns: str, read_only: bool = False) -> str:
    return json.dumps(
        {
            "eventVersion": "1.09",
            "eventCategory": "Data",
            "eventSource": "dynamodb.amazonaws.com",
            "eventName": name,
            "readOnly": read_only,
            "userIdentity": identity,
            "requestParameters": {"tableName": TABLE},
            "resources": [
                {"accountId": ACCOUNT, "type": "AWS::DynamoDB::Table", "ARN": arn} for arn in arns
            ],
        }
    )


def _management(source: str, name: str, parameters: dict[str, Any]) -> str:
    return json.dumps(
        {
            "eventVersion": "1.09",
            "eventCategory": "Management",
            "eventSource": source,
            "eventName": name,
            "readOnly": False,
            "userIdentity": _role(f"arn:aws:iam::{ACCOUNT}:role/administrator"),
            "requestParameters": parameters,
        }
    )


FOREIGN = {
    "coordinator put": _data("PutItem", _role(COORDINATOR_ROLE_ARN), TABLE_ARN),
    "coordinator transaction, anchor table second": _data(
        "TransactWriteItems", _role(COORDINATOR_ROLE_ARN), OTHER_TABLE_ARN, TABLE_ARN
    ),
    "coordinator PartiQL insert": _data("ExecuteStatement", _role(COORDINATOR_ROLE_ARN), TABLE_ARN),
    "IAM user put": _data(
        "PutItem", {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/someone"}, TABLE_ARN
    ),
    "root delete": _data(
        "DeleteItem", {"type": "Root", "arn": f"arn:aws:iam::{ACCOUNT}:root"}, TABLE_ARN
    ),
}
NOT_FOREIGN = {
    "writer put": _data("PutItem", _role(WRITER_ROLE_ARN), TABLE_ARN),
    "coordinator read": _data("GetItem", _role(COORDINATOR_ROLE_ARN), TABLE_ARN, read_only=True),
    "coordinator put elsewhere": _data("PutItem", _role(COORDINATOR_ROLE_ARN), OTHER_TABLE_ARN),
}
BOUNDARY = {
    "table resource policy removed": _management(
        "dynamodb.amazonaws.com", "DeleteResourcePolicy", {"resourceArn": TABLE_ARN}
    ),
    "table protection changed": _management(
        "dynamodb.amazonaws.com", "UpdateTable", {"tableName": TABLE}
    ),
    "writer configuration changed": _management(
        "lambda.amazonaws.com",
        "UpdateFunctionConfiguration20150331v2",
        {"functionName": FUNCTION},
    ),
    "writer alias moved": _management(
        "lambda.amazonaws.com",
        "UpdateAlias20150331",
        {"functionName": f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{FUNCTION}"},
    ),
    "writer role policy changed": _management(
        "iam.amazonaws.com", "PutRolePolicy", {"roleName": WRITER_ROLE}
    ),
}
NOT_BOUNDARY = {
    "writer put": NOT_FOREIGN["writer put"],
    "another function changed": _management(
        "lambda.amazonaws.com", "UpdateFunctionConfiguration20150331v2", {"functionName": "other"}
    ),
    "another role changed": _management("iam.amazonaws.com", "PutRolePolicy", {"roleName": "x"}),
}


def _matched(pattern: str, events: dict[str, str]) -> set[str]:
    import boto3  # type: ignore[import-untyped]

    names = list(events)
    result = boto3.client("logs", region_name=REGION).test_metric_filter(
        filterPattern=pattern, logEventMessages=[events[name] for name in names]
    )
    return {names[match["eventNumber"] - 1] for match in result["matches"]}


def test_foreign_item_writes_match_and_the_writer_and_reads_do_not() -> None:
    patterns = _patterns()
    events = {**FOREIGN, **NOT_FOREIGN}
    matched = _matched(patterns["ForeignItemWriteByRoleFilter"], events) | _matched(
        patterns["ForeignItemWriteByNonRoleFilter"], events
    )
    assert matched == set(FOREIGN)


def test_boundary_changes_match_and_unrelated_changes_do_not() -> None:
    events = {**BOUNDARY, **NOT_BOUNDARY}
    assert _matched(_patterns()["BoundaryChangeFilter"], events) == set(BOUNDARY)
