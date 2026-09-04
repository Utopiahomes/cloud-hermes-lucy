"""Read-only audit and alert verification for Security Baseline v1.2."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import boto3  # type: ignore[import-untyped]

_ACCOUNT_ID = re.compile(r"[0-9]{12}\Z")
_ADMIN_SESSION = re.compile(
    r"arn:aws:sts::(?P<account>[0-9]{12}):assumed-role/"
    r"AWSReservedSSO_LucySecurityAdministrator_[A-Za-z0-9]+/[^/]+\Z"
)


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


def _values(items: Any, name_key: str, value_key: str) -> dict[str, str]:
    if not isinstance(items, list):
        return {}
    return {
        item[name_key]: item[value_key]
        for item in items
        if isinstance(item, Mapping)
        and isinstance(item.get(name_key), str)
        and isinstance(item.get(value_key), str)
    }


def _normalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [_normalize(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))
    return value


def verify_caller(identity: Mapping[str, Any], account: str) -> list[Check]:
    arn = identity.get("Arn")
    match = _ADMIN_SESSION.fullmatch(arn) if isinstance(arn, str) else None
    return [
        Check(
            "aws.identity",
            identity.get("Account") == account
            and match is not None
            and match.group("account") == account,
            "caller must be the target-account LucySecurityAdministrator SSO session",
        )
    ]


def verify_log_group(
    *, label: str, response: Mapping[str, Any], expected_name: str, account: str
) -> list[Check]:
    groups = response.get("logGroups")
    exact = (
        [item for item in groups if item.get("logGroupName") == expected_name]
        if isinstance(groups, list)
        else []
    )
    group = exact[0] if len(exact) == 1 and isinstance(exact[0], Mapping) else {}
    arn = group.get("arn")
    return [
        Check(
            f"logs.{label}",
            len(exact) == 1
            and isinstance(arn, str)
            and arn == f"arn:aws:logs:us-east-1:{account}:log-group:{expected_name}:*"
            and group.get("retentionInDays") == 90
            and group.get("logGroupClass") in {None, "STANDARD"},
            "exact log group must exist in the target account with 90-day retention",
        )
    ]


def verify_bucket(
    *,
    name: str,
    account: str,
    trail_name: str,
    location: Mapping[str, Any],
    versioning: Mapping[str, Any],
    encryption: Mapping[str, Any],
    public_access: Mapping[str, Any],
    policy_status: Mapping[str, Any],
    raw_policy: Any,
) -> list[Check]:
    configuration = encryption.get("ServerSideEncryptionConfiguration")
    rules = configuration.get("Rules") if isinstance(configuration, Mapping) else None
    encrypted = False
    if isinstance(rules, list) and len(rules) == 1 and isinstance(rules[0], Mapping):
        default = rules[0].get("ApplyServerSideEncryptionByDefault")
        encrypted = isinstance(default, Mapping) and default.get("SSEAlgorithm") == "AES256"
    block = public_access.get("PublicAccessBlockConfiguration")
    blocked = isinstance(block, Mapping) and all(
        block.get(key) is True
        for key in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    )
    expected_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{name}",
                    f"arn:aws:s3:::{name}/*",
                ],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
            {
                "Sid": "CloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{name}",
                "Condition": {
                    "StringEquals": {
                        "AWS:SourceArn": (
                            f"arn:aws:cloudtrail:us-east-1:{account}:trail/{trail_name}"
                        )
                    }
                },
            },
            {
                "Sid": "CloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{name}/AWSLogs/{account}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "AWS:SourceArn": (
                            f"arn:aws:cloudtrail:us-east-1:{account}:trail/{trail_name}"
                        ),
                    }
                },
            },
        ],
    }
    try:
        policy = json.loads(raw_policy) if isinstance(raw_policy, str) else None
    except json.JSONDecodeError:
        policy = None
    status = policy_status.get("PolicyStatus")
    return [
        Check(
            "s3.audit_bucket.base",
            location.get("LocationConstraint") in {None, ""}
            and versioning.get("Status") == "Enabled"
            and encrypted
            and blocked
            and isinstance(status, Mapping)
            and status.get("IsPublic") is False,
            "audit bucket must be us-east-1, versioned, encrypted, and non-public",
        ),
        Check(
            "s3.audit_bucket.policy",
            _normalize(policy) == _normalize(expected_policy),
            "audit bucket policy must allow only scoped CloudTrail delivery",
        ),
    ]


def verify_trail(
    *,
    trail: Mapping[str, Any],
    status: Mapping[str, Any],
    selectors: Mapping[str, Any],
    outputs: Mapping[str, str],
    account: str,
) -> list[Check]:
    expected_log_arn = (
        f"arn:aws:logs:us-east-1:{account}:log-group:"
        f"{outputs['AuditCloudTrailLogGroupName']}:*"
    )
    state = (
        trail.get("Name") == outputs["AuditTrailName"]
        and trail.get("S3BucketName") == outputs["AuditBucketName"]
        and trail.get("HomeRegion") == "us-east-1"
        and trail.get("IncludeGlobalServiceEvents") is True
        and trail.get("IsMultiRegionTrail") is False
        and trail.get("LogFileValidationEnabled") is True
        and trail.get("CloudWatchLogsLogGroupArn") == expected_log_arn
        and trail.get("CloudWatchLogsRoleArn") == outputs["CloudTrailLogsRoleArn"]
    )
    healthy = (
        status.get("IsLogging") is True
        and not status.get("LatestDeliveryError")
        and not status.get("LatestCloudWatchLogsDeliveryError")
    )
    table_arns = [
        f"arn:aws:dynamodb:us-east-1:{account}:table/{outputs[key]}"
        for key in (
            "WrappedKeyTableName",
            "RetrievalReceiptTableName",
            "DeletionReceiptTableName",
            "DeletionIntentTableName",
            "DeletionJournalHeadTableName",
            "DeletionJournalIntentTableName",
        )
    ]
    function_arns = [
        outputs["RetrievalExecutorAliasArn"].rsplit(":", 1)[0],
        outputs["DeletionExecutorAliasArn"].rsplit(":", 1)[0],
    ]
    expected_selectors = [
        {
            "IncludeManagementEvents": True,
            "ReadWriteType": "All",
            "DataResources": [
                {"Type": "AWS::DynamoDB::Table", "Values": table_arns},
                {"Type": "AWS::Lambda::Function", "Values": function_arns},
            ],
        }
    ]
    return [
        Check("cloudtrail.configuration", state, "trail destinations and validation must be exact"),
        Check("cloudtrail.delivery", healthy, "S3 and CloudWatch delivery must be active"),
        Check(
            "cloudtrail.selectors",
            _normalize(selectors.get("EventSelectors")) == _normalize(expected_selectors)
            and not selectors.get("AdvancedEventSelectors"),
            "management and exact Lambda/DynamoDB data events must remain enabled",
        ),
    ]


def _squash(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def verify_metric_filter(
    *,
    label: str,
    response: Mapping[str, Any],
    expected_name: str,
    expected_pattern: str,
    expected_metric: str,
) -> list[Check]:
    filters = response.get("metricFilters")
    exact = (
        [item for item in filters if item.get("filterName") == expected_name]
        if isinstance(filters, list)
        else []
    )
    item = exact[0] if len(exact) == 1 and isinstance(exact[0], Mapping) else {}
    expected_transformation = [
        {
            "metricName": expected_metric,
            "metricNamespace": "CloudLucy/SecurityV1_2",
            "metricValue": "1",
            "defaultValue": 0.0,
        }
    ]
    return [
        Check(
            f"logs.metric_filter.{label}",
            len(exact) == 1
            and _squash(str(item.get("filterPattern", ""))) == _squash(expected_pattern)
            and _normalize(item.get("metricTransformations"))
            == _normalize(expected_transformation),
            "metric filter pattern and content-free metric transformation must be exact",
        )
    ]


def expected_alarm_contracts(
    outputs: Mapping[str, str], parameters: Mapping[str, str]
) -> dict[str, dict[str, Any]]:
    retrieval_function = (
        outputs["RetrievalExecutorAliasArn"].split(":function:", 1)[1].split(":")[0]
    )
    deletion_function = outputs["DeletionExecutorAliasArn"].split(":function:", 1)[1].split(":")[0]

    def contract(
        *,
        output: str,
        namespace: str,
        metric: str,
        threshold: float,
        period: int = 300,
        dimensions: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        return {
            "AlarmName": outputs[output],
            "Namespace": namespace,
            "MetricName": metric,
            "Statistic": "Sum",
            "Period": period,
            "EvaluationPeriods": 1,
            "Threshold": threshold,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "TreatMissingData": "notBreaching",
            "AlarmActions": [outputs["SecurityAlertTopicArn"]],
            "Dimensions": dimensions or [],
        }

    def action(value: str) -> list[dict[str, str]]:
        return [{"Name": "Action", "Value": value}]

    return {
        "retrieval_error": contract(
            output="RetrievalErrorAlarmName",
            namespace="AWS/Lambda",
            metric="Errors",
            threshold=1,
            dimensions=[{"Name": "FunctionName", "Value": retrieval_function}],
        ),
        "deletion_invocation": contract(
            output="DeletionInvocationAlarmName",
            namespace="AWS/Lambda",
            metric="Invocations",
            threshold=2,
            dimensions=[{"Name": "FunctionName", "Value": deletion_function}],
        ),
        "retrieval_failed": contract(
            output="RetrievalFailedAlarmName",
            namespace="CloudLucy/SecurityV1_2",
            metric="Failed",
            threshold=1,
            dimensions=action("evidence.retrieve"),
        ),
        "deletion_failed": contract(
            output="DeletionFailedAlarmName",
            namespace="CloudLucy/SecurityV1_2",
            metric="Failed",
            threshold=1,
            dimensions=action("evidence.delete"),
        ),
        "retrieval_integrity": contract(
            output="RetrievalIntegrityDeniedAlarmName",
            namespace="CloudLucy/SecurityV1_2",
            metric="IntegrityDenied",
            threshold=1,
            dimensions=action("evidence.retrieve"),
        ),
        "deletion_integrity": contract(
            output="DeletionIntegrityDeniedAlarmName",
            namespace="CloudLucy/SecurityV1_2",
            metric="IntegrityDenied",
            threshold=1,
            dimensions=action("evidence.delete"),
        ),
        "retrieval_receipt": contract(
            output="RetrievalReceiptFailureAlarmName",
            namespace="CloudLucy/SecurityV1_2",
            metric="ReceiptFailure",
            threshold=1,
            dimensions=action("evidence.retrieve"),
        ),
        "deletion_receipt": contract(
            output="DeletionReceiptFailureAlarmName",
            namespace="CloudLucy/SecurityV1_2",
            metric="ReceiptFailure",
            threshold=1,
            dimensions=action("evidence.delete"),
        ),
        "retrieval_throttle": contract(
            output="RetrievalThrottleAlarmName",
            namespace="CloudLucy/SecurityV1_2",
            metric="Throttled",
            threshold=1,
            dimensions=action("evidence.retrieve"),
        ),
        "deletion_throttle": contract(
            output="DeletionThrottleAlarmName",
            namespace="CloudLucy/SecurityV1_2",
            metric="Throttled",
            threshold=1,
            dimensions=action("evidence.delete"),
        ),
        "kms_decrypt": contract(
            output="KmsDecryptVolumeAlarmName",
            namespace="CloudLucy/SecurityV1_2",
            metric="KmsDecryptCalls",
            threshold=float(parameters["RetrievalMinuteLimit"]),
            period=60,
        ),
        "runtime_denied": contract(
            output="RuntimeAccessDeniedAlarmName",
            namespace="CloudLucy/SecurityV1_2",
            metric="RuntimeAccessDenied",
            threshold=1,
        ),
        "recovery_use": contract(
            output="RecoveryAdministratorUseAlarmName",
            namespace="CloudLucy/SecurityV1_2",
            metric="RecoveryAdministratorUse",
            threshold=1,
        ),
        "finality_use": contract(
            output="FinalityVerifierUseAlarmName",
            namespace="CloudLucy/SecurityV1_2",
            metric="FinalityVerifierUse",
            threshold=1,
        ),
    }


def verify_alarms(
    response: Mapping[str, Any], contracts: Mapping[str, Mapping[str, Any]]
) -> list[Check]:
    items = response.get("MetricAlarms")
    items = items if isinstance(items, list) else []
    by_name = {
        item["AlarmName"]: item
        for item in items
        if isinstance(item, Mapping) and isinstance(item.get("AlarmName"), str)
    }
    checks: list[Check] = []
    for label, expected in contracts.items():
        actual = by_name.get(expected["AlarmName"], {})
        selected = {key: actual.get(key) for key in expected}
        checks.append(
            Check(
                f"cloudwatch.alarm.{label}",
                actual.get("ActionsEnabled") is True
                and _normalize(selected) == _normalize(expected),
                "alarm metric, threshold, dimensions, and SNS action must be exact",
            )
        )
    return checks


def verify_sns(
    *,
    topic: str,
    attributes: Mapping[str, Any],
    subscriptions: Mapping[str, Any],
    expected_email: str,
) -> list[Check]:
    attrs = attributes.get("Attributes")
    attrs = attrs if isinstance(attrs, Mapping) else {}
    items = subscriptions.get("Subscriptions")
    items = items if isinstance(items, list) else []
    exact = [
        item
        for item in items
        if item.get("TopicArn") == topic
        and item.get("Protocol") == "email"
        and item.get("Endpoint") == expected_email
        and item.get("SubscriptionArn") not in {None, "PendingConfirmation"}
    ]
    try:
        policy = json.loads(attrs.get("Policy", ""))
    except (json.JSONDecodeError, TypeError):
        policy = None
    statements = policy.get("Statement") if isinstance(policy, Mapping) else None
    policy_ok = False
    if isinstance(statements, list) and len(statements) == 1:
        statement = statements[0]
        policy_ok = (
            isinstance(statement, Mapping)
            and statement.get("Effect") == "Allow"
            and statement.get("Principal") == {"Service": "events.amazonaws.com"}
            and statement.get("Action") == "sns:Publish"
            and statement.get("Resource") == topic
        )
    return [
        Check(
            "sns.topic",
            attrs.get("TopicArn") == topic
            and attrs.get("SubscriptionsConfirmed") == "1"
            and attrs.get("SubscriptionsPending") == "0"
            and policy_ok,
            "alert topic must have one confirmed email route and scoped EventBridge policy",
        ),
        Check(
            "sns.subscription",
            len(exact) == 1 and not subscriptions.get("NextToken"),
            "the reviewed alert mailbox subscription must be confirmed",
        ),
    ]


def verify_event_rule(
    *,
    rule: Mapping[str, Any],
    targets: Mapping[str, Any],
    expected_name: str,
    expected_topic: str,
) -> list[Check]:
    try:
        pattern = json.loads(rule.get("EventPattern", ""))
    except (json.JSONDecodeError, TypeError):
        pattern = None
    sources = set(pattern.get("source", [])) if isinstance(pattern, Mapping) else set()
    events = (
        set(pattern.get("detail", {}).get("eventName", []))
        if isinstance(pattern, Mapping) and isinstance(pattern.get("detail"), Mapping)
        else set()
    )
    target_items = targets.get("Targets")
    target_items = target_items if isinstance(target_items, list) else []
    return [
        Check(
            "eventbridge.security_changes",
            rule.get("Name") == expected_name
            and rule.get("State") == "ENABLED"
            and {
                "aws.kms",
                "aws.lambda",
                "aws.iam",
                "aws.dynamodb",
                "aws.backup",
                "aws.cloudtrail",
                "aws.logs",
                "aws.events",
                "aws.cloudwatch",
                "aws.sns",
                "aws.s3",
            }
            == sources
            and {
                "DisableKey",
                "ScheduleKeyDeletion",
                "PutKeyPolicy",
                "UpdateFunctionCode",
                "UpdateAlias",
                "UpdateContinuousBackups",
                "StopLogging",
                "DeleteTrail",
                "DeleteLogGroup",
                "DeleteMetricFilter",
                "PutMetricAlarm",
                "DisableRule",
                "DeleteTopic",
                "DeleteBucketPolicy",
                "PutBucketVersioning",
            }
            <= events,
            "security-change rule must be enabled across data and monitoring controls",
        ),
        Check(
            "eventbridge.security_target",
            targets.get("NextToken") in {None, ""}
            and target_items
            == [{"Id": "lucy-security-change-alert", "Arn": expected_topic}],
            "security-change rule must target only the reviewed SNS topic",
        ),
    ]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--expected-alert-email", required=True)
    parser.add_argument("--region", choices=("us-east-1",), default="us-east-1")
    parser.add_argument("--report", type=Path)
    return parser


def _render(checks: list[Check], region: str) -> tuple[dict[str, Any], str]:
    report = {
        "object_type": "lucy.security-baseline-v1.2-audit-verification",
        "region": region,
        "passed": all(check.passed for check in checks),
        "checks": [asdict(check) for check in checks],
    }
    return report, json.dumps(report, indent=2, sort_keys=True) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    checks: list[Check] = []
    try:
        if _ACCOUNT_ID.fullmatch(args.expected_account_id) is None:
            raise ValueError("expected AWS account ID must contain exactly 12 digits")
        if args.report is not None and not args.report.parent.is_dir():
            raise FileNotFoundError("report directory does not exist")
        session = boto3.Session(region_name=args.region)
        checks.extend(
            verify_caller(session.client("sts").get_caller_identity(), args.expected_account_id)
        )
        cloudformation = session.client("cloudformation")
        stack = cloudformation.describe_stacks(StackName=args.stack_name)["Stacks"][0]
        if stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
            raise RuntimeError("stack is not complete")
        outputs = _values(stack.get("Outputs"), "OutputKey", "OutputValue")
        parameters = _values(stack.get("Parameters"), "ParameterKey", "ParameterValue")

        logs = session.client("logs")
        for label, output in (
            ("retrieval", "RetrievalLogGroupName"),
            ("deletion", "DeletionLogGroupName"),
            ("cloudtrail", "AuditCloudTrailLogGroupName"),
        ):
            name = outputs[output]
            checks.extend(
                verify_log_group(
                    label=label,
                    response=logs.describe_log_groups(logGroupNamePrefix=name, limit=2),
                    expected_name=name,
                    account=args.expected_account_id,
                )
            )

        s3 = session.client("s3")
        bucket = outputs["AuditBucketName"]
        checks.extend(
            verify_bucket(
                name=bucket,
                account=args.expected_account_id,
                trail_name=outputs["AuditTrailName"],
                location=s3.get_bucket_location(Bucket=bucket),
                versioning=s3.get_bucket_versioning(Bucket=bucket),
                encryption=s3.get_bucket_encryption(Bucket=bucket),
                public_access=s3.get_public_access_block(Bucket=bucket),
                policy_status=s3.get_bucket_policy_status(Bucket=bucket),
                raw_policy=s3.get_bucket_policy(Bucket=bucket).get("Policy"),
            )
        )

        cloudtrail = session.client("cloudtrail")
        trail_name = outputs["AuditTrailName"]
        checks.extend(
            verify_trail(
                trail=cloudtrail.get_trail(Name=trail_name)["Trail"],
                status=cloudtrail.get_trail_status(Name=trail_name),
                selectors=cloudtrail.get_event_selectors(TrailName=trail_name),
                outputs=outputs,
                account=args.expected_account_id,
            )
        )

        patterns = {
            "kms_decrypt": (
                "KmsDecryptMetricFilterName",
                (
                    '{ ($.eventSource = "kms.amazonaws.com") && '
                    '($.eventName = "Decrypt") && '
                    f'($.resources[*].ARN = "{outputs["EvidenceKeyArn"]}") }}'
                ),
                "KmsDecryptCalls",
            ),
            "runtime_denied": (
                "RuntimeAccessDeniedMetricFilterName",
                (
                    '{ (($.errorCode = "*AccessDenied*") || '
                    '($.errorCode = "UnauthorizedOperation")) && '
                    "(($.userIdentity.sessionContext.sessionIssuer.arn = "
                    f'"{outputs["RetrievalExecutorRuntimeRoleArn"]}") || '
                    "($.userIdentity.sessionContext.sessionIssuer.arn = "
                    f'"{outputs["DeletionExecutorRuntimeRoleArn"]}")) }}'
                ),
                "RuntimeAccessDenied",
            ),
            "recovery_use": (
                "RecoveryUseMetricFilterName",
                (
                    "{ $.userIdentity.sessionContext.sessionIssuer.arn = "
                    f'"{outputs["RecoveryAdministratorRoleArn"]}" }}'
                ),
                "RecoveryAdministratorUse",
            ),
            "finality_use": (
                "FinalityUseMetricFilterName",
                (
                    "{ $.userIdentity.sessionContext.sessionIssuer.arn = "
                    f'"{outputs["FinalityVerifierRoleArn"]}" }}'
                ),
                "FinalityVerifierUse",
            ),
        }
        audit_log = outputs["AuditCloudTrailLogGroupName"]
        for label, (output, pattern, metric) in patterns.items():
            name = outputs[output]
            checks.extend(
                verify_metric_filter(
                    label=label,
                    response=logs.describe_metric_filters(
                        logGroupName=audit_log, filterNamePrefix=name, limit=2
                    ),
                    expected_name=name,
                    expected_pattern=pattern,
                    expected_metric=metric,
                )
            )

        contracts = expected_alarm_contracts(outputs, parameters)
        cloudwatch = session.client("cloudwatch")
        checks.extend(
            verify_alarms(
                cloudwatch.describe_alarms(
                    AlarmNames=[contract["AlarmName"] for contract in contracts.values()]
                ),
                contracts,
            )
        )

        sns = session.client("sns")
        topic = outputs["SecurityAlertTopicArn"]
        checks.extend(
            verify_sns(
                topic=topic,
                attributes=sns.get_topic_attributes(TopicArn=topic),
                subscriptions=sns.list_subscriptions_by_topic(TopicArn=topic),
                expected_email=args.expected_alert_email,
            )
        )
        events = session.client("events")
        rule_name = outputs["SecurityAdministrationAlertName"]
        checks.extend(
            verify_event_rule(
                rule=events.describe_rule(Name=rule_name),
                targets=events.list_targets_by_rule(Rule=rule_name, Limit=2),
                expected_name=rule_name,
                expected_topic=topic,
            )
        )
    except Exception as exc:  # CLI boundary: never print provider payloads or identifiers.
        checks.append(Check("verification.execution", False, f"failed: {type(exc).__name__}"))

    report, rendered = _render(checks, args.region)
    if args.report is not None:
        try:
            with args.report.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(rendered)
        except OSError as exc:
            checks.append(
                Check("verification.report", False, f"report not written: {type(exc).__name__}")
            )
            report, rendered = _render(checks, args.region)
    sys.stdout.write(rendered)
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
