from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).parents[2]
ACCOUNT = "123456789012"


def _verifier() -> ModuleType:
    path = ROOT / "deploy" / "aws" / "verify_security_v1_2_audit.py"
    spec = importlib.util.spec_from_file_location("verify_security_v1_2_audit", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _outputs() -> dict[str, str]:
    prefix = "lucy-prod-v12"
    return {
        "AuditBucketName": f"{prefix}-audit",
        "AuditTrailName": f"{prefix}-security-audit",
        "AuditCloudTrailLogGroupName": f"/aws/cloudtrail/{prefix}-security-audit",
        "CloudTrailLogsRoleArn": f"arn:aws:iam::{ACCOUNT}:role/{prefix}-cloudtrail-logs",
        "SecurityAlertTopicArn": f"arn:aws:sns:us-east-1:{ACCOUNT}:{prefix}-alerts",
        "SecurityAdministrationAlertName": f"{prefix}-security-changes",
        "EvidenceKeyArn": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/evidence",
        "RetrievalExecutorRuntimeRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/{prefix}-retrieval-runtime"
        ),
        "DeletionExecutorRuntimeRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/{prefix}-deletion-runtime"
        ),
        "RecoveryAdministratorRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/{prefix}-recovery-administrator"
        ),
        "FinalityVerifierRoleArn": f"arn:aws:iam::{ACCOUNT}:role/{prefix}-finality-verifier",
        "WrappedKeyTableName": f"{prefix}-wrapped-keys",
        "RetrievalReceiptTableName": f"{prefix}-retrieval-receipts",
        "DeletionReceiptTableName": f"{prefix}-deletion-receipts",
        "DeletionIntentTableName": f"{prefix}-deletion-intents",
        "DeletionJournalHeadTableName": f"{prefix}-journal-head",
        "DeletionJournalIntentTableName": f"{prefix}-journal-intents",
        "RetrievalExecutorAliasArn": (
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:lucy-retrieval:production"
        ),
        "DeletionExecutorAliasArn": (
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:lucy-deletion:production"
        ),
        "RetrievalErrorAlarmName": f"{prefix}-retrieval-errors",
        "DeletionInvocationAlarmName": f"{prefix}-deletion-invocations",
        "RetrievalFailedAlarmName": f"{prefix}-retrieval-failed",
        "DeletionFailedAlarmName": f"{prefix}-deletion-failed",
        "RetrievalIntegrityDeniedAlarmName": f"{prefix}-retrieval-integrity",
        "DeletionIntegrityDeniedAlarmName": f"{prefix}-deletion-integrity",
        "RetrievalReceiptFailureAlarmName": f"{prefix}-retrieval-receipt",
        "DeletionReceiptFailureAlarmName": f"{prefix}-deletion-receipt",
        "RetrievalThrottleAlarmName": f"{prefix}-retrieval-throttle",
        "DeletionThrottleAlarmName": f"{prefix}-deletion-throttle",
        "KmsDecryptVolumeAlarmName": f"{prefix}-kms-decrypt",
        "RuntimeAccessDeniedAlarmName": f"{prefix}-runtime-denied",
        "RecoveryAdministratorUseAlarmName": f"{prefix}-recovery-use",
        "FinalityVerifierUseAlarmName": f"{prefix}-finality-use",
    }


def test_log_group_requires_exact_target_and_retention() -> None:
    module = _verifier()
    name = "/aws/lambda/lucy-retrieval"
    response = {
        "logGroups": [
            {
                "logGroupName": name,
                "arn": f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:{name}:*",
                "retentionInDays": 90,
                "logGroupClass": "STANDARD",
            }
        ]
    }
    assert module.verify_log_group(
        label="retrieval", response=response, expected_name=name, account=ACCOUNT
    )[0].passed
    response["logGroups"][0]["retentionInDays"] = 7
    assert not module.verify_log_group(
        label="retrieval", response=response, expected_name=name, account=ACCOUNT
    )[0].passed


def test_audit_bucket_requires_exact_delivery_policy() -> None:
    module = _verifier()
    outputs = _outputs()
    bucket = outputs["AuditBucketName"]
    trail = outputs["AuditTrailName"]
    trail_arn = f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/{trail}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{bucket}",
                    f"arn:aws:s3:::{bucket}/*",
                ],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
            {
                "Sid": "CloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"AWS:SourceArn": trail_arn}},
            },
            {
                "Sid": "CloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{ACCOUNT}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "AWS:SourceArn": trail_arn,
                    }
                },
            },
        ],
    }
    checks = module.verify_bucket(
        name=bucket,
        account=ACCOUNT,
        trail_name=trail,
        location={"LocationConstraint": None},
        versioning={"Status": "Enabled"},
        encryption={
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        },
        public_access={
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
        policy_status={"PolicyStatus": {"IsPublic": False}},
        raw_policy=json.dumps(policy),
    )
    assert all(check.passed for check in checks)


def test_trail_requires_active_dual_delivery_and_exact_data_events() -> None:
    module = _verifier()
    outputs = _outputs()
    log_arn = (
        f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:{outputs['AuditCloudTrailLogGroupName']}:*"
    )
    table_arns = [
        f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/{outputs[key]}"
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
    checks = module.verify_trail(
        trail={
            "Name": outputs["AuditTrailName"],
            "S3BucketName": outputs["AuditBucketName"],
            "HomeRegion": "us-east-1",
            "IncludeGlobalServiceEvents": True,
            "IsMultiRegionTrail": False,
            "LogFileValidationEnabled": True,
            "CloudWatchLogsLogGroupArn": log_arn,
            "CloudWatchLogsRoleArn": outputs["CloudTrailLogsRoleArn"],
        },
        status={"IsLogging": True},
        selectors={
            "EventSelectors": [
                {
                    "IncludeManagementEvents": True,
                    "ReadWriteType": "All",
                    "ExcludeManagementEventSources": [],
                    "DataResources": [
                        {"Type": "AWS::DynamoDB::Table", "Values": table_arns},
                        {"Type": "AWS::Lambda::Function", "Values": function_arns},
                    ],
                }
            ]
        },
        outputs=outputs,
        account=ACCOUNT,
    )
    assert all(check.passed for check in checks)

    selectors = {
        "EventSelectors": [
            {
                "IncludeManagementEvents": True,
                "ReadWriteType": "All",
                "ExcludeManagementEventSources": ["kms.amazonaws.com"],
                "DataResources": [
                    {"Type": "AWS::DynamoDB::Table", "Values": table_arns},
                    {"Type": "AWS::Lambda::Function", "Values": function_arns},
                ],
            }
        ]
    }
    failed = module.verify_trail(
        trail={
            "Name": outputs["AuditTrailName"],
            "S3BucketName": outputs["AuditBucketName"],
            "HomeRegion": "us-east-1",
            "IncludeGlobalServiceEvents": True,
            "IsMultiRegionTrail": False,
            "LogFileValidationEnabled": True,
            "CloudWatchLogsLogGroupArn": log_arn,
            "CloudWatchLogsRoleArn": outputs["CloudTrailLogsRoleArn"],
        },
        status={"IsLogging": True},
        selectors=selectors,
        outputs=outputs,
        account=ACCOUNT,
    )
    assert not next(check for check in failed if check.name == "cloudtrail.selectors").passed


def test_metric_filter_requires_exact_content_free_transformation() -> None:
    module = _verifier()
    pattern = '{ $.eventName = "Decrypt" }'
    response = {
        "metricFilters": [
            {
                "filterName": "kms-decrypt",
                "filterPattern": pattern,
                "metricTransformations": [
                    {
                        "metricName": "KmsDecryptCalls",
                        "metricNamespace": "CloudLucy/SecurityV1_2",
                        "metricValue": "1",
                        "defaultValue": 0.0,
                    }
                ],
            }
        ]
    }
    assert module.verify_metric_filter(
        label="kms",
        response=response,
        expected_name="kms-decrypt",
        expected_pattern=pattern,
        expected_metric="KmsDecryptCalls",
    )[0].passed
    response["metricFilters"][0]["metricTransformations"][0]["metricName"] = "Other"
    assert not module.verify_metric_filter(
        label="kms",
        response=response,
        expected_name="kms-decrypt",
        expected_pattern=pattern,
        expected_metric="KmsDecryptCalls",
    )[0].passed


def test_all_fourteen_alarm_contracts_are_exact() -> None:
    module = _verifier()
    contracts = module.expected_alarm_contracts(_outputs(), {"RetrievalMinuteLimit": "5"})
    assert len(contracts) == 14
    alarms: list[dict[str, Any]] = []
    for contract in contracts.values():
        alarms.append({**contract, "ActionsEnabled": True})
    checks = module.verify_alarms({"MetricAlarms": alarms}, contracts)
    assert all(check.passed for check in checks)

    alarms[0]["AlarmActions"] = []
    failed = module.verify_alarms({"MetricAlarms": alarms}, contracts)
    assert any(not check.passed for check in failed)


def test_sns_requires_confirmed_email_and_scoped_alarm_publishing() -> None:
    module = _verifier()
    topic = _outputs()["SecurityAlertTopicArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sns:Publish",
                "Resource": topic,
            }
        ],
    }
    parts = topic.split(":")
    policy["Statement"].append(
        {
            "Effect": "Allow",
            "Sid": "CloudWatchAlarmPublish",
            "Principal": {"Service": "cloudwatch.amazonaws.com"},
            "Action": "sns:Publish",
            "Resource": topic,
            "Condition": {
                "StringEquals": {"aws:SourceAccount": parts[4]},
                "ArnLike": {
                    "aws:SourceArn": (
                        f"arn:{parts[1]}:cloudwatch:{parts[3]}:{parts[4]}:alarm:test-stack-*"
                    )
                },
            },
        }
    )
    subscription = {
        "TopicArn": topic,
        "Protocol": "email",
        "Endpoint": "alerts@example.com",
        "SubscriptionArn": "arn:confirmed",
    }
    checks = module.verify_sns(
        topic=topic,
        attributes={
            "Attributes": {
                "TopicArn": topic,
                "SubscriptionsConfirmed": "1",
                "SubscriptionsPending": "0",
                "Policy": json.dumps(policy),
            }
        },
        subscriptions={"Subscriptions": [subscription]},
        expected_email="alerts@example.com",
        stack_name="test-stack",
    )
    assert all(check.passed for check in checks)

    policy["Statement"][1]["Condition"]["ArnLike"]["aws:SourceArn"] = "*"
    denied = module.verify_sns(
        topic=topic,
        attributes={
            "Attributes": {
                "TopicArn": topic,
                "SubscriptionsConfirmed": "1",
                "SubscriptionsPending": "0",
                "Policy": json.dumps(policy),
            }
        },
        subscriptions={"Subscriptions": [subscription]},
        expected_email="alerts@example.com",
        stack_name="test-stack",
    )
    assert not denied[0].passed

    subscription["SubscriptionArn"] = "PendingConfirmation"
    failed = module.verify_sns(
        topic=topic,
        attributes={"Attributes": {"TopicArn": topic, "Policy": json.dumps(policy)}},
        subscriptions={"Subscriptions": [subscription]},
        expected_email="alerts@example.com",
        stack_name="test-stack",
    )
    assert all(not check.passed for check in failed)


def test_security_change_rule_must_be_enabled_and_single_targeted() -> None:
    module = _verifier()
    outputs = _outputs()
    sources = [
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
    ]
    events = [
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
    ]
    checks = module.verify_event_rule(
        rule={
            "Name": outputs["SecurityAdministrationAlertName"],
            "State": "ENABLED",
            "EventPattern": json.dumps({"source": sources, "detail": {"eventName": events}}),
        },
        targets={
            "Targets": [
                {
                    "Id": "lucy-security-change-alert",
                    "Arn": outputs["SecurityAlertTopicArn"],
                }
            ]
        },
        expected_name=outputs["SecurityAdministrationAlertName"],
        expected_topic=outputs["SecurityAlertTopicArn"],
    )
    assert all(check.passed for check in checks)
