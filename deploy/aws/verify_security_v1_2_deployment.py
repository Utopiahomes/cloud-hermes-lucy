"""Read-only deployed-resource verification for Security Baseline v1.2.

This first verifier covers CloudFormation state, exact published Lambda
executors, KMS key-purpose separation, and DynamoDB protection. It reports no
environment values, identifiers, secrets, or record content.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import boto3  # type: ignore[import-untyped]

_ACCOUNT_ID = re.compile(r"[0-9]{12}\Z")
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+=-]{0,511}\Z")
_ADMIN_SESSION = re.compile(
    r"arn:aws:sts::(?P<account>[0-9]{12}):assumed-role/"
    r"AWSReservedSSO_LucySecurityAdministrator_[A-Za-z0-9]+/[^/]+\Z"
)
_REQUIRED_OUTPUTS = {
    "EvidenceKeyArn",
    "RetrievalReceiptKeyArn",
    "DeletionReceiptKeyArn",
    "WrappedKeyTableName",
    "RetrievalReceiptTableName",
    "DeletionReceiptTableName",
    "DeletionIntentTableName",
    "DeletionJournalHeadTableName",
    "DeletionJournalIntentTableName",
    "RetrievalQuotaTableName",
    "DeletionQuotaTableName",
    "ArchiveRoleArn",
    "EvidenceCallerRoleArn",
    "DeletionCallerRoleArn",
    "FinalityVerifierRoleArn",
    "RecoveryAdministratorRoleArn",
    "LambdaDeployerRoleArn",
    "RetrievalExecutorRuntimeRoleArn",
    "DeletionExecutorRuntimeRoleArn",
    "RetrievalExecutorAliasArn",
    "RetrievalExecutorVersion",
    "RetrievalExecutorIdentity",
    "DeletionExecutorAliasArn",
    "DeletionExecutorVersion",
    "DeletionExecutorIdentity",
    "ExecutorArtifactCodeSha256",
    "SecurityEnvironment",
    "StorageEpoch",
    "RegistryEpoch",
    "KeyEpoch",
    "ArchiveRecordVersion",
    "ArchiveRegistryId",
    "DeletionJournalId",
    "RetrievalLogGroupName",
    "DeletionLogGroupName",
    "AuditBucketName",
    "AuditTrailName",
    "SecurityAlertTopicArn",
    "SecurityAdministrationAlertName",
    "RetrievalErrorAlarmName",
    "DeletionInvocationAlarmName",
    "FinalityQuarantineTablePrefix",
}


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


def _values(items: Any, name_key: str, value_key: str) -> dict[str, str]:
    if not isinstance(items, list):
        return {}
    result: dict[str, str] = {}
    for item in items:
        if not isinstance(item, Mapping):
            continue
        name = item.get(name_key)
        value = item.get(value_key)
        if isinstance(name, str) and isinstance(value, str):
            result[name] = value
    return result


def verify_caller(identity: Mapping[str, Any], expected_account_id: str) -> list[Check]:
    arn = identity.get("Arn")
    account = identity.get("Account")
    match = _ADMIN_SESSION.fullmatch(arn) if isinstance(arn, str) else None
    return [
        Check(
            "aws.target_account",
            account == expected_account_id and match is not None
            and match.group("account") == expected_account_id,
            "caller and target account must match",
        ),
        Check(
            "aws.identity_center_admin",
            match is not None,
            "caller must be the LucySecurityAdministrator SSO session, not root",
        ),
    ]


def verify_stack(
    stack: Mapping[str, Any], termination: Mapping[str, Any]
) -> tuple[list[Check], dict[str, str], dict[str, str]]:
    outputs = _values(stack.get("Outputs"), "OutputKey", "OutputValue")
    parameters = _values(stack.get("Parameters"), "ParameterKey", "ParameterValue")
    status = stack.get("StackStatus")
    checks = [
        Check(
            "cloudformation.complete",
            status in {"CREATE_COMPLETE", "UPDATE_COMPLETE"},
            "stack must be completely deployed, not rolling back or updating",
        ),
        Check(
            "cloudformation.termination_protection",
            termination.get("EnableTerminationProtection") is True,
            "stack termination protection must be enabled",
        ),
        Check(
            "cloudformation.outputs",
            outputs.keys() >= _REQUIRED_OUTPUTS,
            "every reviewed v1.2 output must exist",
        ),
        Check(
            "cloudformation.production",
            parameters.get("SecurityEnvironment") == "production"
            and outputs.get("SecurityEnvironment") == "production",
            "stack parameter and output must both identify production",
        ),
        Check(
            "cloudformation.artifact_digest",
            bool(parameters.get("ExecutorArtifactCodeSha256"))
            and parameters.get("ExecutorArtifactCodeSha256")
            == outputs.get("ExecutorArtifactCodeSha256"),
            "artifact digest parameter and stack output must match",
        ),
    ]
    return checks, outputs, parameters


def _lambda_arn_parts(alias_arn: str) -> tuple[str, str] | None:
    match = re.fullmatch(
        r"arn:aws:lambda:us-east-1:[0-9]{12}:function:"
        r"(?P<function>[A-Za-z0-9_-]{1,64}):(?P<alias>(?![0-9]+\Z)[A-Za-z0-9_-]{1,128})",
        alias_arn,
    )
    if match is None:
        return None
    return match.group("function"), match.group("alias")


def verify_executor(
    *,
    kind: str,
    alias_arn: str,
    version: str,
    configuration: Mapping[str, Any],
    alias: Mapping[str, Any],
    concurrency: Mapping[str, Any],
    outputs: Mapping[str, str],
    parameters: Mapping[str, str],
    expected_account_id: str,
) -> list[Check]:
    parts = _lambda_arn_parts(alias_arn)
    expected_identity = outputs.get(
        "RetrievalExecutorIdentity" if kind == "retrieval" else "DeletionExecutorIdentity"
    )
    expected_session_user = parameters.get(
        "EvidenceDatabaseSessionUser" if kind == "retrieval" else "DeletionDatabaseSessionUser"
    )
    expected_receipt_key = outputs.get(
        "RetrievalReceiptKeyArn" if kind == "retrieval" else "DeletionReceiptKeyArn"
    )
    expected_receipt_table = outputs.get(
        "RetrievalReceiptTableName" if kind == "retrieval" else "DeletionReceiptTableName"
    )
    expected_quota_table = outputs.get(
        "RetrievalQuotaTableName" if kind == "retrieval" else "DeletionQuotaTableName"
    )
    expected_minute_limit = parameters.get(
        "RetrievalMinuteLimit" if kind == "retrieval" else "DeletionMinuteLimit"
    )
    expected_day_limit = parameters.get(
        "RetrievalDayLimit" if kind == "retrieval" else "DeletionDayLimit"
    )
    expected_handler = (
        "lucy.executors.handlers.retrieval_lambda_handler"
        if kind == "retrieval"
        else "lucy.executors.handlers.deletion_lambda_handler"
    )
    expected_concurrency = 2 if kind == "retrieval" else 1
    variables_raw = configuration.get("Environment")
    variables = variables_raw.get("Variables") if isinstance(variables_raw, Mapping) else None
    if not isinstance(variables, Mapping):
        variables = {}

    expected_variables = {
        "LUCY_EXECUTOR_ENVIRONMENT": "production",
        "LUCY_SECURITY_STORAGE_EPOCH": outputs.get("StorageEpoch"),
        "LUCY_SECURITY_REGISTRY_EPOCH": outputs.get("RegistryEpoch"),
        "LUCY_SECURITY_KEY_EPOCH": outputs.get("KeyEpoch"),
        "LUCY_ARCHIVE_RECORD_VERSION": outputs.get("ArchiveRecordVersion"),
        "LUCY_EXECUTOR_IDENTITY": expected_identity,
        "LUCY_EXECUTOR_ALIAS_NAME": "production",
        "LUCY_EXPECTED_DATABASE_SESSION_USER": expected_session_user,
        "LUCY_AWS_RECEIPT_SIGNING_KEY_ARN": expected_receipt_key,
        "LUCY_AWS_WRAPPED_KEY_TABLE": outputs.get("WrappedKeyTableName"),
        "LUCY_AWS_EXECUTOR_RECEIPT_TABLE": expected_receipt_table,
        "LUCY_AWS_EXECUTOR_QUOTA_TABLE": expected_quota_table,
        "LUCY_EXECUTOR_MINUTE_LIMIT": expected_minute_limit,
        "LUCY_EXECUTOR_DAY_LIMIT": expected_day_limit,
    }
    if kind == "retrieval":
        expected_variables["LUCY_AWS_EVIDENCE_KEY_ARN"] = outputs.get("EvidenceKeyArn")
    else:
        expected_variables["LUCY_AWS_DELETION_INTENT_TABLE"] = outputs.get(
            "DeletionIntentTableName"
        )
    trust_store = variables.get("LUCY_POLICY_TRUST_STORE_JSON")
    expected_variable_names = {*expected_variables, "LUCY_POLICY_TRUST_STORE_JSON"}
    static_credentials = {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
    }
    routing = alias.get("RoutingConfig")
    no_weights = not isinstance(routing, Mapping) or not routing.get("AdditionalVersionWeights")
    role = configuration.get("Role")
    checks = [
        Check(
            f"lambda.{kind}.alias_arn",
            parts is not None and parts[1] == "production",
            "executor must use the exact named production alias",
        ),
        Check(
            f"lambda.{kind}.alias_version",
            version.isdigit()
            and version != "0"
            and alias.get("FunctionVersion") == version
            and alias.get("AliasArn") == alias_arn
            and no_weights,
            "alias must point only to one exact published numeric version",
        ),
        Check(
            f"lambda.{kind}.artifact",
            configuration.get("Version") == version
            and configuration.get("CodeSha256") == outputs.get("ExecutorArtifactCodeSha256"),
            "published version must match the reviewed executor artifact digest",
        ),
        Check(
            f"lambda.{kind}.runtime",
            configuration.get("Runtime") == "python3.12"
            and configuration.get("Architectures") == ["x86_64"]
            and configuration.get("Handler") == expected_handler
            and configuration.get("State") == "Active"
            and configuration.get("LastUpdateStatus") == "Successful",
            "published executor must be healthy Python 3.12 Linux AMD64",
        ),
        Check(
            f"lambda.{kind}.role_account",
            isinstance(role, str)
            and re.fullmatch(
                rf"arn:aws:iam::{re.escape(expected_account_id)}:role/[A-Za-z0-9_+=,.@/-]+",
                role,
            )
            is not None,
            "executor runtime role must belong to the exact target account",
        ),
        Check(
            f"lambda.{kind}.concurrency",
            concurrency.get("ReservedConcurrentExecutions") == expected_concurrency,
            "retrieval reserves 2 and deletion reserves 1 execution",
        ),
        Check(
            f"lambda.{kind}.environment",
            set(variables) == expected_variable_names
            and all(variables.get(key) == value for key, value in expected_variables.items())
            and isinstance(trust_store, str)
            and bool(trust_store),
            "environment must match exact stack bindings and contain only reviewed keys",
        ),
        Check(
            f"lambda.{kind}.policy_trust_store",
            verify_policy_trust_store(trust_store),
            "executor must contain only valid production policy-notary public keys",
        ),
        Check(
            f"lambda.{kind}.no_static_credentials",
            static_credentials.isdisjoint(variables),
            "executor environment must not contain AWS credential variables",
        ),
    ]
    return checks


def verify_policy_trust_store(raw: Any) -> bool:
    if not isinstance(raw, str):
        return False
    try:
        keys = json.loads(raw)
    except json.JSONDecodeError:
        return False
    if not isinstance(keys, list) or not keys:
        return False
    active = 0
    key_ids: set[str] = set()
    allowed_fields = {
        "algorithm",
        "compromise_suspected_from",
        "contract_version",
        "environment",
        "issuance_not_after",
        "issuer",
        "key_id",
        "object_type",
        "public_key_b64",
        "purpose",
        "status",
        "valid_from",
        "verify_not_after",
    }
    for key in keys:
        if not isinstance(key, Mapping):
            return False
        if not set(key).issubset(allowed_fields):
            return False
        key_id = key.get("key_id")
        issuer = key.get("issuer")
        if (
            key.get("object_type") != "lucy.verification-key.v1"
            or key.get("contract_version") != "1"
            or key.get("purpose") != "policy_notary"
            or key.get("algorithm") != "Ed25519"
            or key.get("environment") != "production"
            or key.get("status") not in {"active", "retiring"}
            or not isinstance(key_id, str)
            or _SAFE_IDENTIFIER.fullmatch(key_id) is None
            or key_id in key_ids
            or not isinstance(issuer, str)
            or _SAFE_IDENTIFIER.fullmatch(issuer) is None
        ):
            return False
        key_ids.add(key_id)
        encoded_public_key = key.get("public_key_b64")
        if not isinstance(encoded_public_key, str):
            return False
        try:
            public_key = base64.b64decode(encoded_public_key, validate=True)
        except (TypeError, ValueError):
            return False
        if len(public_key) != 32:
            return False
        try:
            valid_from = datetime.fromisoformat(str(key["valid_from"]).replace("Z", "+00:00"))
            issuance_not_after = datetime.fromisoformat(
                str(key["issuance_not_after"]).replace("Z", "+00:00")
            )
            verify_not_after = datetime.fromisoformat(
                str(key["verify_not_after"]).replace("Z", "+00:00")
            )
        except (KeyError, TypeError, ValueError):
            return False
        if (
            valid_from.utcoffset() is None
            or issuance_not_after.utcoffset() is None
            or verify_not_after.utcoffset() is None
            or not valid_from < issuance_not_after <= verify_not_after
        ):
            return False
        compromise_suspected_from = key.get("compromise_suspected_from")
        if compromise_suspected_from is not None:
            try:
                compromise_at = datetime.fromisoformat(
                    str(compromise_suspected_from).replace("Z", "+00:00")
                )
            except (TypeError, ValueError):
                return False
            if compromise_at.utcoffset() is None:
                return False
        if key.get("status") == "active":
            active += 1
    return active == 1


def verify_kms_key(
    metadata: Mapping[str, Any],
    *,
    purpose: str,
    expected_arn: str,
    expected_account_id: str,
    rotation: Any = None,
) -> list[Check]:
    arn_is_target = re.fullmatch(
        rf"arn:aws:kms:us-east-1:{re.escape(expected_account_id)}:key/"
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        expected_arn,
    ) is not None
    common = (
        arn_is_target
        and metadata.get("Arn") == expected_arn
        and metadata.get("Enabled") is True
        and metadata.get("KeyState") == "Enabled"
        and metadata.get("Origin") == "AWS_KMS"
        and metadata.get("KeyManager") == "CUSTOMER"
        and metadata.get("MultiRegion") is False
    )
    if purpose == "evidence":
        shape = (
            metadata.get("KeyUsage") == "ENCRYPT_DECRYPT"
            and metadata.get("KeySpec") == "SYMMETRIC_DEFAULT"
            and isinstance(rotation, Mapping)
            and rotation.get("KeyRotationEnabled") is True
        )
    else:
        shape = metadata.get("KeyUsage") == "SIGN_VERIFY" and metadata.get("KeySpec") == (
            "ECC_NIST_P256"
        )
    return [
        Check(f"kms.{purpose}.state", common, "key must be enabled, single-region AWS KMS"),
        Check(
            f"kms.{purpose}.purpose",
            shape,
            "key usage and specification must match its one reviewed purpose",
        ),
    ]


def verify_table(
    *,
    name: str,
    table: Mapping[str, Any],
    backups: Mapping[str, Any] | None,
    ttl: Mapping[str, Any] | None,
    protected: bool,
    recovery_days: int | None = None,
    ttl_required: bool = False,
) -> list[Check]:
    billing = table.get("BillingModeSummary")
    sse = table.get("SSEDescription")
    schemas = {
        "wrapped_keys": ([{"AttributeName": "key_ref", "KeyType": "HASH"}], ["key_ref"]),
        "retrieval_receipts": (
            [{"AttributeName": "operation_id", "KeyType": "HASH"}],
            ["operation_id"],
        ),
        "deletion_receipts": (
            [{"AttributeName": "operation_id", "KeyType": "HASH"}],
            ["operation_id"],
        ),
        "deletion_intents": (
            [{"AttributeName": "operation_id", "KeyType": "HASH"}],
            ["operation_id"],
        ),
        "journal_head": (
            [{"AttributeName": "journal_key", "KeyType": "HASH"}],
            ["journal_key"],
        ),
        "journal_intents": (
            [
                {"AttributeName": "journal_id", "KeyType": "HASH"},
                {"AttributeName": "entry_key", "KeyType": "RANGE"},
            ],
            ["entry_key", "journal_id"],
        ),
        "retrieval_quota": (
            [{"AttributeName": "quota_key", "KeyType": "HASH"}],
            ["quota_key"],
        ),
        "deletion_quota": (
            [{"AttributeName": "quota_key", "KeyType": "HASH"}],
            ["quota_key"],
        ),
    }
    expected_schema, expected_attributes = schemas[name]
    definitions = table.get("AttributeDefinitions")
    observed_attributes: list[str] = []
    if isinstance(definitions, list):
        for item in definitions:
            if not isinstance(item, Mapping):
                continue
            attribute_name = item.get("AttributeName")
            if isinstance(attribute_name, str):
                observed_attributes.append(attribute_name)
        observed_attributes.sort()
    base = (
        table.get("TableStatus") == "ACTIVE"
        and isinstance(billing, Mapping)
        and billing.get("BillingMode") == "PAY_PER_REQUEST"
        and isinstance(sse, Mapping)
        and sse.get("Status") == "ENABLED"
        and table.get("DeletionProtectionEnabled") is protected
        and table.get("KeySchema") == expected_schema
        and observed_attributes == expected_attributes
    )
    checks = [
        Check(
            f"dynamodb.{name}.base",
            base,
            "table must be active, encrypted, on-demand, and correctly deletion-protected",
        )
    ]
    if backups is not None:
        continuous = backups.get("ContinuousBackupsDescription")
        description = (
            continuous.get("PointInTimeRecoveryDescription")
            if isinstance(continuous, Mapping)
            else None
        )
        pitr = isinstance(description, Mapping) and description.get(
            "PointInTimeRecoveryStatus"
        ) == "ENABLED"
        if recovery_days is not None:
            pitr = (
                pitr
                and isinstance(description, Mapping)
                and description.get("RecoveryPeriodInDays") == recovery_days
            )
        checks.append(
            Check(
                f"dynamodb.{name}.pitr",
                pitr,
                "PITR must be enabled with the reviewed recovery period",
            )
        )
    if ttl_required:
        description = ttl.get("TimeToLiveDescription") if isinstance(ttl, Mapping) else None
        checks.append(
            Check(
                f"dynamodb.{name}.ttl",
                isinstance(description, Mapping)
                and description.get("TimeToLiveStatus") == "ENABLED"
                and description.get("AttributeName") == "expires_at",
                "quota TTL must be enabled on expires_at",
            )
        )
    return checks


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--region", choices=("us-east-1",), default="us-east-1")
    parser.add_argument("--report", type=Path)
    return parser


def _render(checks: list[Check], region: str) -> tuple[dict[str, Any], str]:
    report = {
        "object_type": "lucy.security-baseline-v1.2-deployment-verification",
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
        termination = cloudformation.describe_termination_protection(StackName=args.stack_name)
        stack_checks, outputs, parameters = verify_stack(stack, termination)
        checks.extend(stack_checks)

        lambdas = session.client("lambda")
        for kind in ("retrieval", "deletion"):
            title = "Retrieval" if kind == "retrieval" else "Deletion"
            alias_arn = outputs[f"{title}ExecutorAliasArn"]
            version = outputs[f"{title}ExecutorVersion"]
            parts = _lambda_arn_parts(alias_arn)
            if parts is None:
                checks.append(Check(f"lambda.{kind}.collect", False, "invalid alias output"))
                continue
            function_name, alias_name = parts
            checks.extend(
                verify_executor(
                    kind=kind,
                    alias_arn=alias_arn,
                    version=version,
                    configuration=lambdas.get_function_configuration(
                        FunctionName=function_name, Qualifier=version
                    ),
                    alias=lambdas.get_alias(FunctionName=function_name, Name=alias_name),
                    concurrency=lambdas.get_function_concurrency(FunctionName=function_name),
                    outputs=outputs,
                    parameters=parameters,
                    expected_account_id=args.expected_account_id,
                )
            )

        kms = session.client("kms")
        for purpose, output in (
            ("evidence", "EvidenceKeyArn"),
            ("retrieval_receipt", "RetrievalReceiptKeyArn"),
            ("deletion_receipt", "DeletionReceiptKeyArn"),
        ):
            arn = outputs[output]
            metadata = kms.describe_key(KeyId=arn)["KeyMetadata"]
            rotation = kms.get_key_rotation_status(KeyId=arn) if purpose == "evidence" else None
            checks.extend(
                verify_kms_key(
                    metadata,
                    purpose=purpose,
                    expected_arn=arn,
                    expected_account_id=args.expected_account_id,
                    rotation=rotation,
                )
            )

        dynamodb = session.client("dynamodb")
        table_specs = (
            ("wrapped_keys", "WrappedKeyTableName", True, True, 30, False),
            ("retrieval_receipts", "RetrievalReceiptTableName", True, True, None, False),
            ("deletion_receipts", "DeletionReceiptTableName", True, True, None, False),
            ("deletion_intents", "DeletionIntentTableName", True, True, None, False),
            ("journal_head", "DeletionJournalHeadTableName", True, True, None, False),
            ("journal_intents", "DeletionJournalIntentTableName", True, True, None, False),
            ("retrieval_quota", "RetrievalQuotaTableName", False, False, None, True),
            ("deletion_quota", "DeletionQuotaTableName", False, False, None, True),
        )
        for name, output, protected, pitr, days, ttl_required in table_specs:
            table_name = outputs[output]
            backup_state = (
                dynamodb.describe_continuous_backups(TableName=table_name) if pitr else None
            )
            ttl_state = (
                dynamodb.describe_time_to_live(TableName=table_name)
                if ttl_required
                else None
            )
            checks.extend(
                verify_table(
                    name=name,
                    table=dynamodb.describe_table(TableName=table_name)["Table"],
                    backups=backup_state,
                    ttl=ttl_state,
                    protected=protected,
                    recovery_days=days,
                    ttl_required=ttl_required,
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
