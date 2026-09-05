"""Read-only IAM and KMS-policy verification for Security Baseline v1.2.

Run only after the core deployment verifier passes. The tool compares every
deployed role and KMS resource policy with the approved least-privilege
contract, then asks IAM to simulate critical positive and negative decisions.
It never assumes a workload role or accesses application data.
"""

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


@dataclass(frozen=True)
class SimulationCase:
    name: str
    role: str
    action: str
    resource: str
    allowed: bool
    context: tuple[dict[str, Any], ...] = ()


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


def _role_name(arn: str, account: str) -> str | None:
    match = re.fullmatch(
        rf"arn:aws:iam::{re.escape(account)}:role/(?P<name>[A-Za-z0-9_+=,.@/-]+)", arn
    )
    return match.group("name") if match is not None else None


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


def verify_role(
    *,
    label: str,
    expected_arn: str,
    account: str,
    role: Mapping[str, Any],
    inline_names: Mapping[str, Any],
    attached: Mapping[str, Any],
    expected_policy_name: str,
    actual_policy: Mapping[str, Any],
    expected_trust: Mapping[str, Any],
    expected_policy: Mapping[str, Any],
) -> list[Check]:
    expected_name = _role_name(expected_arn, account)
    actual = role.get("Role")
    actual = actual if isinstance(actual, Mapping) else {}
    names = inline_names.get("PolicyNames")
    attached_items = attached.get("AttachedPolicies")
    return [
        Check(
            f"iam.{label}.identity",
            expected_name is not None
            and actual.get("Arn") == expected_arn
            and actual.get("RoleName") == expected_name
            and actual.get("MaxSessionDuration") == 3600
            and "PermissionsBoundary" not in actual,
            "role ARN, name, session duration, and boundary state must be exact",
        ),
        Check(
            f"iam.{label}.trust",
            _normalize(actual.get("AssumeRolePolicyDocument")) == _normalize(expected_trust),
            "role trust policy must exactly match its one approved principal",
        ),
        Check(
            f"iam.{label}.policy_inventory",
            inline_names.get("IsTruncated") is not True
            and names == [expected_policy_name]
            and attached.get("IsTruncated") is not True
            and attached_items == [],
            "role must have one exact inline policy and no attached managed policies",
        ),
        Check(
            f"iam.{label}.policy_document",
            actual_policy.get("RoleName") == expected_name
            and actual_policy.get("PolicyName") == expected_policy_name
            and _normalize(actual_policy.get("PolicyDocument")) == _normalize(expected_policy),
            "inline policy must exactly match the approved action, resource, and condition set",
        ),
    ]


def verify_kms_policy(
    *, label: str, raw: Any, expected: Mapping[str, Any]
) -> list[Check]:
    try:
        actual = json.loads(raw) if isinstance(raw, str) else None
    except json.JSONDecodeError:
        actual = None
    return [
        Check(
            f"kms.{label}.resource_policy",
            _normalize(actual) == _normalize(expected),
            "KMS resource policy must exactly match approved administrators and workload use",
        )
    ]


def verify_simulation(case: SimulationCase, response: Mapping[str, Any]) -> Check:
    results = response.get("EvaluationResults")
    result = results[0] if isinstance(results, list) and len(results) == 1 else None
    decision = result.get("EvalDecision") if isinstance(result, Mapping) else None
    passed = decision == "allowed" if case.allowed else decision in {
        "implicitDeny",
        "explicitDeny",
    }
    return Check(
        f"simulation.{case.name}",
        passed,
        "IAM simulator decision must match the approved allow/deny matrix",
    )


def _oidc_trust(
    provider: str, workspace: str, environment: str, service: str
) -> dict[str, Any]:
    issuer = f"oidc.render.com/{workspace}"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": provider},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"{issuer}:aud": "sts.amazonaws.com",
                        f"{issuer}:sub": (
                            f"workspace:{workspace}:environment:{environment}:service:{service}"
                        ),
                    }
                },
            }
        ],
    }


def _human_trust(account: str, principal_pattern: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"ArnLike": {"aws:PrincipalArn": principal_pattern}},
            }
        ],
    }


def _lambda_trust() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _service_trust(service: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _context_condition(environment: str) -> dict[str, Any]:
    fields = [
        "application",
        "environment",
        "evidence-id",
        "storage-epoch",
        "registry-epoch",
        "key-epoch",
        "record-version",
    ]
    return {
        "StringEquals": {
            "kms:EncryptionContext:application": "cloud-hermes-lucy",
            "kms:EncryptionContext:environment": environment,
        },
        "ForAllValues:StringEquals": {"kms:EncryptionContextKeys": fields},
        "Null": {
            f"kms:EncryptionContext:{field}": "false"
            for field in fields
            if field not in {"application", "environment"}
        },
    }


def expected_role_contracts(
    outputs: Mapping[str, str], parameters: Mapping[str, str], account: str
) -> dict[str, tuple[str, dict[str, Any], dict[str, Any]]]:
    namespace = parameters["ResourceNamespace"]
    region = "us-east-1"

    def table(name: str) -> str:
        return f"arn:aws:dynamodb:{region}:{account}:table/{outputs[name]}"

    def oidc(service: str) -> dict[str, Any]:
        return _oidc_trust(
            parameters["RenderOidcProviderArn"],
            parameters["RenderWorkspaceId"],
            parameters["RenderEnvironmentId"],
            parameters[service],
        )

    retrieval_function = outputs["RetrievalExecutorAliasArn"].rsplit(":", 1)[0]
    deletion_function = outputs["DeletionExecutorAliasArn"].rsplit(":", 1)[0]
    wrapped = table("WrappedKeyTableName")
    retrieval_receipts = table("RetrievalReceiptTableName")
    deletion_receipts = table("DeletionReceiptTableName")
    deletion_intents = table("DeletionIntentTableName")
    journal_head = table("DeletionJournalHeadTableName")
    retrieval_quota = table("RetrievalQuotaTableName")
    deletion_quota = table("DeletionQuotaTableName")
    quarantine = (
        f"arn:aws:dynamodb:{region}:{account}:table/"
        f"{outputs['FinalityQuarantineTablePrefix']}*"
    )
    context = _context_condition(parameters["SecurityEnvironment"])
    version = "2012-10-17"
    enclosing = {
        "ForAnyValue:StringEquals": {"dynamodb:EnclosingOperation": "TransactWriteItems"}
    }
    policies: dict[str, tuple[str, dict[str, Any], dict[str, Any]]] = {
        "archive": (
            f"{namespace}-archive-only",
            oidc("RenderArchiveServiceId"),
            {
                "Version": version,
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "kms:GenerateDataKey",
                        "Resource": outputs["EvidenceKeyArn"],
                        "Condition": context,
                    },
                    {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": wrapped},
                    {
                        "Effect": "Allow",
                        "Action": "dynamodb:GetItem",
                        "Resource": journal_head,
                        "Condition": {
                            "ForAllValues:StringEquals": {
                                "dynamodb:LeadingKeys": ["HEAD"],
                                "dynamodb:Attributes": [
                                    "journal_key",
                                    "journal_id",
                                    "registry_id",
                                    "sequence",
                                    "digest",
                                ]
                            }
                        },
                    },
                ],
            },
        ),
        "evidence_caller": (
            f"{namespace}-invoke-retrieval-alias-only",
            oidc("RenderEvidenceServiceId"),
            {
                "Version": version,
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Resource": outputs["RetrievalExecutorAliasArn"],
                    }
                ],
            },
        ),
        "deletion_caller": (
            f"{namespace}-invoke-deletion-alias-only",
            oidc("RenderDeletionServiceId"),
            {
                "Version": version,
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Resource": outputs["DeletionExecutorAliasArn"],
                    }
                ],
            },
        ),
        "finality": (
            f"{namespace}-finality-metadata-only",
            oidc("RenderFinalityServiceId"),
            {
                "Version": version,
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "dynamodb:DescribeTable",
                            "dynamodb:DescribeContinuousBackups",
                        ],
                        "Resource": wrapped,
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["dynamodb:DescribeTable", "dynamodb:ListTagsOfResource"],
                        "Resource": quarantine,
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "dynamodb:ListTables",
                            "dynamodb:ListBackups",
                            "dynamodb:ListExports",
                            "dynamodb:ListImports",
                            "dynamodb:ListGlobalTables",
                            "backup:ListProtectedResources",
                            "backup:ListRecoveryPointsByResource",
                        ],
                        "Resource": "*",
                        "Condition": {"StringEquals": {"aws:RequestedRegion": region}},
                    },
                ],
            },
        ),
        "recovery": (
            f"{namespace}-quarantined-recovery",
            _human_trust(account, parameters["KeyAdministratorPrincipalArnPattern"]),
            {
                "Version": version,
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "dynamodb:DescribeTable",
                            "dynamodb:DescribeContinuousBackups",
                            "dynamodb:RestoreTableToPointInTime",
                        ],
                        "Resource": wrapped,
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "dynamodb:DescribeTable",
                            "dynamodb:TagResource",
                            "dynamodb:UntagResource",
                            "dynamodb:GetItem",
                            "dynamodb:DeleteTable",
                            "dynamodb:RestoreTableToPointInTime",
                        ],
                        "Resource": quarantine,
                    },
                    {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": wrapped},
                    {
                        "Effect": "Allow",
                        "Action": ["dynamodb:ListTables", "dynamodb:ListBackups"],
                        "Resource": "*",
                        "Condition": {"StringEquals": {"aws:RequestedRegion": region}},
                    },
                ],
            },
        ),
        "deployer": (
            f"{namespace}-lambda-deployer-only",
            _human_trust(account, parameters["KeyAdministratorPrincipalArnPattern"]),
            {
                "Version": version,
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "lambda:GetFunction",
                            "lambda:UpdateFunctionCode",
                            "lambda:UpdateFunctionConfiguration",
                            "lambda:PublishVersion",
                        ],
                        "Resource": [retrieval_function, deletion_function],
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["lambda:GetAlias", "lambda:UpdateAlias"],
                        "Resource": [
                            outputs["RetrievalExecutorAliasArn"],
                            outputs["DeletionExecutorAliasArn"],
                        ],
                    },
                    {
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
                        "Resource": [
                            outputs["RetrievalExecutorRuntimeRoleArn"],
                            outputs["DeletionExecutorRuntimeRoleArn"],
                        ],
                        "Condition": {
                            "StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}
                        },
                    },
                ],
            },
        ),
        "retrieval_runtime": (
            f"{namespace}-retrieval-runtime-only",
            _lambda_trust(),
            {
                "Version": version,
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": (
                            f"arn:aws:logs:{region}:{account}:log-group:"
                            f"{outputs['RetrievalLogGroupName']}:*"
                        ),
                    },
                    {
                        "Effect": "Allow",
                        "Action": "dynamodb:GetItem",
                        "Resource": [wrapped, retrieval_receipts],
                    },
                    {
                        "Effect": "Allow",
                        "Action": "dynamodb:PutItem",
                        "Resource": retrieval_receipts,
                    },
                    {
                        "Effect": "Allow",
                        "Action": "dynamodb:UpdateItem",
                        "Resource": retrieval_quota,
                        "Condition": enclosing,
                    },
                    {
                        "Effect": "Allow",
                        "Action": "kms:Decrypt",
                        "Resource": outputs["EvidenceKeyArn"],
                        "Condition": context,
                    },
                    {
                        "Effect": "Allow",
                        "Action": "kms:Sign",
                        "Resource": outputs["RetrievalReceiptKeyArn"],
                        "Condition": {
                            "StringEquals": {"kms:SigningAlgorithm": "ECDSA_SHA_256"}
                        },
                    },
                ],
            },
        ),
        "deletion_runtime": (
            f"{namespace}-deletion-runtime-only",
            _lambda_trust(),
            {
                "Version": version,
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": (
                            f"arn:aws:logs:{region}:{account}:log-group:"
                            f"{outputs['DeletionLogGroupName']}:*"
                        ),
                    },
                    {
                        "Effect": "Allow",
                        "Action": "dynamodb:GetItem",
                        "Resource": deletion_receipts,
                    },
                    {
                        "Effect": "Allow",
                        "Action": "dynamodb:DeleteItem",
                        "Resource": wrapped,
                        "Condition": enclosing,
                    },
                    {
                        "Effect": "Allow",
                        "Action": "dynamodb:PutItem",
                        "Resource": [deletion_receipts, deletion_intents],
                        "Condition": enclosing,
                    },
                    {
                        "Effect": "Allow",
                        "Action": "dynamodb:UpdateItem",
                        "Resource": deletion_quota,
                        "Condition": enclosing,
                    },
                    {
                        "Effect": "Allow",
                        "Action": "kms:Sign",
                        "Resource": outputs["DeletionReceiptKeyArn"],
                        "Condition": {
                            "StringEquals": {"kms:SigningAlgorithm": "ECDSA_SHA_256"}
                        },
                    },
                ],
            },
        ),
        "cloudtrail_logs": (
            f"{namespace}-cloudtrail-logs-only",
            _service_trust("cloudtrail.amazonaws.com"),
            {
                "Version": version,
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": (
                            f"arn:aws:logs:{region}:{account}:log-group:"
                            f"{outputs['AuditCloudTrailLogGroupName']}:*"
                        ),
                    }
                ],
            },
        ),
    }
    return policies


def expected_kms_contracts(
    outputs: Mapping[str, str], parameters: Mapping[str, str], account: str
) -> dict[str, dict[str, Any]]:
    admin = {
        "Sid": "IdentityCenterHumanKeyAdministrator",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
        "Action": [
            "kms:Create*",
            "kms:Describe*",
            "kms:Enable*",
            "kms:List*",
            "kms:Put*",
            "kms:Update*",
            "kms:Revoke*",
            "kms:Disable*",
            "kms:Get*",
            "kms:Delete*",
            "kms:TagResource",
            "kms:UntagResource",
            "kms:ScheduleKeyDeletion",
            "kms:CancelKeyDeletion",
        ],
        "Resource": "*",
        "Condition": {
            "ArnLike": {
                "aws:PrincipalArn": parameters["KeyAdministratorPrincipalArnPattern"]
            }
        },
    }
    context = _context_condition(parameters["SecurityEnvironment"])
    return {
        "evidence": {
            "Version": "2012-10-17",
            "Statement": [
                admin,
                {
                    "Sid": "ArchiveGenerateOnly",
                    "Effect": "Allow",
                    "Principal": {"AWS": outputs["ArchiveRoleArn"]},
                    "Action": "kms:GenerateDataKey",
                    "Resource": "*",
                    "Condition": context,
                },
                {
                    "Sid": "RetrievalExecutorDecryptOnly",
                    "Effect": "Allow",
                    "Principal": {"AWS": outputs["RetrievalExecutorRuntimeRoleArn"]},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": context,
                },
            ],
        },
        "retrieval_receipt": {
            "Version": "2012-10-17",
            "Statement": [
                admin,
                {
                    "Sid": "RetrievalReceiptSignOnly",
                    "Effect": "Allow",
                    "Principal": {"AWS": outputs["RetrievalExecutorRuntimeRoleArn"]},
                    "Action": "kms:Sign",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"kms:SigningAlgorithm": "ECDSA_SHA_256"}
                    },
                },
            ],
        },
        "deletion_receipt": {
            "Version": "2012-10-17",
            "Statement": [
                admin,
                {
                    "Sid": "DeletionReceiptSignOnly",
                    "Effect": "Allow",
                    "Principal": {"AWS": outputs["DeletionExecutorRuntimeRoleArn"]},
                    "Action": "kms:Sign",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"kms:SigningAlgorithm": "ECDSA_SHA_256"}
                    },
                },
            ],
        },
    }


def simulation_cases(
    outputs: Mapping[str, str], account: str
) -> tuple[SimulationCase, ...]:
    region = "us-east-1"
    wrapped = f"arn:aws:dynamodb:{region}:{account}:table/{outputs['WrappedKeyTableName']}"
    quarantine = (
        f"arn:aws:dynamodb:{region}:{account}:table/"
        f"{outputs['FinalityQuarantineTablePrefix']}iam-simulation"
    )
    retrieval_function = outputs["RetrievalExecutorAliasArn"].rsplit(":", 1)[0]
    context = (
        {
            "ContextKeyName": "kms:EncryptionContext:application",
            "ContextKeyValues": ["cloud-hermes-lucy"],
            "ContextKeyType": "string",
        },
        {
            "ContextKeyName": "kms:EncryptionContext:environment",
            "ContextKeyValues": ["production"],
            "ContextKeyType": "string",
        },
        {
            "ContextKeyName": "kms:EncryptionContextKeys",
            "ContextKeyValues": [
                "application",
                "environment",
                "evidence-id",
                "storage-epoch",
                "registry-epoch",
                "key-epoch",
                "record-version",
            ],
            "ContextKeyType": "stringList",
        },
        *(
            {
                "ContextKeyName": f"kms:EncryptionContext:{field}",
                "ContextKeyValues": ["synthetic-acceptance"],
                "ContextKeyType": "string",
            }
            for field in (
                "evidence-id",
                "storage-epoch",
                "registry-epoch",
                "key-epoch",
                "record-version",
            )
        ),
    )
    signing = (
        {
            "ContextKeyName": "kms:SigningAlgorithm",
            "ContextKeyValues": ["ECDSA_SHA_256"],
            "ContextKeyType": "string",
        },
    )
    transact = (
        {
            "ContextKeyName": "dynamodb:EnclosingOperation",
            "ContextKeyValues": ["TransactWriteItems"],
            "ContextKeyType": "stringList",
        },
    )
    return (
        SimulationCase(
            "evidence_caller_own_alias",
            "EvidenceCallerRoleArn",
            "lambda:InvokeFunction",
            outputs["RetrievalExecutorAliasArn"],
            True,
        ),
        SimulationCase(
            "evidence_caller_other_alias",
            "EvidenceCallerRoleArn",
            "lambda:InvokeFunction",
            outputs["DeletionExecutorAliasArn"],
            False,
        ),
        SimulationCase(
            "evidence_caller_unqualified",
            "EvidenceCallerRoleArn",
            "lambda:InvokeFunction",
            retrieval_function,
            False,
        ),
        SimulationCase(
            "deletion_caller_own_alias",
            "DeletionCallerRoleArn",
            "lambda:InvokeFunction",
            outputs["DeletionExecutorAliasArn"],
            True,
        ),
        SimulationCase(
            "deletion_caller_kms",
            "DeletionCallerRoleArn",
            "kms:Decrypt",
            outputs["EvidenceKeyArn"],
            False,
        ),
        SimulationCase(
            "archive_generate",
            "ArchiveRoleArn",
            "kms:GenerateDataKey",
            outputs["EvidenceKeyArn"],
            True,
            context,
        ),
        SimulationCase(
            "archive_decrypt",
            "ArchiveRoleArn",
            "kms:Decrypt",
            outputs["EvidenceKeyArn"],
            False,
            context,
        ),
        SimulationCase(
            "retrieval_exact_get",
            "RetrievalExecutorRuntimeRoleArn",
            "dynamodb:GetItem",
            wrapped,
            True,
        ),
        SimulationCase(
            "retrieval_scan",
            "RetrievalExecutorRuntimeRoleArn",
            "dynamodb:Scan",
            wrapped,
            False,
        ),
        SimulationCase(
            "retrieval_decrypt",
            "RetrievalExecutorRuntimeRoleArn",
            "kms:Decrypt",
            outputs["EvidenceKeyArn"],
            True,
            context,
        ),
        SimulationCase(
            "retrieval_other_receipt_key",
            "RetrievalExecutorRuntimeRoleArn",
            "kms:Sign",
            outputs["DeletionReceiptKeyArn"],
            False,
        ),
        SimulationCase(
            "retrieval_own_receipt_key",
            "RetrievalExecutorRuntimeRoleArn",
            "kms:Sign",
            outputs["RetrievalReceiptKeyArn"],
            True,
            signing,
        ),
        SimulationCase(
            "deletion_exact_delete",
            "DeletionExecutorRuntimeRoleArn",
            "dynamodb:DeleteItem",
            wrapped,
            True,
            transact,
        ),
        SimulationCase(
            "deletion_scan",
            "DeletionExecutorRuntimeRoleArn",
            "dynamodb:Scan",
            wrapped,
            False,
        ),
        SimulationCase(
            "deletion_decrypt",
            "DeletionExecutorRuntimeRoleArn",
            "kms:Decrypt",
            outputs["EvidenceKeyArn"],
            False,
            context,
        ),
        SimulationCase(
            "deletion_own_receipt_key",
            "DeletionExecutorRuntimeRoleArn",
            "kms:Sign",
            outputs["DeletionReceiptKeyArn"],
            True,
            signing,
        ),
        SimulationCase(
            "finality_no_data",
            "FinalityVerifierRoleArn",
            "dynamodb:GetItem",
            wrapped,
            False,
        ),
        SimulationCase(
            "recovery_no_kms",
            "RecoveryAdministratorRoleArn",
            "kms:Decrypt",
            outputs["EvidenceKeyArn"],
            False,
        ),
        SimulationCase(
            "recovery_restore_source",
            "RecoveryAdministratorRoleArn",
            "dynamodb:RestoreTableToPointInTime",
            wrapped,
            True,
        ),
        SimulationCase(
            "recovery_restore_quarantine_target",
            "RecoveryAdministratorRoleArn",
            "dynamodb:RestoreTableToPointInTime",
            quarantine,
            True,
        ),
        SimulationCase(
            "deployer_update_exact_function",
            "LambdaDeployerRoleArn",
            "lambda:UpdateFunctionCode",
            retrieval_function,
            True,
        ),
        SimulationCase(
            "deployer_no_invoke",
            "LambdaDeployerRoleArn",
            "lambda:InvokeFunction",
            outputs["RetrievalExecutorAliasArn"],
            False,
        ),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--region", choices=("us-east-1",), default="us-east-1")
    parser.add_argument("--report", type=Path)
    return parser


def _render(checks: list[Check], region: str) -> tuple[dict[str, Any], str]:
    report = {
        "object_type": "lucy.security-baseline-v1.2-iam-verification",
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
        contracts = expected_role_contracts(outputs, parameters, args.expected_account_id)
        role_outputs = {
            "archive": "ArchiveRoleArn",
            "evidence_caller": "EvidenceCallerRoleArn",
            "deletion_caller": "DeletionCallerRoleArn",
            "finality": "FinalityVerifierRoleArn",
            "recovery": "RecoveryAdministratorRoleArn",
            "deployer": "LambdaDeployerRoleArn",
            "retrieval_runtime": "RetrievalExecutorRuntimeRoleArn",
            "deletion_runtime": "DeletionExecutorRuntimeRoleArn",
            "cloudtrail_logs": "CloudTrailLogsRoleArn",
        }
        iam = session.client("iam")
        for label, output_name in role_outputs.items():
            arn = outputs[output_name]
            name = _role_name(arn, args.expected_account_id)
            if name is None:
                raise ValueError("invalid role output")
            policy_name, trust, policy = contracts[label]
            checks.extend(
                verify_role(
                    label=label,
                    expected_arn=arn,
                    account=args.expected_account_id,
                    role=iam.get_role(RoleName=name),
                    inline_names=iam.list_role_policies(RoleName=name),
                    attached=iam.list_attached_role_policies(RoleName=name),
                    expected_policy_name=policy_name,
                    actual_policy=iam.get_role_policy(RoleName=name, PolicyName=policy_name),
                    expected_trust=trust,
                    expected_policy=policy,
                )
            )

        kms = session.client("kms")
        key_outputs = {
            "evidence": "EvidenceKeyArn",
            "retrieval_receipt": "RetrievalReceiptKeyArn",
            "deletion_receipt": "DeletionReceiptKeyArn",
        }
        key_contracts = expected_kms_contracts(outputs, parameters, args.expected_account_id)
        for label, output_name in key_outputs.items():
            response = kms.get_key_policy(KeyId=outputs[output_name], PolicyName="default")
            checks.extend(
                verify_kms_policy(
                    label=label,
                    raw=response.get("Policy"),
                    expected=key_contracts[label],
                )
            )

        for case in simulation_cases(outputs, args.expected_account_id):
            response = iam.simulate_principal_policy(
                PolicySourceArn=outputs[case.role],
                ActionNames=[case.action],
                ResourceArns=[case.resource],
                ContextEntries=list(case.context),
            )
            checks.append(verify_simulation(case, response))
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
