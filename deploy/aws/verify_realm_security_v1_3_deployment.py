"""Read-only deployed-state verification for one V1.3 realm security stamp."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any
from uuid import UUID

import boto3  # type: ignore[import-untyped]
from pydantic import ValidationError

from deploy.aws.verify_security_v1_2_deployment import (
    _ACCOUNT_ID,
    _REQUIRED_OUTPUTS,
    Check,
    _lambda_arn_parts,
    verify_caller,
    verify_kms_key,
    verify_stack,
    verify_table,
)
from lucy.contracts.security_v1_2 import DeploymentEnvironment
from lucy.contracts.security_v1_3 import (
    V13SigningKeyPurpose,
    V13VerificationKeyStatus,
    V13VerificationKeyV1,
)

_REALM_OUTPUT_PARAMETERS = {
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
}
_UUID_PARAMETERS = _REALM_OUTPUT_PARAMETERS - {
    "RealmSlug",
    "TenureEpoch",
    "RealmBindingGeneration",
    "NodeAuthzEpoch",
}
_STATIC_CREDENTIALS = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
}


def verify_realm_stack(
    stack: Mapping[str, Any], *, expected_account_id: str
) -> tuple[list[Check], dict[str, str], dict[str, str]]:
    checks, outputs, parameters = verify_stack(stack)
    exact_realm_binding = all(
        parameters.get(name) == outputs.get(name) for name in _REALM_OUTPUT_PARAMETERS
    )
    valid_uuids = True
    try:
        for name in _UUID_PARAMETERS:
            UUID(parameters[name])
    except (KeyError, ValueError):
        valid_uuids = False
    positive_epochs = all(
        parameters.get(name, "").isdigit() and int(parameters[name]) > 0
        for name in ("TenureEpoch", "RealmBindingGeneration", "NodeAuthzEpoch")
    )
    namespace = parameters.get("ResourceNamespace", "")
    expected_journals = {
        "AuthorityRecoveryJournalTableArn": (
            f"arn:aws:dynamodb:us-east-1:{expected_account_id}:"
            f"table/{namespace}-authority-journal"
        ),
        "CostRecoveryJournalTableArn": (
            f"arn:aws:dynamodb:us-east-1:{expected_account_id}:"
            f"table/{namespace}-cost-journal"
        ),
    }
    checks.extend(
        (
            Check(
                "cloudformation.realm_binding",
                exact_realm_binding,
                "realm identity parameters and outputs must match exactly",
            ),
            Check(
                "cloudformation.realm_identity",
                valid_uuids
                and positive_epochs
                and re.fullmatch(r"[a-z][a-z0-9]{0,30}", parameters.get("RealmSlug", ""))
                is not None,
                "realm UUIDs, epochs, generations, and slug must be valid",
            ),
            Check(
                "cloudformation.realm_outputs",
                outputs.keys() >= (_REQUIRED_OUTPUTS | _REALM_OUTPUT_PARAMETERS),
                "every reviewed V1.3 realm output must exist",
            ),
            Check(
                "cloudformation.recovery_journal_audit_bindings",
                all(parameters.get(name) == arn for name, arn in expected_journals.items()),
                "recovery journal audit bindings must name this realm's exact tables",
            ),
        )
    )
    return checks, outputs, parameters


def verify_recovery_audit_selectors(
    response: Mapping[str, Any], parameters: Mapping[str, str]
) -> list[Check]:
    table_values: set[str] = set()
    selectors = response.get("EventSelectors")
    if isinstance(selectors, Sequence) and not isinstance(selectors, (str, bytes)):
        for selector in selectors:
            if not isinstance(selector, Mapping):
                continue
            resources = selector.get("DataResources")
            if not isinstance(resources, Sequence) or isinstance(resources, (str, bytes)):
                continue
            for resource in resources:
                if (
                    not isinstance(resource, Mapping)
                    or resource.get("Type") != "AWS::DynamoDB::Table"
                ):
                    continue
                values = resource.get("Values")
                if isinstance(values, Sequence) and not isinstance(values, (str, bytes)):
                    table_values.update(value for value in values if isinstance(value, str))
    expected = {
        parameters.get("AuthorityRecoveryJournalTableArn"),
        parameters.get("CostRecoveryJournalTableArn"),
    }
    return [
        Check(
            "cloudtrail.recovery_journal_data_events",
            None not in expected and expected <= table_values,
            "CloudTrail must select both exact independent recovery journal tables",
        )
    ]


def _expected_scope(parameters: Mapping[str, str]) -> dict[str, object]:
    return {
        "tenant_account_id": parameters.get("TenantAccountUuid"),
        "node_id": parameters.get("NodeId"),
        "node_tenure_id": parameters.get("NodeTenureId"),
        "tenure_epoch": int(parameters.get("TenureEpoch", "0")),
        "security_realm_id": parameters.get("SecurityRealmId"),
        "storage_epoch": int(parameters.get("StorageEpoch", "0")),
    }


def _expected_binding(parameters: Mapping[str, str]) -> dict[str, object]:
    return {
        "deployment_id": parameters.get("DeploymentId"),
        "active_realm_id": parameters.get("SecurityRealmId"),
        "active_storage_epoch": int(parameters.get("StorageEpoch", "0")),
        "realm_binding_generation": int(parameters.get("RealmBindingGeneration", "0")),
        "node_authz_epoch": int(parameters.get("NodeAuthzEpoch", "0")),
    }


def _json_equals(raw: object, expected: object) -> bool:
    if not isinstance(raw, str):
        return False
    try:
        value: object = json.loads(raw)
        return value == expected
    except json.JSONDecodeError:
        return False


def verify_v13_policy_trust_store(raw: object) -> bool:
    if not isinstance(raw, str):
        return False
    try:
        payload = json.loads(raw)
        if not isinstance(payload, list) or not payload:
            return False
        keys = tuple(V13VerificationKeyV1.model_validate(item) for item in payload)
    except (json.JSONDecodeError, ValidationError):
        return False
    return (
        len({key.key_id for key in keys}) == len(keys)
        and all(
            key.environment == DeploymentEnvironment.PRODUCTION
            and key.purpose == V13SigningKeyPurpose.POLICY_NOTARY
            for key in keys
        )
        and sum(key.status == V13VerificationKeyStatus.ACTIVE for key in keys) == 1
    )


def verify_realm_executor(
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
    title = "Retrieval" if kind == "retrieval" else "Deletion"
    caller_output = "EvidenceCallerRoleArn" if kind == "retrieval" else "DeletionCallerRoleArn"
    parts = _lambda_arn_parts(alias_arn)
    environment = configuration.get("Environment")
    variables = environment.get("Variables") if isinstance(environment, Mapping) else None
    if not isinstance(variables, Mapping):
        variables = {}
    expected_variables = {
        "LUCY_EXECUTOR_ENVIRONMENT": "production",
        "LUCY_V13_WORKSPACE_ID": parameters.get("RealmWorkspaceUuid"),
        "LUCY_V13_CALLER_IDENTITY": outputs.get(caller_output),
        "LUCY_ARCHIVE_RECORD_VERSION": outputs.get("ArchiveRecordVersion"),
        "LUCY_EXECUTOR_IDENTITY": outputs.get(f"{title}ExecutorIdentity"),
        "LUCY_EXECUTOR_ALIAS_NAME": "realm-v13",
        "LUCY_AWS_RECEIPT_SIGNING_KEY_ARN": outputs.get(f"{title}ReceiptKeyArn"),
        "LUCY_AWS_WRAPPED_KEY_TABLE": outputs.get("WrappedKeyTableName"),
        "LUCY_AWS_EXECUTOR_RECEIPT_TABLE": outputs.get(f"{title}ReceiptTableName"),
        "LUCY_AWS_EXECUTOR_QUOTA_TABLE": outputs.get(f"{title}QuotaTableName"),
        "LUCY_EXECUTOR_MINUTE_LIMIT": parameters.get(f"{title}MinuteLimit"),
        "LUCY_EXECUTOR_DAY_LIMIT": parameters.get(f"{title}DayLimit"),
    }
    if kind == "retrieval":
        expected_variables["LUCY_AWS_EVIDENCE_KEY_ARN"] = outputs.get("EvidenceKeyArn")
        expected_handler = "lucy.executors.handlers_v1_3.realm_retrieval_lambda_handler"
        expected_concurrency = 2
    else:
        expected_variables["LUCY_AWS_DELETION_INTENT_TABLE"] = outputs.get(
            "DeletionIntentTableName"
        )
        expected_variables["LUCY_ARCHIVE_REGISTRY_ID"] = outputs.get("ArchiveRegistryId")
        expected_handler = "lucy.executors.handlers_v1_3.realm_deletion_lambda_handler"
        expected_concurrency = 1
    trust_store = variables.get("LUCY_POLICY_TRUST_STORE_JSON")
    expected_names = {
        *expected_variables,
        "LUCY_V13_TARGET_SCOPE_JSON",
        "LUCY_V13_EXECUTION_BINDING_JSON",
        "LUCY_POLICY_TRUST_STORE_JSON",
    }
    routing = alias.get("RoutingConfig")
    no_weights = not isinstance(routing, Mapping) or not routing.get("AdditionalVersionWeights")
    role = configuration.get("Role")
    return [
        Check(
            f"lambda.{kind}.qualified_alias",
            parts is not None
            and parts[1] == "realm-v13"
            and alias.get("AliasArn") == alias_arn
            and alias.get("FunctionVersion") == version
            and version.isdigit()
            and version != "0"
            and no_weights,
            "realm executor alias must target one published numeric version",
        ),
        Check(
            f"lambda.{kind}.artifact",
            configuration.get("Version") == version
            and configuration.get("CodeSha256") == outputs.get("ExecutorArtifactCodeSha256"),
            "published executor must match the reviewed artifact digest",
        ),
        Check(
            f"lambda.{kind}.runtime",
            configuration.get("Runtime") == "python3.12"
            and configuration.get("Architectures") == ["x86_64"]
            and configuration.get("Handler") == expected_handler
            and configuration.get("State") == "Active"
            and configuration.get("LastUpdateStatus") == "Successful",
            "realm executor runtime and handler must be exact and healthy",
        ),
        Check(
            f"lambda.{kind}.role_account",
            isinstance(role, str)
            and re.fullmatch(
                rf"arn:aws:iam::{re.escape(expected_account_id)}:role/[A-Za-z0-9_+=,.@/-]+",
                role,
            )
            is not None,
            "realm executor role must belong to the target account",
        ),
        Check(
            f"lambda.{kind}.concurrency",
            concurrency.get("ReservedConcurrentExecutions") == expected_concurrency,
            "realm executor concurrency must match the reviewed limit",
        ),
        Check(
            f"lambda.{kind}.environment",
            set(variables) == expected_names
            and all(variables.get(name) == value for name, value in expected_variables.items())
            and _json_equals(
                variables.get("LUCY_V13_TARGET_SCOPE_JSON"), _expected_scope(parameters)
            )
            and _json_equals(
                variables.get("LUCY_V13_EXECUTION_BINDING_JSON"), _expected_binding(parameters)
            ),
            "deployment environment must contain only the exact realm bindings",
        ),
        Check(
            f"lambda.{kind}.policy_trust",
            verify_v13_policy_trust_store(trust_store)
            and isinstance(trust_store, str)
            and hashlib.sha256(trust_store.encode()).hexdigest()
            == outputs.get("PolicyTrustStoreSha256"),
            "policy trust inventory must be public-only and digest-bound",
        ),
        Check(
            f"lambda.{kind}.no_static_credentials",
            _STATIC_CREDENTIALS.isdisjoint(variables),
            "realm executor environment must not contain static AWS credentials",
        ),
    ]


def _render(checks: list[Check], region: str) -> tuple[dict[str, Any], str]:
    report = {
        "object_type": "lucy.realm-security-v1.3-deployment-verification",
        "region": region,
        "passed": all(check.passed for check in checks),
        "checks": [asdict(check) for check in checks],
    }
    return report, json.dumps(report, indent=2, sort_keys=True) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--profile", default="lucy-dev")
    parser.add_argument("--region", choices=("us-east-1",), default="us-east-1")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    checks: list[Check] = []
    try:
        if _ACCOUNT_ID.fullmatch(args.expected_account_id) is None:
            raise ValueError("expected AWS account ID must contain exactly 12 digits")
        if args.report is not None and not args.report.parent.is_dir():
            raise FileNotFoundError("report directory does not exist")
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        checks.extend(
            verify_caller(
                session.client("sts").get_caller_identity(), args.expected_account_id
            )
        )
        cloudformation = session.client("cloudformation")
        stack = cloudformation.describe_stacks(StackName=args.stack_name)["Stacks"][0]
        stack_checks, outputs, parameters = verify_realm_stack(
            stack, expected_account_id=args.expected_account_id
        )
        checks.extend(stack_checks)
        checks.extend(
            verify_recovery_audit_selectors(
                session.client("cloudtrail").get_event_selectors(
                    TrailName=outputs["AuditTrailName"]
                ),
                parameters,
            )
        )

        lambdas = session.client("lambda")
        for kind in ("retrieval", "deletion"):
            title = "Retrieval" if kind == "retrieval" else "Deletion"
            alias_arn, version = outputs[f"{title}ExecutorAliasArn"], outputs[
                f"{title}ExecutorVersion"
            ]
            parts = _lambda_arn_parts(alias_arn)
            if parts is None:
                checks.append(Check(f"lambda.{kind}.collect", False, "invalid alias output"))
                continue
            function_name, alias_name = parts
            checks.extend(
                verify_realm_executor(
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
            checks.extend(
                verify_kms_key(
                    kms.describe_key(KeyId=arn)["KeyMetadata"],
                    purpose=purpose,
                    expected_arn=arn,
                    expected_account_id=args.expected_account_id,
                    rotation=(
                        kms.get_key_rotation_status(KeyId=arn)
                        if purpose == "evidence"
                        else None
                    ),
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
        for name, output, protected, pitr, recovery_days, ttl_required in table_specs:
            table_name = outputs[output]
            checks.extend(
                verify_table(
                    name=name,
                    table=dynamodb.describe_table(TableName=table_name)["Table"],
                    backups=(
                        dynamodb.describe_continuous_backups(TableName=table_name)
                        if pitr
                        else None
                    ),
                    ttl=(
                        dynamodb.describe_time_to_live(TableName=table_name)
                        if ttl_required
                        else None
                    ),
                    protected=protected,
                    recovery_days=recovery_days,
                    ttl_required=ttl_required,
                )
            )
    except Exception as exc:
        checks.append(Check("verification.execution", False, f"failed: {type(exc).__name__}"))

    report, rendered = _render(checks, args.region)
    if args.report is not None:
        try:
            with args.report.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(rendered)
        except OSError as exc:
            checks.append(Check("verification.report", False, f"failed: {type(exc).__name__}"))
            report, rendered = _render(checks, args.region)
    sys.stdout.write(rendered)
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
