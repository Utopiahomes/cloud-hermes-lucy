from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).parents[2]
ACCOUNT = "123456789012"


def _verifier() -> ModuleType:
    path = ROOT / "deploy" / "aws" / "verify_security_v1_2_deployment.py"
    spec = importlib.util.spec_from_file_location("verify_security_v1_2_deployment", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _outputs() -> dict[str, str]:
    return {
        "EvidenceKeyArn": (
            f"arn:aws:kms:us-east-1:{ACCOUNT}:key/11111111-1111-4111-8111-111111111111"
        ),
        "RetrievalReceiptKeyArn": (
            f"arn:aws:kms:us-east-1:{ACCOUNT}:key/22222222-2222-4222-8222-222222222222"
        ),
        "DeletionReceiptKeyArn": (
            f"arn:aws:kms:us-east-1:{ACCOUNT}:key/33333333-3333-4333-8333-333333333333"
        ),
        "WrappedKeyTableName": "lucy-prod-v12-wrapped-keys",
        "RetrievalReceiptTableName": "lucy-prod-v12-retrieval-receipts",
        "DeletionReceiptTableName": "lucy-prod-v12-deletion-receipts",
        "DeletionIntentTableName": "lucy-prod-v12-deletion-execution-intents",
        "DeletionJournalHeadTableName": "lucy-prod-v12-deletion-journal-head",
        "DeletionJournalIntentTableName": "lucy-prod-v12-deletion-journal-intents",
        "RetrievalQuotaTableName": "lucy-prod-v12-retrieval-quotas",
        "DeletionQuotaTableName": "lucy-prod-v12-deletion-quotas",
        "ArchiveRoleArn": f"arn:aws:iam::{ACCOUNT}:role/lucy-prod-v12-render-archive",
        "EvidenceCallerRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/lucy-prod-v12-render-evidence-caller"
        ),
        "DeletionCallerRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/lucy-prod-v12-render-deletion-caller"
        ),
        "FinalityVerifierRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/lucy-prod-v12-finality-verifier"
        ),
        "RecoveryAdministratorRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/lucy-prod-v12-recovery-administrator"
        ),
        "LambdaDeployerRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/lucy-prod-v12-lambda-deployer"
        ),
        "RetrievalExecutorRuntimeRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/lucy-prod-v12-retrieval-runtime"
        ),
        "DeletionExecutorRuntimeRoleArn": (
            f"arn:aws:iam::{ACCOUNT}:role/lucy-prod-v12-deletion-runtime"
        ),
        "RetrievalExecutorAliasArn": (
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:lucy-evidence-executor-v12:production"
        ),
        "RetrievalExecutorVersion": "3",
        "RetrievalExecutorIdentity": "lucy-evidence-executor",
        "DeletionExecutorAliasArn": (
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:lucy-deletion-executor-v12:production"
        ),
        "DeletionExecutorVersion": "4",
        "DeletionExecutorIdentity": "lucy-deletion-executor",
        "ExecutorArtifactCodeSha256": "reviewed-base64-digest",
        "SecurityEnvironment": "production",
        "StorageEpoch": "1",
        "RegistryEpoch": "1",
        "KeyEpoch": "1",
        "ArchiveRecordVersion": "1",
        "ArchiveRegistryId": "archive-registry.production.1",
        "DeletionJournalId": "deletion-journal.production.1",
        "RetrievalLogGroupName": "/aws/lambda/lucy-evidence-executor-v12",
        "DeletionLogGroupName": "/aws/lambda/lucy-deletion-executor-v12",
        "AuditBucketName": "lucy-prod-v12-audit-example",
        "AuditTrailName": "lucy-prod-v12-security-audit",
        "SecurityAlertTopicArn": (
            f"arn:aws:sns:us-east-1:{ACCOUNT}:lucy-prod-v12-security-alerts"
        ),
        "SecurityAdministrationAlertName": "lucy-prod-v12-security-change",
        "RetrievalErrorAlarmName": "lucy-prod-v12-retrieval-errors",
        "DeletionInvocationAlarmName": "lucy-prod-v12-deletion-invocations",
        "RetrievalFailedAlarmName": "lucy-prod-v12-retrieval-failed",
        "DeletionFailedAlarmName": "lucy-prod-v12-deletion-failed",
        "RetrievalIntegrityDeniedAlarmName": "lucy-prod-v12-retrieval-integrity",
        "DeletionIntegrityDeniedAlarmName": "lucy-prod-v12-deletion-integrity",
        "RetrievalReceiptFailureAlarmName": "lucy-prod-v12-retrieval-receipt-failed",
        "DeletionReceiptFailureAlarmName": "lucy-prod-v12-deletion-receipt-failed",
        "RetrievalThrottleAlarmName": "lucy-prod-v12-retrieval-throttled",
        "DeletionThrottleAlarmName": "lucy-prod-v12-deletion-throttled",
        "FinalityQuarantineTablePrefix": "lucy-prod-v12-quarantine-",
    }


def _parameters() -> dict[str, str]:
    return {
        "SecurityEnvironment": "production",
        "ExecutorArtifactCodeSha256": "reviewed-base64-digest",
        "EvidenceDatabaseSessionUser": "lucy_evidence_workflow",
        "DeletionDatabaseSessionUser": "lucy_deletion_workflow",
        "RetrievalMinuteLimit": "5",
        "RetrievalDayLimit": "20",
        "DeletionMinuteLimit": "3",
        "DeletionDayLimit": "10",
    }


def _stack_items(values: dict[str, str], name: str, value: str) -> list[dict[str, str]]:
    return [{name: key, value: item} for key, item in values.items()]


def test_stack_requires_complete_protected_production_with_every_output() -> None:
    module = _verifier()
    stack = {
        "StackStatus": "CREATE_COMPLETE",
        "Outputs": _stack_items(_outputs(), "OutputKey", "OutputValue"),
        "Parameters": _stack_items(_parameters(), "ParameterKey", "ParameterValue"),
    }
    checks, outputs, parameters = module.verify_stack(
        stack, {"EnableTerminationProtection": True}
    )
    assert all(check.passed for check in checks)
    assert outputs["SecurityEnvironment"] == parameters["SecurityEnvironment"] == "production"


def _executor_fixture(kind: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, int]]:
    outputs = _outputs()
    parameters = _parameters()
    retrieval = kind == "retrieval"
    identity = (
        outputs["RetrievalExecutorIdentity"]
        if retrieval
        else outputs["DeletionExecutorIdentity"]
    )
    version = (
        outputs["RetrievalExecutorVersion"]
        if retrieval
        else outputs["DeletionExecutorVersion"]
    )
    receipt_key = (
        outputs["RetrievalReceiptKeyArn"] if retrieval else outputs["DeletionReceiptKeyArn"]
    )
    receipt_table = (
        outputs["RetrievalReceiptTableName"]
        if retrieval
        else outputs["DeletionReceiptTableName"]
    )
    quota_table = (
        outputs["RetrievalQuotaTableName"] if retrieval else outputs["DeletionQuotaTableName"]
    )
    variables: dict[str, str] = {
        "LUCY_EXECUTOR_ENVIRONMENT": "production",
        "LUCY_SECURITY_STORAGE_EPOCH": "1",
        "LUCY_SECURITY_REGISTRY_EPOCH": "1",
        "LUCY_SECURITY_KEY_EPOCH": "1",
        "LUCY_ARCHIVE_RECORD_VERSION": "1",
        "LUCY_EXECUTOR_IDENTITY": identity,
        "LUCY_EXECUTOR_ALIAS_NAME": "production",
        "LUCY_EXPECTED_DATABASE_SESSION_USER": (
            parameters["EvidenceDatabaseSessionUser"]
            if retrieval
            else parameters["DeletionDatabaseSessionUser"]
        ),
        "LUCY_AWS_RECEIPT_SIGNING_KEY_ARN": receipt_key,
        "LUCY_AWS_WRAPPED_KEY_TABLE": outputs["WrappedKeyTableName"],
        "LUCY_AWS_EXECUTOR_RECEIPT_TABLE": receipt_table,
        "LUCY_AWS_EXECUTOR_QUOTA_TABLE": quota_table,
        "LUCY_EXECUTOR_MINUTE_LIMIT": (
            parameters["RetrievalMinuteLimit"]
            if retrieval
            else parameters["DeletionMinuteLimit"]
        ),
        "LUCY_EXECUTOR_DAY_LIMIT": (
            parameters["RetrievalDayLimit"]
            if retrieval
            else parameters["DeletionDayLimit"]
        ),
        "LUCY_POLICY_TRUST_STORE_JSON": json.dumps(
            [
                {
                    "algorithm": "Ed25519",
                    "contract_version": "1",
                    "environment": "production",
                    "issuance_not_after": "2027-09-01T00:00:00Z",
                    "issuer": "lucy-policy",
                    "key_id": "policy-notary.production.1",
                    "object_type": "lucy.verification-key.v1",
                    "public_key_b64": base64.b64encode(b"p" * 32).decode("ascii"),
                    "purpose": "policy_notary",
                    "status": "active",
                    "valid_from": "2026-09-01T00:00:00Z",
                    "verify_not_after": "2027-09-02T00:00:00Z",
                }
            ]
        ),
    }
    if retrieval:
        variables["LUCY_AWS_EVIDENCE_KEY_ARN"] = outputs["EvidenceKeyArn"]
    else:
        variables["LUCY_AWS_DELETION_INTENT_TABLE"] = outputs["DeletionIntentTableName"]
    configuration = {
        "Architectures": ["x86_64"],
        "CodeSha256": outputs["ExecutorArtifactCodeSha256"],
        "Environment": {"Variables": variables},
        "Handler": (
            "lucy.executors.handlers.retrieval_lambda_handler"
            if retrieval
            else "lucy.executors.handlers.deletion_lambda_handler"
        ),
        "LastUpdateStatus": "Successful",
        "Role": f"arn:aws:iam::{ACCOUNT}:role/lucy-prod-v12-runtime",
        "Runtime": "python3.12",
        "State": "Active",
        "Version": version,
    }
    alias_arn = (
        outputs["RetrievalExecutorAliasArn"]
        if retrieval
        else outputs["DeletionExecutorAliasArn"]
    )
    alias = {"AliasArn": alias_arn, "FunctionVersion": version, "RoutingConfig": {}}
    concurrency = {"ReservedConcurrentExecutions": 2 if retrieval else 1}
    return configuration, alias, concurrency


def test_both_executor_kinds_pass_exact_version_environment_and_concurrency() -> None:
    module = _verifier()
    for kind in ("retrieval", "deletion"):
        configuration, alias, concurrency = _executor_fixture(kind)
        title = "Retrieval" if kind == "retrieval" else "Deletion"
        checks = module.verify_executor(
            kind=kind,
            alias_arn=_outputs()[f"{title}ExecutorAliasArn"],
            version=_outputs()[f"{title}ExecutorVersion"],
            configuration=configuration,
            alias=alias,
            concurrency=concurrency,
            outputs=_outputs(),
            parameters=_parameters(),
            expected_account_id=ACCOUNT,
        )
        assert all(check.passed for check in checks)


def test_executor_rejects_weighted_alias_and_static_credentials() -> None:
    module = _verifier()
    configuration, alias, concurrency = _executor_fixture("retrieval")
    alias["RoutingConfig"] = {"AdditionalVersionWeights": {"2": 0.1}}
    configuration["Environment"]["Variables"]["AWS_ACCESS_KEY_ID"] = "forbidden"
    checks = module.verify_executor(
        kind="retrieval",
        alias_arn=_outputs()["RetrievalExecutorAliasArn"],
        version=_outputs()["RetrievalExecutorVersion"],
        configuration=configuration,
        alias=alias,
        concurrency=concurrency,
        outputs=_outputs(),
        parameters=_parameters(),
        expected_account_id=ACCOUNT,
    )
    failed = {check.name for check in checks if not check.passed}
    assert {
        "lambda.retrieval.alias_version",
        "lambda.retrieval.environment",
        "lambda.retrieval.no_static_credentials",
    } <= failed


def test_kms_keys_are_enabled_and_purpose_separated() -> None:
    module = _verifier()
    evidence_arn = _outputs()["EvidenceKeyArn"]
    evidence = {
        "Arn": evidence_arn,
        "Enabled": True,
        "KeyState": "Enabled",
        "KeyManager": "CUSTOMER",
        "Origin": "AWS_KMS",
        "MultiRegion": False,
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeySpec": "SYMMETRIC_DEFAULT",
    }
    receipt_arn = _outputs()["RetrievalReceiptKeyArn"]
    receipt = {
        "Arn": receipt_arn,
        "Enabled": True,
        "KeyState": "Enabled",
        "KeyManager": "CUSTOMER",
        "Origin": "AWS_KMS",
        "MultiRegion": False,
        "KeyUsage": "SIGN_VERIFY",
        "KeySpec": "ECC_NIST_P256",
    }
    assert all(
        check.passed
        for check in module.verify_kms_key(
            evidence,
            purpose="evidence",
            expected_arn=evidence_arn,
            expected_account_id=ACCOUNT,
            rotation={"KeyRotationEnabled": True},
        )
    )
    assert all(
        check.passed
        for check in module.verify_kms_key(
            receipt,
            purpose="retrieval_receipt",
            expected_arn=receipt_arn,
            expected_account_id=ACCOUNT,
        )
    )


def _table(protected: bool, name: str) -> dict[str, Any]:
    keys = {
        "wrapped_keys": "key_ref",
        "retrieval_quota": "quota_key",
    }
    key = keys[name]
    return {
        "AttributeDefinitions": [{"AttributeName": key, "AttributeType": "S"}],
        "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
        "DeletionProtectionEnabled": protected,
        "KeySchema": [{"AttributeName": key, "KeyType": "HASH"}],
        "SSEDescription": {"Status": "ENABLED"},
        "TableStatus": "ACTIVE",
    }


def test_wrapped_key_table_requires_exact_30_day_pitr() -> None:
    module = _verifier()
    checks = module.verify_table(
        name="wrapped_keys",
        table=_table(True, "wrapped_keys"),
        backups={
            "ContinuousBackupsDescription": {
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "ENABLED",
                    "RecoveryPeriodInDays": 30,
                }
            }
        },
        ttl=None,
        protected=True,
        recovery_days=30,
    )
    assert all(check.passed for check in checks)


def test_quota_table_requires_expires_at_ttl_without_deletion_protection() -> None:
    module = _verifier()
    checks = module.verify_table(
        name="retrieval_quota",
        table=_table(False, "retrieval_quota"),
        backups=None,
        ttl={
            "TimeToLiveDescription": {
                "TimeToLiveStatus": "ENABLED",
                "AttributeName": "expires_at",
            }
        },
        protected=False,
        ttl_required=True,
    )
    assert all(check.passed for check in checks)


def test_policy_trust_store_rejects_secret_and_invalid_windows() -> None:
    module = _verifier()
    configuration, _, _ = _executor_fixture("retrieval")
    raw = configuration["Environment"]["Variables"]["LUCY_POLICY_TRUST_STORE_JSON"]
    valid = json.loads(raw)

    secret = [{**valid[0], "private_key_b64": "forbidden"}]
    assert not module.verify_policy_trust_store(json.dumps(secret))

    invalid_window = [
        {
            **valid[0],
            "valid_from": valid[0]["issuance_not_after"],
        }
    ]
    assert not module.verify_policy_trust_store(json.dumps(invalid_window))

    duplicate = [valid[0], {**valid[0], "status": "retiring"}]
    assert not module.verify_policy_trust_store(json.dumps(duplicate))
