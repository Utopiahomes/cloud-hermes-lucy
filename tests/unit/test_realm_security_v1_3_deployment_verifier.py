from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).parents[2]
ACCOUNT = "123456789012"


def _module(name: str) -> ModuleType:
    path = ROOT / "deploy" / "aws" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _trust_store() -> str:
    return json.dumps(
        [
            {
                "algorithm": "Ed25519",
                "contract_version": "1",
                "environment": "production",
                "issuance_not_after": "2027-09-01T00:00:00Z",
                "issuer": "lucy-policy",
                "key_id": "policy-notary.production.1",
                "object_type": "lucy.v13-verification-key.v1",
                "public_key_b64": base64.b64encode(b"p" * 32).decode(),
                "purpose": "policy_notary_v13",
                "status": "active",
                "valid_from": "2026-09-01T00:00:00Z",
                "verify_not_after": "2027-09-02T00:00:00Z",
            }
        ]
    )


def _parameters() -> dict[str, str]:
    return {
        "SecurityEnvironment": "production",
        "ExecutorArtifactCodeSha256": "reviewed-base64-digest",
        "PolicyTrustStoreSha256": hashlib.sha256(_trust_store().encode()).hexdigest(),
        "RealmSlug": "utopia",
        "TenantAccountUuid": "11111111-1111-4111-8111-111111111111",
        "NodeId": "22222222-2222-4222-8222-222222222222",
        "NodeTenureId": "33333333-3333-4333-8333-333333333333",
        "TenureEpoch": "1",
        "SecurityRealmId": "44444444-4444-4444-8444-444444444444",
        "RealmWorkspaceUuid": "55555555-5555-4555-8555-555555555555",
        "DeploymentId": "66666666-6666-4666-8666-666666666666",
        "RealmBindingGeneration": "1",
        "NodeAuthzEpoch": "1",
        "ResourceNamespace": "lucy-utopia-v13",
        "AuthorityRecoveryJournalTableArn": (
            f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/"
            "lucy-utopia-v13-authority-journal"
        ),
        "CostRecoveryJournalTableArn": (
            f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/"
            "lucy-utopia-v13-cost-journal"
        ),
        "StorageEpoch": "1",
        "RetrievalMinuteLimit": "5",
        "RetrievalDayLimit": "20",
        "DeletionMinuteLimit": "3",
        "DeletionDayLimit": "10",
    }


def _outputs(module: ModuleType) -> dict[str, str]:
    outputs = {name: "present" for name in module._REQUIRED_OUTPUTS}
    parameters = _parameters()
    outputs.update({name: parameters[name] for name in module._REALM_OUTPUT_PARAMETERS})
    outputs.update(
        {
            "SecurityEnvironment": "production",
            "ExecutorArtifactCodeSha256": parameters["ExecutorArtifactCodeSha256"],
            "PolicyTrustStoreSha256": parameters["PolicyTrustStoreSha256"],
            "ArchiveRecordVersion": "1",
            "EvidenceKeyArn": (
                f"arn:aws:kms:us-east-1:{ACCOUNT}:"
                "key/11111111-1111-4111-8111-111111111111"
            ),
            "RetrievalReceiptKeyArn": (
                f"arn:aws:kms:us-east-1:{ACCOUNT}:"
                "key/22222222-2222-4222-8222-222222222222"
            ),
            "DeletionReceiptKeyArn": (
                f"arn:aws:kms:us-east-1:{ACCOUNT}:"
                "key/33333333-3333-4333-8333-333333333333"
            ),
            "EvidenceCallerRoleArn": f"arn:aws:iam::{ACCOUNT}:role/utopia-evidence",
            "DeletionCallerRoleArn": f"arn:aws:iam::{ACCOUNT}:role/utopia-deletion",
            "RetrievalExecutorAliasArn": (
                f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:"
                "utopia-evidence-executor-v13:realm-v13"
            ),
            "RetrievalExecutorVersion": "3",
            "RetrievalExecutorIdentity": "lucy-utopia-evidence-executor",
            "DeletionExecutorAliasArn": (
                f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:"
                "utopia-deletion-executor-v13:realm-v13"
            ),
            "DeletionExecutorVersion": "4",
            "DeletionExecutorIdentity": "lucy-utopia-deletion-executor",
        }
    )
    return outputs


def _items(values: dict[str, str], key_name: str, value_name: str) -> list[dict[str, str]]:
    return [{key_name: key, value_name: value} for key, value in values.items()]


def test_realm_stack_requires_exact_protected_identity() -> None:
    module = _module("verify_realm_security_v1_3_deployment.py")
    stack = {
        "StackStatus": "CREATE_COMPLETE",
        "EnableTerminationProtection": True,
        "Outputs": _items(_outputs(module), "OutputKey", "OutputValue"),
        "Parameters": _items(_parameters(), "ParameterKey", "ParameterValue"),
    }
    checks, _, _ = module.verify_realm_stack(stack, expected_account_id=ACCOUNT)
    assert all(check.passed for check in checks)

    stack["Outputs"] = _items(
        {**_outputs(module), "SecurityRealmId": "77777777-7777-4777-8777-777777777777"},
        "OutputKey",
        "OutputValue",
    )
    checks, _, _ = module.verify_realm_stack(stack, expected_account_id=ACCOUNT)
    assert "cloudformation.realm_binding" in {
        check.name for check in checks if not check.passed
    }

    stack["Outputs"] = _items(_outputs(module), "OutputKey", "OutputValue")
    stack["Parameters"] = _items(
        {
            **_parameters(),
            "CostRecoveryJournalTableArn": (
                f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/wrong-cost-journal"
            ),
        },
        "ParameterKey",
        "ParameterValue",
    )
    checks, _, _ = module.verify_realm_stack(stack, expected_account_id=ACCOUNT)
    assert "cloudformation.recovery_journal_audit_bindings" in {
        check.name for check in checks if not check.passed
    }


def test_recovery_audit_selectors_require_both_exact_tables() -> None:
    module = _module("verify_realm_security_v1_3_deployment.py")
    parameters = _parameters()
    values = [
        parameters["AuthorityRecoveryJournalTableArn"],
        parameters["CostRecoveryJournalTableArn"],
    ]
    response = {
        "EventSelectors": [
            {
                "DataResources": [
                    {"Type": "AWS::DynamoDB::Table", "Values": values}
                ]
            }
        ]
    }
    assert all(
        check.passed
        for check in module.verify_recovery_audit_selectors(response, parameters)
    )
    response["EventSelectors"][0]["DataResources"][0]["Values"] = values[:1]
    assert not all(
        check.passed
        for check in module.verify_recovery_audit_selectors(response, parameters)
    )


def _executor(
    module: ModuleType, kind: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, int]]:
    outputs, parameters = _outputs(module), _parameters()
    title = "Retrieval" if kind == "retrieval" else "Deletion"
    caller = "EvidenceCallerRoleArn" if kind == "retrieval" else "DeletionCallerRoleArn"
    variables = {
        "LUCY_EXECUTOR_ENVIRONMENT": "production",
        "LUCY_V13_TARGET_SCOPE_JSON": json.dumps(module._expected_scope(parameters)),
        "LUCY_V13_EXECUTION_BINDING_JSON": json.dumps(module._expected_binding(parameters)),
        "LUCY_V13_WORKSPACE_ID": parameters["RealmWorkspaceUuid"],
        "LUCY_V13_CALLER_IDENTITY": outputs[caller],
        "LUCY_ARCHIVE_RECORD_VERSION": "1",
        "LUCY_EXECUTOR_IDENTITY": outputs[f"{title}ExecutorIdentity"],
        "LUCY_EXECUTOR_ALIAS_NAME": "realm-v13",
        "LUCY_AWS_RECEIPT_SIGNING_KEY_ARN": outputs[f"{title}ReceiptKeyArn"],
        "LUCY_AWS_WRAPPED_KEY_TABLE": outputs["WrappedKeyTableName"],
        "LUCY_AWS_EXECUTOR_RECEIPT_TABLE": outputs[f"{title}ReceiptTableName"],
        "LUCY_AWS_EXECUTOR_QUOTA_TABLE": outputs[f"{title}QuotaTableName"],
        "LUCY_EXECUTOR_MINUTE_LIMIT": parameters[f"{title}MinuteLimit"],
        "LUCY_EXECUTOR_DAY_LIMIT": parameters[f"{title}DayLimit"],
        "LUCY_POLICY_TRUST_STORE_JSON": _trust_store(),
    }
    if kind == "retrieval":
        variables["LUCY_AWS_EVIDENCE_KEY_ARN"] = outputs["EvidenceKeyArn"]
    else:
        variables["LUCY_AWS_DELETION_INTENT_TABLE"] = outputs["DeletionIntentTableName"]
        variables["LUCY_ARCHIVE_REGISTRY_ID"] = outputs["ArchiveRegistryId"]
    version = outputs[f"{title}ExecutorVersion"]
    alias_arn = outputs[f"{title}ExecutorAliasArn"]
    configuration = {
        "Architectures": ["x86_64"],
        "CodeSha256": outputs["ExecutorArtifactCodeSha256"],
        "Environment": {"Variables": variables},
        "Handler": (
            "lucy.executors.handlers_v1_3.realm_retrieval_lambda_handler"
            if kind == "retrieval"
            else "lucy.executors.handlers_v1_3.realm_deletion_lambda_handler"
        ),
        "LastUpdateStatus": "Successful",
        "Role": f"arn:aws:iam::{ACCOUNT}:role/utopia-{kind}-runtime",
        "Runtime": "python3.12",
        "State": "Active",
        "Version": version,
    }
    return (
        configuration,
        {"AliasArn": alias_arn, "FunctionVersion": version, "RoutingConfig": {}},
        {"ReservedConcurrentExecutions": 2 if kind == "retrieval" else 1},
    )


def test_realm_executors_bind_exact_scope_and_reject_static_credentials() -> None:
    module = _module("verify_realm_security_v1_3_deployment.py")
    for kind in ("retrieval", "deletion"):
        configuration, alias, concurrency = _executor(module, kind)
        title = "Retrieval" if kind == "retrieval" else "Deletion"
        checks = module.verify_realm_executor(
            kind=kind,
            alias_arn=_outputs(module)[f"{title}ExecutorAliasArn"],
            version=_outputs(module)[f"{title}ExecutorVersion"],
            configuration=configuration,
            alias=alias,
            concurrency=concurrency,
            outputs=_outputs(module),
            parameters=_parameters(),
            expected_account_id=ACCOUNT,
        )
        assert all(check.passed for check in checks)

    configuration, alias, concurrency = _executor(module, "retrieval")
    configuration["Environment"]["Variables"]["AWS_ACCESS_KEY_ID"] = "forbidden"
    configuration["Environment"]["Variables"]["LUCY_V13_TARGET_SCOPE_JSON"] = "{}"
    checks = module.verify_realm_executor(
        kind="retrieval",
        alias_arn=_outputs(module)["RetrievalExecutorAliasArn"],
        version=_outputs(module)["RetrievalExecutorVersion"],
        configuration=configuration,
        alias=alias,
        concurrency=concurrency,
        outputs=_outputs(module),
        parameters=_parameters(),
        expected_account_id=ACCOUNT,
    )
    failed = {check.name for check in checks if not check.passed}
    assert {"lambda.retrieval.environment", "lambda.retrieval.no_static_credentials"} <= failed


def test_v13_trust_store_rejects_the_v12_contract() -> None:
    module = _module("verify_realm_security_v1_3_deployment.py")
    payload = json.loads(_trust_store())
    payload[0]["object_type"] = "lucy.verification-key.v1"
    payload[0]["purpose"] = "policy_notary"
    assert not module.verify_v13_policy_trust_store(json.dumps(payload))
