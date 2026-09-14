from __future__ import annotations

from copy import deepcopy
from typing import Any
from uuid import UUID

import pytest

from deploy.aws.build_realm_security_stamp_v1_3 import build_stamp

ACCOUNT = "123456789012"
IDS = [UUID(int=value) for value in range(1, 19)]


def _binding() -> dict[str, object]:
    return {
        "realm_slug": "utopia",
        "content_scope_id": str(IDS[0]),
        "tenant_account_id": str(IDS[1]),
        "node_id": str(IDS[2]),
        "node_tenure_id": str(IDS[3]),
        "tenure_epoch": 1,
        "security_realm_id": str(IDS[4]),
        "storage_epoch": 1,
        "realm_binding_id": str(IDS[5]),
        "workspace_id": str(IDS[6]),
        "deployment_id": str(IDS[7]),
        "service_binding_id": str(IDS[8]),
        "routine_login": "lucy_utopia_routine",
        "routine_principal_id": str(IDS[9]),
        "archive_actor_binding_id": str(IDS[10]),
        "policy_login": "lucy_utopia_policy",
        "policy_principal_id": str(IDS[11]),
        "policy_actor_binding_id": str(IDS[12]),
        "workflow_login": "lucy_utopia_workflow",
        "workflow_principal_id": str(IDS[13]),
        "workflow_actor_binding_id": str(IDS[14]),
        "finality_login": "lucy_utopia_finality",
        "finality_principal_id": str(IDS[15]),
        "finality_actor_binding_id": str(IDS[16]),
        "binding_generation": 1,
        "node_authz_epoch": 1,
        "policy_version": 1,
        "retrieval_executor_binding_id": str(IDS[17]),
        "deletion_executor_binding_id": "00000000-0000-0000-0000-000000000019",
    }


def _realm_values() -> dict[str, str]:
    binding = _binding()
    return {
        "RealmSlug": "utopia",
        "TenantAccountUuid": str(binding["tenant_account_id"]),
        "NodeId": str(binding["node_id"]),
        "NodeTenureId": str(binding["node_tenure_id"]),
        "TenureEpoch": str(binding["tenure_epoch"]),
        "SecurityRealmId": str(binding["security_realm_id"]),
        "RealmWorkspaceUuid": str(binding["workspace_id"]),
        "DeploymentId": str(binding["deployment_id"]),
        "RealmBindingGeneration": str(binding["binding_generation"]),
        "NodeAuthzEpoch": str(binding["node_authz_epoch"]),
        "StorageEpoch": str(binding["storage_epoch"]),
    }


def _stack() -> dict[str, Any]:
    values = _realm_values()
    values.update(
        {
            "EvidenceCallerRoleArn": f"arn:aws:iam::{ACCOUNT}:role/lucy-utopia-evidence",
            "DeletionCallerRoleArn": f"arn:aws:iam::{ACCOUNT}:role/lucy-utopia-deletion",
            "RetrievalExecutorAliasArn": (
                f"arn:aws:lambda:us-east-1:{ACCOUNT}:"
                "function:lucy-utopia-evidence-v13:realm-v13"
            ),
            "RetrievalExecutorVersion": "3",
            "RetrievalExecutorIdentity": "lucy-utopia-evidence-executor",
            "RetrievalReceiptKeyArn": (
                f"arn:aws:kms:us-east-1:{ACCOUNT}:"
                "key/11111111-1111-4111-8111-111111111111"
            ),
            "DeletionExecutorAliasArn": (
                f"arn:aws:lambda:us-east-1:{ACCOUNT}:"
                "function:lucy-utopia-deletion-v13:realm-v13"
            ),
            "DeletionExecutorVersion": "4",
            "DeletionExecutorIdentity": "lucy-utopia-deletion-executor",
            "DeletionReceiptKeyArn": (
                f"arn:aws:kms:us-east-1:{ACCOUNT}:"
                "key/22222222-2222-4222-8222-222222222222"
            ),
        }
    )
    return {
        "Stacks": [
            {
                "StackStatus": "CREATE_COMPLETE",
                "EnableTerminationProtection": True,
                "Parameters": [
                    {"ParameterKey": key, "ParameterValue": value}
                    for key, value in _realm_values().items()
                ],
                "Outputs": [
                    {"OutputKey": key, "OutputValue": value}
                    for key, value in values.items()
                ],
            }
        ]
    }


def test_builder_combines_stack_evidence_with_postgres_binding() -> None:
    stamp = build_stamp(_stack(), _binding(), expected_account_id=ACCOUNT)
    assert stamp.realm_slug == "utopia"
    assert stamp.security_realm_id == IDS[4]
    assert stamp.retrieval_executor.executor_version == 3
    assert stamp.deletion_executor.executor_version == 4
    assert stamp.retrieval_executor.caller_identity.endswith("lucy-utopia-evidence")
    assert len(stamp.digest_hex()) == 64


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (
            lambda stack: stack["Stacks"][0].update(
                {"StackStatus": "UPDATE_ROLLBACK_COMPLETE"}
            ),
            "not completely deployed",
        ),
        (
            lambda stack: stack["Stacks"][0].update({"EnableTerminationProtection": False}),
            "termination protection",
        ),
        (
            lambda stack: stack["Stacks"][0]["Outputs"][5].update(
                {"OutputValue": str(UUID(int=99))}
            ),
            "differs",
        ),
    ),
)
def test_builder_fails_closed_on_untrusted_stack_state(
    mutation: Any, message: str
) -> None:
    stack = deepcopy(_stack())
    mutation(stack)
    with pytest.raises(ValueError, match=message):
        build_stamp(stack, _binding(), expected_account_id=ACCOUNT)


def test_builder_rejects_unknown_binding_fields_and_cross_account_arns() -> None:
    binding = _binding()
    binding["surprise"] = "not-reviewed"
    with pytest.raises(ValueError, match="missing or unknown"):
        build_stamp(_stack(), binding, expected_account_id=ACCOUNT)

    with pytest.raises(ValueError, match="combined realm security stamp is invalid"):
        build_stamp(_stack(), _binding(), expected_account_id="999999999999")
