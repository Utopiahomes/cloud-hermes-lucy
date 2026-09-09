"""Build a validated realm-security stamp from reviewed stack evidence.

The input is a saved ``cloudformation describe-stacks`` response plus a
content-free PostgreSQL realm-binding description.  The script performs no AWS
or database calls and never accepts credentials.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from lucy.realm_provisioning import RealmSecurityStampV1

_REALM_OUTPUTS = {
    "RealmSlug": "realm_slug",
    "TenantAccountUuid": "tenant_account_id",
    "NodeId": "node_id",
    "NodeTenureId": "node_tenure_id",
    "TenureEpoch": "tenure_epoch",
    "SecurityRealmId": "security_realm_id",
    "RealmWorkspaceUuid": "workspace_id",
    "DeploymentId": "deployment_id",
    "RealmBindingGeneration": "binding_generation",
    "NodeAuthzEpoch": "node_authz_epoch",
    "StorageEpoch": "storage_epoch",
}
_AWS_OUTPUTS = {
    "EvidenceCallerRoleArn",
    "DeletionCallerRoleArn",
    "RetrievalExecutorAliasArn",
    "RetrievalExecutorVersion",
    "RetrievalExecutorIdentity",
    "RetrievalReceiptKeyArn",
    "DeletionExecutorAliasArn",
    "DeletionExecutorVersion",
    "DeletionExecutorIdentity",
    "DeletionReceiptKeyArn",
}
_BINDING_FIELDS = {
    "realm_slug",
    "content_scope_id",
    "tenant_account_id",
    "node_id",
    "node_tenure_id",
    "tenure_epoch",
    "security_realm_id",
    "storage_epoch",
    "realm_binding_id",
    "workspace_id",
    "deployment_id",
    "service_binding_id",
    "routine_login",
    "routine_principal_id",
    "archive_actor_binding_id",
    "policy_login",
    "policy_principal_id",
    "policy_actor_binding_id",
    "workflow_login",
    "workflow_principal_id",
    "workflow_actor_binding_id",
    "finality_login",
    "finality_principal_id",
    "finality_actor_binding_id",
    "binding_generation",
    "node_authz_epoch",
    "policy_version",
    "retrieval_executor_binding_id",
    "deletion_executor_binding_id",
}


def _named_values(
    items: object, *, name_key: str, value_key: str
) -> dict[str, str]:
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        raise ValueError("stack values must be a list")
    values: dict[str, str] = {}
    for item in items:
        if not isinstance(item, Mapping):
            raise ValueError("stack value is not an object")
        name, value = item.get(name_key), item.get(value_key)
        if not isinstance(name, str) or not isinstance(value, str) or name in values:
            raise ValueError("stack value has an invalid or duplicate name")
        values[name] = value
    return values


def _one_stack(document: object) -> Mapping[str, Any]:
    if not isinstance(document, Mapping) or set(document) != {"Stacks"}:
        raise ValueError("expected an exact CloudFormation describe-stacks response")
    stacks = document["Stacks"]
    if (
        not isinstance(stacks, Sequence)
        or isinstance(stacks, (str, bytes))
        or len(stacks) != 1
        or not isinstance(stacks[0], Mapping)
    ):
        raise ValueError("describe-stacks response must contain exactly one stack")
    return stacks[0]


def build_stamp(
    stack_document: object,
    binding_document: object,
    *,
    expected_account_id: str,
) -> RealmSecurityStampV1:
    stack = _one_stack(stack_document)
    if stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
        raise ValueError("realm security stack is not completely deployed")
    if stack.get("EnableTerminationProtection") is not True:
        raise ValueError("realm security stack termination protection is not enabled")

    outputs = _named_values(
        stack.get("Outputs"), name_key="OutputKey", value_key="OutputValue"
    )
    parameters = _named_values(
        stack.get("Parameters"), name_key="ParameterKey", value_key="ParameterValue"
    )
    missing = (_REALM_OUTPUTS.keys() | _AWS_OUTPUTS) - outputs.keys()
    if missing:
        raise ValueError(f"realm security stack is missing required outputs: {sorted(missing)}")
    if not isinstance(binding_document, Mapping) or set(binding_document) != _BINDING_FIELDS:
        raise ValueError("realm binding description has missing or unknown fields")

    values = dict(binding_document)
    for output_name, field_name in _REALM_OUTPUTS.items():
        expected = str(values[field_name])
        if outputs[output_name] != expected or parameters.get(output_name) != expected:
            raise ValueError(f"stack realm binding differs for {field_name}")

    values.update(
        {
            "contract_version": "1",
            "object_type": "lucy.realm-security-stamp.v1",
            "realm_slug": outputs["RealmSlug"],
            "aws_account_id": expected_account_id,
            "aws_region": "us-east-1",
            "retrieval_executor": {
                "binding_id": values.pop("retrieval_executor_binding_id"),
                "caller_identity": outputs["EvidenceCallerRoleArn"],
                "executor_identity": outputs["RetrievalExecutorIdentity"],
                "executor_alias_arn": outputs["RetrievalExecutorAliasArn"],
                "executor_version": outputs["RetrievalExecutorVersion"],
                "receipt_key_id": outputs["RetrievalReceiptKeyArn"],
            },
            "deletion_executor": {
                "binding_id": values.pop("deletion_executor_binding_id"),
                "caller_identity": outputs["DeletionCallerRoleArn"],
                "executor_identity": outputs["DeletionExecutorIdentity"],
                "executor_alias_arn": outputs["DeletionExecutorAliasArn"],
                "executor_version": outputs["DeletionExecutorVersion"],
                "receipt_key_id": outputs["DeletionReceiptKeyArn"],
            },
        }
    )
    try:
        return RealmSecurityStampV1.model_validate(values)
    except ValidationError as exc:
        raise ValueError("combined realm security stamp is invalid") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stack-description", type=Path, required=True)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--force", action="store_true")
    arguments = parser.parse_args()

    output = arguments.output.resolve()
    if output.exists() and not arguments.force:
        raise FileExistsError(f"refusing to overwrite existing output: {output}")
    stamp = build_stamp(
        json.loads(arguments.stack_description.read_text(encoding="utf-8")),
        json.loads(arguments.binding.read_text(encoding="utf-8")),
        expected_account_id=arguments.expected_account_id,
    )
    payload = {
        "realm_security_stamp": stamp.model_dump(mode="json"),
        "realm_security_stamp_sha256": stamp.digest_hex(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"wrote validated realm security stamp: {output}")


if __name__ == "__main__":
    main()
