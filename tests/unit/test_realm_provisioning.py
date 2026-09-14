from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from lucy.realm_provisioning import RealmExecutorStampV1, RealmSecurityStampV1

ACCOUNT = "123456789012"


def _executor(label: str) -> RealmExecutorStampV1:
    return RealmExecutorStampV1(
        binding_id=uuid4(),
        caller_identity=f"arn:aws:iam::{ACCOUNT}:role/lucy-utopia-{label}-workflow",
        executor_identity=f"lucy-utopia-{label}-executor-v13",
        executor_alias_arn=(
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:"
            f"function:lucy-utopia-{label}-executor-v13:production"
        ),
        executor_version=3,
        receipt_key_id=(
            f"arn:aws:kms:us-east-1:{ACCOUNT}:"
            f"key/00000000-0000-4000-8000-00000000000{'1' if label == 'retrieval' else '2'}"
        ),
    )


def _stamp(**changes: object) -> RealmSecurityStampV1:
    values: dict[str, object] = {
        "realm_slug": "utopia",
        "aws_account_id": ACCOUNT,
        "content_scope_id": uuid4(),
        "tenant_account_id": uuid4(),
        "node_id": uuid4(),
        "node_tenure_id": uuid4(),
        "tenure_epoch": 1,
        "security_realm_id": uuid4(),
        "storage_epoch": 1,
        "realm_binding_id": uuid4(),
        "workspace_id": uuid4(),
        "deployment_id": uuid4(),
        "service_binding_id": uuid4(),
        "routine_login": "lucy_utopia_routine",
        "routine_principal_id": uuid4(),
        "archive_actor_binding_id": uuid4(),
        "policy_login": "lucy_utopia_policy",
        "policy_principal_id": uuid4(),
        "policy_actor_binding_id": uuid4(),
        "workflow_login": "lucy_utopia_sensitive_workflow",
        "workflow_principal_id": uuid4(),
        "workflow_actor_binding_id": uuid4(),
        "finality_login": "lucy_utopia_finality",
        "finality_principal_id": uuid4(),
        "finality_actor_binding_id": uuid4(),
        "binding_generation": 1,
        "node_authz_epoch": 1,
        "policy_version": 1,
        "retrieval_executor": _executor("retrieval"),
        "deletion_executor": _executor("deletion"),
    }
    values.update(changes)
    return RealmSecurityStampV1.model_validate(values)


def test_realm_security_stamp_is_stable_and_content_free() -> None:
    stamp = _stamp()
    assert len(stamp.digest_hex()) == 64
    assert stamp.digest_hex() == RealmSecurityStampV1.model_validate_json(
        stamp.model_dump_json()
    ).digest_hex()
    serialized = stamp.model_dump_json()
    assert "password" not in serialized and "database_url" not in serialized


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"policy_login": "lucy_raymond_policy"}, "namespace"),
        ({"policy_login": "lucy_utopia_routine"}, "distinct"),
        ({"aws_account_id": "123"}, "at least 12 characters"),
        ({"policy_principal_id": UUID(int=0), "routine_principal_id": UUID(int=0)}, "principals"),
    ],
)
def test_realm_security_stamp_rejects_scope_identity_ambiguity(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises((ValidationError, ValueError), match=message):
        _stamp(**changes)


def test_realm_security_stamp_rejects_cross_account_or_moving_executor() -> None:
    retrieval = _executor("retrieval")
    for alias in (
        retrieval.executor_alias_arn.replace(ACCOUNT, "999999999999"),
        retrieval.executor_alias_arn.rsplit(":", 1)[0] + ":$LATEST",
        retrieval.executor_alias_arn.rsplit(":", 1)[0] + ":17",
    ):
        with pytest.raises(ValidationError, match="executor"):
            _stamp(retrieval_executor=retrieval.model_copy(update={"executor_alias_arn": alias}))


def test_realm_security_stamp_rejects_duplicate_executor_authority() -> None:
    retrieval = _executor("retrieval")
    deletion = _executor("deletion").model_copy(
        update={"receipt_key_id": retrieval.receipt_key_id}
    )
    with pytest.raises(ValidationError, match="must be distinct"):
        _stamp(retrieval_executor=retrieval, deletion_executor=deletion)
