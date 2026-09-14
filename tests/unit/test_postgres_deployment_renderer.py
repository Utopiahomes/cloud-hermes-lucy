from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[2]


def _renderer() -> ModuleType:
    path = ROOT / "deploy" / "postgres" / "render_security_v1_2_sql.py"
    spec = importlib.util.spec_from_file_location("render_security_v1_2_sql", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_roles_renderer_replaces_only_valid_distinct_logins() -> None:
    rendered = _renderer().render_roles(
        routine_login="lucy_routine_login",
        policy_login="lucy_policy_login",
        evidence_login="lucy_evidence_login",
        deletion_login="lucy_deletion_login",
        finality_login="lucy_finality_login",
    )
    assert "__LUCY_" not in rendered
    assert 'TO "lucy_policy_login"' in rendered
    assert 'TO "lucy_evidence_login"' in rendered
    assert 'TO "lucy_deletion_login"' in rendered
    assert 'TO "lucy_finality_login"' in rendered


def test_revision_0021_renderer_is_frozen_to_functions_at_that_revision() -> None:
    rendered = _renderer().render_roles_at_revision_0021(
        routine_login="lucy_routine_login",
        policy_login="lucy_policy_login",
        evidence_login="lucy_evidence_login",
        deletion_login="lucy_deletion_login",
        finality_login="lucy_finality_login",
    )
    assert "record_finality_verification_v1(uuid,jsonb)" in rendered
    assert "record_scoped_finality_inventory_v2" not in rendered


@pytest.mark.parametrize("login", ["Lucy-Policy", "lucy;drop", "", "a" * 64])
def test_roles_renderer_rejects_unsafe_login_identifiers(login: str) -> None:
    with pytest.raises(ValueError, match="invalid PostgreSQL LOGIN"):
        _renderer().render_roles(
            routine_login="lucy_routine_login",
            policy_login=login,
            evidence_login="lucy_evidence_login",
            deletion_login="lucy_deletion_login",
            finality_login="lucy_finality_login",
        )


def test_roles_renderer_rejects_duplicate_logins() -> None:
    with pytest.raises(ValueError, match="must be distinct"):
        _renderer().render_roles(
            routine_login="lucy_shared_login",
            policy_login="lucy_shared_login",
            evidence_login="lucy_evidence_login",
            deletion_login="lucy_deletion_login",
            finality_login="lucy_finality_login",
        )


def _bindings(module: ModuleType, *, account: str = "123456789012") -> str:
    return module.render_bindings(
        aws_account_id=account,
        retrieval_alias_arn=(
            f"arn:aws:lambda:us-east-1:{account}:function:lucy-evidence-executor-v12:live"
        ),
        deletion_alias_arn=(
            f"arn:aws:lambda:us-east-1:{account}:function:lucy-deletion-executor-v12:live"
        ),
        retrieval_receipt_key_arn=(
            f"arn:aws:kms:us-east-1:{account}:key/00000000-0000-4000-8000-000000000001"
        ),
        deletion_receipt_key_arn=(
            f"arn:aws:kms:us-east-1:{account}:key/00000000-0000-4000-8000-000000000002"
        ),
        retrieval_version=3,
        deletion_version=4,
        security_storage_epoch=5,
        security_registry_epoch=6,
        security_key_epoch=7,
    )


def test_binding_renderer_replaces_every_reviewed_marker() -> None:
    rendered = _bindings(_renderer())
    assert "__RETRIEVAL_" not in rendered
    assert "__DELETION_" not in rendered
    assert "__SECURITY_" not in rendered
    assert "lucy-evidence-executor-v12:live" in rendered
    assert "v_storage_epoch bigint := '5'" in rendered
    assert "v_registry_epoch bigint := '6'" in rendered
    assert "v_key_epoch bigint := '7'" in rendered


def test_binding_renderer_rejects_cross_account_resources() -> None:
    module = _renderer()
    with pytest.raises(ValueError, match="match the target AWS account"):
        module.render_bindings(
            aws_account_id="123456789012",
            retrieval_alias_arn=(
                "arn:aws:lambda:us-east-1:123456789012:"
                "function:lucy-evidence-executor-v12:live"
            ),
            deletion_alias_arn=(
                "arn:aws:lambda:us-east-1:123456789012:"
                "function:lucy-deletion-executor-v12:live"
            ),
            retrieval_receipt_key_arn=(
                "arn:aws:kms:us-east-1:123456789012:"
                "key/00000000-0000-4000-8000-000000000001"
            ),
            deletion_receipt_key_arn=(
                "arn:aws:kms:us-east-1:999999999999:"
                "key/00000000-0000-4000-8000-000000000002"
            ),
            retrieval_version=1,
            deletion_version=1,
            security_storage_epoch=1,
            security_registry_epoch=1,
            security_key_epoch=1,
        )


@pytest.mark.parametrize("qualifier", ["$LATEST", "17"])
def test_binding_renderer_requires_a_named_lambda_alias(qualifier: str) -> None:
    module = _renderer()
    with pytest.raises(ValueError, match="Lambda alias ARNs"):
        module.render_bindings(
            aws_account_id="123456789012",
            retrieval_alias_arn=(
                "arn:aws:lambda:us-east-1:123456789012:"
                f"function:lucy-evidence-executor-v12:{qualifier}"
            ),
            deletion_alias_arn=(
                "arn:aws:lambda:us-east-1:123456789012:"
                "function:lucy-deletion-executor-v12:live"
            ),
            retrieval_receipt_key_arn=(
                "arn:aws:kms:us-east-1:123456789012:"
                "key/00000000-0000-4000-8000-000000000001"
            ),
            deletion_receipt_key_arn=(
                "arn:aws:kms:us-east-1:123456789012:"
                "key/00000000-0000-4000-8000-000000000002"
            ),
            retrieval_version=1,
            deletion_version=1,
            security_storage_epoch=1,
            security_registry_epoch=1,
            security_key_epoch=1,
        )


def test_binding_renderer_rejects_non_positive_or_boolean_epochs() -> None:
    module = _renderer()
    for value in (0, -1, True):
        with pytest.raises(ValueError, match="must be a positive integer"):
            module.render_bindings(
                aws_account_id="123456789012",
                retrieval_alias_arn=(
                    "arn:aws:lambda:us-east-1:123456789012:"
                    "function:lucy-evidence-executor-v12:live"
                ),
                deletion_alias_arn=(
                    "arn:aws:lambda:us-east-1:123456789012:"
                    "function:lucy-deletion-executor-v12:live"
                ),
                retrieval_receipt_key_arn=(
                    "arn:aws:kms:us-east-1:123456789012:"
                    "key/00000000-0000-4000-8000-000000000001"
                ),
                deletion_receipt_key_arn=(
                    "arn:aws:kms:us-east-1:123456789012:"
                    "key/00000000-0000-4000-8000-000000000002"
                ),
                retrieval_version=1,
                deletion_version=1,
                security_storage_epoch=value,
                security_registry_epoch=1,
                security_key_epoch=1,
            )


def test_binding_renderer_rejects_a_consistent_but_wrong_aws_account() -> None:
    module = _renderer()
    with pytest.raises(ValueError, match="match the target AWS account"):
        module.render_bindings(
            aws_account_id="999999999999",
            retrieval_alias_arn=(
                "arn:aws:lambda:us-east-1:123456789012:"
                "function:lucy-evidence-executor-v12:live"
            ),
            deletion_alias_arn=(
                "arn:aws:lambda:us-east-1:123456789012:"
                "function:lucy-deletion-executor-v12:live"
            ),
            retrieval_receipt_key_arn=(
                "arn:aws:kms:us-east-1:123456789012:"
                "key/00000000-0000-4000-8000-000000000001"
            ),
            deletion_receipt_key_arn=(
                "arn:aws:kms:us-east-1:123456789012:"
                "key/00000000-0000-4000-8000-000000000002"
            ),
            retrieval_version=1,
            deletion_version=1,
            security_storage_epoch=1,
            security_registry_epoch=1,
            security_key_epoch=1,
        )


def test_renderer_refuses_to_overwrite_output(tmp_path: Path) -> None:
    module = _renderer()
    output = tmp_path / "rendered.sql"
    output.write_text("review me", encoding="utf-8")
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        module._write(output, _bindings(module), overwrite=False)
