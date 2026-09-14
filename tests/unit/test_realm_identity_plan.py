from datetime import UTC, datetime
from pathlib import Path

import pytest

from deploy.prepare_realm_identity_v1_3 import main
from lucy.realm_identity_plan import create_realm_identity_plan


def _plan():
    return create_realm_identity_plan(
        realm_slug="raymond",
        resource_namespace="lucy-raymond-v13",
        aws_account_id="429870640638",
        account_slug="raymond",
        account_display_name="Raymond DeLuca",
        node_slug="raymond",
        node_display_name="Raymond DeLuca",
        node_kind="person",
        workspace_slug="private",
        planned_at=datetime(2026, 9, 14, tzinfo=UTC),
    )


def test_realm_identity_plan_is_distinct_stable_and_not_authorization() -> None:
    plan = _plan()

    assert plan.status == "planned_not_authorized"
    assert plan.routine_login == "lucy_raymond_routine"
    assert plan.policy_login == "lucy_raymond_policy"
    assert plan.workflow_login == "lucy_raymond_sensitive_workflow"
    assert plan.finality_login == "lucy_raymond_finality"
    assert len(plan.digest) == 64
    uuid_values = {
        value
        for name in type(plan).model_fields
        if (value := getattr(plan, name, None)).__class__.__name__ == "UUID"
    }
    assert len(uuid_values) == 22


def test_realm_identity_plan_rejects_cross_realm_issuer() -> None:
    with pytest.raises(ValueError, match="service issuer"):
        plan = _plan()
        type(plan).model_validate(
            plan.model_dump() | {"service_issuer": "lucy://utopia/services"}
        )


def test_prepare_cli_writes_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "raymond-plan.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "prepare_realm_identity_v1_3.py",
            "--realm-slug",
            "raymond",
            "--resource-namespace",
            "lucy-raymond-v13",
            "--aws-account-id",
            "429870640638",
            "--account-slug",
            "raymond",
            "--account-display-name",
            "Raymond DeLuca",
            "--node-slug",
            "raymond",
            "--node-display-name",
            "Raymond DeLuca",
            "--node-kind",
            "person",
            "--output",
            str(output),
        ],
    )

    assert main() == 0
    assert output.is_file()
    with pytest.raises(FileExistsError, match="already exists"):
        main()
