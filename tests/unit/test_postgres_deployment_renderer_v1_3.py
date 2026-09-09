from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[2]


def _renderer() -> ModuleType:
    path = ROOT / "deploy" / "postgres" / "render_security_v1_3_sql.py"
    spec = importlib.util.spec_from_file_location("render_security_v1_3_sql", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _render(module: ModuleType, **changes: str) -> str:
    values = {
        "realm_slug": "utopia",
        "routine_login": "lucy_utopia_routine",
        "policy_login": "lucy_utopia_policy",
        "workflow_login": "lucy_utopia_sensitive_workflow",
        "finality_login": "lucy_utopia_finality",
    }
    values.update(changes)
    return module.render_realm_roles(**values)


def test_realm_renderer_emits_execute_only_scoped_grants() -> None:
    rendered = _render(_renderer())
    assert "__LUCY_" not in rendered
    assert "Realm label: utopia" in rendered
    assert 'TO "lucy_utopia_routine"' in rendered
    assert "register_capturable_scoped_evidence_v2" not in rendered
    assert "claim_capturable_scoped_archive_v1" in rendered
    assert "record_scoped_archive_aws_outcome_v1" in rendered
    assert "reconcile_capturable_scoped_archive_v1" in rendered
    assert "register_scoped_evidence_v2(jsonb" not in rendered
    assert 'TO "lucy_utopia_policy"' in rendered
    assert 'TO "lucy_utopia_sensitive_workflow"' in rendered
    assert 'TO "lucy_utopia_finality"' in rendered
    assert "GRANT SELECT ON lucy.scoped_" not in rendered


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("realm_slug", "Utopia-Homes", "invalid realm slug"),
        ("routine_login", "lucy;drop", "invalid PostgreSQL LOGIN"),
        ("policy_login", "lucy_raymond_policy", "does not match"),
        ("workflow_login", "lucy_utopia_policy", "must be distinct"),
    ],
)
def test_realm_renderer_rejects_unsafe_or_cross_realm_names(
    field: str, value: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _render(_renderer(), **{field: value})
