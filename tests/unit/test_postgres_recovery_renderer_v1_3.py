from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[2]


def _module() -> ModuleType:
    path = ROOT / "deploy" / "postgres" / "render_recovery_roles_v1_3.py"
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _values() -> dict[str, str]:
    return {
        "realm_slug": "utopia",
        "authority_writer_login": "lucy_utopia_authority_writer",
        "cost_writer_login": "lucy_utopia_cost_writer",
        "authority_recovery_login": "lucy_utopia_authority_recovery",
        "cost_recovery_login": "lucy_utopia_cost_recovery",
    }


def test_recovery_renderer_grants_only_exact_functions() -> None:
    sql = _module().render_recovery_roles(**_values())
    assert "__LUCY_" not in sql
    assert sql.count("GRANT EXECUTE ON FUNCTION") == 4
    assert "GRANT SELECT ON public.alembic_version" in sql
    assert "GRANT SELECT ON lucy." not in sql
    assert "GRANT INSERT" not in sql
    assert "GRANT UPDATE" not in sql
    assert "GRANT DELETE" not in sql
    assert "GRANT lucy_" not in sql
    assert "NOT rolinherit" in sql
    for login in _values().values():
        if login != "utopia":
            assert login in sql


def test_recovery_renderer_rejects_cross_realm_or_reused_login() -> None:
    module = _module()
    with pytest.raises(ValueError, match="does not match"):
        module.render_recovery_roles(
            **(_values() | {"cost_writer_login": "lucy_alpha_cost_writer"})
        )
    with pytest.raises(ValueError, match="distinct"):
        module.render_recovery_roles(
            **(
                _values()
                | {"cost_recovery_login": "lucy_utopia_authority_recovery"}
            )
        )
