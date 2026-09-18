from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _module() -> ModuleType:
    path = ROOT / "deploy" / "postgres" / "bootstrap_tiamat_staging_v1.py"
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("bootstrap_tiamat_staging_v1", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _configure_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TIAMAT_ENVIRONMENT", "staging")
    monkeypatch.setenv(
        "TIAMAT_BOOTSTRAP_DATABASE_URL",
        "postgresql+psycopg://temporary_owner:owner-secret@tiamat-private/tiamat_staging?sslmode=require",
    )
    monkeypatch.setenv("TIAMAT_RUNTIME_PASSWORD", "runtime-secret-material-000001")
    monkeypatch.setenv("TIAMAT_RECOVERY_PASSWORD", "recovery-secret-material-00001")


def test_bootstrap_config_derives_private_tls_urls_without_owner_reuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    _configure_environment(monkeypatch)

    config = module.load_config_from_environment()

    assert config.owner_url.username == "temporary_owner"
    assert set(config.role_urls) == set(module.ACTIVE_BOOTSTRAP_ROLES)
    assert all(url.host == "tiamat-private" for url in config.role_urls.values())
    assert all(url.database == "tiamat_staging" for url in config.role_urls.values())
    assert all(url.query["sslmode"] == "require" for url in config.role_urls.values())
    assert {url.username for url in config.role_urls.values()} == set(module.ACTIVE_BOOTSTRAP_ROLES)


def test_bootstrap_normalizes_render_owner_url_to_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    _configure_environment(monkeypatch)
    monkeypatch.setenv(
        "TIAMAT_BOOTSTRAP_DATABASE_URL",
        "postgresql://temporary_owner:owner-secret@tiamat-private/tiamat_staging",
    )

    config = module.load_config_from_environment()
    assert config.owner_url.query["sslmode"] == "require"


def test_bootstrap_rejects_explicitly_weakened_owner_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    _configure_environment(monkeypatch)
    monkeypatch.setenv(
        "TIAMAT_BOOTSTRAP_DATABASE_URL",
        "postgresql://temporary_owner:owner-secret@tiamat-private/tiamat_staging?sslmode=disable",
    )

    with pytest.raises(module.BootstrapRejected, match="must not weaken"):
        module.load_config_from_environment()


def test_bootstrap_report_is_content_free(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    _configure_environment(monkeypatch)
    config = module.load_config_from_environment()
    calls: list[str] = []
    monkeypatch.setattr(module, "_migrate", lambda _: calls.append("migrate"))
    monkeypatch.setattr(
        module, "_create_and_password_roles", lambda _: calls.append("configure_roles")
    )
    monkeypatch.setattr(module, "_verify_role_connections", lambda _: calls.append("verify_roles"))

    report = module.bootstrap_tiamat_staging(config)
    rendered = json.dumps(report.__dict__, sort_keys=True)

    assert calls == ["migrate", "configure_roles", "verify_roles"]
    assert report.dispatch_enabled is False
    assert report.secrets_recorded is False
    assert "secret-material" not in rendered
    assert "owner-secret" not in rendered


def test_command_requires_exact_bootstrap_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    _configure_environment(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["bootstrap_tiamat_staging_v1.py"])
    monkeypatch.setattr(
        module,
        "bootstrap_tiamat_staging",
        lambda _: pytest.fail("bootstrap must not run without confirmation"),
    )

    with pytest.raises(module.BootstrapRejected, match="confirmation must equal"):
        module.main()


def test_idle_hold_only_accepts_a_valid_render_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = ROOT / "deploy" / "postgres" / "bootstrap_tiamat_staging_hold_v1.py"
    spec = importlib.util.spec_from_file_location("bootstrap_tiamat_staging_hold_v1", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    monkeypatch.setenv("PORT", "10000")
    assert module._address() == ("0.0.0.0", 10000)

    monkeypatch.setenv("PORT", "0")
    with pytest.raises(SystemExit, match="invalid port"):
        module._address()
