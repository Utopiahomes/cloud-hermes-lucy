from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.postgres import migrate_workspaces_v1 as migration

ROOT = Path(__file__).resolve().parents[2]


def _environment() -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_WORKSPACES_MIGRATION_AUTHORIZATION": migration.AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_utopia"
        ),
    }


def test_accepts_exact_quarantined_private_render_configuration() -> None:
    value = migration.configuration_from_environment(_environment())

    assert value.username == "lucy_migration"
    assert value.host == "dpg-example-a"
    assert {
        "0054_stage2_scoped_turn_commit",
        "0057_public_conversation",
        "0068_workspaces_service_auth",
    } == migration.ACCEPTED_SOURCE_REVISIONS


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("RENDER", "false"),
        ("LUCY_ENVIRONMENT", "development"),
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true"),
        ("LUCY_WORKSPACES_MIGRATION_AUTHORIZATION", "wrong"),
        (
            "LUCY_MIGRATION_DATABASE_URL",
            "postgresql://lucy_app:secret@dpg-example-a/lucy_utopia",
        ),
        (
            "LUCY_MIGRATION_DATABASE_URL",
            "postgresql://lucy_migration:secret@example.com/lucy_utopia",
        ),
    ],
)
def test_rejects_changed_configuration_boundary(key: str, value: str) -> None:
    with pytest.raises(migration.WorkspacesMigrationError):
        migration.configuration_from_environment(_environment() | {key: value})


def test_production_image_contains_workspaces_migration_gate() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "deploy/postgres/migrate_workspaces_v1.py" in dockerfile


def test_migration_source_keeps_admission_closed_and_verifies_existing_surfaces() -> None:
    source = (ROOT / "deploy/postgres/migrate_workspaces_v1.py").read_text(
        encoding="utf-8"
    )

    assert "before[2] != \"quarantined\"" in source
    assert "state='ready'" not in source
    assert "capture_boundary_safe_v1()" in source
    assert "public_projection_knowledge_v1" not in source
    assert "_v13_required_functions" in source
    assert "workspaces_tasks_v1" in source
    assert "residual_schema_create" in source


def test_migration_replays_full_quarantined_boundary_and_keeps_it_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {"revision": "0057_public_conversation", "targets": []}

    class Result:
        def __init__(self, row: tuple[object, ...] | None = None) -> None:
            self.row = row

        def fetchone(self) -> tuple[object, ...] | None:
            return self.row

    class Connection:
        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, query: object, *_args: object, **_kwargs: object) -> Result:
            text = str(query)
            if text.startswith("SELECT current_user"):
                return Result(
                    (
                        "lucy_migration",
                        state["revision"],
                        "quarantined",
                        "epoch",
                        "ready",
                        True,
                        True,
                    )
                )
            if text.startswith("SELECT has_function_privilege"):
                return Result((True,))
            if text.startswith("SELECT has_table_privilege"):
                return Result((False,))
            if text.startswith("SELECT has_schema_privilege"):
                return Result((False,))
            return Result()

    monkeypatch.setattr(migration.psycopg, "connect", lambda *_args: Connection())

    def advance(_url: object, *, target_revision: str) -> None:
        state["targets"].append(target_revision)  # type: ignore[union-attr]
        state["revision"] = target_revision

    monkeypatch.setattr(migration, "migrate_realm_database", advance)
    monkeypatch.setattr(migration, "render_realm_roles", lambda **_kwargs: "GRANTS")
    url = migration.configuration_from_environment(_environment())

    receipt = migration.migrate(url)

    assert receipt.source_revision == "0057_public_conversation"
    assert receipt.target_revision == "0068_workspaces_service_auth"
    assert receipt.admission_state == "quarantined"
    assert state["targets"] == ["0068_workspaces_service_auth"]


def test_migration_refuses_ready_admission_before_any_schema_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Result:
        def fetchone(self) -> tuple[object, ...]:
            return (
                "lucy_migration",
                "0057_public_conversation",
                "ready",
                "epoch",
                "ready",
                True,
                True,
            )

    class Connection:
        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, query: object, *_args: object) -> object:
            return Result() if str(query).startswith("SELECT current_user") else SimpleNamespace()

    monkeypatch.setattr(migration.psycopg, "connect", lambda *_args: Connection())
    called = False

    def advance(*_args: object, **_kwargs: object) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(migration, "migrate_realm_database", advance)
    url = migration.configuration_from_environment(_environment())

    with pytest.raises(migration.WorkspacesMigrationError, match="pre-migration"):
        migration.migrate(url)

    assert called is False
