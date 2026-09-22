from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from deploy.postgres.apply_tiamat_definer_migration_v1 import (
    DefinerMigrationRejected,
    apply_definer_migration,
    load_migration,
)

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "tiamat_migrations" / "versions" / "0014_attestation_expiry.py"


def _migration() -> Any:
    return load_migration(MIGRATION, function="verify_attestation_current", signature="bigint")


class _Result:
    def __init__(self, row: tuple[Any, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class _Connection:
    """A ledger at a chosen revision whose definer function has a chosen owner."""

    def __init__(self, *, version: str, function_owner: str, runtime_executes: bool = True) -> None:
        self.version = version
        self.function_owner = function_owner
        self.runtime_executes = runtime_executes
        self.statements: list[str] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def transaction(self) -> Any:
        from contextlib import nullcontext

        return nullcontext()

    def execute(self, query: Any, params: tuple[Any, ...] | None = None) -> _Result:
        text = query if isinstance(query, str) else query.as_string(None)
        normalized = " ".join(text.split())
        self.statements.append(normalized)
        if normalized == "SELECT current_user":
            return _Result(("tiamat_test_owner",))
        if "alembic_version FOR UPDATE" in normalized:
            return _Result((self.version,))
        if "pg_get_userbyid" in normalized:
            return _Result((self.function_owner,))
        if "has_function_privilege" in normalized:
            # After the handoff the borrowed privileges are gone again.
            return _Result((self.runtime_executes, False, False, False))
        return _Result(None)


def test_a_fresh_ledger_needs_no_ownership_handoff() -> None:
    """Before finalization the migration owner still owns the function."""

    connection = _Connection(version="0013_retire_coordinator", function_owner="tiamat_test_owner")

    status = _apply(connection)

    assert status == "applied_as_migration_owner"
    assert not any("GRANT tiamat_recovery" in statement for statement in connection.statements)
    assert not any("SET LOCAL ROLE" in statement for statement in connection.statements)
    assert any("CREATE OR REPLACE FUNCTION" in statement for statement in connection.statements)


def test_a_finalized_ledger_borrows_and_returns_the_ownership() -> None:
    """The handoff is taken, used and given back inside the one transaction."""

    connection = _Connection(version="0013_retire_coordinator", function_owner="tiamat_recovery")

    status = _apply(connection)

    assert status == "applied_and_verified"
    order = [
        index
        for index, statement in enumerate(connection.statements)
        if "GRANT tiamat_recovery" in statement
        or "SET LOCAL ROLE" in statement
        or "CREATE OR REPLACE FUNCTION" in statement
        or "RESET ROLE" in statement
        or "UPDATE tiamat.alembic_version" in statement
        or "REVOKE tiamat_recovery" in statement
    ]
    assert order == sorted(order)
    assert any("REVOKE CREATE ON SCHEMA" in statement for statement in connection.statements)


def test_a_ledger_at_the_wrong_revision_is_refused() -> None:
    connection = _Connection(version="0011_recovery_checkpoint", function_owner="tiamat_recovery")

    with pytest.raises(DefinerMigrationRejected, match="predecessor"):
        _apply(connection)

    assert not any("CREATE OR REPLACE" in statement for statement in connection.statements)


def test_an_already_applied_revision_is_refused() -> None:
    connection = _Connection(version="0014_attestation_expiry", function_owner="tiamat_recovery")

    with pytest.raises(DefinerMigrationRejected, match="already applied"):
        _apply(connection)


def test_a_runtime_that_lost_execution_fails_the_whole_transaction() -> None:
    connection = _Connection(
        version="0013_retire_coordinator",
        function_owner="tiamat_recovery",
        runtime_executes=False,
    )

    with pytest.raises(DefinerMigrationRejected, match="lost execution"):
        _apply(connection)


def test_the_runner_applies_the_revision_s_own_statement() -> None:
    migration = _migration()

    assert migration.revision == "0014_attestation_expiry"
    assert "CREATE OR REPLACE FUNCTION tiamat.verify_attestation_current" in migration.statement
    assert "attested.expires_at <= pg_catalog.clock_timestamp()" in migration.statement


def _apply(connection: _Connection) -> str:
    import deploy.postgres.apply_tiamat_definer_migration_v1 as runner

    original = runner.psycopg.connect
    runner.psycopg.connect = lambda *_args, **_kwargs: connection  # type: ignore[assignment]
    try:
        return apply_definer_migration("postgresql://owner@example/tiamat", _migration())
    finally:
        runner.psycopg.connect = original  # type: ignore[assignment]
