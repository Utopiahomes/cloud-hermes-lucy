from __future__ import annotations

import importlib.util
from contextlib import nullcontext
from pathlib import Path
from types import ModuleType
from typing import Any
from uuid import uuid4

import pytest

from deploy.postgres import finalize_tiamat_d1_v1 as finalizer

ROOT = Path(__file__).resolve().parents[2]


def _migration() -> ModuleType:
    path = ROOT / "tiamat_migrations" / "versions" / "0007_startup_attestation.py"
    spec = importlib.util.spec_from_file_location("tiamat_d1_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _expiry_migration() -> ModuleType:
    path = ROOT / "tiamat_migrations" / "versions" / "0008_startup_attestation_expiry_bound.py"
    spec = importlib.util.spec_from_file_location("tiamat_d1_expiry_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _consume_v2_migration() -> ModuleType:
    path = ROOT / "tiamat_migrations" / "versions" / "0009_attestation_consume_v2.py"
    spec = importlib.util.spec_from_file_location("tiamat_d1_consume_v2_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _database_clock_migration() -> ModuleType:
    path = ROOT / "tiamat_migrations" / "versions" / "0010_attestation_database_clock.py"
    spec = importlib.util.spec_from_file_location("tiamat_d1_database_clock_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_d1_migration_installs_locked_functions_and_single_claimant_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = _migration()
    statements: list[str] = []
    monkeypatch.setattr(migration.op, "execute", statements.append)
    migration.upgrade()
    sql = "\n".join(statements)

    assert "anchor_floor_version bigint NOT NULL DEFAULT 0" in sql
    assert "CREATE TABLE tiamat.startup_attestations" in sql
    assert "WHERE consumed_at IS NULL AND superseded_at IS NULL" in sql
    assert "consumed_coordinator_generation" in sql
    assert "FORCE ROW LEVEL SECURITY" in sql
    assert "current_user = 'tiamat_recovery'" in sql
    assert sql.count("LANGUAGE plpgsql SECURITY DEFINER") == 3
    assert sql.count("SET search_path = pg_catalog, pg_temp") == 3
    assert "pg_catalog.pg_current_wal_flush_lsn()" in sql
    assert "FOR UPDATE OF gate" in sql
    assert "ERRCODE = 'ZX101'" in sql
    assert "ERRCODE = 'ZX102'" in sql
    assert "ERRCODE = 'ZX103'" in sql
    assert "ERRCODE = 'ZX104'" in sql
    assert "REVOKE ALL ON FUNCTION tiamat.consume_startup_attestation(text) FROM PUBLIC" in sql
    assert "GRANT EXECUTE ON FUNCTION" not in sql


def test_d1_expiry_migration_enforces_the_launcher_lifetime_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = _expiry_migration()
    statements: list[str] = []
    monkeypatch.setattr(migration.op, "execute", statements.append)
    migration.upgrade()
    sql = "\n".join(statements)

    assert "ADD COLUMN created_at timestamptz" in sql
    assert "ALTER COLUMN created_at SET DEFAULT clock_timestamp()" in sql
    assert "created_at IS NULL OR" in sql
    assert "expires_at > created_at" in sql
    assert "expires_at <= created_at + interval '10 minutes'" in sql
    assert "CREATE FUNCTION tiamat.enforce_startup_attestation_expiry_bound()" in sql
    assert "BEFORE INSERT OR UPDATE OF created_at, expires_at" in sql


def test_d1_consume_v2_rechecks_expiry_after_the_gate_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = _consume_v2_migration()
    statements: list[str] = []
    monkeypatch.setattr(migration.op, "execute", statements.append)
    migration.upgrade()
    sql = "\n".join(statements)

    assert "CREATE FUNCTION tiamat.consume_startup_attestation_v2(" in sql
    assert "FOR UPDATE OF gate" in sql
    assert "attested.expires_at <= pg_catalog.clock_timestamp()" in sql
    assert "REVOKE ALL ON FUNCTION tiamat.consume_startup_attestation_v2(text) FROM PUBLIC" in sql


def test_d1_database_clock_migration_overrides_caller_issuance_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = _database_clock_migration()
    statements: list[str] = []
    monkeypatch.setattr(migration.op, "execute", statements.append)
    migration.upgrade()
    sql = "\n".join(statements)

    assert "CREATE OR REPLACE FUNCTION tiamat.enforce_startup_attestation_expiry_bound()" in sql
    assert "NEW.created_at := database_now" in sql
    assert "NEW.created_at IS DISTINCT FROM OLD.created_at" in sql
    assert "NEW.expires_at <= database_now" in sql
    assert "ERRCODE = 'ZX105'" in sql
    assert "ERRCODE = 'ZX106'" in sql


class _Result:
    def __init__(
        self, row: tuple[Any, ...] | None = None, rows: list[tuple[Any, ...]] | None = None
    ):
        self.row = row
        self.rows = rows or []

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.row

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self.rows


class _Connection:
    def __init__(
        self,
        ledger_id: Any,
        *,
        blocked: bool = True,
        postcheck_owner: str = "tiamat_recovery",
        postcheck_execute: bool = True,
        postcheck_set: bool = False,
        postcheck_usage: bool = False,
        postcheck_create: bool = False,
        postcheck_deprecated_execute: bool = False,
        recovery_owned_v1: bool = False,
    ):
        self.ledger_id = ledger_id
        self.blocked = blocked
        self.postcheck_owner = postcheck_owner
        self.postcheck_execute = postcheck_execute
        self.postcheck_set = postcheck_set
        self.postcheck_usage = postcheck_usage
        self.postcheck_create = postcheck_create
        self.postcheck_deprecated_execute = postcheck_deprecated_execute
        self.recovery_owned_v1 = recovery_owned_v1
        self.statements: list[str] = []

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def transaction(self) -> Any:
        return nullcontext()

    def execute(self, query: Any, params: Any = None) -> _Result:
        statement = str(query)
        self.statements.append(statement)
        if "FROM tiamat.ledger_identity AS i" in statement:
            return _Result(("tiamat_owner", "tiamat_test", self.ledger_id, self.blocked))
        if "FROM pg_catalog.pg_roles" in statement:
            return _Result(rows=[("tiamat_recovery", True), ("tiamat_runtime", True)])
        if "pg_catalog.pg_has_role" in statement:
            if sum("pg_catalog.pg_has_role" in earlier for earlier in self.statements) > 1:
                return _Result((self.postcheck_set, self.postcheck_usage, self.postcheck_create))
            return _Result((False, False, False))
        if "pg_catalog.pg_get_userbyid" in statement:
            if "has_function_privilege" in statement:
                is_deprecated = bool(params and "consume_startup_attestation(text)" in params[0])
                runtime_execute = (
                    self.postcheck_deprecated_execute if is_deprecated else self.postcheck_execute
                )
                return _Result(
                    (
                        self.postcheck_owner,
                        runtime_execute,
                    )
                )
            if (
                self.recovery_owned_v1
                and params
                and "consume_startup_attestation(text)" in params[0]
            ):
                return _Result(("tiamat_recovery",))
            return _Result(("tiamat_owner",))
        if "pg_catalog.has_table_privilege" in statement:
            return _Result((False,))
        return _Result()


def test_finalization_refuses_open_gate_before_role_grants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_id = uuid4()
    connection = _Connection(ledger_id, blocked=False)
    monkeypatch.setattr(finalizer.psycopg, "connect", lambda _: connection)

    with pytest.raises(finalizer.D1FinalizationRejected, match="blocked ledger"):
        finalizer.finalize_d1(
            "postgresql://synthetic", environment="staging", expected_ledger_id=ledger_id
        )
    assert not any("GRANT" in statement for statement in connection.statements)


def test_finalization_transfers_then_grants_runtime_functions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_id = uuid4()
    connection = _Connection(ledger_id)
    monkeypatch.setattr(finalizer.psycopg, "connect", lambda _: connection)

    finalizer.finalize_d1(
        "postgresql://synthetic", environment="staging", expected_ledger_id=ledger_id
    )

    statements = connection.statements
    # Finalization grants no direct UPDATE; it explicitly removes the old runtime grant.
    assert "REVOKE UPDATE ON tiamat.restore_gate FROM tiamat_runtime" in statements
    assert sum("ALTER FUNCTION" in statement for statement in statements) == 6
    assert sum("GRANT EXECUTE ON FUNCTION" in statement for statement in statements) == 5
    assert sum("REVOKE ALL ON FUNCTION" in statement for statement in statements) == 6
    first_grant = next(
        index
        for index, statement in enumerate(statements)
        if "GRANT EXECUTE ON FUNCTION" in statement
    )
    # V1 is deliberately transferred without a runtime grant; each non-deprecated
    # entry receives EXECUTE before its own ownership transfer.
    assert first_grant < statements.index(
        next(
            statement
            for statement in statements
            if "ALTER FUNCTION" in statement and "consume_startup_attestation_v2" in statement
        )
    )
    assert (
        statements.index("REVOKE UPDATE ON tiamat.restore_gate FROM tiamat_runtime")
        < len(statements) - 1
    )
    assert sum("has_function_privilege" in statement for statement in statements) == 6
    assert sum("pg_catalog.pg_has_role" in statement for statement in statements) == 2


def test_finalization_revokes_legacy_entrypoint_under_its_recovery_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_id = uuid4()
    connection = _Connection(ledger_id, recovery_owned_v1=True)
    monkeypatch.setattr(finalizer.psycopg, "connect", lambda _: connection)

    finalizer.finalize_d1(
        "postgresql://synthetic", environment="staging", expected_ledger_id=ledger_id
    )

    statements = connection.statements
    assert "SET LOCAL ROLE tiamat_recovery" in statements
    assert "RESET ROLE" in statements
    assert sum("ALTER FUNCTION" in statement for statement in statements) == 5
    assert sum("GRANT EXECUTE ON FUNCTION" in statement for statement in statements) == 5


@pytest.mark.parametrize(
    ("postcheck", "message"),
    [
        ({"postcheck_owner": "tiamat_owner"}, "ownership or execution grant"),
        ({"postcheck_execute": False}, "ownership or execution grant"),
        ({"postcheck_set": True}, "temporary recovery-role privileges"),
        ({"postcheck_usage": True}, "temporary recovery-role privileges"),
        ({"postcheck_create": True}, "temporary recovery-role privileges"),
        ({"postcheck_deprecated_execute": True}, "ownership or execution grant"),
    ],
)
def test_finalization_rejects_incomplete_postconditions(
    monkeypatch: pytest.MonkeyPatch, postcheck: dict[str, Any], message: str
) -> None:
    ledger_id = uuid4()
    connection = _Connection(ledger_id, **postcheck)
    monkeypatch.setattr(finalizer.psycopg, "connect", lambda _: connection)

    with pytest.raises(finalizer.D1FinalizationRejected, match=message):
        finalizer.finalize_d1(
            "postgresql://synthetic", environment="staging", expected_ledger_id=ledger_id
        )
