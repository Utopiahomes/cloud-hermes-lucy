from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from lucy.shared_execution.postgres_ledger import (
    LedgerAdmission,
    LedgerRecord,
    LedgerScope,
    RecoveryWitness,
)

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "tiamat_migrations" / "versions" / "0001_execution_ledger.py"
SETTLEMENT_MIGRATION = (
    ROOT / "tiamat_migrations" / "versions" / "0002_route_settlement_retention.py"
)


def test_tiamat_has_an_independent_migration_lineage() -> None:
    config = (ROOT / "tiamat_alembic.ini").read_text(encoding="utf-8")
    environment = (ROOT / "tiamat_migrations" / "env.py").read_text(encoding="utf-8")
    assert "script_location = tiamat_migrations" in config
    assert "TIAMAT_MIGRATION_DATABASE_URL" in environment
    assert 'version_table_schema="tiamat"' in environment
    assert not (ROOT / "migrations" / "versions" / "0072_tiamat_execution_ledger.py").exists()


def test_ledger_schema_is_content_free_and_partition_forced() -> None:
    source = "\n".join(
        (
            MIGRATION.read_text(encoding="utf-8"),
            SETTLEMENT_MIGRATION.read_text(encoding="utf-8"),
        )
    )
    for required in (
        "CREATE TABLE tiamat.restore_gate",
        "CREATE TABLE tiamat.jti_replay",
        "CREATE TABLE tiamat.spending_partitions",
        "CREATE TABLE tiamat.execution_records",
        "CREATE TABLE tiamat.grant_releases",
        "CREATE TABLE tiamat.route_rate_quarantines",
        "CREATE TABLE tiamat.financial_events",
        "provider_route_id",
        "rate_release_id",
        "external_liability_microusd",
        "FORCE ROW LEVEL SECURITY",
        "current_setting('tiamat.caller_id', true)",
        "current_setting('tiamat.realm', true)",
        "current_setting('tiamat.environment', true)",
        "current_setting('tiamat.partition_id', true)",
    ):
        assert required in source
    for forbidden_column in (
        "prompt text",
        "message text",
        "transcript text",
        "candidate text",
        "response_content",
        "output_content",
    ):
        assert forbidden_column not in source.lower()


def test_serving_role_cannot_bypass_rls_or_inherit_owner() -> None:
    source = (ROOT / "deploy" / "postgres" / "tiamat_roles.sql.example").read_text(encoding="utf-8")
    runtime = next(
        line for line in source.splitlines() if line.startswith("CREATE ROLE tiamat_runtime")
    )
    assert "NOINHERIT" in runtime
    assert "NOBYPASSRLS" in runtime
    assert "NOSUPERUSER" in runtime
    assert "tiamat_recovery" not in runtime


def test_recovery_witness_requires_positive_generation() -> None:
    with pytest.raises(ValueError, match="witness"):
        RecoveryWitness("local-test", uuid4(), 0)


def test_admission_rejects_content_identity_shape_drift() -> None:
    now = datetime(2026, 9, 17, 12, tzinfo=UTC)
    with pytest.raises(ValueError, match="admission"):
        LedgerAdmission(
            idempotency_key_digest="short",
            identity_digest="a" * 64,
            digest_key_version="digest-v1",
            operation="inference.execute",
            contract_major=1,
            execution_profile_id="profile.v1",
            profile_release_id="profiles.1",
            provider_route_id="vertex-primary",
            rate_release_id="rates.1",
            owner_id=uuid4(),
            execution_deadline=now + timedelta(seconds=10),
            eligibility_generation=1,
            reserved_microusd=100,
        )


def test_scope_requires_every_isolation_dimension() -> None:
    with pytest.raises(ValueError, match="scope"):
        LedgerScope(
            issuer="homes.internal",
            caller_id="",
            realm="utopia-homes",
            environment="local-test",
            partition_id="utopia-public",
        )


def test_database_row_maps_only_content_free_receipt_state() -> None:
    now = datetime(2026, 9, 17, 12, tzinfo=UTC)
    execution_id, owner_id = uuid4(), uuid4()
    record = LedgerRecord.from_row(
        {
            "execution_id": execution_id,
            "identity_digest": "a" * 64,
            "state": "outcome_unknown",
            "coordinator_generation": 3,
            "record_generation": 7,
            "lease_owner_id": owner_id,
            "lease_expires_at": now,
            "execution_deadline": now - timedelta(seconds=30),
            "reserved_microusd": 2_000,
            "settlement_status": "pending_reconciliation",
            "settled_microusd": None,
            "failure_code": "execution_outcome_unknown",
            "provider_route_id": "vertex-primary",
            "rate_release_id": "rates.1",
        }
    )
    assert record.execution_id == execution_id
    assert record.lease_owner_id == owner_id
    assert record.settled_microusd is None
    assert UUID(str(record.execution_id)) == execution_id
