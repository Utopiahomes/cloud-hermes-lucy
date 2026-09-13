from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_job_replay_migration_allows_only_exact_existing_job_after_settlement() -> None:
    migration = (
        ROOT / "migrations" / "versions" / "0071_memory_import_job_replay.py"
    ).read_text(encoding="utf-8")

    assert 'down_revision: str | None = "0070_memory_pilot_transport"' in migration
    assert "CREATE OR REPLACE FUNCTION lucy.register_memory_import_job_v1" in migration

    source_gate = "PERFORM lucy.require_memory_import_sources_v1"
    existing_job_lookup = (
        "SELECT * INTO v_existing FROM lucy.memory_import_extraction_jobs_v1"
    )
    exact_job_gate = "v_existing.serialized_job<>p_job"
    settlement_gate = (
        "IF EXISTS (SELECT 1 FROM lucy.memory_import_attempt_settlements_v1"
    )
    insert_job = "INSERT INTO lucy.memory_import_extraction_jobs_v1"
    assert migration.index(source_gate) < migration.index(existing_job_lookup)
    assert migration.index(existing_job_lookup) < migration.index(exact_job_gate)
    assert migration.index(exact_job_gate) < migration.index(settlement_gate)
    assert migration.index(settlement_gate) < migration.index(insert_job)

    assert "manifest_digest=p_job->>'manifest_digest'" in migration
    assert "expires_at>v_now" in migration
    assert "content_scope_id=v_binding.content_scope_id" in migration
    assert "service_binding_id=v_binding.id" in migration
    assert "OWNER TO lucy_security_function_owner" in migration
    assert "FROM PUBLIC,lucy_app" in migration
    assert "reviewed forward migration" in migration
