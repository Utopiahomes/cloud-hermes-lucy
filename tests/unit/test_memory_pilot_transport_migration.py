from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_transport_migration_separates_operator_registration_and_runtime_admission() -> None:
    migration = (
        ROOT / "migrations" / "versions" / "0070_memory_pilot_transport_admission.py"
    ).read_text(encoding="utf-8")

    assert 'down_revision: str | None = "0069_memory_outcome_policy"' in migration
    assert "pg_has_role(session_user,'lucy_migration','MEMBER')" in migration
    assert "capability_token_digest=p_capability_digest" in migration
    campaign_lock = "'memory-pilot-transport:'||v_campaign_id::text"
    assert migration.index(campaign_lock) < migration.index(
        "content_scope_id=v_binding.content_scope_id", migration.index(campaign_lock)
    )
    assert "v_registration.expires_at<=clock_timestamp()" in migration
    assert "memory_pilot_transport_revocations_v1" in migration
    assert "TO lucy_migration" in migration
    assert "WHERE service_role='realm_evidence'" in migration
    assert "evidence.archive" in migration and "memory.propose" in migration
    assert "serialized_registration" in migration
    assert "serialized_batch" not in migration

    roles = (
        ROOT / "deploy" / "postgres" / "production_realm_roles_v1.3.sql.example"
    ).read_text(encoding="utf-8")
    routine = roles.split("-- Normal/private Lucy plus archive ingestion.", 1)[1].split(
        "-- Content-free policy notary.", 1
    )[0]
    policy = roles.split("-- Content-free policy notary.", 1)[1].split(
        "-- Workflow owns", 1
    )[0]
    for function in (
        "read_memory_pilot_transport_admission_v1(text,uuid)",
        "admit_memory_pilot_transport_v1(text,uuid,text,bigint,uuid,text)",
        "require_memory_import_sources_v1(uuid,text,jsonb)",
    ):
        assert function in routine
        assert function not in policy
