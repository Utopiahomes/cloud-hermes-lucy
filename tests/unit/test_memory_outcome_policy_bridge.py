from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_migration_requires_exact_operator_authorization_and_policy_execute_only() -> None:
    migration = (
        ROOT / "migrations" / "versions" / "0069_memory_outcome_policy_bridge.py"
    ).read_text(encoding="utf-8")

    assert 'down_revision: str | None = "0068_workspaces_service_auth"' in migration
    assert "pg_has_role(session_user,'lucy_migration','MEMBER')" in migration
    assert "serialized_authorization=p_auth" in migration
    assert "serialized_envelope=p_package->'envelope'" in migration
    assert "memory.outcome.recover" in migration
    assert "memory outcome source is ineligible" in migration
    assert (
        "GRANT EXECUTE ON FUNCTION "
        "lucy.register_memory_import_pilot_authorization_v1(jsonb)"
    ) in migration
    assert "TO lucy_migration" in migration


def test_production_roles_expose_only_exact_bridge_functions() -> None:
    roles = (
        ROOT / "deploy" / "postgres" / "production_realm_roles_v1.3.sql.example"
    ).read_text(encoding="utf-8")

    policy_section = roles.split("-- Content-free policy notary.", 1)[1].split(
        "-- Workflow owns", 1
    )[0]
    routine_section = roles.split("-- Normal/private Lucy plus archive ingestion.", 1)[1].split(
        "-- Content-free policy notary.", 1
    )[0]
    for function in (
        "admit_memory_outcome_recovery_v1(jsonb,jsonb,text,text)",
        "read_memory_outcome_recovery_grant_v1(text)",
        "record_memory_outcome_recovery_grant_v1(text,text,jsonb)",
    ):
        assert function in policy_section
        assert function not in routine_section
    assert "load_memory_import_provider_outcome_v1(uuid)" in routine_section
    assert "load_memory_import_provider_outcome_v1(uuid)" not in policy_section
