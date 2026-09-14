from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_admission_returns_only_the_exact_registered_authorization_context() -> None:
    migration = (
        ROOT / "migrations" / "versions" / "0072_memory_pilot_auth_context.py"
    ).read_text(encoding="utf-8")

    assert 'down_revision: str | None = "0071_memory_import_job_replay"' in migration
    assert "'authorization',a.serialized_authorization" in migration
    for equality in (
        "a.owner_approval_ref=r.owner_approval_ref",
        "a.campaign_id=r.campaign_id",
        "a.content_scope_id=r.content_scope_id",
        "a.bundle_digest=r.bundle_digest",
        "a.manifest_digest=r.manifest_digest",
    ):
        assert equality in migration
    assert "a.expires_at>clock_timestamp()" in migration
    assert "memory_pilot_transport_revocations_v1" in migration
    assert "service_role='realm_evidence'" in migration
    assert "FROM PUBLIC,lucy_app" in migration
