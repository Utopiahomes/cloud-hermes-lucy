"""Read-only, content-free diagnostics for the exact Raymond pilot recovery job."""

import os
from uuid import UUID

import psycopg
from sqlalchemy.engine import make_url


JOB_ID = UUID("79f96e27-3087-5399-9297-71af75cf288d")
CAMPAIGN_ID = UUID("c1800ec3-1158-42f0-bb0b-46a04df7a65c")
SCOPE_ID = UUID("5ee9fc67-4c46-4416-876e-5e028bf8ae4e")


def main() -> None:
    if os.environ.get("RENDER") != "true" or os.environ.get("LUCY_ENVIRONMENT") != "production":
        raise RuntimeError("Raymond recovery diagnostic requires production Render")
    if os.environ.get("LUCY_RAYMOND_DIAGNOSTIC") != "exact-first-pilot-job-read-only-v1":
        raise RuntimeError("Raymond recovery diagnostic authorization changed")
    raw = os.environ["LUCY_MIGRATION_DATABASE_URL"]
    url = make_url(raw)
    if (url.host, url.database, url.username) != (
        "dpg-dak5bqad0e5s73b2e3d0-a", "lucy_raymond", "lucy_migration"
    ):
        raise RuntimeError("Raymond recovery diagnostic database target changed")
    with psycopg.connect(raw.replace("postgresql+psycopg://", "postgresql://")) as db:
        print("policy actor ready:", db.execute(
            "SELECT EXISTS(SELECT 1 FROM lucy.realm_sensitive_actor_bindings_v1 "
            "WHERE session_login='lucy_raymond_policy' AND actor_role='policy_notary' "
            "AND active AND allowed_actions @> '[\"memory.outcome.recover\"]'::jsonb "
            "AND content_scope_id=%s)", (SCOPE_ID,)
        ).fetchone()[0], flush=True)
        print("authorization ready:", db.execute(
            "SELECT EXISTS(SELECT 1 FROM lucy.memory_import_pilot_authorizations_v1 "
            "WHERE campaign_id=%s AND content_scope_id=%s AND expires_at>clock_timestamp())",
            (CAMPAIGN_ID, SCOPE_ID)
        ).fetchone()[0], flush=True)
        print("job ready:", db.execute(
            "SELECT EXISTS(SELECT 1 FROM lucy.memory_import_extraction_jobs_v1 "
            "WHERE id=%s AND campaign_id=%s AND content_scope_id=%s)",
            (JOB_ID, CAMPAIGN_ID, SCOPE_ID)
        ).fetchone()[0], flush=True)
        print("provider outcome present:", db.execute(
            "SELECT EXISTS(SELECT 1 FROM lucy.memory_import_provider_outcomes_v1 "
            "WHERE extraction_job_id=%s AND content_scope_id=%s)",
            (JOB_ID, SCOPE_ID)
        ).fetchone()[0], flush=True)
        print("attempt settlement present:", db.execute(
            "SELECT EXISTS(SELECT 1 FROM lucy.memory_import_attempt_settlements_v1 s "
            "JOIN lucy.memory_import_extraction_jobs_v1 j ON j.reservation_id=s.reservation_id "
            "WHERE j.id=%s)", (JOB_ID,)
        ).fetchone()[0], flush=True)
        print("attempt settlement state:", db.execute(
            "SELECT s.result,s.billed_microusd FROM lucy.memory_import_attempt_settlements_v1 s "
            "JOIN lucy.memory_import_extraction_jobs_v1 j ON j.reservation_id=s.reservation_id "
            "WHERE j.id=%s", (JOB_ID,)
        ).fetchone(), flush=True)
        print("source count:", db.execute(
            "SELECT jsonb_array_length(source_record_ids) FROM lucy.memory_import_extraction_jobs_v1 "
            "WHERE id=%s", (JOB_ID,)
        ).fetchone()[0], flush=True)
        print("archived source count:", db.execute(
            "SELECT count(*) FROM lucy.memory_import_extraction_jobs_v1 j "
            "CROSS JOIN LATERAL jsonb_array_elements_text(j.source_record_ids) source_id(value) "
            "JOIN lucy.memory_import_campaigns_v1 c ON c.id=j.campaign_id "
            "CROSS JOIN LATERAL jsonb_array_elements(c.serialized_manifest->'records') record "
            "JOIN lucy.scoped_evidence_records_v2 e ON e.content_scope_id=j.content_scope_id "
            "AND e.status='active' AND e.idempotency_key='memory-import'||chr(58)||"
            "j.manifest_digest||chr(58)||(record->>'source_record_id')||chr(58)||"
            "'r'||(record->>'source_revision') "
            "JOIN lucy.scoped_evidence_payloads_v2 ep ON ep.evidence_id=e.id "
            "AND ep.record_version=(record->>'source_revision')::bigint "
            "WHERE j.id=%s AND record->>'source_record_id'=source_id.value "
            "AND coalesce((record->>'included')::boolean,false) "
            "AND NOT EXISTS(SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f "
            "WHERE f.evidence_id=e.id) "
            "AND NOT EXISTS(SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v3 f "
            "WHERE f.evidence_id=e.id AND f.content_scope_id=e.content_scope_id)",
            (JOB_ID,)
        ).fetchone()[0], flush=True)


if __name__ == "__main__":
    main()
