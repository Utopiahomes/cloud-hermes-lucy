"""Fail closed on deleted sources during candidate approval and outcome recovery."""

from __future__ import annotations

from alembic import op

revision: str = "0061_memory_import_revocation"
down_revision: str | None = "0060_memory_import_outcomes"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE FUNCTION lucy.reject_ineligible_memory_candidate_approval_v1()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM lucy.scoped_memory_candidate_sources_v1 s
            WHERE s.candidate_id=NEW.candidate_id
              AND s.candidate_version=NEW.candidate_version
              AND (
                NOT EXISTS (
                  SELECT 1 FROM lucy.scoped_evidence_records_v2 e
                  JOIN lucy.scoped_evidence_payloads_v2 p ON p.evidence_id=e.id
                  WHERE e.id=s.evidence_id
                    AND e.content_scope_id=NEW.content_scope_id
                    AND e.status='active' AND p.record_version=s.record_version
                ) OR EXISTS (
                  SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
                  WHERE f.evidence_id=s.evidence_id
                    AND f.content_scope_id=NEW.content_scope_id
                )
              )
          ) THEN RAISE EXCEPTION 'memory candidate source became unavailable'; END IF;
          RETURN NEW;
        END
        $function$;
        ALTER FUNCTION lucy.reject_ineligible_memory_candidate_approval_v1()
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.reject_ineligible_memory_candidate_approval_v1()
          FROM PUBLIC,lucy_app;
        CREATE TRIGGER memory_candidate_approval_source_gate
        BEFORE INSERT ON lucy.scoped_memory_candidate_approvals_v1
        FOR EACH ROW EXECUTE FUNCTION lucy.reject_ineligible_memory_candidate_approval_v1();

        CREATE OR REPLACE FUNCTION lucy.load_memory_import_provider_outcome_v1(p_job_id uuid)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_job lucy.memory_import_extraction_jobs_v1%ROWTYPE; v_value jsonb;
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.propose"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import outcome unavailable'; END IF;
          SELECT * INTO v_job FROM lucy.memory_import_extraction_jobs_v1
          WHERE id=p_job_id AND content_scope_id=v_binding.content_scope_id
            AND service_binding_id=v_binding.id;
          IF NOT FOUND THEN RETURN NULL; END IF;
          PERFORM lucy.require_memory_import_sources_v1(
            v_job.campaign_id,v_job.manifest_digest,v_job.source_record_ids);
          SELECT serialized_envelope INTO v_value
          FROM lucy.memory_import_provider_outcomes_v1
          WHERE extraction_job_id=v_job.id AND content_scope_id=v_binding.content_scope_id
            AND service_binding_id=v_binding.id;
          RETURN v_value;
        END
        $function$;
        ALTER FUNCTION lucy.load_memory_import_provider_outcome_v1(uuid)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.load_memory_import_provider_outcome_v1(uuid)
          FROM PUBLIC,lucy_app;
        """
    )


def downgrade() -> None:
    raise RuntimeError("memory import revocation gates require a reviewed forward migration")
