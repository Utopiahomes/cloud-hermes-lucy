"""Add exact realm-scoped source eligibility for memory import execution."""

from __future__ import annotations

from alembic import op

revision: str = "0058_memory_import_eligibility"
down_revision: str | None = "0057_public_conversation"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE FUNCTION lucy.require_memory_import_sources_v1(
          p_campaign_id uuid,p_manifest_digest text,p_source_record_ids jsonb
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_campaign lucy.memory_import_campaigns_v1%ROWTYPE;
          v_requested text[]; v_source text; v_evidence_id uuid; v_distinct bigint;
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.propose"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import source eligibility unavailable'; END IF;
          IF p_manifest_digest!~'^[0-9a-f]{64}$'
             OR jsonb_typeof(p_source_record_ids)<>'array'
             OR jsonb_array_length(p_source_record_ids)<1
          THEN RAISE EXCEPTION 'memory import source eligibility is invalid'; END IF;
          SELECT array_agg(value ORDER BY ordinal),count(DISTINCT value)
            INTO v_requested,v_distinct
          FROM jsonb_array_elements_text(p_source_record_ids) WITH ORDINALITY item(value,ordinal);
          IF cardinality(v_requested)<>v_distinct
          THEN RAISE EXCEPTION 'memory import source eligibility is invalid'; END IF;
          SELECT * INTO v_campaign FROM lucy.memory_import_campaigns_v1
          WHERE id=p_campaign_id AND content_scope_id=v_binding.content_scope_id
            AND manifest_digest=p_manifest_digest AND expires_at>clock_timestamp();
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import campaign is unavailable'; END IF;
          FOREACH v_source IN ARRAY v_requested LOOP
            IF coalesce(btrim(v_source),'')='' OR length(v_source)>512
            THEN RAISE EXCEPTION 'memory import source eligibility is invalid'; END IF;
            v_evidence_id:=NULL;
            SELECT e.id INTO v_evidence_id
            FROM jsonb_array_elements(v_campaign.serialized_manifest->'records') record
            JOIN lucy.scoped_evidence_records_v2 e
              ON e.content_scope_id=v_campaign.content_scope_id AND e.status='active'
             AND e.idempotency_key='memory-import'||chr(58)||v_campaign.manifest_digest||
               chr(58)||(record->>'source_record_id')||chr(58)||'r'||
               (record->>'source_revision')
            JOIN lucy.scoped_evidence_payloads_v2 p
              ON p.evidence_id=e.id
             AND p.record_version=(record->>'source_revision')::bigint
            WHERE record->>'source_record_id'=v_source
              AND coalesce((record->>'included')::boolean,false)
              AND NOT EXISTS (
                SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
                WHERE f.evidence_id=e.id);
            IF v_evidence_id IS NULL
            THEN RAISE EXCEPTION 'memory import source is ineligible'; END IF;
          END LOOP;
          RETURN jsonb_build_object('eligible',true,'source_count',cardinality(v_requested));
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR character_not_in_repertoire OR numeric_value_out_of_range THEN
          RAISE EXCEPTION 'memory import source eligibility is invalid';
        END
        $function$;
        ALTER FUNCTION lucy.require_memory_import_sources_v1(uuid,text,jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.require_memory_import_sources_v1(uuid,text,jsonb)
          FROM PUBLIC,lucy_app;
        GRANT SELECT ON lucy.memory_import_campaigns_v1,
          lucy.realm_service_bindings_v1,lucy.scoped_evidence_records_v2,
          lucy.scoped_evidence_payloads_v2,lucy.scoped_evidence_deletion_fences_v2
          TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("memory import source eligibility requires a reviewed forward migration")
