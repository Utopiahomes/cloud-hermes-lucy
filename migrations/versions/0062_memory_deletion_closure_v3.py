"""Build exact V3 deletion targets for imported-memory derivations."""

from __future__ import annotations

from alembic import op

revision: str = "0062_memory_deletion_closure"
down_revision: str | None = "0061_memory_import_revocation"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE FUNCTION lucy.build_scoped_deletion_targets_v3(p_operation_id uuid)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_record lucy.scoped_evidence_records_v2%ROWTYPE;
          v_payload lucy.scoped_evidence_payloads_v2%ROWTYPE;
          v_wrapper lucy.scoped_evidence_wrappers_v2%ROWTYPE;
          v_targets jsonb;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.deletion_manifest.issue"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped deletion closure unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id
            AND target_service_binding_id=v_actor.target_service_binding_id
            AND workflow_actor_binding_id IS NOT NULL
            AND action='evidence.delete' AND state='CLAIMED';
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped deletion closure unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'evidence-derive:'||v_operation.resource_object_id::text,0));
          SELECT * INTO v_record FROM lucy.scoped_evidence_records_v2
          WHERE id=v_operation.resource_object_id
            AND content_scope_id=v_operation.content_scope_id AND status='active';
          IF NOT FOUND OR EXISTS (
            SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2
            WHERE evidence_id=v_operation.resource_object_id
              AND content_scope_id=v_operation.content_scope_id
          ) THEN RAISE EXCEPTION 'scoped deletion root unavailable'; END IF;
          SELECT * INTO STRICT v_payload FROM lucy.scoped_evidence_payloads_v2
          WHERE evidence_id=v_record.id
            AND record_version=v_operation.resource_object_version;
          SELECT * INTO STRICT v_wrapper FROM lucy.scoped_evidence_wrappers_v2
          WHERE evidence_id=v_record.id AND content_scope_id=v_record.content_scope_id
            AND current;

          SELECT jsonb_agg(target ORDER BY target->>'artifact_class',
            target->>'artifact_id',(target->>'artifact_version')::bigint,
            coalesce(target->>'representation_id','')) INTO v_targets
          FROM (
            SELECT jsonb_build_object(
              'artifact_class','encrypted_archive','artifact_id',v_record.id,
              'artifact_version',v_payload.record_version,'root_evidence_id',v_record.id,
              'disposition','destroy_wrapped_key','representation_id',
              v_wrapper.representation_id,'wrapped_key_ref',v_wrapper.wrapped_key_ref,
              'key_registry_id',NULL) target
            UNION
            SELECT DISTINCT jsonb_build_object(
              'artifact_class','memory_candidate','artifact_id',s.candidate_id,
              'artifact_version',s.candidate_version,'root_evidence_id',v_record.id,
              'disposition','invalidate','representation_id',NULL,
              'wrapped_key_ref',NULL,'key_registry_id',NULL) target
            FROM lucy.scoped_memory_candidate_sources_v1 s
            WHERE s.evidence_id=v_record.id
              AND s.content_scope_id=v_record.content_scope_id
            UNION
            SELECT jsonb_build_object(
              'artifact_class','memory_claim','artifact_id',s.claim_id,
              'artifact_version',1,'root_evidence_id',v_record.id,
              'disposition','invalidate','representation_id',NULL,
              'wrapped_key_ref',NULL,'key_registry_id',NULL) target
            FROM lucy.scoped_memory_claim_sources_v2 s
            WHERE s.evidence_id=v_record.id
              AND s.content_scope_id=v_record.content_scope_id
            UNION
            SELECT jsonb_build_object(
              'artifact_class','memory_import_provider_outcome',
              'artifact_id',o.extraction_job_id,
              'artifact_version',(o.serialized_envelope->>'record_version')::bigint,
              'root_evidence_id',v_record.id,
              'disposition','destroy_wrapped_key','representation_id',o.encryption_id,
              'wrapped_key_ref',o.encryption_id,'key_registry_id',o.registry_id) target
            FROM lucy.memory_import_provider_outcomes_v1 o
            JOIN lucy.memory_import_extraction_jobs_v1 j
              ON j.id=o.extraction_job_id AND j.content_scope_id=o.content_scope_id
            JOIN lucy.memory_import_campaigns_v1 c
              ON c.id=j.campaign_id AND c.content_scope_id=j.content_scope_id
            WHERE o.content_scope_id=v_record.content_scope_id AND EXISTS (
              SELECT 1
              FROM jsonb_array_elements_text(j.source_record_ids) source(source_record_id)
              JOIN jsonb_array_elements(c.serialized_manifest->'records') record
                ON record->>'source_record_id'=source.source_record_id
              WHERE coalesce((record->>'included')::boolean,false)
                AND 'memory-import'||chr(58)||c.manifest_digest||chr(58)||
                    (record->>'source_record_id')||chr(58)||'r'||
                    (record->>'source_revision')=v_record.idempotency_key
            )
          ) closure;
          IF jsonb_array_length(v_targets)>90
          THEN RAISE EXCEPTION 'scoped deletion closure exceeds execution bound'; END IF;
          RETURN v_targets;
        EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation
          OR numeric_value_out_of_range THEN
          RAISE EXCEPTION 'scoped deletion closure unavailable';
        END
        $function$;
        ALTER FUNCTION lucy.build_scoped_deletion_targets_v3(uuid)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.build_scoped_deletion_targets_v3(uuid)
          FROM PUBLIC,lucy_app;
        GRANT SELECT ON lucy.memory_import_campaigns_v1,
          lucy.memory_import_extraction_jobs_v1,lucy.memory_import_provider_outcomes_v1,
          lucy.scoped_memory_candidate_sources_v1 TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("memory deletion closure V3 requires a reviewed forward migration")
