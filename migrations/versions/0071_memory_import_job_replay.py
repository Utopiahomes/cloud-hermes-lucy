"""Permit exact durable job replay after settlement without permitting a new job."""

from collections.abc import Sequence

from alembic import op

revision: str = "0071_memory_import_job_replay"
down_revision: str | None = "0070_memory_pilot_transport"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE OR REPLACE FUNCTION lucy.register_memory_import_job_v1(p_job jsonb)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_campaign lucy.memory_import_campaigns_v1%ROWTYPE;
          v_reservation lucy.memory_import_attempt_reservations_v1%ROWTYPE;
          v_existing lucy.memory_import_extraction_jobs_v1%ROWTYPE;
          v_source_count bigint; v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.propose"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import job registration unavailable'; END IF;
          IF jsonb_typeof(p_job)<>'object' OR p_job-ARRAY[
            'contract_version','extraction_job_id','reservation_id','campaign_id',
            'manifest_digest','attempt_key','source_record_ids','request_commitment',
            'request_bytes','input_token_upper_bound','maximum_output_tokens',
            'token_accounting_version','provider_policy_id','model_route','maximum_microusd'
          ]<>'{}'::jsonb OR p_job->>'contract_version'<>'1'
             OR p_job->>'manifest_digest'!~'^[0-9a-f]{64}$'
             OR p_job->>'request_commitment'!~'^[0-9a-f]{64}$'
             OR coalesce(btrim(p_job->>'attempt_key'),'')=''
             OR length(p_job->>'attempt_key')>512
             OR jsonb_typeof(p_job->'source_record_ids')<>'array'
             OR jsonb_array_length(p_job->'source_record_ids')<1
             OR (p_job->>'request_bytes')::bigint<1
             OR (p_job->>'input_token_upper_bound')::bigint<1
             OR (p_job->>'maximum_output_tokens')::bigint<1
             OR (p_job->>'maximum_microusd')::bigint<0
          THEN RAISE EXCEPTION 'memory import job is invalid'; END IF;
          SELECT count(DISTINCT value) INTO v_source_count
          FROM jsonb_array_elements_text(p_job->'source_record_ids');
          IF v_source_count<>jsonb_array_length(p_job->'source_record_ids')
          THEN RAISE EXCEPTION 'memory import job is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-import-job:'||(p_job->>'extraction_job_id'),0));
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-import-reservation:'||(p_job->>'reservation_id'),0));
          SELECT * INTO v_reservation FROM lucy.memory_import_attempt_reservations_v1
          WHERE id=(p_job->>'reservation_id')::uuid
            AND campaign_id=(p_job->>'campaign_id')::uuid
            AND content_scope_id=v_binding.content_scope_id
            AND service_binding_id=v_binding.id
            AND attempt_key=p_job->>'attempt_key'
            AND reserved_microusd=(p_job->>'maximum_microusd')::bigint;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import reservation is unavailable'; END IF;
          SELECT * INTO v_campaign FROM lucy.memory_import_campaigns_v1
          WHERE id=v_reservation.campaign_id
            AND content_scope_id=v_binding.content_scope_id
            AND manifest_digest=p_job->>'manifest_digest'
            AND model_route=p_job->>'model_route'
            AND expires_at>v_now;
          IF NOT FOUND
             OR p_job->>'provider_policy_id'<>v_campaign.serialized_manifest->>'provider_policy_id'
             OR p_job->>'token_accounting_version'<>
                v_campaign.serialized_manifest->>'token_accounting_version'
             OR (p_job->>'request_bytes')::bigint<>
                (p_job->>'input_token_upper_bound')::bigint
             OR (p_job->>'input_token_upper_bound')::bigint>
                (v_campaign.serialized_manifest->>'max_request_input_tokens')::bigint
             OR (p_job->>'maximum_output_tokens')::bigint>
                (v_campaign.serialized_manifest->>'max_request_output_tokens')::bigint
             OR (p_job->>'input_token_upper_bound')::bigint+
                (p_job->>'maximum_output_tokens')::bigint>
                (v_campaign.serialized_manifest->>'max_request_total_tokens')::bigint
          THEN RAISE EXCEPTION 'memory import campaign is unavailable'; END IF;
          PERFORM lucy.require_memory_import_sources_v1(
            v_campaign.id,v_campaign.manifest_digest,p_job->'source_record_ids');
          SELECT * INTO v_existing FROM lucy.memory_import_extraction_jobs_v1
          WHERE id=(p_job->>'extraction_job_id')::uuid
             OR reservation_id=v_reservation.id;
          IF FOUND THEN
            IF v_existing.id<>(p_job->>'extraction_job_id')::uuid
               OR v_existing.reservation_id<>v_reservation.id
               OR v_existing.serialized_job<>p_job
            THEN RAISE EXCEPTION 'memory import job conflict'; END IF;
            RETURN jsonb_build_object('extraction_job_id',v_existing.id,'replayed',true);
          END IF;
          IF EXISTS (SELECT 1 FROM lucy.memory_import_attempt_settlements_v1
                     WHERE reservation_id=v_reservation.id)
          THEN RAISE EXCEPTION 'memory import reservation is unavailable'; END IF;
          INSERT INTO lucy.memory_import_extraction_jobs_v1(
            id,reservation_id,campaign_id,content_scope_id,service_binding_id,
            manifest_digest,attempt_key,source_record_ids,request_commitment,request_bytes,
            input_token_upper_bound,maximum_output_tokens,token_accounting_version,
            provider_policy_id,model_route,maximum_microusd,serialized_job,created_at)
          VALUES ((p_job->>'extraction_job_id')::uuid,v_reservation.id,v_campaign.id,
            v_binding.content_scope_id,v_binding.id,p_job->>'manifest_digest',
            p_job->>'attempt_key',p_job->'source_record_ids',p_job->>'request_commitment',
            (p_job->>'request_bytes')::bigint,(p_job->>'input_token_upper_bound')::bigint,
            (p_job->>'maximum_output_tokens')::bigint,p_job->>'token_accounting_version',
            p_job->>'provider_policy_id',p_job->>'model_route',
            (p_job->>'maximum_microusd')::bigint,p_job,v_now);
          RETURN jsonb_build_object(
            'extraction_job_id',p_job->>'extraction_job_id','replayed',false);
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR character_not_in_repertoire OR numeric_value_out_of_range THEN
          RAISE EXCEPTION 'memory import job is invalid';
        END
        $function$;
        ALTER FUNCTION lucy.register_memory_import_job_v1(jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.register_memory_import_job_v1(jsonb)
          FROM PUBLIC,lucy_app;
        """
    )


def downgrade() -> None:
    raise RuntimeError("durable memory import job replay requires a reviewed forward migration")
