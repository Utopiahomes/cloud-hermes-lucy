"""Persist encrypted provider outcomes for exact memory import jobs."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0060_memory_import_outcomes"
down_revision: str | None = "0059_memory_import_jobs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "memory_import_provider_outcomes_v1",
        sa.Column("extraction_job_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("service_binding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("encryption_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("registry_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("keyed_commitment", sa.String(64), nullable=False),
        sa.Column("billed_microusd", sa.BigInteger(), nullable=False),
        sa.Column("provider_reference_commitment", sa.String(64), nullable=False),
        sa.Column("serialized_envelope", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["extraction_job_id"], ["lucy.memory_import_extraction_jobs_v1.id"]
        ),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["service_binding_id"], ["lucy.realm_service_bindings_v1.id"]
        ),
        sa.CheckConstraint("billed_microusd >= 0", name="ck_import_outcome_cost"),
        schema="lucy",
    )
    op.execute(
        r"""
        CREATE TRIGGER memory_import_provider_outcomes_v1_immutable
        BEFORE UPDATE OR DELETE ON lucy.memory_import_provider_outcomes_v1
        FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation();

        CREATE FUNCTION lucy.record_memory_import_provider_outcome_v1(p_envelope jsonb)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_job lucy.memory_import_extraction_jobs_v1%ROWTYPE;
          v_existing lucy.memory_import_provider_outcomes_v1%ROWTYPE;
          v_exact jsonb; v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.propose"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import outcome unavailable'; END IF;
          IF jsonb_typeof(p_envelope)<>'object' OR p_envelope-ARRAY[
            'contract_version','binding','encryption_id','registry_id','algorithm',
            'encryption_context_version','record_version','storage_epoch','registry_epoch',
            'key_epoch','ciphertext_b64','content_nonce_b64','keyed_commitment',
            'billed_microusd','provider_reference_commitment']<>'{}'::jsonb
             OR p_envelope->>'contract_version'<>'1'
             OR jsonb_typeof(p_envelope->'binding')<>'object'
             OR p_envelope->>'keyed_commitment'!~'^[0-9a-f]{64}$'
             OR p_envelope->>'provider_reference_commitment'!~'^[0-9a-f]{64}$'
             OR (p_envelope->>'billed_microusd')::bigint<0
             OR coalesce(p_envelope->>'ciphertext_b64','')=''
             OR octet_length(decode(p_envelope->>'ciphertext_b64','base64'))<=16
             OR coalesce(p_envelope->>'content_nonce_b64','')=''
             OR length(decode(p_envelope->>'content_nonce_b64','base64'))<>12
             OR p_envelope->>'algorithm' NOT IN
                ('AES-256-GCM+AES-KW-GCM','AES-256-GCM+AWS-KMS')
             OR (p_envelope->>'encryption_context_version')::bigint<1
             OR (p_envelope->>'record_version')::bigint<1
             OR (p_envelope->>'storage_epoch')::bigint<1
             OR (p_envelope->>'registry_epoch')::bigint<1
             OR (p_envelope->>'key_epoch')::bigint<1
          THEN RAISE EXCEPTION 'memory import outcome is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-import-job:'||(p_envelope->'binding'->>'extraction_job_id'),0));
          SELECT * INTO v_job FROM lucy.memory_import_extraction_jobs_v1
          WHERE id=(p_envelope->'binding'->>'extraction_job_id')::uuid
            AND content_scope_id=v_binding.content_scope_id
            AND service_binding_id=v_binding.id;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import job is unavailable'; END IF;
          IF NOT EXISTS (
            SELECT 1 FROM lucy.realm_content_scopes_v1 s
            WHERE s.id=v_job.content_scope_id
              AND s.storage_epoch=(p_envelope->>'storage_epoch')::bigint
          ) THEN RAISE EXCEPTION 'memory import outcome storage epoch is stale'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-import-reservation:'||v_job.reservation_id::text,0));
          v_exact:=jsonb_build_object(
            'contract_version','1','extraction_job_id',v_job.id::text,
            'reservation_id',v_job.reservation_id::text,'campaign_id',v_job.campaign_id::text,
            'destination_content_scope_id',v_job.content_scope_id::text,
            'manifest_digest',v_job.manifest_digest,'attempt_key',v_job.attempt_key,
            'source_record_ids',v_job.source_record_ids,
            'request_commitment',v_job.request_commitment,
            'provider_policy_id',v_job.provider_policy_id,'model_route',v_job.model_route,
            'maximum_microusd',v_job.maximum_microusd);
          IF p_envelope->'binding'<>v_exact
             OR (p_envelope->>'billed_microusd')::bigint>v_job.maximum_microusd
          THEN RAISE EXCEPTION 'memory import outcome binding is invalid'; END IF;
          SELECT * INTO v_existing FROM lucy.memory_import_provider_outcomes_v1
          WHERE extraction_job_id=v_job.id;
          IF FOUND THEN
            IF v_existing.serialized_envelope<>p_envelope
            THEN RAISE EXCEPTION 'memory import outcome conflict'; END IF;
            RETURN v_existing.serialized_envelope;
          END IF;
          IF EXISTS (SELECT 1 FROM lucy.memory_import_attempt_settlements_v1
                     WHERE reservation_id=v_job.reservation_id)
          THEN RAISE EXCEPTION 'memory import outcome arrived after settlement'; END IF;
          INSERT INTO lucy.memory_import_provider_outcomes_v1(
            extraction_job_id,content_scope_id,service_binding_id,encryption_id,registry_id,
            keyed_commitment,billed_microusd,provider_reference_commitment,
            serialized_envelope,created_at)
          VALUES (v_job.id,v_job.content_scope_id,v_job.service_binding_id,
            (p_envelope->>'encryption_id')::uuid,(p_envelope->>'registry_id')::uuid,
            p_envelope->>'keyed_commitment',(p_envelope->>'billed_microusd')::bigint,
            p_envelope->>'provider_reference_commitment',p_envelope,v_now);
          RETURN p_envelope;
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR character_not_in_repertoire OR numeric_value_out_of_range THEN
          RAISE EXCEPTION 'memory import outcome is invalid';
        END
        $function$;

        CREATE FUNCTION lucy.load_memory_import_provider_outcome_v1(p_job_id uuid)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE; v_value jsonb;
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.propose"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import outcome unavailable'; END IF;
          SELECT o.serialized_envelope INTO v_value
          FROM lucy.memory_import_provider_outcomes_v1 o
          JOIN lucy.memory_import_extraction_jobs_v1 j ON j.id=o.extraction_job_id
          WHERE o.extraction_job_id=p_job_id
            AND o.content_scope_id=v_binding.content_scope_id
            AND o.service_binding_id=v_binding.id
            AND j.content_scope_id=v_binding.content_scope_id
            AND j.service_binding_id=v_binding.id;
          RETURN v_value;
        END
        $function$;
        ALTER FUNCTION lucy.record_memory_import_provider_outcome_v1(jsonb)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.load_memory_import_provider_outcome_v1(uuid)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.record_memory_import_provider_outcome_v1(jsonb),
          lucy.load_memory_import_provider_outcome_v1(uuid) FROM PUBLIC,lucy_app;
        REVOKE ALL ON lucy.memory_import_provider_outcomes_v1 FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.memory_import_provider_outcomes_v1
          TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("memory import provider outcomes require a reviewed forward migration")
