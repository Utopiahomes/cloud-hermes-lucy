"""Add content-free, capability-scoped admission for pilot batch transport."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0070_memory_pilot_transport"
down_revision: str | None = "0069_memory_outcome_policy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "memory_pilot_transport_registrations_v1",
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("owner_approval_ref", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("bundle_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("manifest_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("transfer_key_commitment", sa.String(64), nullable=False),
        sa.Column("capability_token_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("maximum_transport_bytes", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("serialized_registration", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["owner_approval_ref"],
            ["lucy.memory_import_pilot_authorizations_v1.owner_approval_ref"],
        ),
        sa.ForeignKeyConstraint(["campaign_id"], ["lucy.memory_import_campaigns_v1.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.CheckConstraint("maximum_transport_bytes > 0"),
        schema="lucy",
    )
    op.create_table(
        "memory_pilot_transport_batches_v1",
        sa.Column("batch_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("batch_index", sa.BigInteger(), nullable=False),
        sa.Column("extraction_job_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("attempt_key", sa.String(512), nullable=False),
        sa.Column("source_record_ids", postgresql.JSONB(), nullable=False),
        sa.Column("request_commitment", sa.String(64), nullable=False),
        sa.Column("transport_commitment", sa.String(64), nullable=False, unique=True),
        sa.Column("transport_bytes", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["campaign_id"], ["lucy.memory_pilot_transport_registrations_v1.campaign_id"]
        ),
        sa.UniqueConstraint("campaign_id", "batch_index"),
        sa.CheckConstraint("batch_index > 0"),
        sa.CheckConstraint("transport_bytes > 0"),
        schema="lucy",
    )
    op.create_table(
        "memory_pilot_transport_revocations_v1",
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("revocation_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("reason_commitment", sa.String(64), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["campaign_id"], ["lucy.memory_pilot_transport_registrations_v1.campaign_id"]
        ),
        schema="lucy",
    )
    op.create_table(
        "memory_pilot_transport_admissions_v1",
        sa.Column("batch_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("service_binding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("extraction_job_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("transport_commitment", sa.String(64), nullable=False),
        sa.Column("admitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["batch_id"], ["lucy.memory_pilot_transport_batches_v1.batch_id"]
        ),
        sa.ForeignKeyConstraint(["campaign_id"], ["lucy.memory_import_campaigns_v1.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["service_binding_id"], ["lucy.realm_service_bindings_v1.id"]
        ),
        schema="lucy",
    )
    for name in (
        "memory_pilot_transport_registrations_v1",
        "memory_pilot_transport_batches_v1",
        "memory_pilot_transport_revocations_v1",
        "memory_pilot_transport_admissions_v1",
    ):
        op.execute(
            f"CREATE TRIGGER {name}_immutable BEFORE UPDATE OR DELETE ON lucy.{name} "
            "FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
        )

    op.execute(
        r"""
        CREATE FUNCTION lucy.register_memory_pilot_transport_v1(p_registration jsonb)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_auth lucy.memory_import_pilot_authorizations_v1%ROWTYPE;
          v_existing lucy.memory_pilot_transport_registrations_v1%ROWTYPE;
          v_batch jsonb; v_index bigint:=0; v_total bigint:=0;
          v_now timestamptz:=clock_timestamp();
        BEGIN
          IF NOT pg_has_role(session_user,'lucy_migration','MEMBER')
             OR jsonb_typeof(p_registration)<>'object'
             OR p_registration-ARRAY['contract_version','object_type','owner_approval_ref',
               'campaign_id','destination_content_scope_id','bundle_digest','manifest_digest',
               'transfer_key_commitment','capability_token_digest','maximum_transport_bytes',
               'expires_at','batches']<>'{}'::jsonb
             OR p_registration->>'contract_version'<>'1'
             OR p_registration->>'object_type'<>'lucy.memory-pilot-transport-registration.v1'
             OR p_registration->>'transfer_key_commitment'!~'^[0-9a-f]{64}$'
             OR p_registration->>'capability_token_digest'!~'^[0-9a-f]{64}$'
             OR p_registration->>'bundle_digest'!~'^[0-9a-f]{64}$'
             OR p_registration->>'manifest_digest'!~'^[0-9a-f]{64}$'
             OR jsonb_typeof(p_registration->'batches')<>'array'
             OR jsonb_array_length(p_registration->'batches')<1
          THEN RAISE EXCEPTION 'memory pilot transport registration is invalid'; END IF;
          SELECT * INTO v_auth FROM lucy.memory_import_pilot_authorizations_v1
          WHERE owner_approval_ref=(p_registration->>'owner_approval_ref')::uuid
            AND campaign_id=(p_registration->>'campaign_id')::uuid
            AND content_scope_id=(p_registration->>'destination_content_scope_id')::uuid
            AND bundle_digest=p_registration->>'bundle_digest'
            AND manifest_digest=p_registration->>'manifest_digest'
            AND expires_at>= (p_registration->>'expires_at')::timestamptz
            AND expires_at>v_now;
          IF NOT FOUND OR (p_registration->>'expires_at')::timestamptz<=v_now
             OR (p_registration->>'maximum_transport_bytes')::bigint<1
          THEN RAISE EXCEPTION 'memory pilot transport registration is unavailable'; END IF;
          FOR v_batch IN SELECT value FROM jsonb_array_elements(p_registration->'batches') LOOP
            v_index:=v_index+1;
            IF v_batch-ARRAY['batch_id','batch_index','extraction_job_id','attempt_key',
                 'source_record_ids','request_commitment','transport_commitment',
                 'transport_bytes']<>'{}'::jsonb
               OR (v_batch->>'batch_index')::bigint<>v_index
               OR coalesce(btrim(v_batch->>'attempt_key'),'')=''
               OR length(v_batch->>'attempt_key')>512
               OR jsonb_typeof(v_batch->'source_record_ids')<>'array'
               OR jsonb_array_length(v_batch->'source_record_ids')<1
               OR v_batch->>'request_commitment'!~'^[0-9a-f]{64}$'
               OR v_batch->>'transport_commitment'!~'^[0-9a-f]{64}$'
               OR (v_batch->>'transport_bytes')::bigint<1
            THEN RAISE EXCEPTION 'memory pilot transport batch is invalid'; END IF;
            v_total:=v_total+(v_batch->>'transport_bytes')::bigint;
          END LOOP;
          IF v_total<>(p_registration->>'maximum_transport_bytes')::bigint
          THEN RAISE EXCEPTION 'memory pilot transport byte ceiling is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-pilot-transport:'||v_auth.campaign_id::text,0));
          SELECT * INTO v_existing FROM lucy.memory_pilot_transport_registrations_v1
          WHERE campaign_id=v_auth.campaign_id;
          IF FOUND THEN
            IF v_existing.serialized_registration<>p_registration
            THEN RAISE EXCEPTION 'memory pilot transport registration conflict'; END IF;
            RETURN jsonb_build_object('campaign_id',v_existing.campaign_id,'replayed',true);
          END IF;
          INSERT INTO lucy.memory_pilot_transport_registrations_v1(
            campaign_id,owner_approval_ref,content_scope_id,bundle_digest,manifest_digest,
            transfer_key_commitment,capability_token_digest,maximum_transport_bytes,
            expires_at,serialized_registration,created_at)
          VALUES(v_auth.campaign_id,v_auth.owner_approval_ref,v_auth.content_scope_id,
            v_auth.bundle_digest,v_auth.manifest_digest,
            p_registration->>'transfer_key_commitment',
            p_registration->>'capability_token_digest',
            (p_registration->>'maximum_transport_bytes')::bigint,
            (p_registration->>'expires_at')::timestamptz,p_registration,v_now);
          INSERT INTO lucy.memory_pilot_transport_batches_v1(
            batch_id,campaign_id,batch_index,extraction_job_id,attempt_key,source_record_ids,
            request_commitment,transport_commitment,transport_bytes)
          SELECT (value->>'batch_id')::uuid,v_auth.campaign_id,
            (value->>'batch_index')::bigint,(value->>'extraction_job_id')::uuid,
            value->>'attempt_key',value->'source_record_ids',value->>'request_commitment',
            value->>'transport_commitment',(value->>'transport_bytes')::bigint
          FROM jsonb_array_elements(p_registration->'batches');
          RETURN jsonb_build_object('campaign_id',v_auth.campaign_id,'replayed',false);
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR character_not_in_repertoire OR numeric_value_out_of_range
          THEN RAISE EXCEPTION 'memory pilot transport registration is invalid';
        END $function$;

        CREATE FUNCTION lucy.read_memory_pilot_transport_admission_v1(
          p_capability_digest text,p_batch_id uuid
        ) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE; v_result jsonb;
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND service_role='realm_evidence' AND active
            AND allowed_actions @> '["evidence.archive","memory.propose"]'::jsonb;
          SELECT jsonb_build_object(
            'campaign_id',r.campaign_id,'owner_approval_ref',r.owner_approval_ref,
            'destination_content_scope_id',r.content_scope_id,
            'bundle_digest',r.bundle_digest,'manifest_digest',r.manifest_digest,
            'transfer_key_commitment',r.transfer_key_commitment,'expires_at',r.expires_at,
            'manifest',c.serialized_manifest,
            'batch',jsonb_build_object('batch_id',b.batch_id,'batch_index',b.batch_index,
              'extraction_job_id',b.extraction_job_id,'attempt_key',b.attempt_key,
              'source_record_ids',b.source_record_ids,
              'request_commitment',b.request_commitment,
              'transport_commitment',b.transport_commitment,
              'transport_bytes',b.transport_bytes)) INTO v_result
          FROM lucy.memory_pilot_transport_registrations_v1 r
          JOIN lucy.memory_pilot_transport_batches_v1 b ON b.campaign_id=r.campaign_id
          JOIN lucy.memory_import_campaigns_v1 c ON c.id=r.campaign_id
          WHERE r.capability_token_digest=p_capability_digest AND b.batch_id=p_batch_id
            AND r.content_scope_id=v_binding.content_scope_id AND r.expires_at>clock_timestamp()
            AND NOT EXISTS(SELECT 1 FROM lucy.memory_pilot_transport_revocations_v1 x
                           WHERE x.campaign_id=r.campaign_id);
          IF v_binding.id IS NULL OR v_result IS NULL
          THEN RAISE EXCEPTION 'memory pilot transport admission unavailable'; END IF;
          RETURN v_result;
        END $function$;

        CREATE FUNCTION lucy.admit_memory_pilot_transport_v1(
          p_capability_digest text,p_batch_id uuid,p_transport_commitment text,
          p_transport_bytes bigint,p_extraction_job_id uuid,p_request_commitment text
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_registration lucy.memory_pilot_transport_registrations_v1%ROWTYPE;
          v_batch lucy.memory_pilot_transport_batches_v1%ROWTYPE;
          v_existing lucy.memory_pilot_transport_admissions_v1%ROWTYPE;
          v_campaign_id uuid;
        BEGIN
          SELECT campaign_id INTO v_campaign_id
          FROM lucy.memory_pilot_transport_registrations_v1
          WHERE capability_token_digest=p_capability_digest;
          IF v_campaign_id IS NULL
          THEN RAISE EXCEPTION 'memory pilot transport admission unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-pilot-transport:'||v_campaign_id::text,0));
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND service_role='realm_evidence' AND active
            AND allowed_actions @> '["evidence.archive","memory.propose"]'::jsonb;
          SELECT * INTO v_registration FROM lucy.memory_pilot_transport_registrations_v1
          WHERE capability_token_digest=p_capability_digest
            AND campaign_id=v_campaign_id
            AND content_scope_id=v_binding.content_scope_id
            AND expires_at>clock_timestamp()
            AND NOT EXISTS(SELECT 1 FROM lucy.memory_pilot_transport_revocations_v1 x
                           WHERE x.campaign_id=memory_pilot_transport_registrations_v1.campaign_id);
          SELECT * INTO v_batch FROM lucy.memory_pilot_transport_batches_v1
          WHERE batch_id=p_batch_id AND campaign_id=v_registration.campaign_id
            AND transport_commitment=p_transport_commitment
            AND transport_bytes=p_transport_bytes
            AND extraction_job_id=p_extraction_job_id
            AND request_commitment=p_request_commitment;
          IF v_binding.id IS NULL OR v_registration.campaign_id IS NULL OR v_batch.batch_id IS NULL
          THEN RAISE EXCEPTION 'memory pilot transport admission unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-pilot-transport-batch:'||p_batch_id::text,0));
          IF v_registration.expires_at<=clock_timestamp()
             OR NOT EXISTS(SELECT 1 FROM lucy.realm_service_bindings_v1
               WHERE id=v_binding.id AND session_login=session_user
                 AND service_role='realm_evidence' AND active
                 AND allowed_actions @> '["evidence.archive","memory.propose"]'::jsonb)
             OR EXISTS(SELECT 1 FROM lucy.memory_pilot_transport_revocations_v1
                       WHERE campaign_id=v_registration.campaign_id)
          THEN RAISE EXCEPTION 'memory pilot transport admission unavailable'; END IF;
          SELECT * INTO v_existing FROM lucy.memory_pilot_transport_admissions_v1
          WHERE batch_id=p_batch_id;
          IF FOUND THEN
            IF v_existing.service_binding_id<>v_binding.id
               OR v_existing.transport_commitment<>p_transport_commitment
            THEN RAISE EXCEPTION 'memory pilot transport admission conflict'; END IF;
            RETURN jsonb_build_object('batch_id',p_batch_id,'admitted_at',
              v_existing.admitted_at,'replayed',true);
          END IF;
          INSERT INTO lucy.memory_pilot_transport_admissions_v1(
            batch_id,campaign_id,content_scope_id,service_binding_id,extraction_job_id,
            transport_commitment,admitted_at)
          VALUES(p_batch_id,v_registration.campaign_id,v_registration.content_scope_id,
            v_binding.id,v_batch.extraction_job_id,p_transport_commitment,clock_timestamp())
          RETURNING * INTO v_existing;
          RETURN jsonb_build_object('batch_id',p_batch_id,'admitted_at',
            v_existing.admitted_at,'replayed',false);
        END $function$;

        CREATE FUNCTION lucy.revoke_memory_pilot_transport_v1(
          p_campaign_id uuid,p_revocation_id uuid,p_reason_commitment text
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_existing lucy.memory_pilot_transport_revocations_v1%ROWTYPE;
        BEGIN
          IF NOT pg_has_role(session_user,'lucy_migration','MEMBER')
             OR p_reason_commitment!~'^[0-9a-f]{64}$'
             OR NOT EXISTS(SELECT 1 FROM lucy.memory_pilot_transport_registrations_v1
                           WHERE campaign_id=p_campaign_id)
          THEN RAISE EXCEPTION 'memory pilot transport revocation is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-pilot-transport:'||p_campaign_id::text,0));
          SELECT * INTO v_existing FROM lucy.memory_pilot_transport_revocations_v1
          WHERE campaign_id=p_campaign_id;
          IF FOUND THEN
            IF v_existing.revocation_id<>p_revocation_id
               OR v_existing.reason_commitment<>p_reason_commitment
            THEN RAISE EXCEPTION 'memory pilot transport revocation conflict'; END IF;
            RETURN jsonb_build_object('campaign_id',p_campaign_id,
              'revoked_at',v_existing.revoked_at,'replayed',true);
          END IF;
          INSERT INTO lucy.memory_pilot_transport_revocations_v1(
            campaign_id,revocation_id,reason_commitment,revoked_at)
          VALUES(p_campaign_id,p_revocation_id,p_reason_commitment,clock_timestamp())
          RETURNING * INTO v_existing;
          RETURN jsonb_build_object('campaign_id',p_campaign_id,
            'revoked_at',v_existing.revoked_at,'replayed',false);
        END $function$;

        ALTER FUNCTION lucy.register_memory_pilot_transport_v1(jsonb)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.read_memory_pilot_transport_admission_v1(text,uuid)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.admit_memory_pilot_transport_v1(text,uuid,text,bigint,uuid,text)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.revoke_memory_pilot_transport_v1(uuid,uuid,text)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.register_memory_pilot_transport_v1(jsonb),
          lucy.read_memory_pilot_transport_admission_v1(text,uuid),
          lucy.admit_memory_pilot_transport_v1(text,uuid,text,bigint,uuid,text),
          lucy.revoke_memory_pilot_transport_v1(uuid,uuid,text)
          FROM PUBLIC,lucy_app;
        GRANT EXECUTE ON FUNCTION lucy.register_memory_pilot_transport_v1(jsonb),
          lucy.revoke_memory_pilot_transport_v1(uuid,uuid,text) TO lucy_migration;
        DO $grant$
        DECLARE v_login text;
        BEGIN
          FOR v_login IN SELECT session_login FROM lucy.realm_service_bindings_v1
            WHERE service_role='realm_evidence'
              AND allowed_actions @> '["evidence.archive","memory.propose"]'::jsonb LOOP
            EXECUTE format('GRANT EXECUTE ON FUNCTION '
              'lucy.read_memory_pilot_transport_admission_v1(text,uuid) TO %I',v_login);
            EXECUTE format('GRANT EXECUTE ON FUNCTION '
              'lucy.admit_memory_pilot_transport_v1(text,uuid,text,bigint,uuid,text) TO %I',
              v_login);
          END LOOP;
        END $grant$;
        REVOKE ALL ON lucy.memory_pilot_transport_registrations_v1,
          lucy.memory_pilot_transport_batches_v1,
          lucy.memory_pilot_transport_revocations_v1,
          lucy.memory_pilot_transport_admissions_v1 FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.memory_pilot_transport_registrations_v1,
          lucy.memory_pilot_transport_batches_v1,
          lucy.memory_pilot_transport_revocations_v1,
          lucy.memory_pilot_transport_admissions_v1 TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("memory pilot transport admission requires a reviewed forward migration")
