"""Enforce cumulative governed-memory import campaign spend and retry limits."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0056_memory_import_budget"
down_revision: str | None = "0055_memory_candidate_governance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "memory_import_campaigns_v1",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_actor_binding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("manifest_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("serialized_manifest", postgresql.JSONB(), nullable=False),
        sa.Column("extractor_version", sa.String(100), nullable=False),
        sa.Column("prompt_version", sa.String(100), nullable=False),
        sa.Column("model_route", sa.String(200), nullable=False),
        sa.Column("max_model_spend_microusd", sa.BigInteger(), nullable=False),
        sa.Column("max_attempts", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["policy_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.CheckConstraint(
            "max_model_spend_microusd >= 0", name="ck_import_campaign_spend"
        ),
        sa.CheckConstraint("max_attempts > 0", name="ck_import_campaign_attempts"),
        schema="lucy",
    )
    op.create_table(
        "memory_import_attempt_reservations_v1",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("service_binding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("attempt_key", sa.String(512), nullable=False),
        sa.Column("reserved_microusd", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["lucy.memory_import_campaigns_v1.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["service_binding_id"], ["lucy.realm_service_bindings_v1.id"]
        ),
        sa.UniqueConstraint("campaign_id", "attempt_key", name="uq_import_attempt_key"),
        sa.CheckConstraint("reserved_microusd >= 0", name="ck_import_attempt_reservation"),
        schema="lucy",
    )
    op.create_table(
        "memory_import_attempt_settlements_v1",
        sa.Column("reservation_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("billed_microusd", sa.BigInteger(), nullable=False),
        sa.Column("result", sa.String(30), nullable=False),
        sa.Column("settled_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["reservation_id"], ["lucy.memory_import_attempt_reservations_v1.id"]
        ),
        sa.ForeignKeyConstraint(["campaign_id"], ["lucy.memory_import_campaigns_v1.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.CheckConstraint("billed_microusd >= 0", name="ck_import_attempt_billed"),
        sa.CheckConstraint(
            "result IN ('succeeded','failed','discarded')", name="ck_import_attempt_result"
        ),
        schema="lucy",
    )
    for name in (
        "memory_import_campaigns_v1",
        "memory_import_attempt_reservations_v1",
        "memory_import_attempt_settlements_v1",
    ):
        op.execute(
            f"CREATE TRIGGER {name}_immutable BEFORE UPDATE OR DELETE ON lucy.{name} "
            "FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
        )

    op.execute(
        r"""
        CREATE FUNCTION lucy.authorize_memory_import_campaign_v1(
          p_campaign_id uuid,p_manifest jsonb,p_manifest_digest text,
          p_max_model_spend_microusd bigint,
          p_max_attempts bigint,p_expires_at timestamptz,p_extractor_version text,
          p_prompt_version text,p_model_route text
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_existing lucy.memory_import_campaigns_v1%ROWTYPE; v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["memory.candidate.approve"]'::jsonb;
          IF NOT FOUND THEN
            RAISE EXCEPTION 'memory import campaign authorization unavailable';
          END IF;
          IF p_manifest_digest!~'^[0-9a-f]{64}$' OR p_max_model_spend_microusd<0
             OR p_max_attempts<1 OR p_expires_at<=v_now
             OR coalesce(btrim(p_extractor_version),'')='' OR length(p_extractor_version)>100
             OR coalesce(btrim(p_prompt_version),'')='' OR length(p_prompt_version)>100
             OR coalesce(btrim(p_model_route),'')='' OR length(p_model_route)>200
             OR jsonb_typeof(p_manifest)<>'object'
             OR (p_manifest->>'campaign_id')::uuid<>p_campaign_id
             OR (p_manifest->>'destination_content_scope_id')::uuid<>v_actor.content_scope_id
             OR jsonb_typeof(p_manifest->'records')<>'array'
             OR jsonb_array_length(p_manifest->'records')<1
          THEN RAISE EXCEPTION 'memory import campaign authorization is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-import-campaign:'||p_campaign_id::text,0));
          SELECT * INTO v_existing FROM lucy.memory_import_campaigns_v1 WHERE id=p_campaign_id;
          IF FOUND THEN
            IF v_existing.content_scope_id<>v_actor.content_scope_id
               OR v_existing.manifest_digest<>p_manifest_digest
               OR v_existing.serialized_manifest<>p_manifest
               OR v_existing.max_model_spend_microusd<>p_max_model_spend_microusd
               OR v_existing.max_attempts<>p_max_attempts OR v_existing.expires_at<>p_expires_at
               OR v_existing.extractor_version<>p_extractor_version
               OR v_existing.prompt_version<>p_prompt_version
               OR v_existing.model_route<>p_model_route
            THEN RAISE EXCEPTION 'memory import campaign authorization conflict'; END IF;
            RETURN jsonb_build_object('campaign_id',v_existing.id,'replayed',true);
          END IF;
          INSERT INTO lucy.memory_import_campaigns_v1(
            id,content_scope_id,policy_actor_binding_id,manifest_digest,serialized_manifest,
            extractor_version,prompt_version,model_route,max_model_spend_microusd,
            max_attempts,expires_at,created_at)
          VALUES (p_campaign_id,v_actor.content_scope_id,v_actor.id,p_manifest_digest,p_manifest,
            p_extractor_version,p_prompt_version,p_model_route,p_max_model_spend_microusd,
            p_max_attempts,p_expires_at,v_now);
          RETURN jsonb_build_object('campaign_id',p_campaign_id,'replayed',false);
        END
        $function$;

        CREATE FUNCTION lucy.register_memory_import_evidence_v1(
          p_campaign_id uuid,p_source_record_id text,p_payload jsonb,p_wrapper jsonb
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_campaign lucy.memory_import_campaigns_v1%ROWTYPE;
          v_record jsonb; v_header jsonb; v_idempotency_key text;
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["evidence.archive","memory.propose"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import archive unavailable'; END IF;
          SELECT * INTO v_campaign FROM lucy.memory_import_campaigns_v1
          WHERE id=p_campaign_id AND content_scope_id=v_binding.content_scope_id
            AND expires_at>clock_timestamp();
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import campaign is unavailable'; END IF;
          SELECT value INTO v_record
          FROM jsonb_array_elements(v_campaign.serialized_manifest->'records')
          WHERE value->>'source_record_id'=p_source_record_id
            AND coalesce((value->>'included')::boolean,false);
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import record is outside manifest'; END IF;
          v_header:=convert_from(
            decode(p_payload->>'authenticated_header_b64','base64'),'UTF8')::jsonb;
          IF jsonb_typeof(v_header)<>'object' OR v_header-ARRAY[
            'contract_version','manifest_digest','source_namespace','source_record_id',
            'content_commitment','byte_length','source_revision','role',
            'parent_source_record_id','displayed','destination_content_scope_id',
            'protection_class']<>'{}'::jsonb
             OR v_header->>'contract_version'<>'1'
             OR v_header->>'manifest_digest'<>v_campaign.manifest_digest
             OR v_header->>'source_record_id'<>p_source_record_id
             OR v_header->>'content_commitment'<>v_record->>'content_commitment'
             OR (v_header->>'byte_length')::bigint<>(v_record->>'byte_length')::bigint
             OR (v_header->>'source_revision')::bigint<>(v_record->>'source_revision')::bigint
             OR v_header->>'role'<>v_record->>'role'
             OR v_header->'parent_source_record_id' IS DISTINCT FROM
                v_record->'parent_source_record_id'
             OR (v_header->>'displayed')::boolean<>(v_record->>'displayed')::boolean
             OR (v_header->>'destination_content_scope_id')::uuid<>
                v_campaign.content_scope_id
             OR v_header->>'protection_class'<>'protected'
          THEN RAISE EXCEPTION 'memory import archive binding is invalid'; END IF;
          v_idempotency_key:='memory-import'||chr(58)||v_campaign.manifest_digest||chr(58)||
            p_source_record_id||chr(58)||'r'||(v_record->>'source_revision');
          RETURN lucy.register_scoped_evidence_v2(
            p_payload,p_wrapper,'memory_import.protected','[]'::jsonb,v_idempotency_key);
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR character_not_in_repertoire OR numeric_value_out_of_range THEN
          RAISE EXCEPTION 'memory import archive binding is invalid';
        END
        $function$;

        CREATE FUNCTION lucy.stage_memory_import_candidate_v1(p_candidate jsonb)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_campaign lucy.memory_import_campaigns_v1%ROWTYPE;
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.propose"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import candidate staging unavailable'; END IF;
          SELECT * INTO v_campaign FROM lucy.memory_import_campaigns_v1
          WHERE id=(p_candidate->>'campaign_id')::uuid
            AND content_scope_id=v_binding.content_scope_id
            AND manifest_digest=p_candidate->>'manifest_digest'
            AND extractor_version=p_candidate->>'extractor_version'
            AND prompt_version=p_candidate->>'prompt_version'
            AND model_route=p_candidate->>'model_route'
            AND expires_at>clock_timestamp();
          IF NOT FOUND OR (p_candidate->>'extraction_job_id')::uuid IS NULL
          THEN RAISE EXCEPTION 'memory import campaign is unavailable'; END IF;
          IF EXISTS (
            SELECT 1 FROM jsonb_array_elements(p_candidate->'sources') source
            WHERE NOT EXISTS (
              SELECT 1 FROM jsonb_array_elements(v_campaign.serialized_manifest->'records') record
              JOIN lucy.scoped_evidence_records_v2 evidence
                ON evidence.id=(source->>'evidence_id')::uuid
               AND evidence.content_scope_id=v_campaign.content_scope_id
               AND evidence.status='active'
              WHERE record->>'source_record_id'=source->>'source_record_id'
                AND coalesce((record->>'included')::boolean,false)
                AND evidence.idempotency_key='memory-import'||chr(58)||
                  v_campaign.manifest_digest||chr(58)||(record->>'source_record_id')||
                  chr(58)||'r'||(record->>'source_revision')
            )
          ) THEN RAISE EXCEPTION 'memory import candidate source is outside manifest'; END IF;
          RETURN lucy.stage_scoped_memory_candidate_v1(p_candidate);
        EXCEPTION WHEN invalid_text_representation THEN
          RAISE EXCEPTION 'memory import candidate staging is invalid';
        END
        $function$;

        CREATE FUNCTION lucy.reserve_memory_import_attempt_v1(
          p_campaign_id uuid,p_attempt_key text,p_reserved_microusd bigint
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_campaign lucy.memory_import_campaigns_v1%ROWTYPE;
          v_existing lucy.memory_import_attempt_reservations_v1%ROWTYPE;
          v_count bigint; v_reserved bigint; v_id uuid:=gen_random_uuid();
          v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.propose"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import attempt reservation unavailable'; END IF;
          IF coalesce(btrim(p_attempt_key),'')='' OR length(p_attempt_key)>512
             OR p_reserved_microusd<0
          THEN RAISE EXCEPTION 'memory import attempt reservation is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-import-campaign:'||p_campaign_id::text,0));
          SELECT * INTO v_campaign FROM lucy.memory_import_campaigns_v1
          WHERE id=p_campaign_id AND content_scope_id=v_binding.content_scope_id;
          IF NOT FOUND OR v_campaign.expires_at<=v_now
          THEN RAISE EXCEPTION 'memory import campaign is unavailable'; END IF;
          SELECT * INTO v_existing FROM lucy.memory_import_attempt_reservations_v1
          WHERE campaign_id=p_campaign_id AND attempt_key=p_attempt_key;
          IF FOUND THEN
            IF v_existing.reserved_microusd<>p_reserved_microusd
            THEN RAISE EXCEPTION 'memory import attempt reservation conflict'; END IF;
            RETURN jsonb_build_object('reservation_id',v_existing.id,'replayed',true);
          END IF;
          SELECT count(*),coalesce(sum(reserved_microusd),0) INTO v_count,v_reserved
          FROM lucy.memory_import_attempt_reservations_v1 WHERE campaign_id=p_campaign_id;
          IF v_count>=v_campaign.max_attempts
             OR v_reserved+p_reserved_microusd>v_campaign.max_model_spend_microusd
          THEN RAISE EXCEPTION 'memory import campaign limit exceeded'; END IF;
          INSERT INTO lucy.memory_import_attempt_reservations_v1(
            id,campaign_id,content_scope_id,service_binding_id,attempt_key,
            reserved_microusd,created_at)
          VALUES (v_id,p_campaign_id,v_binding.content_scope_id,v_binding.id,p_attempt_key,
            p_reserved_microusd,v_now);
          RETURN jsonb_build_object('reservation_id',v_id,'replayed',false);
        END
        $function$;

        CREATE FUNCTION lucy.settle_memory_import_attempt_v1(
          p_reservation_id uuid,p_billed_microusd bigint,p_result text
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_reservation lucy.memory_import_attempt_reservations_v1%ROWTYPE;
          v_existing lucy.memory_import_attempt_settlements_v1%ROWTYPE;
          v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.propose"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import attempt settlement unavailable'; END IF;
          IF p_billed_microusd<0 OR p_result NOT IN ('succeeded','failed','discarded')
          THEN RAISE EXCEPTION 'memory import attempt settlement is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-import-reservation:'||p_reservation_id::text,0));
          SELECT * INTO v_reservation FROM lucy.memory_import_attempt_reservations_v1
          WHERE id=p_reservation_id AND content_scope_id=v_binding.content_scope_id
            AND service_binding_id=v_binding.id;
          IF NOT FOUND OR p_billed_microusd>v_reservation.reserved_microusd
          THEN RAISE EXCEPTION 'memory import attempt settlement unavailable'; END IF;
          SELECT * INTO v_existing FROM lucy.memory_import_attempt_settlements_v1
          WHERE reservation_id=p_reservation_id;
          IF FOUND THEN
            IF v_existing.billed_microusd<>p_billed_microusd OR v_existing.result<>p_result
            THEN RAISE EXCEPTION 'memory import attempt settlement conflict'; END IF;
            RETURN jsonb_build_object('reservation_id',p_reservation_id,'replayed',true);
          END IF;
          INSERT INTO lucy.memory_import_attempt_settlements_v1(
            reservation_id,campaign_id,content_scope_id,billed_microusd,result,settled_at)
          VALUES (p_reservation_id,v_reservation.campaign_id,v_binding.content_scope_id,
            p_billed_microusd,p_result,v_now);
          RETURN jsonb_build_object('reservation_id',p_reservation_id,'replayed',false);
        END
        $function$;

        ALTER FUNCTION lucy.authorize_memory_import_campaign_v1(
          uuid,jsonb,text,bigint,bigint,timestamptz,text,text,text)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.stage_memory_import_candidate_v1(jsonb)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.register_memory_import_evidence_v1(uuid,text,jsonb,jsonb)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.reserve_memory_import_attempt_v1(uuid,text,bigint)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.settle_memory_import_attempt_v1(uuid,bigint,text)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION
          lucy.authorize_memory_import_campaign_v1(
            uuid,jsonb,text,bigint,bigint,timestamptz,text,text,text),
          lucy.register_memory_import_evidence_v1(uuid,text,jsonb,jsonb),
          lucy.stage_memory_import_candidate_v1(jsonb),
          lucy.reserve_memory_import_attempt_v1(uuid,text,bigint),
          lucy.settle_memory_import_attempt_v1(uuid,bigint,text)
          FROM PUBLIC,lucy_app;
        DO $revoke$
        DECLARE v_login text;
        BEGIN
          FOR v_login IN SELECT session_login FROM lucy.realm_service_bindings_v1 LOOP
            EXECUTE format(
              'REVOKE EXECUTE ON FUNCTION lucy.stage_scoped_memory_candidate_v1(jsonb) '
              'FROM %I',v_login);
          END LOOP;
        END
        $revoke$;
        REVOKE ALL ON lucy.memory_import_campaigns_v1,
          lucy.memory_import_attempt_reservations_v1,
          lucy.memory_import_attempt_settlements_v1 FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.memory_import_campaigns_v1,
          lucy.memory_import_attempt_reservations_v1,
          lucy.memory_import_attempt_settlements_v1 TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("memory import campaign accounting requires a reviewed forward migration")
