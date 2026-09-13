"""Add exact authorization and durable policy admission for outcome recovery."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0069_memory_outcome_policy"
down_revision: str | None = "0068_workspaces_service_auth"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "memory_import_pilot_authorizations_v1",
        sa.Column("owner_approval_ref", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("manifest_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("bundle_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("owner_actor_id", sa.String(512), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("serialized_authorization", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["lucy.memory_import_campaigns_v1.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        schema="lucy",
    )
    op.create_table(
        "memory_outcome_recovery_admissions_v1",
        sa.Column("request_digest", sa.String(64), primary_key=True),
        sa.Column("owner_approval_ref", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("extraction_job_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_actor_binding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("package_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("authorization_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("admitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["owner_approval_ref"],
            ["lucy.memory_import_pilot_authorizations_v1.owner_approval_ref"],
        ),
        sa.ForeignKeyConstraint(["campaign_id"], ["lucy.memory_import_campaigns_v1.id"]),
        sa.ForeignKeyConstraint(
            ["extraction_job_id"], ["lucy.memory_import_extraction_jobs_v1.id"]
        ),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["policy_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        schema="lucy",
    )
    op.create_table(
        "memory_outcome_recovery_grants_v1",
        sa.Column("request_digest", sa.String(64), primary_key=True),
        sa.Column("grant_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("grant_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("serialized_grant", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["request_digest"], ["lucy.memory_outcome_recovery_admissions_v1.request_digest"]
        ),
        schema="lucy",
    )
    for name in (
        "memory_import_pilot_authorizations_v1",
        "memory_outcome_recovery_admissions_v1",
        "memory_outcome_recovery_grants_v1",
    ):
        op.execute(
            f"CREATE TRIGGER {name}_immutable BEFORE UPDATE OR DELETE ON lucy.{name} "
            "FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
        )

    op.execute(
        r"""
        ALTER TABLE lucy.realm_sensitive_actor_bindings_v1
          DISABLE TRIGGER sensitive_actor_binding_monotonic;
        UPDATE lucy.realm_sensitive_actor_bindings_v1
        SET allowed_actions=allowed_actions||'["memory.outcome.recover"]'::jsonb
        WHERE actor_role='policy_notary'
          AND NOT allowed_actions @> '["memory.outcome.recover"]'::jsonb;
        ALTER TABLE lucy.realm_sensitive_actor_bindings_v1
          ENABLE TRIGGER sensitive_actor_binding_monotonic;

        CREATE FUNCTION lucy.register_memory_import_pilot_authorization_v1(p_auth jsonb)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_campaign lucy.memory_import_campaigns_v1%ROWTYPE;
          v_existing lucy.memory_import_pilot_authorizations_v1%ROWTYPE;
          v_approval uuid; v_now timestamptz:=clock_timestamp();
        BEGIN
          IF NOT pg_has_role(session_user,'lucy_migration','MEMBER')
             OR jsonb_typeof(p_auth)<>'object'
             OR p_auth-ARRAY['contract_version','bundle','bundle_digest','owner_approval_ref',
               'owner_actor_id','approved_at','permitted_operations','authorization_state']
                <>'{}'::jsonb
             OR p_auth->>'contract_version'<>'1'
             OR p_auth->>'authorization_state'<>'authorized'
             OR p_auth->'permitted_operations'<>'["archive","extract"]'::jsonb
             OR p_auth->>'bundle_digest'!~'^[0-9a-f]{64}$'
             OR coalesce(btrim(p_auth->>'owner_actor_id'),'')=''
             OR length(p_auth->>'owner_actor_id')>512
          THEN RAISE EXCEPTION 'pilot authorization is invalid'; END IF;
          v_approval:=(p_auth->>'owner_approval_ref')::uuid;
          SELECT * INTO v_campaign FROM lucy.memory_import_campaigns_v1
          WHERE id=(p_auth->'bundle'->>'campaign_id')::uuid
            AND content_scope_id=(p_auth->'bundle'->>'destination_content_scope_id')::uuid;
          IF NOT FOUND
             OR p_auth->'bundle'->>'authorization_state'<>'proposed_not_authorized'
             OR p_auth->'bundle'->'manifest'<>v_campaign.serialized_manifest
             OR p_auth->>'bundle_digest'<>encode(public.digest(
                convert_to('LUCY-CHATGPT-PILOT-MANIFEST-BUNDLE-V1','UTF8')||
                decode('00','hex')||convert_to(
                  lucy.canonical_jsonb_v1(p_auth->'bundle'),'UTF8'),'sha256'),'hex')
             OR (p_auth->>'approved_at')::timestamptz>=v_campaign.expires_at
             OR v_campaign.expires_at<=v_now
          THEN RAISE EXCEPTION 'pilot authorization is unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-pilot-authorization:'||v_approval::text,0));
          SELECT * INTO v_existing FROM lucy.memory_import_pilot_authorizations_v1
          WHERE owner_approval_ref=v_approval;
          IF FOUND THEN
            IF v_existing.serialized_authorization<>p_auth
            THEN RAISE EXCEPTION 'pilot authorization conflict'; END IF;
            RETURN jsonb_build_object('owner_approval_ref',v_approval,'replayed',true);
          END IF;
          INSERT INTO lucy.memory_import_pilot_authorizations_v1(
            owner_approval_ref,campaign_id,content_scope_id,manifest_digest,bundle_digest,
            owner_actor_id,approved_at,expires_at,serialized_authorization,created_at)
          VALUES(v_approval,v_campaign.id,v_campaign.content_scope_id,v_campaign.manifest_digest,
            p_auth->>'bundle_digest',p_auth->>'owner_actor_id',
            (p_auth->>'approved_at')::timestamptz,v_campaign.expires_at,p_auth,v_now);
          RETURN jsonb_build_object('owner_approval_ref',v_approval,'replayed',false);
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR character_not_in_repertoire OR numeric_value_out_of_range
          THEN RAISE EXCEPTION 'pilot authorization is invalid';
        END $function$;

        CREATE FUNCTION lucy.admit_memory_outcome_recovery_v1(
          p_auth jsonb,p_package jsonb,p_package_digest text,p_request_digest text
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_authorization lucy.memory_import_pilot_authorizations_v1%ROWTYPE;
          v_job lucy.memory_import_extraction_jobs_v1%ROWTYPE;
          v_outcome lucy.memory_import_provider_outcomes_v1%ROWTYPE;
          v_existing lucy.memory_outcome_recovery_admissions_v1%ROWTYPE;
          v_source text; v_evidence_id uuid; v_replayed boolean:=true;
          v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["memory.outcome.recover"]'::jsonb;
           IF NOT FOUND OR p_package_digest!~'^[0-9a-f]{64}$'
              OR p_request_digest!~'^[0-9a-f]{64}$'
              OR jsonb_typeof(p_auth)<>'object' OR jsonb_typeof(p_package)<>'object'
              OR p_package->>'object_type'<>'lucy.memory-outcome-recovery-package.v1'
              OR p_package_digest<>encode(public.digest(
                convert_to('LUCY-MEMORY-OUTCOME-PACKAGE-V1','UTF8')||
                decode('00','hex')||convert_to(
                  lucy.canonical_jsonb_v1(p_package),'UTF8'),'sha256'),'hex')
              OR p_request_digest<>encode(public.digest(
                convert_to('LUCY-MEMORY-OUTCOME-GRANT-REQUEST-V1','UTF8')||
                decode('00','hex')||convert_to(lucy.canonical_jsonb_v1(
                  jsonb_build_object('contract_version','1','authorization',p_auth,
                    'package',p_package)),'UTF8'),'sha256'),'hex')
           THEN RAISE EXCEPTION 'memory outcome recovery unavailable'; END IF;
          SELECT * INTO v_authorization FROM lucy.memory_import_pilot_authorizations_v1
          WHERE owner_approval_ref=(p_auth->>'owner_approval_ref')::uuid
            AND content_scope_id=v_actor.content_scope_id
            AND serialized_authorization=p_auth AND expires_at>v_now;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory outcome recovery unavailable'; END IF;
          SELECT * INTO v_job FROM lucy.memory_import_extraction_jobs_v1
          WHERE id=(p_package->'envelope'->'binding'->>'extraction_job_id')::uuid
            AND campaign_id=v_authorization.campaign_id
            AND content_scope_id=v_actor.content_scope_id
            AND service_binding_id=v_actor.target_service_binding_id
            AND manifest_digest=v_authorization.manifest_digest;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory outcome recovery unavailable'; END IF;
          SELECT * INTO v_outcome FROM lucy.memory_import_provider_outcomes_v1
          WHERE extraction_job_id=v_job.id AND content_scope_id=v_job.content_scope_id
            AND service_binding_id=v_job.service_binding_id
            AND serialized_envelope=p_package->'envelope';
          IF NOT FOUND OR p_package->'target_scope'<>jsonb_build_object(
              'tenant_account_id',(SELECT tenant_account_id FROM lucy.realm_content_scopes_v1
                WHERE id=v_job.content_scope_id),
              'node_id',(SELECT node_id FROM lucy.realm_content_scopes_v1
                WHERE id=v_job.content_scope_id),
              'node_tenure_id',(SELECT node_tenure_id FROM lucy.realm_content_scopes_v1
                WHERE id=v_job.content_scope_id),
              'tenure_epoch',(SELECT tenure_epoch FROM lucy.realm_content_scopes_v1
                WHERE id=v_job.content_scope_id),
              'security_realm_id',(SELECT security_realm_id FROM lucy.realm_content_scopes_v1
                WHERE id=v_job.content_scope_id),
              'storage_epoch',(SELECT storage_epoch FROM lucy.realm_content_scopes_v1
                WHERE id=v_job.content_scope_id))
             OR EXISTS(SELECT 1 FROM lucy.memory_import_attempt_settlements_v1
                       WHERE reservation_id=v_job.reservation_id)
          THEN RAISE EXCEPTION 'memory outcome recovery unavailable'; END IF;
          FOREACH v_source IN ARRAY ARRAY(
            SELECT jsonb_array_elements_text(v_job.source_record_ids)) LOOP
            v_evidence_id:=NULL;
             SELECT e.id INTO v_evidence_id
             FROM jsonb_array_elements(
               (SELECT serialized_manifest FROM lucy.memory_import_campaigns_v1
                WHERE id=v_job.campaign_id)->'records') record
            JOIN lucy.scoped_evidence_records_v2 e ON e.content_scope_id=v_job.content_scope_id
              AND e.status='active' AND e.idempotency_key='memory-import'||chr(58)||
                v_job.manifest_digest||chr(58)||(record->>'source_record_id')||chr(58)||
                'r'||(record->>'source_revision')
            JOIN lucy.scoped_evidence_payloads_v2 ep ON ep.evidence_id=e.id
              AND ep.record_version=(record->>'source_revision')::bigint
            WHERE record->>'source_record_id'=v_source
              AND coalesce((record->>'included')::boolean,false)
              AND NOT EXISTS(SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
                             WHERE f.evidence_id=e.id)
              AND NOT EXISTS(SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v3 f
                             WHERE f.evidence_id=e.id AND f.content_scope_id=e.content_scope_id);
            IF v_evidence_id IS NULL
            THEN RAISE EXCEPTION 'memory outcome source is ineligible'; END IF;
          END LOOP;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-outcome-recovery:'||p_request_digest,0));
          SELECT * INTO v_existing FROM lucy.memory_outcome_recovery_admissions_v1
          WHERE request_digest=p_request_digest;
          IF FOUND THEN
            IF v_existing.owner_approval_ref<>v_authorization.owner_approval_ref
               OR v_existing.extraction_job_id<>v_job.id
               OR v_existing.package_digest<>p_package_digest
            THEN RAISE EXCEPTION 'memory outcome recovery conflict'; END IF;
          ELSE
            INSERT INTO lucy.memory_outcome_recovery_admissions_v1(
              request_digest,owner_approval_ref,campaign_id,extraction_job_id,
              content_scope_id,policy_actor_binding_id,package_digest,
              authorization_expires_at,admitted_at)
            VALUES(p_request_digest,v_authorization.owner_approval_ref,v_job.campaign_id,v_job.id,
              v_job.content_scope_id,v_actor.id,p_package_digest,v_authorization.expires_at,v_now)
            RETURNING * INTO v_existing;
            v_replayed:=false;
          END IF;
          RETURN jsonb_build_object('request_digest',v_existing.request_digest,
            'admitted_at',v_existing.admitted_at,
            'authorization_expires_at',v_existing.authorization_expires_at,
            'replayed',v_replayed);
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR character_not_in_repertoire OR numeric_value_out_of_range
          THEN RAISE EXCEPTION 'memory outcome recovery unavailable';
        END $function$;

        CREATE FUNCTION lucy.read_memory_outcome_recovery_grant_v1(p_request_digest text)
        RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE; v_grant jsonb;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["memory.outcome.recover"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory outcome recovery unavailable'; END IF;
          SELECT g.serialized_grant INTO v_grant FROM lucy.memory_outcome_recovery_grants_v1 g
          JOIN lucy.memory_outcome_recovery_admissions_v1 a
            ON a.request_digest=g.request_digest
          WHERE g.request_digest=p_request_digest
            AND a.policy_actor_binding_id=v_actor.id;
          RETURN v_grant;
        END $function$;

        CREATE FUNCTION lucy.record_memory_outcome_recovery_grant_v1(
          p_request_digest text,p_grant_digest text,p_grant jsonb
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_admission lucy.memory_outcome_recovery_admissions_v1%ROWTYPE;
          v_job lucy.memory_import_extraction_jobs_v1%ROWTYPE;
          v_outcome lucy.memory_import_provider_outcomes_v1%ROWTYPE;
          v_existing lucy.memory_outcome_recovery_grants_v1%ROWTYPE;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["memory.outcome.recover"]'::jsonb;
          SELECT * INTO v_admission FROM lucy.memory_outcome_recovery_admissions_v1
          WHERE request_digest=p_request_digest AND policy_actor_binding_id=v_actor.id;
          SELECT * INTO v_job FROM lucy.memory_import_extraction_jobs_v1
          WHERE id=v_admission.extraction_job_id
            AND campaign_id=v_admission.campaign_id
            AND content_scope_id=v_admission.content_scope_id
            AND service_binding_id=v_actor.target_service_binding_id;
          SELECT * INTO v_outcome FROM lucy.memory_import_provider_outcomes_v1
          WHERE extraction_job_id=v_job.id
            AND content_scope_id=v_job.content_scope_id
            AND service_binding_id=v_job.service_binding_id;
          IF NOT FOUND OR p_grant_digest!~'^[0-9a-f]{64}$'
             OR p_grant->>'object_type'<>'lucy.memory-outcome-recovery-grant.v1'
             OR p_grant_digest<>encode(public.digest(
               convert_to('LUCY-SIGNED-CONTRACT','UTF8')||decode('00','hex')||
               convert_to(lucy.canonical_jsonb_v1(p_grant-'signature'),'UTF8'),
               'sha256'),'hex')
             OR (p_grant->>'pilot_authorization_id')::uuid<>v_admission.owner_approval_ref
             OR (p_grant->>'campaign_id')::uuid<>v_admission.campaign_id
             OR (p_grant->>'extraction_job_id')::uuid<>v_admission.extraction_job_id
             OR p_grant->>'manifest_digest'<>v_job.manifest_digest
             OR (p_grant->>'reservation_id')::uuid<>v_job.reservation_id
             OR (p_grant->>'destination_content_scope_id')::uuid<>v_job.content_scope_id
             OR (p_grant->>'encryption_id')::uuid<>
                (v_outcome.serialized_envelope->>'encryption_id')::uuid
             OR (p_grant->>'registry_id')::uuid<>
                (v_outcome.serialized_envelope->>'registry_id')::uuid
             OR p_grant->'target_scope'<>jsonb_build_object(
               'tenant_account_id',(SELECT tenant_account_id FROM lucy.realm_content_scopes_v1
                 WHERE id=v_job.content_scope_id),
               'node_id',(SELECT node_id FROM lucy.realm_content_scopes_v1
                 WHERE id=v_job.content_scope_id),
               'node_tenure_id',(SELECT node_tenure_id FROM lucy.realm_content_scopes_v1
                 WHERE id=v_job.content_scope_id),
               'tenure_epoch',(SELECT tenure_epoch FROM lucy.realm_content_scopes_v1
                 WHERE id=v_job.content_scope_id),
               'security_realm_id',(SELECT security_realm_id FROM lucy.realm_content_scopes_v1
                 WHERE id=v_job.content_scope_id),
               'storage_epoch',(SELECT storage_epoch FROM lucy.realm_content_scopes_v1
                 WHERE id=v_job.content_scope_id))
             OR (p_grant->'execution_binding'->>'active_realm_id')::uuid<>
                (SELECT security_realm_id FROM lucy.realm_content_scopes_v1
                 WHERE id=v_job.content_scope_id)
             OR (p_grant->'execution_binding'->>'active_storage_epoch')::bigint<>
                (SELECT storage_epoch FROM lucy.realm_content_scopes_v1
                 WHERE id=v_job.content_scope_id)
             OR (p_grant->'execution_binding'->>'deployment_id')::uuid<>
                (SELECT deployment_id FROM lucy.realm_content_scopes_v1
                 WHERE id=v_job.content_scope_id)
             OR (p_grant->'execution_binding'->>'node_authz_epoch')::bigint<>
                v_actor.node_authz_epoch
             OR p_grant->>'package_digest'<>v_admission.package_digest
             OR (p_grant->>'issued_at')::timestamptz<>v_admission.admitted_at
             OR (p_grant->>'execution_completion_deadline')::timestamptz>
                v_admission.authorization_expires_at
          THEN RAISE EXCEPTION 'memory outcome recovery grant is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-outcome-recovery:'||p_request_digest,0));
          SELECT * INTO v_existing FROM lucy.memory_outcome_recovery_grants_v1
          WHERE request_digest=p_request_digest;
          IF NOT FOUND THEN
            INSERT INTO lucy.memory_outcome_recovery_grants_v1(
              request_digest,grant_id,grant_digest,serialized_grant,created_at)
            VALUES(p_request_digest,(p_grant->>'operation_id')::uuid,p_grant_digest,
              p_grant,clock_timestamp()) RETURNING * INTO v_existing;
          END IF;
          RETURN v_existing.serialized_grant;
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR character_not_in_repertoire OR numeric_value_out_of_range
          THEN RAISE EXCEPTION 'memory outcome recovery grant is invalid';
        END $function$;

        ALTER FUNCTION lucy.register_memory_import_pilot_authorization_v1(jsonb)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.admit_memory_outcome_recovery_v1(jsonb,jsonb,text,text)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.read_memory_outcome_recovery_grant_v1(text)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.record_memory_outcome_recovery_grant_v1(text,text,jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION
          lucy.register_memory_import_pilot_authorization_v1(jsonb),
          lucy.admit_memory_outcome_recovery_v1(jsonb,jsonb,text,text),
          lucy.read_memory_outcome_recovery_grant_v1(text),
          lucy.record_memory_outcome_recovery_grant_v1(text,text,jsonb)
          FROM PUBLIC,lucy_app;
        GRANT EXECUTE ON FUNCTION lucy.register_memory_import_pilot_authorization_v1(jsonb)
          TO lucy_migration;
        GRANT USAGE ON SCHEMA lucy TO lucy_migration;
        REVOKE ALL ON lucy.memory_import_pilot_authorizations_v1,
          lucy.memory_outcome_recovery_admissions_v1,
          lucy.memory_outcome_recovery_grants_v1 FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.memory_import_pilot_authorizations_v1,
          lucy.memory_outcome_recovery_admissions_v1,
          lucy.memory_outcome_recovery_grants_v1 TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("memory outcome policy admission requires a reviewed forward migration")
