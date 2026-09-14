"""Replay proven V3 deletions into a quarantined PostgreSQL restore."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0067_memory_deletion_recovery"
down_revision: str | None = "0066_workspaces_task_queue"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "scoped_authorized_deletion_recoveries_v3",
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("permit_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("manifest_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("grant_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("receipt_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("root_evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("root_representation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("restore_mapping_id", postgresql.UUID(as_uuid=True)),
        sa.Column("caller_identity", sa.Text(), nullable=False),
        sa.Column("executor_identity", sa.Text(), nullable=False),
        sa.Column("executor_alias_arn", sa.Text(), nullable=False),
        sa.Column("executor_version", sa.BigInteger(), nullable=False),
        sa.Column("receipt_key_id", sa.Text(), nullable=False),
        sa.Column("reason_category", sa.String(40), nullable=False),
        sa.Column("permit_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("manifest_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("grant_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("receipt_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("targets_digest", sa.String(64), nullable=False),
        sa.Column("scope_digest", sa.String(64), nullable=False),
        sa.Column("target_count", sa.BigInteger(), nullable=False),
        sa.Column("recovery_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("authority_evidence_digest", sa.String(64), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("derived_summary", postgresql.JSONB(), nullable=False),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["lucy.workspaces.id"]),
        sa.CheckConstraint("target_count BETWEEN 1 AND 90", name="ck_recovery_v3_count"),
        sa.CheckConstraint("executor_version > 0", name="ck_recovery_v3_executor_version"),
        schema="lucy",
    )
    op.create_table(
        "scoped_authorized_deletion_recovery_targets_v3",
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("artifact_class", sa.String(60), primary_key=True),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("artifact_version", sa.BigInteger(), primary_key=True),
        sa.Column("root_evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("disposition", sa.String(40), nullable=False),
        sa.Column("representation_id", postgresql.UUID(as_uuid=True)),
        sa.Column("wrapped_key_ref", postgresql.UUID(as_uuid=True)),
        sa.Column("key_registry_id", postgresql.UUID(as_uuid=True)),
        sa.ForeignKeyConstraint(
            ["operation_id"], ["lucy.scoped_authorized_deletion_recoveries_v3.operation_id"]
        ),
        sa.CheckConstraint("artifact_version > 0", name="ck_recovery_target_v3_version"),
        schema="lucy",
    )
    op.create_index(
        "ix_recovery_targets_v3_identity",
        "scoped_authorized_deletion_recovery_targets_v3",
        ["artifact_class", "artifact_id", "artifact_version"],
        schema="lucy",
    )
    op.create_table(
        "scoped_recovery_deletion_fences_v3",
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["operation_id"], ["lucy.scoped_authorized_deletion_recoveries_v3.operation_id"]
        ),
        schema="lucy",
    )
    op.execute(
        r"""
        CREATE TRIGGER scoped_recoveries_v3_immutable BEFORE UPDATE OR DELETE
        ON lucy.scoped_authorized_deletion_recoveries_v3 FOR EACH ROW
        EXECUTE FUNCTION lucy.reject_mutation();
        CREATE TRIGGER scoped_recovery_targets_v3_immutable BEFORE UPDATE OR DELETE
        ON lucy.scoped_authorized_deletion_recovery_targets_v3 FOR EACH ROW
        EXECUTE FUNCTION lucy.reject_mutation();
        CREATE TRIGGER scoped_recovery_fences_v3_immutable BEFORE UPDATE OR DELETE
        ON lucy.scoped_recovery_deletion_fences_v3 FOR EACH ROW
        EXECUTE FUNCTION lucy.reject_mutation();

        CREATE FUNCTION lucy.apply_scoped_authorized_deletion_recovery_v3(p_recovery jsonb)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_operation_id uuid; v_scope_id uuid; v_root uuid; v_count bigint;
          v_scope_digest text; v_targets_digest text; v_recovery_digest text;
          v_existing lucy.scoped_authorized_deletion_recoveries_v3%ROWTYPE;
          v_target record; v_now timestamptz:=clock_timestamp(); v_summary jsonb;
        BEGIN
          IF jsonb_typeof(p_recovery)<>'object' OR NOT p_recovery ?& ARRAY[
            'contract_version','object_type','operation_id','permit_id','manifest_id',
            'grant_id','receipt_id','permit_digest','manifest_digest','grant_digest',
            'receipt_digest','targets_digest','target_count','scope_digest','target_scope',
            'workspace_id','root_evidence_id','root_representation_id','restore_mapping_id',
            'caller_identity','executor_identity','executor_alias_arn','executor_version',
            'receipt_key_id','completed_at','reason_category','recovery_digest',
            'authority_evidence_digest','targets'] OR p_recovery-ARRAY[
            'contract_version','object_type','operation_id','permit_id','manifest_id',
            'grant_id','receipt_id','permit_digest','manifest_digest','grant_digest',
            'receipt_digest','targets_digest','target_count','scope_digest','target_scope',
            'workspace_id','root_evidence_id','root_representation_id','restore_mapping_id',
            'caller_identity','executor_identity','executor_alias_arn','executor_version',
            'receipt_key_id','completed_at','reason_category','recovery_digest',
            'authority_evidence_digest','targets']<>'{}'::jsonb
          THEN RAISE EXCEPTION 'V3 deletion recovery contract is malformed'; END IF;
          IF p_recovery->>'contract_version'<>'3'
             OR p_recovery->>'object_type'<>'lucy.authorized-deletion-recovery.v3'
             OR jsonb_typeof(p_recovery->'target_scope')<>'object'
             OR jsonb_typeof(p_recovery->'targets')<>'array'
             OR p_recovery->>'reason_category' NOT IN
               ('owner_request','sensitive_data','retention_expired')
             OR coalesce(p_recovery->>'caller_identity','')=''
             OR coalesce(p_recovery->>'executor_identity','')=''
             OR coalesce(p_recovery->>'executor_alias_arn','')=''
             OR coalesce(p_recovery->>'receipt_key_id','')=''
             OR (p_recovery->>'executor_version')::bigint<1
             OR (p_recovery->>'completed_at')::timestamptz>v_now+interval '5 minutes'
          THEN RAISE EXCEPTION 'V3 deletion recovery contract is unsupported'; END IF;
          IF NOT EXISTS (SELECT 1 FROM lucy.runtime_admission
                         WHERE singleton AND state='quarantined')
             OR NOT lucy.capture_boundary_safe_v1()
          THEN RAISE EXCEPTION 'V3 deletion recovery requires quarantined capture-off storage';
          END IF;
          v_operation_id:=(p_recovery->>'operation_id')::uuid;
          v_root:=(p_recovery->>'root_evidence_id')::uuid;
          v_count:=(p_recovery->>'target_count')::bigint;
          IF v_count NOT BETWEEN 1 AND 90
             OR jsonb_array_length(p_recovery->'targets')<>v_count
             OR EXISTS (SELECT 1 FROM (VALUES
               (p_recovery->>'permit_digest'),(p_recovery->>'manifest_digest'),
               (p_recovery->>'grant_digest'),(p_recovery->>'receipt_digest'),
               (p_recovery->>'targets_digest'),(p_recovery->>'scope_digest'),
               (p_recovery->>'recovery_digest'),(p_recovery->>'authority_evidence_digest')
             ) d(value) WHERE value IS NULL OR value!~'^[0-9a-f]{64}$')
          THEN RAISE EXCEPTION 'V3 deletion recovery digest or count is invalid'; END IF;
          IF (p_recovery->'target_scope')-ARRAY['tenant_account_id','node_id','node_tenure_id',
             'tenure_epoch','security_realm_id','storage_epoch']<>'{}'::jsonb
             OR NOT ((p_recovery->'target_scope') ?& ARRAY['tenant_account_id','node_id',
             'node_tenure_id','tenure_epoch','security_realm_id','storage_epoch'])
          THEN RAISE EXCEPTION 'V3 deletion recovery scope is malformed'; END IF;
          v_scope_digest:=encode(public.digest(
            convert_to('lucy:authorized-deletion-recovery-scope:v2','UTF8')||decode('00','hex')||
            convert_to(lucy.canonical_jsonb_v1(p_recovery->'target_scope'),'UTF8'),'sha256'),'hex');
          IF v_scope_digest<>p_recovery->>'scope_digest'
          THEN RAISE EXCEPTION 'V3 deletion recovery scope digest is invalid'; END IF;
          SELECT id INTO v_scope_id FROM lucy.realm_content_scopes_v1 WHERE
            tenant_account_id=(p_recovery->'target_scope'->>'tenant_account_id')::uuid AND
            node_id=(p_recovery->'target_scope'->>'node_id')::uuid AND
            node_tenure_id=(p_recovery->'target_scope'->>'node_tenure_id')::uuid AND
            tenure_epoch=(p_recovery->'target_scope'->>'tenure_epoch')::bigint AND
            security_realm_id=(p_recovery->'target_scope'->>'security_realm_id')::uuid AND
            storage_epoch=(p_recovery->'target_scope'->>'storage_epoch')::bigint AND
            workspace_id=(p_recovery->>'workspace_id')::uuid;
          IF NOT FOUND THEN RAISE EXCEPTION 'V3 deletion recovery realm is unavailable'; END IF;
          v_targets_digest:=lucy.deletion_targets_digest_v3(p_recovery->'targets');
          IF v_targets_digest<>p_recovery->>'targets_digest'
          THEN RAISE EXCEPTION 'V3 deletion recovery targets digest is invalid'; END IF;
          v_recovery_digest:=encode(public.digest(
            convert_to('lucy:authorized-deletion-recovery:v3','UTF8')||decode('00','hex')||
            convert_to(lucy.canonical_jsonb_v1(jsonb_build_object(
              'operation_id',p_recovery->>'operation_id','permit_digest',p_recovery->>'permit_digest',
              'manifest_digest',p_recovery->>'manifest_digest','grant_digest',p_recovery->>'grant_digest',
              'receipt_digest',p_recovery->>'receipt_digest','targets_digest',p_recovery->>'targets_digest',
              'scope_digest',p_recovery->>'scope_digest')),'UTF8'),'sha256'),'hex');
          IF v_recovery_digest<>p_recovery->>'recovery_digest'
          THEN RAISE EXCEPTION 'V3 deletion recovery proof digest is invalid'; END IF;
          -- Same exclusive admission lock used by the protected recovery handoff.
          PERFORM pg_advisory_xact_lock(83929085854020);
          PERFORM pg_advisory_xact_lock(hashtextextended('evidence-derive:'||v_root::text,0));
          SELECT * INTO v_existing FROM lucy.scoped_authorized_deletion_recoveries_v3
          WHERE operation_id=v_operation_id;
          IF FOUND THEN
            IF v_existing.recovery_digest<>v_recovery_digest
               OR v_existing.authority_evidence_digest<>p_recovery->>'authority_evidence_digest'
               OR (SELECT count(*) FROM lucy.scoped_authorized_deletion_recovery_targets_v3
                   WHERE operation_id=v_operation_id)<>v_count
               OR NOT EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v3
                              WHERE operation_id=v_operation_id)
            THEN RAISE EXCEPTION 'V3 deletion recovery replay state mismatch'; END IF;
            RETURN jsonb_build_object('state','FINALITY_PENDING','replayed',true,
                                      'derived_summary',v_existing.derived_summary);
          END IF;
          IF (SELECT count(*) FROM (SELECT DISTINCT artifact_class,artifact_id,artifact_version
              FROM jsonb_to_recordset(p_recovery->'targets')
              AS x(artifact_class text,artifact_id uuid,artifact_version bigint)) q)<>v_count
          THEN RAISE EXCEPTION 'V3 deletion recovery targets are duplicated'; END IF;
          IF (SELECT count(*) FROM jsonb_to_recordset(p_recovery->'targets') AS x(
              artifact_class text,artifact_id uuid,artifact_version bigint,
              root_evidence_id uuid,disposition text,representation_id uuid,
              wrapped_key_ref uuid,key_registry_id uuid)
              WHERE artifact_class='encrypted_archive' AND artifact_id=v_root
                AND representation_id=(p_recovery->>'root_representation_id')::uuid
                AND disposition='destroy_wrapped_key' AND wrapped_key_ref IS NOT NULL
                AND key_registry_id IS NULL)=0
             OR (SELECT count(*) FROM jsonb_to_recordset(p_recovery->'targets') AS x(
              artifact_class text,artifact_id uuid) WHERE artifact_class='encrypted_archive')<>1
          THEN RAISE EXCEPTION 'V3 deletion recovery root target is invalid'; END IF;
          FOR v_target IN SELECT * FROM jsonb_to_recordset(p_recovery->'targets') AS x(
            artifact_class text,artifact_id uuid,artifact_version bigint,
            root_evidence_id uuid,disposition text,representation_id uuid,
            wrapped_key_ref uuid,key_registry_id uuid)
          LOOP
            IF v_target.artifact_version<1 OR v_target.root_evidence_id<>v_root
               OR v_target.artifact_class NOT IN ('encrypted_archive','memory_candidate',
                  'memory_claim','memory_import_provider_outcome')
               OR (v_target.artifact_class IN ('encrypted_archive','memory_import_provider_outcome')
                  AND (v_target.disposition<>'destroy_wrapped_key'
                    OR v_target.representation_id IS NULL OR v_target.wrapped_key_ref IS NULL))
               OR (v_target.artifact_class='memory_import_provider_outcome'
                  AND v_target.key_registry_id IS NULL)
               OR (v_target.artifact_class='encrypted_archive'
                  AND v_target.key_registry_id IS NOT NULL)
               OR (v_target.artifact_class IN ('memory_candidate','memory_claim') AND
                  (v_target.disposition<>'invalidate' OR v_target.representation_id IS NOT NULL
                   OR v_target.wrapped_key_ref IS NOT NULL OR v_target.key_registry_id IS NOT NULL))
            THEN RAISE EXCEPTION 'V3 deletion recovery target is unsupported'; END IF;
            IF EXISTS (
              SELECT 1 FROM lucy.scoped_authorized_deletion_recovery_targets_v3 t
              JOIN lucy.scoped_authorized_deletion_recoveries_v3 r
                ON r.operation_id=t.operation_id
              WHERE r.content_scope_id=v_scope_id
                AND t.artifact_class=v_target.artifact_class
                AND t.artifact_id=v_target.artifact_id
                AND t.artifact_version=v_target.artifact_version AND
                (t.disposition IS DISTINCT FROM v_target.disposition
                 OR t.representation_id IS DISTINCT FROM v_target.representation_id
                 OR t.wrapped_key_ref IS DISTINCT FROM v_target.wrapped_key_ref
                 OR t.key_registry_id IS DISTINCT FROM v_target.key_registry_id))
            THEN
              RAISE EXCEPTION 'V3 deletion recovery target conflicts with durable history';
            END IF;
            IF v_target.artifact_class='encrypted_archive' AND EXISTS (
              SELECT 1 FROM lucy.scoped_evidence_records_v2 e WHERE e.id=v_target.artifact_id
                AND e.content_scope_id<>v_scope_id)
            THEN RAISE EXCEPTION 'restored V3 archive target has incompatible scope'; END IF;
            IF v_target.artifact_class='memory_candidate' AND EXISTS (
              SELECT 1 FROM lucy.scoped_memory_candidate_versions_v1 c
              WHERE c.candidate_id=v_target.artifact_id
                AND c.candidate_version=v_target.artifact_version AND
                (c.content_scope_id<>v_scope_id OR NOT EXISTS (
                  SELECT 1 FROM lucy.scoped_memory_candidate_sources_v1 s
                  WHERE s.candidate_id=c.candidate_id AND s.candidate_version=c.candidate_version
                    AND s.evidence_id=v_root AND s.content_scope_id=v_scope_id)))
            THEN RAISE EXCEPTION 'restored V3 candidate target is incompatible'; END IF;
            IF v_target.artifact_class='memory_claim' AND EXISTS (
              SELECT 1 FROM lucy.scoped_memory_claims_v1 c WHERE c.id=v_target.artifact_id AND
                (c.content_scope_id<>v_scope_id OR NOT EXISTS (
                  SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                  WHERE s.claim_id=c.id AND s.evidence_id=v_root
                    AND s.content_scope_id=v_scope_id)))
            THEN RAISE EXCEPTION 'restored V3 claim target is incompatible'; END IF;
            IF v_target.artifact_class='memory_import_provider_outcome' AND EXISTS (
              SELECT 1 FROM lucy.memory_import_provider_outcomes_v1 o
              WHERE o.extraction_job_id=v_target.artifact_id AND
                (o.content_scope_id<>v_scope_id OR o.encryption_id<>v_target.representation_id
                 OR o.encryption_id<>v_target.wrapped_key_ref
                 OR o.registry_id<>v_target.key_registry_id
                 OR (o.serialized_envelope->>'record_version')::bigint<>v_target.artifact_version))
            THEN RAISE EXCEPTION 'restored V3 outcome target is incompatible'; END IF;
          END LOOP;
          v_summary:=jsonb_build_object(
            'archive_keys_destroyed',(SELECT count(*) FROM jsonb_to_recordset(
              p_recovery->'targets') AS x(artifact_class text)
              WHERE artifact_class='encrypted_archive'),
            'candidates_suppressed',(SELECT count(*) FROM jsonb_to_recordset(
              p_recovery->'targets') AS x(artifact_class text)
              WHERE artifact_class='memory_candidate'),
            'claims_suppressed',(SELECT count(*) FROM jsonb_to_recordset(
              p_recovery->'targets') AS x(artifact_class text)
              WHERE artifact_class='memory_claim'),
            'provider_outcome_keys_destroyed',(SELECT count(*) FROM jsonb_to_recordset(
              p_recovery->'targets') AS x(artifact_class text)
              WHERE artifact_class='memory_import_provider_outcome'),'target_count',v_count);
          INSERT INTO lucy.scoped_authorized_deletion_recoveries_v3(
            operation_id,permit_id,manifest_id,grant_id,receipt_id,content_scope_id,
            workspace_id,root_evidence_id,root_representation_id,restore_mapping_id,
            caller_identity,executor_identity,executor_alias_arn,executor_version,receipt_key_id,
            reason_category,permit_digest,manifest_digest,grant_digest,receipt_digest,
            targets_digest,scope_digest,target_count,recovery_digest,authority_evidence_digest,
            completed_at,recovered_at,derived_summary) VALUES (
            v_operation_id,(p_recovery->>'permit_id')::uuid,(p_recovery->>'manifest_id')::uuid,
            (p_recovery->>'grant_id')::uuid,(p_recovery->>'receipt_id')::uuid,v_scope_id,
            (p_recovery->>'workspace_id')::uuid,v_root,
            (p_recovery->>'root_representation_id')::uuid,
            nullif(p_recovery->>'restore_mapping_id','')::uuid,p_recovery->>'caller_identity',
            p_recovery->>'executor_identity',p_recovery->>'executor_alias_arn',
            (p_recovery->>'executor_version')::bigint,p_recovery->>'receipt_key_id',
            p_recovery->>'reason_category',p_recovery->>'permit_digest',
            p_recovery->>'manifest_digest',p_recovery->>'grant_digest',
            p_recovery->>'receipt_digest',v_targets_digest,v_scope_digest,v_count,
            v_recovery_digest,p_recovery->>'authority_evidence_digest',
            (p_recovery->>'completed_at')::timestamptz,v_now,v_summary);
          INSERT INTO lucy.scoped_authorized_deletion_recovery_targets_v3(
            operation_id,artifact_class,artifact_id,artifact_version,root_evidence_id,
            disposition,representation_id,wrapped_key_ref,key_registry_id)
          SELECT v_operation_id,x.* FROM jsonb_to_recordset(p_recovery->'targets') AS x(
            artifact_class text,artifact_id uuid,artifact_version bigint,root_evidence_id uuid,
            disposition text,representation_id uuid,wrapped_key_ref uuid,key_registry_id uuid);
          INSERT INTO lucy.scoped_recovery_deletion_fences_v3(
            evidence_id,content_scope_id,operation_id,created_at)
          VALUES(v_root,v_scope_id,v_operation_id,v_now);
          RETURN jsonb_build_object('state','FINALITY_PENDING','replayed',false,
                                    'derived_summary',v_summary);
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR character_not_in_repertoire OR numeric_value_out_of_range
          OR not_null_violation OR check_violation
          THEN RAISE EXCEPTION 'V3 deletion recovery contract is malformed';
        END $function$;
        """
    )
    op.execute(
        r"""
        CREATE OR REPLACE FUNCTION lucy.reject_recovery_fenced_derivation_v2() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
        BEGIN
          IF EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v2 f
            WHERE f.evidence_id=NEW.evidence_id AND f.content_scope_id=NEW.content_scope_id)
             OR EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v3 f
            WHERE f.evidence_id=NEW.evidence_id AND f.content_scope_id=NEW.content_scope_id)
          THEN RAISE EXCEPTION 'scoped evidence derivation unavailable'; END IF;
          RETURN NEW;
        END $function$;
        CREATE TRIGGER memory_candidate_source_recovery_v3_gate
        BEFORE INSERT ON lucy.scoped_memory_candidate_sources_v1 FOR EACH ROW
        EXECUTE FUNCTION lucy.reject_recovery_fenced_derivation_v2();

        CREATE OR REPLACE FUNCTION lucy.reject_ineligible_memory_candidate_approval_v1()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        BEGIN
          IF EXISTS (SELECT 1 FROM lucy.scoped_authorized_deletion_recovery_targets_v3 t
            JOIN lucy.scoped_authorized_deletion_recoveries_v3 r ON r.operation_id=t.operation_id
            WHERE r.content_scope_id=NEW.content_scope_id AND t.artifact_class='memory_candidate'
              AND t.artifact_id=NEW.candidate_id AND t.artifact_version=NEW.candidate_version)
             OR EXISTS (
              SELECT 1 FROM lucy.scoped_memory_candidate_sources_v1 s
              WHERE s.candidate_id=NEW.candidate_id AND s.candidate_version=NEW.candidate_version
                AND (NOT EXISTS (SELECT 1 FROM lucy.scoped_evidence_records_v2 e
                  JOIN lucy.scoped_evidence_payloads_v2 p ON p.evidence_id=e.id
                  WHERE e.id=s.evidence_id AND e.content_scope_id=NEW.content_scope_id
                    AND e.status='active' AND p.record_version=s.record_version)
                  OR EXISTS (SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
                    WHERE f.evidence_id=s.evidence_id AND f.content_scope_id=NEW.content_scope_id)
                  OR EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v3 f
                    WHERE f.evidence_id=s.evidence_id AND f.content_scope_id=NEW.content_scope_id)))
          THEN RAISE EXCEPTION 'memory candidate source became unavailable'; END IF;
          RETURN NEW;
        END $function$;

        CREATE OR REPLACE FUNCTION lucy.require_memory_import_sources_v1(
          p_campaign_id uuid,p_manifest_digest text,p_source_record_ids jsonb
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_campaign lucy.memory_import_campaigns_v1%ROWTYPE;
          v_requested text[]; v_source text; v_evidence_id uuid; v_distinct bigint;
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.propose"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory import source eligibility unavailable'; END IF;
          IF p_manifest_digest!~'^[0-9a-f]{64}$' OR jsonb_typeof(p_source_record_ids)<>'array'
             OR jsonb_array_length(p_source_record_ids)<1
          THEN RAISE EXCEPTION 'memory import source eligibility is invalid'; END IF;
          SELECT array_agg(value ORDER BY ordinal),count(DISTINCT value)
            INTO v_requested,v_distinct FROM jsonb_array_elements_text(p_source_record_ids)
            WITH ORDINALITY item(value,ordinal);
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
            SELECT e.id INTO v_evidence_id FROM jsonb_array_elements(
              v_campaign.serialized_manifest->'records') record
            JOIN lucy.scoped_evidence_records_v2 e ON e.content_scope_id=v_campaign.content_scope_id
              AND e.status='active' AND e.idempotency_key='memory-import'||chr(58)||
                v_campaign.manifest_digest||chr(58)||(record->>'source_record_id')||chr(58)||
                'r'||(record->>'source_revision')
            JOIN lucy.scoped_evidence_payloads_v2 p ON p.evidence_id=e.id
              AND p.record_version=(record->>'source_revision')::bigint
            WHERE record->>'source_record_id'=v_source
              AND coalesce((record->>'included')::boolean,false)
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
                WHERE f.evidence_id=e.id)
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v3 f
                WHERE f.evidence_id=e.id AND f.content_scope_id=e.content_scope_id);
            IF v_evidence_id IS NULL
            THEN RAISE EXCEPTION 'memory import source is ineligible'; END IF;
          END LOOP;
          RETURN jsonb_build_object('eligible',true,'source_count',cardinality(v_requested));
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR character_not_in_repertoire OR numeric_value_out_of_range
          THEN RAISE EXCEPTION 'memory import source eligibility is invalid';
        END $function$;

        CREATE OR REPLACE FUNCTION lucy.reject_tombstoned_memory_import_outcome_v3()
        RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
        BEGIN
          IF EXISTS (SELECT 1 FROM lucy.scoped_authorized_deletion_recovery_targets_v3 t
            JOIN lucy.scoped_authorized_deletion_recoveries_v3 r ON r.operation_id=t.operation_id
            WHERE r.content_scope_id=NEW.content_scope_id
              AND t.artifact_class='memory_import_provider_outcome'
              AND t.artifact_id=NEW.extraction_job_id
              AND t.artifact_version=(NEW.serialized_envelope->>'record_version')::bigint)
             OR EXISTS (SELECT 1 FROM lucy.memory_import_extraction_jobs_v1 j
              JOIN lucy.memory_import_campaigns_v1 c ON c.id=j.campaign_id
                AND c.content_scope_id=j.content_scope_id
              JOIN jsonb_array_elements_text(j.source_record_ids) source(source_record_id) ON true
              JOIN jsonb_array_elements(c.serialized_manifest->'records') record
                ON record->>'source_record_id'=source.source_record_id
              JOIN lucy.scoped_evidence_records_v2 e ON e.content_scope_id=j.content_scope_id
                AND e.idempotency_key='memory-import'||chr(58)||c.manifest_digest||chr(58)||
                  (record->>'source_record_id')||chr(58)||'r'||(record->>'source_revision')
              WHERE j.id=NEW.extraction_job_id AND j.content_scope_id=NEW.content_scope_id
                AND coalesce((record->>'included')::boolean,false) AND (
                  EXISTS (SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
                    WHERE f.evidence_id=e.id)
                  OR EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v3 f
                    WHERE f.evidence_id=e.id AND f.content_scope_id=e.content_scope_id)))
          THEN RAISE EXCEPTION 'memory import outcome is deletion fenced'; END IF;
          RETURN NEW;
        END $function$;

        CREATE OR REPLACE FUNCTION lucy.reject_fenced_retrieval_package_v2() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
        BEGIN
          IF EXISTS (SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
            WHERE f.evidence_id=NEW.evidence_id AND f.content_scope_id=NEW.content_scope_id)
             OR EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v2 f
            WHERE f.evidence_id=NEW.evidence_id AND f.content_scope_id=NEW.content_scope_id)
             OR EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v3 f
            WHERE f.evidence_id=NEW.evidence_id AND f.content_scope_id=NEW.content_scope_id)
          THEN RAISE EXCEPTION 'scoped evidence is deletion fenced'; END IF;
          RETURN NEW;
        END $function$;
        CREATE OR REPLACE FUNCTION lucy.reject_fenced_retrieval_grant_v2() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
        BEGIN
          IF EXISTS (SELECT 1 FROM lucy.sensitive_operations_v2 o
            JOIN lucy.sensitive_operation_packages_v2 p ON p.operation_id=o.id
            WHERE o.id=NEW.operation_id AND o.action='evidence.retrieve' AND (
              EXISTS (SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
                WHERE f.evidence_id=p.evidence_id AND f.content_scope_id=p.content_scope_id)
              OR EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v2 f
                WHERE f.evidence_id=p.evidence_id AND f.content_scope_id=p.content_scope_id)
              OR EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v3 f
                WHERE f.evidence_id=p.evidence_id AND f.content_scope_id=p.content_scope_id)))
          THEN RAISE EXCEPTION 'scoped evidence is deletion fenced'; END IF;
          RETURN NEW;
        END $function$;
        """
    )
    op.execute(
        r"""
        CREATE OR REPLACE FUNCTION lucy.search_governed_scoped_memory_v1(
          p_query text,p_limit integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE; v_result jsonb;
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.read"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'realm operation unavailable'; END IF;
          IF coalesce(btrim(p_query),'')='' OR length(p_query)>200 OR p_limit NOT BETWEEN 1 AND 50
          THEN RAISE EXCEPTION 'scoped memory request is invalid'; END IF;
          SELECT coalesce(jsonb_agg(jsonb_build_object(
            'claim_id',q.id,'candidate_id',q.candidate_id,'candidate_version',q.candidate_version,
            'subject',q.subject,'predicate',q.predicate,'object',q.object,
            'confidence_millionths',q.confidence_millionths,'status',q.status,
            'protection_class',coalesce(q.protection_class,'ordinary_private'),
            'memory_kind',q.memory_kind,'assertion_status',q.assertion_status,
            'epistemic_status',q.epistemic_status,'domain_tags',coalesce(q.domain_tags,'[]'::jsonb),
            'source_evidence_ids',coalesce((SELECT jsonb_agg(s.evidence_id ORDER BY s.evidence_id)
              FROM lucy.scoped_memory_claim_sources_v2 s WHERE s.claim_id=q.id),'[]'::jsonb))
            ORDER BY q.confidence_millionths DESC,q.created_at DESC,q.id),'[]'::jsonb)
          INTO v_result FROM (SELECT * FROM lucy.scoped_memory_claims_v1 c
            WHERE c.content_scope_id=v_binding.content_scope_id AND c.status='accepted'
              AND coalesce(c.protection_class,'ordinary_private')='ordinary_private'
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                JOIN lucy.scoped_evidence_deletion_fences_v2 f ON f.evidence_id=s.evidence_id
                WHERE s.claim_id=c.id)
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                JOIN lucy.scoped_recovery_deletion_fences_v2 f ON f.evidence_id=s.evidence_id
                WHERE s.claim_id=c.id)
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                JOIN lucy.scoped_recovery_deletion_fences_v3 f ON f.evidence_id=s.evidence_id
                  AND f.content_scope_id=s.content_scope_id WHERE s.claim_id=c.id)
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                WHERE s.claim_id=c.id AND NOT EXISTS (SELECT 1
                  FROM lucy.scoped_evidence_records_v2 e JOIN lucy.scoped_evidence_payloads_v2 p
                    ON p.evidence_id=e.id WHERE e.id=s.evidence_id AND e.status='active'))
              AND (c.subject ILIKE '%'||p_query||'%' OR c.predicate ILIKE '%'||p_query||'%'
                   OR c.object ILIKE '%'||p_query||'%')
            ORDER BY c.confidence_millionths DESC,c.created_at DESC,c.id LIMIT p_limit) q;
          RETURN v_result;
        END $function$;

        CREATE OR REPLACE FUNCTION lucy.search_protected_scoped_memory_v1(
          p_query text,p_limit integer,p_owner_interaction_ref uuid,p_reason_code text)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_result jsonb; v_ids jsonb; v_commitment text;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["memory.protected.read"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'protected memory recall unavailable'; END IF;
          IF coalesce(btrim(p_query),'')='' OR length(p_query)>200 OR p_limit NOT BETWEEN 1 AND 20
             OR coalesce(btrim(p_reason_code),'')='' OR length(p_reason_code)>60
          THEN RAISE EXCEPTION 'protected memory recall is invalid'; END IF;
          SELECT coalesce(jsonb_agg(jsonb_build_object(
            'claim_id',q.id,'candidate_id',q.candidate_id,'candidate_version',q.candidate_version,
            'subject',q.subject,'predicate',q.predicate,'object',q.object,
            'confidence_millionths',q.confidence_millionths,'status',q.status,
            'protection_class',q.protection_class,'memory_kind',q.memory_kind,
            'assertion_status',q.assertion_status,'epistemic_status',q.epistemic_status,
            'domain_tags',q.domain_tags,'source_evidence_ids',(SELECT jsonb_agg(
              s.evidence_id ORDER BY s.evidence_id) FROM lucy.scoped_memory_claim_sources_v2 s
              WHERE s.claim_id=q.id)) ORDER BY q.confidence_millionths DESC,
              q.created_at DESC,q.id),'[]'::jsonb),
            coalesce(jsonb_agg(to_jsonb(q.id) ORDER BY q.id),'[]'::jsonb)
          INTO v_result,v_ids FROM (SELECT * FROM lucy.scoped_memory_claims_v1 c
            WHERE c.content_scope_id=v_actor.content_scope_id AND c.status='accepted'
              AND c.protection_class='protected'
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                JOIN lucy.scoped_evidence_deletion_fences_v2 f ON f.evidence_id=s.evidence_id
                WHERE s.claim_id=c.id)
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                JOIN lucy.scoped_recovery_deletion_fences_v2 f ON f.evidence_id=s.evidence_id
                WHERE s.claim_id=c.id)
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                JOIN lucy.scoped_recovery_deletion_fences_v3 f ON f.evidence_id=s.evidence_id
                  AND f.content_scope_id=s.content_scope_id WHERE s.claim_id=c.id)
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                WHERE s.claim_id=c.id AND NOT EXISTS (SELECT 1
                  FROM lucy.scoped_evidence_records_v2 e JOIN lucy.scoped_evidence_payloads_v2 p
                    ON p.evidence_id=e.id WHERE e.id=s.evidence_id AND e.status='active'))
              AND (c.subject ILIKE '%'||p_query||'%' OR c.predicate ILIKE '%'||p_query||'%'
                   OR c.object ILIKE '%'||p_query||'%')
            ORDER BY c.confidence_millionths DESC,c.created_at DESC,c.id LIMIT p_limit) q;
          v_commitment:=encode(public.digest(convert_to(p_query,'UTF8'),'sha256'),'hex');
          INSERT INTO lucy.scoped_protected_memory_accesses_v1(id,content_scope_id,
            policy_actor_binding_id,owner_interaction_ref,query_commitment,returned_claim_ids,
            reason_code,accessed_at) VALUES(gen_random_uuid(),v_actor.content_scope_id,v_actor.id,
            p_owner_interaction_ref,v_commitment,v_ids,p_reason_code,clock_timestamp());
          RETURN v_result;
        END $function$;

        ALTER FUNCTION lucy.apply_scoped_authorized_deletion_recovery_v3(jsonb)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.reject_recovery_fenced_derivation_v2()
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.reject_ineligible_memory_candidate_approval_v1()
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.require_memory_import_sources_v1(uuid,text,jsonb)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.reject_tombstoned_memory_import_outcome_v3()
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.search_governed_scoped_memory_v1(text,integer)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.search_protected_scoped_memory_v1(text,integer,uuid,text)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.apply_scoped_authorized_deletion_recovery_v3(jsonb)
          FROM PUBLIC,lucy_app;
        GRANT EXECUTE ON FUNCTION lucy.apply_scoped_authorized_deletion_recovery_v3(jsonb)
          TO lucy_migration;
        REVOKE ALL ON lucy.scoped_authorized_deletion_recoveries_v3,
          lucy.scoped_authorized_deletion_recovery_targets_v3,
          lucy.scoped_recovery_deletion_fences_v3 FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.scoped_authorized_deletion_recoveries_v3,
          lucy.scoped_authorized_deletion_recovery_targets_v3,
          lucy.scoped_recovery_deletion_fences_v3 TO lucy_security_function_owner;
        GRANT SELECT ON lucy.scoped_memory_candidate_versions_v1,
          lucy.scoped_memory_candidate_sources_v1,lucy.memory_import_provider_outcomes_v1
          TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("V3 deletion recovery requires a reviewed forward migration")
