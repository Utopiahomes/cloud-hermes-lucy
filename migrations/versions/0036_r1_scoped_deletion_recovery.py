"""Replay proven scoped deletions into a quarantined PostgreSQL restore."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0036_r1_scoped_deletion_recovery"
down_revision: str | None = "0035_r1_scoped_finality"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scoped_authorized_deletion_recoveries_v2",
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
        sa.ForeignKeyConstraint(
            ["root_evidence_id", "content_scope_id"],
            [
                "lucy.scoped_evidence_records_v2.id",
                "lucy.scoped_evidence_records_v2.content_scope_id",
            ],
        ),
        sa.CheckConstraint("target_count BETWEEN 1 AND 90", name="ck_scoped_recovery_count"),
        sa.CheckConstraint("executor_version>0", name="ck_scoped_recovery_executor_version"),
        schema="lucy",
    )
    op.create_table(
        "scoped_authorized_deletion_recovery_targets_v2",
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("artifact_class", sa.String(40), primary_key=True),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("artifact_version", sa.BigInteger(), nullable=False),
        sa.Column("root_evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("disposition", sa.String(40), nullable=False),
        sa.Column("representation_id", postgresql.UUID(as_uuid=True)),
        sa.Column("wrapped_key_ref", postgresql.UUID(as_uuid=True)),
        sa.ForeignKeyConstraint(
            ["operation_id"], ["lucy.scoped_authorized_deletion_recoveries_v2.operation_id"]
        ),
        sa.CheckConstraint(
            "artifact_class IN ('encrypted_archive','memory_claim')",
            name="ck_scoped_recovery_artifact",
        ),
        sa.CheckConstraint("artifact_version>0", name="ck_scoped_recovery_version"),
        schema="lucy",
    )
    op.create_table(
        "scoped_recovery_deletion_fences_v2",
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["operation_id"], ["lucy.scoped_authorized_deletion_recoveries_v2.operation_id"]
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id", "content_scope_id"],
            [
                "lucy.scoped_evidence_records_v2.id",
                "lucy.scoped_evidence_records_v2.content_scope_id",
            ],
        ),
        schema="lucy",
    )
    op.execute(
        "CREATE TRIGGER scoped_recoveries_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_authorized_deletion_recoveries_v2 FOR EACH ROW "
        "EXECUTE FUNCTION lucy.reject_mutation(); "
        "CREATE TRIGGER scoped_recovery_targets_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_authorized_deletion_recovery_targets_v2 FOR EACH ROW "
        "EXECUTE FUNCTION lucy.reject_mutation(); "
        "CREATE TRIGGER scoped_recovery_fences_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_recovery_deletion_fences_v2 FOR EACH ROW "
        "EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.apply_scoped_authorized_deletion_recovery_v2(p_recovery jsonb)
        RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_operation_id uuid; v_scope_id uuid; v_root_evidence_id uuid;
          v_target_count bigint; v_existing lucy.scoped_authorized_deletion_recoveries_v2%ROWTYPE;
          v_scope_digest text; v_recovery_digest text; v_targets_digest text;
          v_claims bigint; v_now timestamptz:=clock_timestamp(); v_summary jsonb;
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
          THEN RAISE EXCEPTION 'scoped deletion recovery contract is malformed'; END IF;
          IF p_recovery->>'contract_version'<>'2'
             OR p_recovery->>'object_type'<>'lucy.authorized-deletion-recovery.v2'
             OR jsonb_typeof(p_recovery->'target_scope')<>'object'
             OR jsonb_typeof(p_recovery->'targets')<>'array'
             OR p_recovery->>'reason_category' NOT IN
               ('owner_request','sensitive_data','retention_expired')
             OR coalesce(p_recovery->>'caller_identity','')=''
             OR coalesce(p_recovery->>'executor_identity','')=''
             OR coalesce(p_recovery->>'executor_alias_arn','')=''
             OR coalesce(p_recovery->>'receipt_key_id','')=''
             OR (p_recovery->>'executor_version')::bigint<1
             OR (p_recovery->>'completed_at')::timestamptz>clock_timestamp()+interval '5 minutes'
          THEN RAISE EXCEPTION 'scoped deletion recovery contract is unsupported'; END IF;
          IF NOT EXISTS (SELECT 1 FROM lucy.runtime_admission
                         WHERE singleton AND state='quarantined')
             OR NOT lucy.capture_boundary_safe_v1()
          THEN RAISE EXCEPTION 'scoped deletion recovery requires quarantined capture-off storage';
          END IF;
          v_operation_id:=(p_recovery->>'operation_id')::uuid;
          v_root_evidence_id:=(p_recovery->>'root_evidence_id')::uuid;
          v_target_count:=(p_recovery->>'target_count')::bigint;
          IF v_target_count NOT BETWEEN 1 AND 90
             OR jsonb_array_length(p_recovery->'targets')<>v_target_count
             OR EXISTS (SELECT 1 FROM (VALUES
               (p_recovery->>'permit_digest'),(p_recovery->>'manifest_digest'),
               (p_recovery->>'grant_digest'),(p_recovery->>'receipt_digest'),
               (p_recovery->>'targets_digest'),(p_recovery->>'scope_digest'),
               (p_recovery->>'recovery_digest'),(p_recovery->>'authority_evidence_digest')
             ) d(value) WHERE value !~ '^[0-9a-f]{64}$')
          THEN RAISE EXCEPTION 'scoped deletion recovery digest or count is invalid'; END IF;
          IF (p_recovery->'target_scope')-ARRAY[
             'tenant_account_id','node_id','node_tenure_id',
             'tenure_epoch','security_realm_id','storage_epoch']<>'{}'::jsonb
             OR NOT ((p_recovery->'target_scope') ?& ARRAY[
             'tenant_account_id','node_id','node_tenure_id','tenure_epoch',
             'security_realm_id','storage_epoch'])
          THEN RAISE EXCEPTION 'scoped deletion recovery scope is malformed'; END IF;
          v_scope_digest:=encode(public.digest(
            convert_to('lucy:authorized-deletion-recovery-scope:v2','UTF8')||decode('00','hex')||
            convert_to(lucy.canonical_jsonb_v1(p_recovery->'target_scope'),'UTF8'),'sha256'),'hex');
          IF v_scope_digest<>p_recovery->>'scope_digest'
          THEN RAISE EXCEPTION 'scoped deletion recovery scope digest is invalid'; END IF;
          SELECT id INTO v_scope_id FROM lucy.realm_content_scopes_v1 WHERE
            tenant_account_id=(p_recovery->'target_scope'->>'tenant_account_id')::uuid AND
            node_id=(p_recovery->'target_scope'->>'node_id')::uuid AND
            node_tenure_id=(p_recovery->'target_scope'->>'node_tenure_id')::uuid AND
            tenure_epoch=(p_recovery->'target_scope'->>'tenure_epoch')::bigint AND
            security_realm_id=(p_recovery->'target_scope'->>'security_realm_id')::uuid AND
            storage_epoch=(p_recovery->'target_scope'->>'storage_epoch')::bigint AND
            workspace_id=(p_recovery->>'workspace_id')::uuid;
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped deletion recovery realm is unavailable'; END IF;
          v_targets_digest:=lucy.deletion_targets_digest_v2(p_recovery->'targets');
          IF v_targets_digest<>p_recovery->>'targets_digest'
          THEN RAISE EXCEPTION 'scoped deletion recovery targets digest is invalid'; END IF;
          v_recovery_digest:=encode(public.digest(
            convert_to('lucy:authorized-deletion-recovery:v2','UTF8')||decode('00','hex')||
            convert_to(lucy.canonical_jsonb_v1(jsonb_build_object(
              'operation_id',p_recovery->>'operation_id',
              'permit_digest',p_recovery->>'permit_digest',
              'manifest_digest',p_recovery->>'manifest_digest',
              'grant_digest',p_recovery->>'grant_digest',
              'receipt_digest',p_recovery->>'receipt_digest',
              'targets_digest',p_recovery->>'targets_digest',
              'scope_digest',p_recovery->>'scope_digest')),'UTF8'),'sha256'),'hex');
          IF v_recovery_digest<>p_recovery->>'recovery_digest'
          THEN RAISE EXCEPTION 'scoped deletion recovery proof digest is invalid'; END IF;
          SELECT * INTO v_existing FROM lucy.scoped_authorized_deletion_recoveries_v2
          WHERE operation_id=v_operation_id;
          IF FOUND THEN
            IF v_existing.recovery_digest<>v_recovery_digest
               OR v_existing.authority_evidence_digest<>
                  p_recovery->>'authority_evidence_digest'
               OR (SELECT count(*) FROM lucy.scoped_authorized_deletion_recovery_targets_v2
                   WHERE operation_id=v_operation_id)<>v_target_count
               OR NOT EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v2
                              WHERE operation_id=v_operation_id)
            THEN RAISE EXCEPTION 'scoped deletion recovery replay state mismatch'; END IF;
            RETURN jsonb_build_object('state','FINALITY_PENDING','replayed',true,
                                      'derived_summary',v_existing.derived_summary);
          END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'evidence-derive:'||v_root_evidence_id::text,0));
          IF (SELECT count(*) FROM (SELECT DISTINCT artifact_class,artifact_id
              FROM jsonb_to_recordset(p_recovery->'targets')
              AS x(artifact_class text,artifact_id uuid)) q)<>v_target_count
             OR EXISTS (SELECT 1 FROM jsonb_to_recordset(p_recovery->'targets') AS x(
               artifact_class text,artifact_id uuid,artifact_version bigint,
               root_evidence_id uuid,disposition text,representation_id uuid,
               wrapped_key_ref uuid) WHERE root_evidence_id<>v_root_evidence_id
               OR artifact_class NOT IN ('encrypted_archive','memory_claim')
               OR (artifact_class='encrypted_archive' AND
                 (disposition<>'destroy_wrapped_key' OR representation_id IS NULL
                  OR wrapped_key_ref IS NULL))
               OR (artifact_class='memory_claim' AND
                 (disposition<>'invalidate' OR representation_id IS NOT NULL
                  OR wrapped_key_ref IS NOT NULL)))
             OR (SELECT count(*) FROM jsonb_to_recordset(p_recovery->'targets') AS x(
               artifact_class text,artifact_id uuid,artifact_version bigint,
               root_evidence_id uuid,disposition text,representation_id uuid,
               wrapped_key_ref uuid) JOIN lucy.scoped_evidence_records_v2 e
                 ON x.artifact_class='encrypted_archive' AND e.id=x.artifact_id
                AND e.content_scope_id=v_scope_id
               JOIN lucy.scoped_evidence_payloads_v2 p ON p.evidence_id=e.id
                AND p.record_version=x.artifact_version
               JOIN lucy.scoped_evidence_wrappers_v2 w ON w.evidence_id=e.id
                AND w.representation_id=x.representation_id
                AND w.wrapped_key_ref=x.wrapped_key_ref
               WHERE x.disposition='destroy_wrapped_key')<>1
             OR EXISTS (SELECT 1 FROM jsonb_to_recordset(p_recovery->'targets') AS x(
               artifact_class text,artifact_id uuid,artifact_version bigint,
               root_evidence_id uuid,disposition text,representation_id uuid,
               wrapped_key_ref uuid) WHERE x.artifact_class='memory_claim' AND NOT EXISTS (
                 SELECT 1 FROM lucy.scoped_memory_claims_v1 c
                 JOIN lucy.scoped_memory_claim_sources_v2 s ON s.claim_id=c.id
                 WHERE c.id=x.artifact_id AND c.content_scope_id=v_scope_id
                   AND s.evidence_id=v_root_evidence_id AND x.artifact_version=1
                   AND x.disposition='invalidate' AND x.representation_id IS NULL
                   AND x.wrapped_key_ref IS NULL))
          THEN RAISE EXCEPTION 'restored scoped targets do not match the authorized manifest';
          END IF;
          SELECT count(*) INTO v_claims FROM jsonb_to_recordset(p_recovery->'targets')
            AS x(artifact_class text) WHERE x.artifact_class='memory_claim';
          v_summary:=jsonb_build_object('claims_suppressed',v_claims,
            'archive_keys_destroyed',1,'target_count',v_target_count);
          INSERT INTO lucy.scoped_authorized_deletion_recoveries_v2(
            operation_id,permit_id,manifest_id,grant_id,receipt_id,content_scope_id,
            workspace_id,root_evidence_id,root_representation_id,restore_mapping_id,
            caller_identity,executor_identity,executor_alias_arn,
            executor_version,receipt_key_id,reason_category,
            permit_digest,manifest_digest,grant_digest,receipt_digest,targets_digest,scope_digest,
            target_count,recovery_digest,authority_evidence_digest,completed_at,
            recovered_at,derived_summary) VALUES (
            v_operation_id,(p_recovery->>'permit_id')::uuid,
            (p_recovery->>'manifest_id')::uuid,(p_recovery->>'grant_id')::uuid,
            (p_recovery->>'receipt_id')::uuid,v_scope_id,
            (p_recovery->>'workspace_id')::uuid,v_root_evidence_id,
            (p_recovery->>'root_representation_id')::uuid,
            nullif(p_recovery->>'restore_mapping_id','')::uuid,
            p_recovery->>'caller_identity',p_recovery->>'executor_identity',
            p_recovery->>'executor_alias_arn',(p_recovery->>'executor_version')::bigint,
            p_recovery->>'receipt_key_id',p_recovery->>'reason_category',
            p_recovery->>'permit_digest',p_recovery->>'manifest_digest',
            p_recovery->>'grant_digest',p_recovery->>'receipt_digest',
            v_targets_digest,v_scope_digest,v_target_count,v_recovery_digest,
            p_recovery->>'authority_evidence_digest',
            (p_recovery->>'completed_at')::timestamptz,v_now,v_summary);
          INSERT INTO lucy.scoped_authorized_deletion_recovery_targets_v2(
            operation_id,artifact_class,artifact_id,artifact_version,root_evidence_id,
            disposition,representation_id,wrapped_key_ref)
          SELECT v_operation_id,x.* FROM jsonb_to_recordset(p_recovery->'targets') AS x(
            artifact_class text,artifact_id uuid,artifact_version bigint,
            root_evidence_id uuid,disposition text,representation_id uuid,
            wrapped_key_ref uuid);
          INSERT INTO lucy.scoped_recovery_deletion_fences_v2(
            evidence_id,content_scope_id,operation_id,created_at)
          VALUES (v_root_evidence_id,v_scope_id,v_operation_id,v_now);
          RETURN jsonb_build_object('state','FINALITY_PENDING','replayed',false,
                                    'derived_summary',v_summary);
        END
        $function$;
        ALTER FUNCTION lucy.apply_scoped_authorized_deletion_recovery_v2(jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.apply_scoped_authorized_deletion_recovery_v2(jsonb)
          FROM PUBLIC,lucy_app;
        GRANT EXECUTE ON FUNCTION lucy.apply_scoped_authorized_deletion_recovery_v2(jsonb)
          TO lucy_migration;
        GRANT SELECT,INSERT ON lucy.scoped_authorized_deletion_recoveries_v2,
          lucy.scoped_authorized_deletion_recovery_targets_v2,
          lucy.scoped_recovery_deletion_fences_v2 TO lucy_security_function_owner;
        GRANT SELECT ON lucy.realm_content_scopes_v1,lucy.scoped_evidence_records_v2,
          lucy.scoped_evidence_payloads_v2,lucy.scoped_evidence_wrappers_v2,
          lucy.scoped_memory_claims_v1,lucy.scoped_memory_claim_sources_v2
          TO lucy_security_function_owner;
        """
    )
    op.execute(
        r"""
        CREATE OR REPLACE FUNCTION lucy.reject_fenced_retrieval_package_v2() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
        AS $function$
        BEGIN
          IF EXISTS (SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
            WHERE f.evidence_id=NEW.evidence_id AND f.content_scope_id=NEW.content_scope_id)
             OR EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v2 f
            WHERE f.evidence_id=NEW.evidence_id AND f.content_scope_id=NEW.content_scope_id)
          THEN RAISE EXCEPTION 'scoped evidence is deletion fenced'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE OR REPLACE FUNCTION lucy.reject_fenced_retrieval_grant_v2() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
        AS $function$
        BEGIN
          IF EXISTS (SELECT 1 FROM lucy.sensitive_operations_v2 o
            JOIN lucy.sensitive_operation_packages_v2 p ON p.operation_id=o.id
            WHERE o.id=NEW.operation_id AND o.action='evidence.retrieve' AND (
              EXISTS (SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
                WHERE f.evidence_id=p.evidence_id AND f.content_scope_id=p.content_scope_id)
              OR EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v2 f
                WHERE f.evidence_id=p.evidence_id AND f.content_scope_id=p.content_scope_id)))
          THEN RAISE EXCEPTION 'scoped evidence is deletion fenced'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE FUNCTION lucy.reject_recovery_fenced_derivation_v2() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
        AS $function$
        BEGIN
          IF EXISTS (SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v2 f
            WHERE f.evidence_id=NEW.evidence_id AND f.content_scope_id=NEW.content_scope_id)
          THEN RAISE EXCEPTION 'scoped evidence derivation unavailable'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER scoped_recovery_fence_blocks_derivation
        BEFORE INSERT ON lucy.scoped_memory_claim_sources_v2 FOR EACH ROW
        EXECUTE FUNCTION lucy.reject_recovery_fenced_derivation_v2();

        CREATE OR REPLACE FUNCTION lucy.search_scoped_memory_v1(
          p_query text,p_limit integer
        ) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE; v_result jsonb;
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.read"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'realm operation unavailable'; END IF;
          IF p_query IS NULL OR btrim(p_query)='' OR length(p_query)>200
             OR p_limit NOT BETWEEN 1 AND 50
          THEN RAISE EXCEPTION 'scoped memory request is invalid'; END IF;
          SELECT coalesce(jsonb_agg(jsonb_build_object(
            'claim_id',q.id,'subject',q.subject,'predicate',q.predicate,'object',q.object,
            'confidence_millionths',q.confidence_millionths,'status',q.status)
            ORDER BY q.confidence_millionths DESC,q.created_at DESC,q.id),'[]'::jsonb)
          INTO v_result FROM (SELECT * FROM lucy.scoped_memory_claims_v1 c
            WHERE c.content_scope_id=v_binding.content_scope_id AND c.status='accepted'
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                JOIN lucy.scoped_evidence_deletion_fences_v2 f
                ON f.evidence_id=s.evidence_id AND f.content_scope_id=s.content_scope_id
                WHERE s.claim_id=c.id AND s.content_scope_id=c.content_scope_id)
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                JOIN lucy.scoped_recovery_deletion_fences_v2 f
                ON f.evidence_id=s.evidence_id AND f.content_scope_id=s.content_scope_id
                WHERE s.claim_id=c.id AND s.content_scope_id=c.content_scope_id)
              AND (c.subject ILIKE '%'||p_query||'%' OR c.predicate ILIKE '%'||p_query||'%'
                OR c.object ILIKE '%'||p_query||'%')
            ORDER BY c.confidence_millionths DESC,c.created_at DESC,c.id LIMIT p_limit) q;
          RETURN v_result;
        END
        $function$;
        """
    )


def downgrade() -> None:
    raise RuntimeError("scoped deletion recovery requires a reviewed forward migration")
