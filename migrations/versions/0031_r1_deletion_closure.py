"""Freeze exact realm-scoped deletion closures behind derivation fences."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0031_r1_deletion_closure"
down_revision: str | None = "0030_r1_scoped_provenance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scoped_deletion_manifests_v2",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("permit_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_actor_binding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("root_evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("root_representation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("manifest_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("targets_digest", sa.String(64), nullable=False),
        sa.Column("target_count", sa.BigInteger(), nullable=False),
        sa.Column("serialized_manifest", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["operation_id"], ["lucy.sensitive_operations_v2.id"]),
        sa.ForeignKeyConstraint(["permit_id"], ["lucy.sensitive_action_permits_v3.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["policy_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.ForeignKeyConstraint(
            ["root_evidence_id", "content_scope_id"],
            [
                "lucy.scoped_evidence_records_v2.id",
                "lucy.scoped_evidence_records_v2.content_scope_id",
            ],
        ),
        sa.ForeignKeyConstraint(
            ["root_representation_id"],
            ["lucy.scoped_evidence_wrappers_v2.representation_id"],
        ),
        sa.CheckConstraint("target_count BETWEEN 1 AND 90", name="ck_scoped_manifest_count"),
        schema="lucy",
    )
    op.create_table(
        "scoped_deletion_manifest_targets_v2",
        sa.Column(
            "manifest_id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("artifact_class", sa.String(40), primary_key=True, nullable=False),
        sa.Column(
            "artifact_id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False
        ),
        sa.Column("artifact_version", sa.BigInteger(), nullable=False),
        sa.Column("root_evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("disposition", sa.String(40), nullable=False),
        sa.Column("representation_id", postgresql.UUID(as_uuid=True)),
        sa.Column("wrapped_key_ref", postgresql.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["manifest_id"], ["lucy.scoped_deletion_manifests_v2.id"]
        ),
        sa.CheckConstraint(
            "artifact_class IN ('encrypted_archive','memory_claim')",
            name="ck_scoped_deletion_artifact",
        ),
        sa.CheckConstraint("artifact_version > 0", name="ck_scoped_deletion_version"),
        schema="lucy",
    )
    op.execute(
        "CREATE TRIGGER scoped_deletion_manifests_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_deletion_manifests_v2 FOR EACH ROW "
        "EXECUTE FUNCTION lucy.reject_mutation(); "
        "CREATE TRIGGER scoped_deletion_manifest_targets_v2_immutable "
        "BEFORE UPDATE OR DELETE ON lucy.scoped_deletion_manifest_targets_v2 "
        "FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.drop_constraint(
        "ck_v2_sensitive_event_type", "sensitive_operation_events_v2", schema="lucy"
    )
    op.create_check_constraint(
        "ck_v2_sensitive_event_type",
        "sensitive_operation_events_v2",
        "event_type IN ('sensitive.permit_issued','sensitive.operation_claimed',"
        "'sensitive.execution_granted','sensitive.executor_receipt_attested',"
        "'sensitive.operation_reconciled','sensitive.deletion_manifest_frozen')",
        schema="lucy",
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.deletion_targets_digest_v2(p_targets jsonb) RETURNS text
        LANGUAGE sql IMMUTABLE STRICT
        SET search_path=pg_catalog,pg_temp
        AS $function$
          SELECT encode(public.digest(
            convert_to('LUCY-DELETION-TARGETS-V2','UTF8') || decode('00','hex') ||
            convert_to(lucy.canonical_jsonb_v1(p_targets),'UTF8'),'sha256'),'hex')
        $function$;
        ALTER FUNCTION lucy.deletion_targets_digest_v2(jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.deletion_targets_digest_v2(jsonb)
          FROM PUBLIC,lucy_app;

        CREATE FUNCTION lucy.store_scoped_deletion_manifest_v2(
          p_operation_id uuid,p_manifest jsonb
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v3%ROWTYPE;
          v_record lucy.scoped_evidence_records_v2%ROWTYPE;
          v_payload lucy.scoped_evidence_payloads_v2%ROWTYPE;
          v_wrapper lucy.scoped_evidence_wrappers_v2%ROWTYPE;
          v_existing lucy.scoped_deletion_manifests_v2%ROWTYPE;
          v_targets jsonb; v_manifest_id uuid; v_digest text; v_targets_digest text;
          v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.deletion_manifest.issue"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped deletion manifest unavailable'; END IF;
          IF jsonb_typeof(p_manifest)<>'object' OR p_manifest-ARRAY[
            'canonicalization_version','signature_algorithm','signing_key_purpose','key_id',
            'issuer','environment','issued_at','signature','contract_version','object_type',
            'manifest_id','permit_id','permit_digest','operation_id','action','target_scope',
            'workspace_id','root_evidence_id','root_representation_id','owner_assertion_id',
            'owner_assertion_digest','idempotency_key','closure_version','targets',
            'target_count','targets_digest','tombstone_policy_version',
            'finality_policy_version','permit_claim_deadline',
            'execution_completion_deadline','nonce']<>'{}'::jsonb
          THEN RAISE EXCEPTION 'invalid scoped deletion manifest'; END IF;
          IF p_manifest->>'contract_version'<>'2'
             OR p_manifest->>'object_type'<>'lucy.deletion-target-manifest.v2'
             OR p_manifest->>'canonicalization_version'<>'lucy-cjson-1'
             OR p_manifest->>'signature_algorithm'<>'Ed25519'
             OR p_manifest->>'signing_key_purpose'<>'policy_notary_v13'
             OR p_manifest->>'action'<>'evidence.delete'
             OR coalesce(p_manifest->>'signature','')=''
             OR jsonb_typeof(p_manifest->'targets')<>'array'
             OR (p_manifest->>'closure_version')::bigint<>1
             OR (p_manifest->>'tombstone_policy_version')::bigint<>1
             OR (p_manifest->>'finality_policy_version')::bigint<>1
          THEN RAISE EXCEPTION 'invalid scoped deletion manifest domain'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id;
          IF NOT FOUND OR v_operation.workflow_actor_binding_id IS NULL
             OR v_operation.content_scope_id<>v_actor.content_scope_id
             OR v_operation.target_service_binding_id<>v_actor.target_service_binding_id
             OR v_operation.action<>'evidence.delete' OR v_operation.state<>'CLAIMED'
          THEN RAISE EXCEPTION 'scoped deletion manifest unavailable'; END IF;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v3
          WHERE id=v_operation.permit_id;
          IF (p_manifest->>'manifest_id') IS NULL
             OR (p_manifest->>'operation_id')::uuid<>v_operation.id
             OR (p_manifest->>'permit_id')::uuid<>v_permit.id
             OR p_manifest->>'permit_digest'<>v_permit.permit_digest
             OR (p_manifest->>'workspace_id')::uuid<>
                (v_permit.serialized_permit->>'workspace_id')::uuid
             OR (p_manifest->>'root_evidence_id')::uuid<>v_operation.resource_object_id
             OR (p_manifest->>'owner_assertion_id')::uuid<>
                (v_permit.serialized_permit->>'owner_assertion_id')::uuid
             OR p_manifest->>'owner_assertion_digest'<>
                v_permit.serialized_permit->>'owner_assertion_digest'
             OR p_manifest->'target_scope'<>v_permit.serialized_permit->'target_scope'
             OR (p_manifest->>'permit_claim_deadline')::timestamptz<>
                v_permit.permit_claim_deadline
             OR (p_manifest->>'execution_completion_deadline')::timestamptz<>
                v_permit.execution_completion_deadline
             OR v_now>v_permit.execution_completion_deadline
          THEN RAISE EXCEPTION 'scoped deletion manifest binding is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'evidence-derive:'||v_operation.resource_object_id::text,0));
          SELECT * INTO v_existing FROM lucy.scoped_deletion_manifests_v2
          WHERE operation_id=p_operation_id;
          IF FOUND THEN
            IF v_existing.serialized_manifest<>p_manifest
            THEN RAISE EXCEPTION 'scoped deletion manifest idempotency conflict'; END IF;
            RETURN jsonb_build_object('manifest_id',v_existing.id,
              'manifest_digest',v_existing.manifest_digest,
              'targets_digest',v_existing.targets_digest,
              'target_count',v_existing.target_count,'replayed',true);
          END IF;
          SELECT * INTO v_record FROM lucy.scoped_evidence_records_v2
          WHERE id=v_operation.resource_object_id
            AND content_scope_id=v_operation.content_scope_id AND status='active';
          IF NOT FOUND OR EXISTS (
            SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2
            WHERE evidence_id=v_operation.resource_object_id
          ) THEN RAISE EXCEPTION 'scoped deletion root unavailable'; END IF;
          SELECT * INTO STRICT v_payload FROM lucy.scoped_evidence_payloads_v2
          WHERE evidence_id=v_record.id AND record_version=v_operation.resource_object_version;
          SELECT * INTO STRICT v_wrapper FROM lucy.scoped_evidence_wrappers_v2
          WHERE evidence_id=v_record.id AND content_scope_id=v_record.content_scope_id AND current;
          IF (p_manifest->>'root_representation_id')::uuid<>v_wrapper.representation_id
          THEN RAISE EXCEPTION 'scoped deletion representation is stale'; END IF;
          SELECT jsonb_agg(target ORDER BY target->>'artifact_class',
            target->>'artifact_id',coalesce(target->>'representation_id','')) INTO v_targets
          FROM (
            SELECT jsonb_build_object(
              'artifact_class','encrypted_archive','artifact_id',v_record.id,
              'artifact_version',v_payload.record_version,'root_evidence_id',v_record.id,
              'disposition','destroy_wrapped_key','representation_id',
              v_wrapper.representation_id,'wrapped_key_ref',v_wrapper.wrapped_key_ref) target
            UNION ALL
            SELECT jsonb_build_object(
              'artifact_class','memory_claim','artifact_id',s.claim_id,
              'artifact_version',1,'root_evidence_id',v_record.id,
              'disposition','invalidate','representation_id',NULL,
              'wrapped_key_ref',NULL) target
            FROM lucy.scoped_memory_claim_sources_v2 s
            WHERE s.evidence_id=v_record.id AND s.content_scope_id=v_record.content_scope_id
          ) closure;
          v_targets_digest:=lucy.deletion_targets_digest_v2(v_targets);
          IF p_manifest->'targets'<>v_targets
             OR (p_manifest->>'target_count')::bigint<>jsonb_array_length(v_targets)
             OR (p_manifest->>'target_count')::bigint>
                (v_permit.serialized_permit->>'max_records')::bigint
             OR p_manifest->>'targets_digest'<>v_targets_digest
          THEN RAISE EXCEPTION 'scoped deletion closure is not exact'; END IF;
          v_manifest_id:=(p_manifest->>'manifest_id')::uuid;
          v_digest:=lucy.security_contract_digest_v2(p_manifest);
          INSERT INTO lucy.scoped_evidence_deletion_fences_v2(
            evidence_id,content_scope_id,operation_id,created_at
          ) VALUES (v_record.id,v_record.content_scope_id,v_operation.id,v_now);
          INSERT INTO lucy.scoped_deletion_manifests_v2(
            id,operation_id,permit_id,content_scope_id,policy_actor_binding_id,
            root_evidence_id,root_representation_id,manifest_digest,targets_digest,
            target_count,serialized_manifest,created_at
          ) VALUES (v_manifest_id,v_operation.id,v_permit.id,v_record.content_scope_id,
            v_actor.id,v_record.id,v_wrapper.representation_id,v_digest,v_targets_digest,
            jsonb_array_length(v_targets),p_manifest,v_now);
          INSERT INTO lucy.scoped_deletion_manifest_targets_v2(
            manifest_id,artifact_class,artifact_id,artifact_version,root_evidence_id,
            disposition,representation_id,wrapped_key_ref,created_at
          ) SELECT v_manifest_id,target->>'artifact_class',(target->>'artifact_id')::uuid,
            (target->>'artifact_version')::bigint,(target->>'root_evidence_id')::uuid,
            target->>'disposition',(target->>'representation_id')::uuid,
            (target->>'wrapped_key_ref')::uuid,v_now FROM jsonb_array_elements(v_targets) target;
          INSERT INTO lucy.sensitive_operation_events_v2(
            id,content_scope_id,operation_id,event_type,details,occurred_at
          ) VALUES (gen_random_uuid(),v_record.content_scope_id,v_operation.id,
            'sensitive.deletion_manifest_frozen',jsonb_build_object(
              'manifest_id',v_manifest_id,'manifest_digest',v_digest,
              'targets_digest',v_targets_digest,'target_count',jsonb_array_length(v_targets)),v_now);
          RETURN jsonb_build_object('manifest_id',v_manifest_id,'manifest_digest',v_digest,
            'targets_digest',v_targets_digest,'target_count',jsonb_array_length(v_targets),
            'replayed',false);
        EXCEPTION WHEN invalid_text_representation OR not_null_violation OR check_violation
          THEN RAISE EXCEPTION 'malformed scoped deletion manifest';
        END
        $function$;
        ALTER FUNCTION lucy.store_scoped_deletion_manifest_v2(uuid,jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.store_scoped_deletion_manifest_v2(uuid,jsonb)
          FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.scoped_deletion_manifests_v2,
          lucy.scoped_deletion_manifest_targets_v2 TO lucy_security_function_owner;
        GRANT SELECT ON lucy.scoped_memory_claim_sources_v2
          TO lucy_security_function_owner;
        GRANT INSERT ON lucy.scoped_evidence_deletion_fences_v2
          TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("scoped deletion closure requires a reviewed forward migration")
