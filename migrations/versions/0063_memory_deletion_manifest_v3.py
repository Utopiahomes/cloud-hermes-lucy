"""Persist exact signed V3 deletion closures without reinterpreting V2."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0063_memory_deletion_manifest"
down_revision: str | None = "0062_memory_deletion_closure"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "scoped_deletion_manifests_v3",
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
        sa.CheckConstraint("target_count BETWEEN 1 AND 90", name="ck_v3_manifest_count"),
        schema="lucy",
    )
    op.create_table(
        "scoped_deletion_manifest_targets_v3",
        sa.Column("manifest_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("artifact_class", sa.String(60), primary_key=True),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("artifact_version", sa.BigInteger(), primary_key=True),
        sa.Column("root_evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("disposition", sa.String(40), nullable=False),
        sa.Column("representation_id", postgresql.UUID(as_uuid=True)),
        sa.Column("wrapped_key_ref", postgresql.UUID(as_uuid=True)),
        sa.Column("key_registry_id", postgresql.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["manifest_id"], ["lucy.scoped_deletion_manifests_v3.id"]),
        sa.CheckConstraint(
            "artifact_class IN ('encrypted_archive','memory_candidate','memory_claim',"
            "'memory_import_provider_outcome','embedding','result_body','public_projection')",
            name="ck_v3_deletion_artifact",
        ),
        sa.CheckConstraint("artifact_version > 0", name="ck_v3_deletion_version"),
        sa.CheckConstraint(
            "(artifact_class='memory_import_provider_outcome' AND key_registry_id IS NOT NULL) "
            "OR (artifact_class<>'memory_import_provider_outcome' AND key_registry_id IS NULL)",
            name="ck_v3_deletion_registry",
        ),
        schema="lucy",
    )
    op.execute(
        r"""
        CREATE TRIGGER scoped_deletion_manifests_v3_immutable BEFORE UPDATE OR DELETE
        ON lucy.scoped_deletion_manifests_v3 FOR EACH ROW
        EXECUTE FUNCTION lucy.reject_mutation();
        CREATE TRIGGER scoped_deletion_manifest_targets_v3_immutable BEFORE UPDATE OR DELETE
        ON lucy.scoped_deletion_manifest_targets_v3 FOR EACH ROW
        EXECUTE FUNCTION lucy.reject_mutation();

        CREATE FUNCTION lucy.deletion_targets_digest_v3(p_targets jsonb) RETURNS text
        LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp
        AS $function$
          SELECT encode(public.digest(
            convert_to('LUCY-DELETION-TARGETS-V3','UTF8') || decode('00','hex') ||
            convert_to(lucy.canonical_jsonb_v1(p_targets),'UTF8'),'sha256'),'hex')
        $function$;
        ALTER FUNCTION lucy.deletion_targets_digest_v3(jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.deletion_targets_digest_v3(jsonb)
          FROM PUBLIC,lucy_app;

        CREATE FUNCTION lucy.store_scoped_deletion_manifest_v4(
          p_operation_id uuid,p_manifest jsonb
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v3%ROWTYPE;
          v_existing lucy.scoped_deletion_manifests_v3%ROWTYPE;
          v_targets jsonb; v_manifest_id uuid; v_digest text; v_targets_digest text;
          v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.deletion_manifest.issue"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped deletion manifest V3 unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id
            AND target_service_binding_id=v_actor.target_service_binding_id
            AND workflow_actor_binding_id IS NOT NULL
            AND action='evidence.delete' AND state='CLAIMED';
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped deletion manifest V3 unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'evidence-derive:'||v_operation.resource_object_id::text,0));
          SELECT * INTO v_existing FROM lucy.scoped_deletion_manifests_v3
          WHERE operation_id=p_operation_id;
          IF FOUND THEN
            IF v_existing.serialized_manifest<>p_manifest
            THEN RAISE EXCEPTION 'scoped deletion manifest V3 idempotency conflict'; END IF;
            RETURN jsonb_build_object('manifest_id',v_existing.id,
              'manifest_digest',v_existing.manifest_digest,
              'targets_digest',v_existing.targets_digest,
              'target_count',v_existing.target_count,'replayed',true);
          END IF;
          IF jsonb_typeof(p_manifest)<>'object' OR p_manifest-ARRAY[
            'canonicalization_version','signature_algorithm','signing_key_purpose','key_id',
            'issuer','environment','issued_at','signature','contract_version','object_type',
            'manifest_id','permit_id','permit_digest','operation_id','action','target_scope',
            'workspace_id','root_evidence_id','root_representation_id','owner_assertion_id',
            'owner_assertion_digest','idempotency_key','closure_version','targets',
            'target_count','targets_digest','tombstone_policy_version',
            'finality_policy_version','permit_claim_deadline',
            'execution_completion_deadline','nonce']<>'{}'::jsonb
          THEN RAISE EXCEPTION 'invalid scoped deletion manifest V3'; END IF;
          IF p_manifest->>'contract_version'<>'3'
             OR p_manifest->>'object_type'<>'lucy.deletion-target-manifest.v3'
             OR p_manifest->>'canonicalization_version'<>'lucy-cjson-1'
             OR p_manifest->>'signature_algorithm'<>'Ed25519'
             OR p_manifest->>'signing_key_purpose'<>'policy_notary_v13'
             OR p_manifest->>'action'<>'evidence.delete'
             OR coalesce(p_manifest->>'signature','')=''
             OR jsonb_typeof(p_manifest->'targets')<>'array'
             OR (p_manifest->>'closure_version')::bigint<>3
             OR (p_manifest->>'tombstone_policy_version')::bigint<>3
             OR (p_manifest->>'finality_policy_version')::bigint<>3
          THEN RAISE EXCEPTION 'invalid scoped deletion manifest V3 domain'; END IF;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v3
          WHERE id=v_operation.permit_id AND content_scope_id=v_actor.content_scope_id
            AND target_service_binding_id=v_actor.target_service_binding_id
            AND action='evidence.delete' AND state='CLAIMED';
          IF (p_manifest->>'operation_id')::uuid<>v_operation.id
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
             OR v_now>v_permit.permit_claim_deadline
             OR v_now>v_permit.execution_completion_deadline
          THEN RAISE EXCEPTION 'scoped deletion manifest V3 binding is invalid'; END IF;
          v_targets:=lucy.build_scoped_deletion_targets_v3(p_operation_id);
          v_targets_digest:=lucy.deletion_targets_digest_v3(v_targets);
          IF p_manifest->'targets'<>v_targets
             OR (p_manifest->>'target_count')::bigint<>jsonb_array_length(v_targets)
             OR (p_manifest->>'target_count')::bigint>
                (v_permit.serialized_permit->>'max_records')::bigint
             OR p_manifest->>'targets_digest'<>v_targets_digest
             OR (p_manifest->>'root_representation_id')::uuid<>
                (v_targets->0->>'representation_id')::uuid
          THEN RAISE EXCEPTION 'scoped deletion manifest V3 closure is not exact'; END IF;
          v_manifest_id:=(p_manifest->>'manifest_id')::uuid;
          v_digest:=lucy.security_contract_digest_v2(p_manifest);
          INSERT INTO lucy.scoped_evidence_deletion_fences_v2(
            evidence_id,content_scope_id,operation_id,created_at
          ) VALUES (v_operation.resource_object_id,v_operation.content_scope_id,
            v_operation.id,v_now);
          INSERT INTO lucy.scoped_deletion_manifests_v3(
            id,operation_id,permit_id,content_scope_id,policy_actor_binding_id,
            root_evidence_id,root_representation_id,manifest_digest,targets_digest,
            target_count,serialized_manifest,created_at
          ) VALUES (v_manifest_id,v_operation.id,v_permit.id,v_operation.content_scope_id,
            v_actor.id,v_operation.resource_object_id,
            (p_manifest->>'root_representation_id')::uuid,v_digest,v_targets_digest,
            jsonb_array_length(v_targets),p_manifest,v_now);
          INSERT INTO lucy.scoped_deletion_manifest_targets_v3(
            manifest_id,artifact_class,artifact_id,artifact_version,root_evidence_id,
            disposition,representation_id,wrapped_key_ref,key_registry_id,created_at
          ) SELECT v_manifest_id,target->>'artifact_class',(target->>'artifact_id')::uuid,
            (target->>'artifact_version')::bigint,(target->>'root_evidence_id')::uuid,
            target->>'disposition',(target->>'representation_id')::uuid,
            (target->>'wrapped_key_ref')::uuid,(target->>'key_registry_id')::uuid,v_now
          FROM jsonb_array_elements(v_targets) target;
          INSERT INTO lucy.sensitive_operation_events_v2(
            id,content_scope_id,operation_id,event_type,details,occurred_at
          ) VALUES (gen_random_uuid(),v_operation.content_scope_id,v_operation.id,
            'sensitive.deletion_manifest_frozen',jsonb_build_object(
              'manifest_id',v_manifest_id,'manifest_digest',v_digest,
              'targets_digest',v_targets_digest,'target_count',jsonb_array_length(v_targets),
              'contract_version',3),v_now);
          RETURN jsonb_build_object('manifest_id',v_manifest_id,'manifest_digest',v_digest,
            'targets_digest',v_targets_digest,'target_count',jsonb_array_length(v_targets),
            'replayed',false);
        EXCEPTION WHEN invalid_text_representation OR not_null_violation OR check_violation
          OR numeric_value_out_of_range THEN
          RAISE EXCEPTION 'malformed scoped deletion manifest V3';
        END
        $function$;
        ALTER FUNCTION lucy.store_scoped_deletion_manifest_v4(uuid,jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.store_scoped_deletion_manifest_v4(uuid,jsonb)
          FROM PUBLIC,lucy_app;
        REVOKE ALL ON lucy.scoped_deletion_manifests_v3,
          lucy.scoped_deletion_manifest_targets_v3 FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.scoped_deletion_manifests_v3,
          lucy.scoped_deletion_manifest_targets_v3 TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("memory deletion manifest V3 requires a reviewed forward migration")
