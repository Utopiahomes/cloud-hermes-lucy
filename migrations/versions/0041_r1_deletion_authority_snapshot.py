"""Expose one exact content-free deletion closure to its realm policy notary."""

from collections.abc import Sequence

from alembic import op

revision: str = "0041_r1_deletion_authority_snapshot"
down_revision: str | None = "0040_r1_grant_authority_snapshot"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE FUNCTION lucy.read_claimed_deletion_authority_v1(p_operation_id uuid)
        RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v3%ROWTYPE;
          v_existing jsonb;
          v_root_evidence_id uuid;
          v_record_version bigint;
          v_representation_id uuid;
          v_wrapped_key_ref uuid;
          v_targets jsonb;
          v_targets_digest text;
          v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.deletion_manifest.issue"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'deletion authority snapshot unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id
            AND target_service_binding_id=v_actor.target_service_binding_id
            AND action='evidence.delete' AND state='CLAIMED';
          IF NOT FOUND THEN RAISE EXCEPTION 'deletion authority snapshot unavailable'; END IF;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v3
          WHERE id=v_operation.permit_id AND content_scope_id=v_actor.content_scope_id
            AND target_service_binding_id=v_actor.target_service_binding_id
            AND action='evidence.delete' AND state='CLAIMED';
          SELECT serialized_manifest INTO v_existing
          FROM lucy.scoped_deletion_manifests_v2
          WHERE operation_id=v_operation.id AND content_scope_id=v_actor.content_scope_id;
          IF FOUND THEN
            RETURN jsonb_build_object(
              'operation_id',v_operation.id,
              'action',v_operation.action,
              'claimed_at',v_operation.claimed_at,
              'claim_idempotency_key',v_operation.claim_idempotency_key,
              'permit',v_permit.serialized_permit,
              'root_evidence_id',v_operation.resource_object_id,
              'record_version',v_operation.resource_object_version,
              'existing_manifest',v_existing);
          END IF;
          IF v_now>v_permit.permit_claim_deadline THEN
            RAISE EXCEPTION 'deletion authority admission expired';
          END IF;
          v_root_evidence_id:=v_operation.resource_object_id;
          IF NOT EXISTS (
            SELECT 1 FROM lucy.scoped_evidence_records_v2
            WHERE id=v_root_evidence_id AND content_scope_id=v_actor.content_scope_id
              AND status='active'
          ) OR EXISTS (
            SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2
            WHERE evidence_id=v_root_evidence_id
          ) THEN RAISE EXCEPTION 'deletion authority root unavailable'; END IF;
          SELECT record_version INTO STRICT v_record_version
          FROM lucy.scoped_evidence_payloads_v2
          WHERE evidence_id=v_root_evidence_id
            AND record_version=v_operation.resource_object_version;
          SELECT representation_id,wrapped_key_ref
          INTO STRICT v_representation_id,v_wrapped_key_ref
          FROM lucy.scoped_evidence_wrappers_v2
          WHERE evidence_id=v_root_evidence_id
            AND content_scope_id=v_actor.content_scope_id AND current;
          SELECT jsonb_agg(target ORDER BY target->>'artifact_class',
            target->>'artifact_id',coalesce(target->>'representation_id','')) INTO v_targets
          FROM (
            SELECT jsonb_build_object(
              'artifact_class','encrypted_archive','artifact_id',v_root_evidence_id,
              'artifact_version',v_record_version,'root_evidence_id',v_root_evidence_id,
              'disposition','destroy_wrapped_key','representation_id',
              v_representation_id,'wrapped_key_ref',v_wrapped_key_ref) target
            UNION ALL
            SELECT jsonb_build_object(
              'artifact_class','memory_claim','artifact_id',source.claim_id,
              'artifact_version',1,'root_evidence_id',v_root_evidence_id,
              'disposition','invalidate','representation_id',NULL,
              'wrapped_key_ref',NULL) target
            FROM lucy.scoped_memory_claim_sources_v2 source
            WHERE source.evidence_id=v_root_evidence_id
              AND source.content_scope_id=v_actor.content_scope_id
          ) closure;
          IF jsonb_array_length(v_targets)>(v_permit.serialized_permit->>'max_records')::bigint
          THEN RAISE EXCEPTION 'deletion authority closure exceeds permit'; END IF;
          v_targets_digest:=lucy.deletion_targets_digest_v2(v_targets);
          RETURN jsonb_build_object(
            'operation_id',v_operation.id,
            'action',v_operation.action,
            'claimed_at',v_operation.claimed_at,
            'claim_idempotency_key',v_operation.claim_idempotency_key,
            'permit',v_permit.serialized_permit,
            'root_evidence_id',v_root_evidence_id,
            'record_version',v_record_version,
            'root_representation_id',v_representation_id,
            'targets',v_targets,
            'target_count',jsonb_array_length(v_targets),
            'targets_digest',v_targets_digest,
            'closure_version',1,
            'tombstone_policy_version',1,
            'finality_policy_version',1,
            'existing_manifest',NULL);
        END
        $function$;

        ALTER FUNCTION lucy.read_claimed_deletion_authority_v1(uuid)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.read_claimed_deletion_authority_v1(uuid)
          FROM PUBLIC,lucy_app;

        CREATE FUNCTION lucy.store_scoped_deletion_manifest_v3(
          p_operation_id uuid,p_manifest jsonb
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_claim_deadline timestamptz;
          v_deadline timestamptz;
          v_state text;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.deletion_manifest.issue"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped deletion manifest unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id
            AND target_service_binding_id=v_actor.target_service_binding_id
            AND action='evidence.delete';
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped deletion manifest unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'evidence-derive:'||v_operation.resource_object_id::text,0));
          SELECT operation.state,permit.permit_claim_deadline,
            permit.execution_completion_deadline
          INTO STRICT v_state,v_claim_deadline,v_deadline
          FROM lucy.sensitive_operations_v2 operation
          JOIN lucy.sensitive_action_permits_v3 permit ON permit.id=operation.permit_id
          WHERE operation.id=p_operation_id
            AND operation.content_scope_id=v_actor.content_scope_id
            AND operation.target_service_binding_id=v_actor.target_service_binding_id
            AND operation.action='evidence.delete';
          IF v_state<>'CLAIMED' OR clock_timestamp()>v_claim_deadline
             OR clock_timestamp()>v_deadline THEN
            RAISE EXCEPTION 'scoped deletion manifest authority changed while waiting';
          END IF;
          RETURN lucy.store_scoped_deletion_manifest_v2(p_operation_id,p_manifest);
        END
        $function$;

        ALTER FUNCTION lucy.store_scoped_deletion_manifest_v3(uuid,jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.store_scoped_deletion_manifest_v3(uuid,jsonb)
          FROM PUBLIC,lucy_app;
        """
    )


def downgrade() -> None:
    raise RuntimeError("R1 deletion authority snapshot requires a reviewed forward migration")
