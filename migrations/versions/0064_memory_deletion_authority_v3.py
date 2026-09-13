"""Expose exact V3 deletion authority to the realm policy signer."""

from __future__ import annotations

from alembic import op

revision: str = "0064_memory_deletion_authority"
down_revision: str | None = "0063_memory_deletion_manifest"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE FUNCTION lucy.read_claimed_deletion_authority_v2(p_operation_id uuid)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v3%ROWTYPE;
          v_existing jsonb; v_targets jsonb; v_targets_digest text;
          v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.deletion_manifest.issue"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'deletion authority V3 unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id
            AND target_service_binding_id=v_actor.target_service_binding_id
            AND action='evidence.delete' AND state='CLAIMED';
          IF NOT FOUND THEN RAISE EXCEPTION 'deletion authority V3 unavailable'; END IF;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v3
          WHERE id=v_operation.permit_id AND content_scope_id=v_actor.content_scope_id
            AND target_service_binding_id=v_actor.target_service_binding_id
            AND action='evidence.delete' AND state='CLAIMED';
          SELECT serialized_manifest INTO v_existing
          FROM lucy.scoped_deletion_manifests_v3
          WHERE operation_id=v_operation.id AND content_scope_id=v_actor.content_scope_id;
          IF FOUND THEN
            RETURN jsonb_build_object(
              'operation_id',v_operation.id,'action',v_operation.action,
              'claimed_at',v_operation.claimed_at,
              'claim_idempotency_key',v_operation.claim_idempotency_key,
              'permit',v_permit.serialized_permit,
              'root_evidence_id',v_operation.resource_object_id,
              'record_version',v_operation.resource_object_version,
              'existing_manifest',v_existing);
          END IF;
          IF v_now>v_permit.permit_claim_deadline
          THEN RAISE EXCEPTION 'deletion authority V3 admission expired'; END IF;
          v_targets:=lucy.build_scoped_deletion_targets_v3(p_operation_id);
          IF jsonb_array_length(v_targets)>
             (v_permit.serialized_permit->>'max_records')::bigint
          THEN RAISE EXCEPTION 'deletion authority V3 closure exceeds permit'; END IF;
          v_targets_digest:=lucy.deletion_targets_digest_v3(v_targets);
          RETURN jsonb_build_object(
            'operation_id',v_operation.id,'action',v_operation.action,
            'claimed_at',v_operation.claimed_at,
            'claim_idempotency_key',v_operation.claim_idempotency_key,
            'permit',v_permit.serialized_permit,
            'root_evidence_id',v_operation.resource_object_id,
            'record_version',v_operation.resource_object_version,
            'root_representation_id',v_targets->0->>'representation_id',
            'targets',v_targets,'target_count',jsonb_array_length(v_targets),
            'targets_digest',v_targets_digest,'closure_version',3,
            'tombstone_policy_version',3,'finality_policy_version',3,
            'existing_manifest',NULL);
        EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
          OR no_data_found OR too_many_rows THEN
          RAISE EXCEPTION 'deletion authority V3 unavailable';
        END
        $function$;
        ALTER FUNCTION lucy.read_claimed_deletion_authority_v2(uuid)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.read_claimed_deletion_authority_v2(uuid)
          FROM PUBLIC,lucy_app;
        """
    )


def downgrade() -> None:
    raise RuntimeError("memory deletion authority V3 requires a reviewed forward migration")
