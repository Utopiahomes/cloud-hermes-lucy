"""Expose the exact content-free post-claim authority to the realm policy notary."""

from collections.abc import Sequence

from alembic import op

revision: str = "0040_r1_grant_authority_snapshot"
down_revision: str | None = "0039_r1_scoped_capture_runtime"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE FUNCTION lucy.read_claimed_sensitive_authority_v1(p_operation_id uuid)
        RETURNS jsonb
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v3%ROWTYPE;
          v_executor lucy.realm_executor_bindings_v2%ROWTYPE;
          v_package lucy.sensitive_operation_packages_v2%ROWTYPE;
          v_manifest lucy.scoped_deletion_manifests_v2%ROWTYPE;
          v_existing lucy.sensitive_execution_grants_v2%ROWTYPE;
          v_digest text; v_size bigint; v_manifest_id uuid; v_manifest_digest text;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.grant.issue"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'grant authority snapshot unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id
            AND state='CLAIMED';
          IF NOT FOUND THEN RAISE EXCEPTION 'grant authority snapshot unavailable'; END IF;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v3
          WHERE id=v_operation.permit_id AND content_scope_id=v_actor.content_scope_id
            AND state='CLAIMED';
          SELECT * INTO v_executor FROM lucy.realm_executor_bindings_v2
          WHERE content_scope_id=v_actor.content_scope_id AND action=v_operation.action AND active
            AND node_authz_epoch=v_actor.node_authz_epoch
            AND policy_version=v_actor.policy_version;
          IF NOT FOUND THEN RAISE EXCEPTION 'grant authority executor unavailable'; END IF;
          IF v_operation.action='evidence.retrieve' THEN
            SELECT * INTO STRICT v_package FROM lucy.sensitive_operation_packages_v2
            WHERE operation_id=v_operation.id AND permit_id=v_permit.id;
            v_digest:=v_package.package_digest;
            v_size:=octet_length(convert_to(
              lucy.canonical_jsonb_v1(v_package.serialized_package),'UTF8'));
          ELSIF v_operation.action='evidence.delete' THEN
            SELECT * INTO STRICT v_manifest FROM lucy.scoped_deletion_manifests_v2
            WHERE operation_id=v_operation.id AND permit_id=v_permit.id;
            v_digest:=v_manifest.manifest_digest;
            v_size:=octet_length(convert_to(
              lucy.canonical_jsonb_v1(v_manifest.serialized_manifest),'UTF8'));
            v_manifest_id:=v_manifest.id;
            v_manifest_digest:=v_manifest.manifest_digest;
          ELSE
            RAISE EXCEPTION 'grant authority action unavailable';
          END IF;
          SELECT * INTO v_existing FROM lucy.sensitive_execution_grants_v2
          WHERE operation_id=v_operation.id AND content_scope_id=v_actor.content_scope_id;
          RETURN jsonb_build_object(
            'operation_id',v_operation.id,
            'action',v_operation.action,
            'claimed_at',v_operation.claimed_at,
            'claim_idempotency_key',v_operation.claim_idempotency_key,
            'permit',v_permit.serialized_permit,
            'package_digest',v_digest,
            'package_size_bytes',v_size,
            'executor_binding_id',v_executor.id,
            'caller_identity',v_executor.caller_identity,
            'executor_identity',v_executor.executor_identity,
            'executor_alias_arn',v_executor.executor_alias_arn,
            'executor_version',v_executor.executor_version,
            'receipt_key_id',v_executor.receipt_key_id,
            'deletion_manifest_id',v_manifest_id,
            'deletion_manifest_digest',v_manifest_digest,
            'existing_grant',v_existing.serialized_grant);
        END
        $function$;

        ALTER FUNCTION lucy.read_claimed_sensitive_authority_v1(uuid)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.read_claimed_sensitive_authority_v1(uuid)
          FROM PUBLIC,lucy_app;

        CREATE FUNCTION lucy.read_sensitive_operation_status_v1(p_operation_id uuid)
        RETURNS jsonb
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_finality timestamptz;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='sensitive_workflow' AND active
            AND allowed_actions @> '["sensitive.operation.reconcile"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'sensitive operation status unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id
            AND workflow_actor_binding_id=v_actor.id;
          IF NOT FOUND THEN RAISE EXCEPTION 'sensitive operation status unavailable'; END IF;
          IF v_operation.action='evidence.delete' THEN
            SELECT finality_not_before INTO v_finality FROM lucy.scoped_deletion_effects_v2
            WHERE operation_id=v_operation.id AND content_scope_id=v_actor.content_scope_id;
          END IF;
          RETURN jsonb_build_object(
            'operation_id',v_operation.id,
            'action',v_operation.action,
            'state',v_operation.state,
            'result',v_operation.executor_result,
            'receipt_digest',v_operation.executor_receipt_digest,
            'finality_not_before',v_finality);
        END
        $function$;

        ALTER FUNCTION lucy.read_sensitive_operation_status_v1(uuid)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.read_sensitive_operation_status_v1(uuid)
          FROM PUBLIC,lucy_app;
        """
    )


def downgrade() -> None:
    raise RuntimeError("R1 grant authority snapshot requires a reviewed forward migration")
