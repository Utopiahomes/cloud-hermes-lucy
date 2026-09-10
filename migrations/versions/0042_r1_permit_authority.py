"""Add exact-record policy authority and permit handoff snapshots."""

from collections.abc import Sequence

from alembic import op

revision: str = "0042_r1_permit_authority"
down_revision: str | None = "0041_r1_deletion_auth_snapshot"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE FUNCTION lucy.read_sensitive_permit_authority_v1(
          p_principal_id uuid,
          p_channel_binding_id uuid,
          p_action text,
          p_resource_object_id uuid,
          p_resource_object_version bigint
        ) RETURNS jsonb
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_result jsonb;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.permit.issue"]'::jsonb;
          IF NOT FOUND OR p_action NOT IN ('evidence.retrieve','evidence.delete')
             OR p_resource_object_version < 1
          THEN RAISE EXCEPTION 'sensitive permit authority unavailable'; END IF;

          SELECT jsonb_build_object(
            'principal_id',p.id,
            'identity_issuer',p.issuer,
            'identity_subject',p.subject,
            'target_scope',jsonb_build_object(
              'tenant_account_id',cs.tenant_account_id,
              'node_id',cs.node_id,
              'node_tenure_id',cs.node_tenure_id,
              'tenure_epoch',cs.tenure_epoch,
              'security_realm_id',cs.security_realm_id,
              'storage_epoch',cs.storage_epoch
            ),
            'workspace_id',cs.workspace_id,
            'service_principal_id',sb.service_principal_id,
            'service_binding_id',sb.id,
            'service_binding_generation',sb.binding_generation,
            'execution_binding',jsonb_build_object(
              'deployment_id',cs.deployment_id,
              'active_realm_id',cs.security_realm_id,
              'active_storage_epoch',cs.storage_epoch,
              'realm_binding_generation',rb.binding_version,
              'node_authz_epoch',n.authz_epoch
            ),
            'membership_generation',m.generation,
            'channel_binding_id',ch.id,
            'channel_generation',ch.generation,
            'policy_version',sb.policy_version,
            'resource_selector',jsonb_build_object(
              'selector_type','exact_object',
              'object_id',e.id,
              'object_version',ep.record_version
            )
          ) INTO v_result
          FROM lucy.realm_content_scopes_v1 cs
          JOIN lucy.realm_service_bindings_v1 sb
            ON sb.id=v_actor.target_service_binding_id
            AND sb.content_scope_id=cs.id AND sb.active
            AND sb.allowed_actions @> jsonb_build_array(p_action)
          JOIN lucy.principals sp
            ON sp.id=sb.service_principal_id AND sp.principal_kind='service'
            AND sp.status='active'
          JOIN lucy.principals p
            ON p.id=p_principal_id AND p.principal_kind='human' AND p.status='active'
          JOIN lucy.node_memberships m
            ON m.principal_id=p.id AND m.workspace_id=cs.workspace_id
            AND m.role='owner' AND m.status='active'
          JOIN lucy.channel_bindings ch
            ON ch.id=p_channel_binding_id AND ch.workspace_id=cs.workspace_id
            AND ch.node_id=cs.node_id AND ch.tenure_id=cs.node_tenure_id
            AND ch.channel_kind='internal' AND ch.active
          JOIN lucy.nodes n
            ON n.id=cs.node_id AND n.authz_epoch=v_actor.node_authz_epoch
            AND n.authz_epoch=sb.node_authz_epoch
          JOIN lucy.node_tenures nt
            ON nt.id=cs.node_tenure_id AND nt.node_id=cs.node_id
            AND nt.account_id=cs.tenant_account_id
            AND nt.sequence=cs.tenure_epoch AND nt.ends_at IS NULL
          JOIN lucy.realm_bindings rb
            ON rb.id=cs.realm_binding_id AND rb.tenure_id=cs.node_tenure_id
            AND rb.realm_id=cs.security_realm_id AND rb.valid_to IS NULL
          JOIN lucy.scoped_evidence_records_v2 e
            ON e.id=p_resource_object_id AND e.content_scope_id=cs.id
            AND e.status='active'
          JOIN lucy.scoped_evidence_payloads_v2 ep
            ON ep.evidence_id=e.id AND ep.record_version=p_resource_object_version
          WHERE cs.id=v_actor.content_scope_id
            AND v_actor.target_service_binding_id=sb.id
            AND v_actor.node_authz_epoch=sb.node_authz_epoch
            AND v_actor.policy_version=sb.policy_version
            AND NOT EXISTS (
              SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
              WHERE f.content_scope_id=cs.id AND f.evidence_id=e.id
            )
            AND NOT EXISTS (
              SELECT 1 FROM lucy.scoped_recovery_deletion_fences_v2 rf
              WHERE rf.content_scope_id=cs.id AND rf.evidence_id=e.id
            );

          IF v_result IS NULL THEN
            RAISE EXCEPTION 'sensitive permit authority unavailable';
          END IF;
          RETURN v_result;
        END
        $function$;

        CREATE FUNCTION lucy.read_sensitive_action_permit_v3(
          p_permit_id uuid, p_expected_action text
        ) RETURNS jsonb
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_permit jsonb;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='sensitive_workflow' AND active
            AND allowed_actions @> '["sensitive.operation.claim"]'::jsonb;
          IF NOT FOUND OR p_expected_action NOT IN ('evidence.retrieve','evidence.delete')
          THEN RAISE EXCEPTION 'sensitive permit handoff unavailable'; END IF;
          SELECT p.serialized_permit INTO v_permit
          FROM lucy.sensitive_action_permits_v3 p
          WHERE p.id=p_permit_id AND p.action=p_expected_action
            AND p.content_scope_id=v_actor.content_scope_id
            AND p.target_service_binding_id=v_actor.target_service_binding_id;
          IF v_permit IS NULL THEN
            RAISE EXCEPTION 'sensitive permit handoff unavailable';
          END IF;
          RETURN v_permit;
        END
        $function$;
        """
    )
    for signature in (
        "lucy.read_sensitive_permit_authority_v1(uuid,uuid,text,uuid,bigint)",
        "lucy.read_sensitive_action_permit_v3(uuid,text)",
    ):
        op.execute(
            f"ALTER FUNCTION {signature} OWNER TO lucy_security_function_owner; "
            f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC, lucy_app"
        )
    op.execute(
        "GRANT SELECT ON lucy.scoped_evidence_deletion_fences_v2, "
        "lucy.scoped_recovery_deletion_fences_v2 TO lucy_security_function_owner"
    )


def downgrade() -> None:
    raise RuntimeError("R1 permit authority snapshots require a reviewed forward migration")
