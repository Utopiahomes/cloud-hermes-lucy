"""Admit the explicitly bound Workspaces service authority."""

from collections.abc import Sequence

from alembic import op

revision: str = "0068_workspaces_service_auth"
down_revision: str | None = "0067_memory_deletion_recovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_SIGNATURE = (
    "text,text,text,uuid,uuid,uuid,bigint,uuid,bigint,uuid,uuid,uuid,uuid,"
    "bigint,uuid,text,uuid,bigint,timestamptz"
)


def upgrade() -> None:
    op.execute(
        rf"""
        CREATE OR REPLACE FUNCTION lucy.resolve_internal_admission_v1(
          p_identity_issuer text,p_identity_subject text,p_principal_type text,
          p_tenant_account_id uuid,p_node_id uuid,p_node_tenure_id uuid,
          p_tenure_epoch bigint,p_security_realm_id uuid,p_storage_epoch bigint,
          p_workspace_id uuid,p_deployment_id uuid,p_service_principal_id uuid,
          p_service_binding_id uuid,p_service_binding_generation bigint,
          p_channel_binding_id uuid,p_action text,p_resource_object_id uuid,
          p_resource_object_version bigint,p_checked_at timestamptz
        ) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_result jsonb;
        BEGIN
          IF p_identity_issuer IS NULL OR btrim(p_identity_issuer)=''
             OR length(p_identity_issuer)>512
             OR p_identity_subject IS NULL OR btrim(p_identity_subject)=''
             OR length(p_identity_subject)>512
             OR p_principal_type NOT IN ('human','agent','service','runtime')
             OR p_action NOT IN ('memory.read','memory.write','task.delegate')
             OR p_tenure_epoch<1 OR p_storage_epoch<1
             OR p_service_binding_generation<1
             OR p_resource_object_version<>1
             OR p_resource_object_id<>p_workspace_id OR p_checked_at IS NULL
          THEN RAISE EXCEPTION 'internal admission unavailable'; END IF;

          SELECT jsonb_build_object(
            'principal_id',p.id,'identity_issuer',p.issuer,
            'identity_subject',p.subject,'principal_type',p.principal_kind,
            'target_scope',jsonb_build_object(
              'tenant_account_id',cs.tenant_account_id,'node_id',cs.node_id,
              'node_tenure_id',cs.node_tenure_id,'tenure_epoch',cs.tenure_epoch,
              'security_realm_id',cs.security_realm_id,'storage_epoch',cs.storage_epoch),
            'workspace_id',w.id,'deployment_id',cs.deployment_id,
            'service_principal_id',sb.service_principal_id,
            'service_binding_id',sb.id,
            'service_binding_generation',sb.binding_generation,
            'channel_binding_id',ch.id,'channel_generation',ch.generation,
            'membership_generations',jsonb_build_array(m.generation),
            'realm_binding_generation',rb.binding_version,
            'node_authz_epoch',n.authz_epoch,'policy_version',sb.policy_version,
            'authorized_action',p_action,
            'resource_selector',jsonb_build_object(
              'selector_type','exact_object','object_id',p_resource_object_id,
              'object_version',p_resource_object_version)
          ) INTO v_result
          FROM lucy.principals p
          JOIN lucy.node_memberships m
            ON m.principal_id=p.id AND m.workspace_id=p_workspace_id
          JOIN lucy.workspaces w ON w.id=m.workspace_id AND w.id=p_workspace_id
          JOIN lucy.nodes n ON n.id=w.node_id AND n.id=p_node_id
          JOIN lucy.node_tenures nt
            ON nt.id=w.tenure_id AND nt.id=p_node_tenure_id
            AND nt.node_id=n.id AND nt.account_id=p_tenant_account_id
          JOIN lucy.realm_bindings rb
            ON rb.tenure_id=nt.id AND rb.realm_id=p_security_realm_id
          JOIN lucy.channel_bindings ch
            ON ch.id=p_channel_binding_id AND ch.workspace_id=w.id
            AND ch.node_id=n.id AND ch.tenure_id=nt.id
          JOIN lucy.realm_content_scopes_v1 cs
            ON cs.tenant_account_id=p_tenant_account_id
            AND cs.node_id=n.id AND cs.node_tenure_id=nt.id
            AND cs.tenure_epoch=p_tenure_epoch
            AND cs.security_realm_id=p_security_realm_id
            AND cs.storage_epoch=p_storage_epoch
            AND cs.realm_binding_id=rb.id AND cs.workspace_id=w.id
            AND cs.deployment_id=p_deployment_id
          JOIN lucy.realm_service_bindings_v1 sb
            ON sb.id=p_service_binding_id AND sb.content_scope_id=cs.id
            AND sb.service_principal_id=p_service_principal_id
          JOIN lucy.principals sp
            ON sp.id=sb.service_principal_id AND sp.principal_kind='service'
            AND sp.status='active'
          WHERE p.issuer=p_identity_issuer AND p.subject=p_identity_subject
            AND p.principal_kind=p_principal_type AND p.status='active'
            AND (p.principal_kind<>'service' OR p.id=sb.service_principal_id)
            AND m.status='active'
            AND ((p_action IN ('memory.read','task.delegate')
                  AND m.role IN ('owner','member'))
              OR (p_action='memory.write' AND m.role='owner'))
            AND w.workspace_kind IN ('private','private_realm')
            AND nt.sequence=p_tenure_epoch AND nt.starts_at<=p_checked_at
            AND (nt.ends_at IS NULL OR nt.ends_at>p_checked_at)
            AND rb.valid_from<=p_checked_at AND rb.valid_to IS NULL
            AND ch.channel_kind='internal' AND ch.active
            AND sb.active AND sb.binding_generation=p_service_binding_generation
            AND sb.node_authz_epoch=n.authz_epoch
            AND sb.allowed_actions @> jsonb_build_array(p_action);
          IF v_result IS NULL THEN
            RAISE EXCEPTION 'internal admission unavailable';
          END IF;
          RETURN v_result;
        END
        $function$;
        ALTER FUNCTION lucy.resolve_internal_admission_v1({_SIGNATURE})
          OWNER TO lucy_directory_function_owner;
        REVOKE ALL ON FUNCTION lucy.resolve_internal_admission_v1({_SIGNATURE})
          FROM PUBLIC,lucy_app,lucy_public_runtime;
        GRANT EXECUTE ON FUNCTION lucy.resolve_internal_admission_v1({_SIGNATURE})
          TO lucy_directory_admission;
        """
    )


def downgrade() -> None:
    op.execute(
        rf"""
        CREATE OR REPLACE FUNCTION lucy.resolve_internal_admission_v1(
          p_identity_issuer text,p_identity_subject text,p_principal_type text,
          p_tenant_account_id uuid,p_node_id uuid,p_node_tenure_id uuid,
          p_tenure_epoch bigint,p_security_realm_id uuid,p_storage_epoch bigint,
          p_workspace_id uuid,p_deployment_id uuid,p_service_principal_id uuid,
          p_service_binding_id uuid,p_service_binding_generation bigint,
          p_channel_binding_id uuid,p_action text,p_resource_object_id uuid,
          p_resource_object_version bigint,p_checked_at timestamptz
        ) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_result jsonb;
        BEGIN
          IF p_action NOT IN ('memory.read','memory.write','task.delegate')
          THEN RAISE EXCEPTION 'internal admission unavailable'; END IF;
          v_result:=lucy.resolve_internal_admission_pre_workspaces_v1(
            p_identity_issuer,p_identity_subject,p_principal_type,
            p_tenant_account_id,p_node_id,p_node_tenure_id,p_tenure_epoch,
            p_security_realm_id,p_storage_epoch,p_workspace_id,p_deployment_id,
            p_service_principal_id,p_service_binding_id,p_service_binding_generation,
            p_channel_binding_id,
            CASE WHEN p_action='task.delegate' THEN 'memory.read' ELSE p_action END,
            p_resource_object_id,p_resource_object_version,p_checked_at);
          IF p_action='task.delegate' AND NOT EXISTS (
            SELECT 1 FROM lucy.realm_service_bindings_v1
            WHERE id=p_service_binding_id AND active
              AND allowed_actions @> '["task.delegate"]'::jsonb)
          THEN RAISE EXCEPTION 'internal admission unavailable'; END IF;
          RETURN jsonb_set(v_result,'{{authorized_action}}',to_jsonb(p_action));
        END
        $function$;
        ALTER FUNCTION lucy.resolve_internal_admission_v1({_SIGNATURE})
          OWNER TO lucy_directory_function_owner;
        REVOKE ALL ON FUNCTION lucy.resolve_internal_admission_v1({_SIGNATURE})
          FROM PUBLIC,lucy_app,lucy_public_runtime;
        GRANT EXECUTE ON FUNCTION lucy.resolve_internal_admission_v1({_SIGNATURE})
          TO lucy_directory_admission;
        """
    )
