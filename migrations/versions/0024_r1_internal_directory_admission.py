"""Add content-free internal directory admission and authority generations."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024_r1_internal_admission"
down_revision: str | None = "0023_r1_scoped_memory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "nodes",
        sa.Column("authz_epoch", sa.BigInteger(), nullable=False, server_default=sa.text("1")),
        schema="lucy",
    )
    op.add_column(
        "principals",
        sa.Column(
            "status", sa.String(20), nullable=False, server_default=sa.text("'active'")
        ),
        schema="lucy",
    )
    op.add_column(
        "node_memberships",
        sa.Column("generation", sa.BigInteger(), nullable=False, server_default=sa.text("1")),
        schema="lucy",
    )
    op.add_column(
        "channel_bindings",
        sa.Column("generation", sa.BigInteger(), nullable=False, server_default=sa.text("1")),
        schema="lucy",
    )
    op.add_column(
        "realm_service_bindings_v1",
        sa.Column("policy_version", sa.BigInteger(), nullable=False, server_default=sa.text("1")),
        schema="lucy",
    )
    op.create_check_constraint("ck_node_authz_epoch", "nodes", "authz_epoch > 0", schema="lucy")
    op.create_check_constraint(
        "ck_principal_status",
        "principals",
        "status IN ('active','disabled')",
        schema="lucy",
    )
    op.create_check_constraint(
        "ck_membership_generation",
        "node_memberships",
        "generation > 0",
        schema="lucy",
    )
    op.create_check_constraint(
        "ck_channel_generation",
        "channel_bindings",
        "generation > 0",
        schema="lucy",
    )
    op.create_check_constraint(
        "ck_service_policy_version",
        "realm_service_bindings_v1",
        "policy_version > 0",
        schema="lucy",
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.node_authority_guard_v1() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
          IF NEW.id<>OLD.id OR NEW.slug<>OLD.slug OR NEW.display_name<>OLD.display_name
             OR NEW.node_kind<>OLD.node_kind OR NEW.created_at<>OLD.created_at
             OR NEW.authz_epoch<>OLD.authz_epoch+1
          THEN RAISE EXCEPTION 'node authority transition unavailable'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER node_authority_monotonic BEFORE UPDATE ON lucy.nodes
        FOR EACH ROW EXECUTE FUNCTION lucy.node_authority_guard_v1();

        CREATE FUNCTION lucy.principal_authority_guard_v1() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
          IF NEW.id<>OLD.id OR NEW.issuer<>OLD.issuer OR NEW.subject<>OLD.subject
             OR NEW.principal_kind<>OLD.principal_kind
             OR NEW.display_name<>OLD.display_name OR NEW.created_at<>OLD.created_at
             OR OLD.status<>'active' OR NEW.status<>'disabled'
          THEN RAISE EXCEPTION 'principal authority transition unavailable'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER principal_authority_monotonic BEFORE UPDATE ON lucy.principals
        FOR EACH ROW EXECUTE FUNCTION lucy.principal_authority_guard_v1();

        CREATE FUNCTION lucy.membership_authority_guard_v1() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
          IF NEW.id<>OLD.id OR NEW.principal_id<>OLD.principal_id
             OR NEW.workspace_id<>OLD.workspace_id OR NEW.role<>OLD.role
             OR NEW.granted_at<>OLD.granted_at OR OLD.status<>'active'
             OR NEW.status<>'revoked' OR NEW.generation<>OLD.generation+1
          THEN RAISE EXCEPTION 'membership authority transition unavailable'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER membership_authority_monotonic
        BEFORE UPDATE ON lucy.node_memberships
        FOR EACH ROW EXECUTE FUNCTION lucy.membership_authority_guard_v1();

        CREATE FUNCTION lucy.channel_authority_guard_v1() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
          IF NEW.id<>OLD.id OR NEW.hostname<>OLD.hostname OR NEW.node_id<>OLD.node_id
             OR NEW.tenure_id<>OLD.tenure_id OR NEW.workspace_id<>OLD.workspace_id
             OR NEW.channel_kind<>OLD.channel_kind OR NEW.created_at<>OLD.created_at
             OR NOT OLD.active OR NEW.active OR NEW.generation<>OLD.generation+1
          THEN RAISE EXCEPTION 'channel authority transition unavailable'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER channel_authority_monotonic
        BEFORE UPDATE ON lucy.channel_bindings
        FOR EACH ROW EXECUTE FUNCTION lucy.channel_authority_guard_v1();

        DROP TRIGGER realm_service_bindings_immutable
          ON lucy.realm_service_bindings_v1;
        CREATE FUNCTION lucy.realm_service_binding_guard_v1() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
          IF TG_OP='DELETE' THEN
            RAISE EXCEPTION 'service binding mutation unavailable';
          END IF;
          IF NEW.id<>OLD.id OR NEW.session_login<>OLD.session_login
             OR NEW.service_principal_id<>OLD.service_principal_id
             OR NEW.content_scope_id<>OLD.content_scope_id
             OR NEW.service_role<>OLD.service_role
             OR NEW.allowed_actions<>OLD.allowed_actions
             OR NEW.node_authz_epoch<>OLD.node_authz_epoch
             OR NEW.policy_version<>OLD.policy_version OR NEW.created_at<>OLD.created_at
             OR NOT OLD.active OR NEW.active
             OR NEW.binding_generation<>OLD.binding_generation+1
          THEN RAISE EXCEPTION 'service binding mutation unavailable'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER realm_service_binding_monotonic
        BEFORE UPDATE OR DELETE ON lucy.realm_service_bindings_v1
        FOR EACH ROW EXECUTE FUNCTION lucy.realm_service_binding_guard_v1();

        GRANT USAGE ON SCHEMA lucy TO lucy_directory_function_owner;
        GRANT SELECT ON lucy.tenant_accounts, lucy.nodes, lucy.node_tenures,
          lucy.security_realms, lucy.realm_bindings, lucy.principals,
          lucy.workspaces, lucy.node_memberships, lucy.channel_bindings,
          lucy.realm_content_scopes_v1, lucy.realm_service_bindings_v1
          TO lucy_directory_function_owner;

        CREATE FUNCTION lucy.resolve_internal_admission_v1(
          p_identity_issuer text,
          p_identity_subject text,
          p_principal_type text,
          p_tenant_account_id uuid,
          p_node_id uuid,
          p_node_tenure_id uuid,
          p_tenure_epoch bigint,
          p_security_realm_id uuid,
          p_storage_epoch bigint,
          p_workspace_id uuid,
          p_deployment_id uuid,
          p_service_principal_id uuid,
          p_service_binding_id uuid,
          p_service_binding_generation bigint,
          p_channel_binding_id uuid,
          p_action text,
          p_resource_object_id uuid,
          p_resource_object_version bigint,
          p_checked_at timestamptz
        ) RETURNS jsonb
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_result jsonb;
        BEGIN
          IF p_identity_issuer IS NULL OR btrim(p_identity_issuer)=''
             OR length(p_identity_issuer)>512
             OR p_identity_subject IS NULL OR btrim(p_identity_subject)=''
             OR length(p_identity_subject)>512
             OR p_principal_type NOT IN ('human','agent','service','runtime')
             OR p_action NOT IN ('memory.read','memory.write')
             OR p_tenure_epoch < 1 OR p_storage_epoch < 1
             OR p_service_binding_generation < 1
             OR p_resource_object_version <> 1
             OR p_resource_object_id <> p_workspace_id
             OR p_checked_at IS NULL
          THEN
            RAISE EXCEPTION 'internal admission unavailable';
          END IF;

          SELECT jsonb_build_object(
            'principal_id', p.id,
            'identity_issuer', p.issuer,
            'identity_subject', p.subject,
            'principal_type', p.principal_kind,
            'target_scope', jsonb_build_object(
              'tenant_account_id', cs.tenant_account_id,
              'node_id', cs.node_id,
              'node_tenure_id', cs.node_tenure_id,
              'tenure_epoch', cs.tenure_epoch,
              'security_realm_id', cs.security_realm_id,
              'storage_epoch', cs.storage_epoch
            ),
            'workspace_id', w.id,
            'deployment_id', cs.deployment_id,
            'service_principal_id', sb.service_principal_id,
            'service_binding_id', sb.id,
            'service_binding_generation', sb.binding_generation,
            'channel_binding_id', ch.id,
            'channel_generation', ch.generation,
            'membership_generations', jsonb_build_array(m.generation),
            'realm_binding_generation', rb.binding_version,
            'node_authz_epoch', n.authz_epoch,
            'policy_version', sb.policy_version,
            'authorized_action', p_action,
            'resource_selector', jsonb_build_object(
              'selector_type', 'exact_object',
              'object_id', p_resource_object_id,
              'object_version', p_resource_object_version
            )
          ) INTO v_result
          FROM lucy.principals p
          JOIN lucy.node_memberships m
            ON m.principal_id=p.id AND m.workspace_id=p_workspace_id
          JOIN lucy.workspaces w
            ON w.id=m.workspace_id AND w.id=p_workspace_id
          JOIN lucy.nodes n
            ON n.id=w.node_id AND n.id=p_node_id
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
            AND m.status='active'
            AND ((p_action='memory.read' AND m.role IN ('owner','member'))
              OR (p_action='memory.write' AND m.role='owner'))
            AND w.workspace_kind='private'
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

        ALTER FUNCTION lucy.resolve_internal_admission_v1(
          text,text,text,uuid,uuid,uuid,bigint,uuid,bigint,uuid,uuid,uuid,uuid,
          bigint,uuid,text,uuid,bigint,timestamptz
        ) OWNER TO lucy_directory_function_owner;
        REVOKE ALL ON FUNCTION lucy.resolve_internal_admission_v1(
          text,text,text,uuid,uuid,uuid,bigint,uuid,bigint,uuid,uuid,uuid,uuid,
          bigint,uuid,text,uuid,bigint,timestamptz
        ) FROM PUBLIC, lucy_app, lucy_public_runtime;
        GRANT EXECUTE ON FUNCTION lucy.resolve_internal_admission_v1(
          text,text,text,uuid,uuid,uuid,bigint,uuid,bigint,uuid,uuid,uuid,uuid,
          bigint,uuid,text,uuid,bigint,timestamptz
        ) TO lucy_directory_admission;

        REVOKE ALL ON lucy.tenant_accounts, lucy.nodes, lucy.node_tenures,
          lucy.security_realms, lucy.realm_bindings, lucy.principals,
          lucy.workspaces, lucy.node_memberships, lucy.channel_bindings,
          lucy.realm_content_scopes_v1, lucy.realm_service_bindings_v1,
          lucy.scoped_memory_claims_v1, lucy.scoped_memory_events_v1
          FROM lucy_directory_admission;
        """
    )


def downgrade() -> None:
    raise RuntimeError("R1 internal admission requires a reviewed forward migration")
