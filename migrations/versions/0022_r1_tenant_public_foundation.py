"""Add the R1 tenant directory and isolated public projection foundation."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0022_r1_tenant_public"
down_revision: str | None = "0021_recovery_capture_safety"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid(name: str, *, primary: bool = False) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), primary_key=primary, nullable=False)


def _time(name: str) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=False)


def upgrade() -> None:
    op.create_table(
        "tenant_accounts",
        _uuid("id", primary=True),
        sa.Column("slug", sa.String(80), nullable=False, unique=True),
        sa.Column("display_name", sa.Text(), nullable=False),
        _time("created_at"),
        schema="lucy",
    )
    op.create_table(
        "nodes",
        _uuid("id", primary=True),
        sa.Column("slug", sa.String(80), nullable=False, unique=True),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("node_kind", sa.String(40), nullable=False),
        _time("created_at"),
        sa.CheckConstraint(
            "node_kind IN ('person','organization','project','community','service')",
            name="ck_nodes_kind",
        ),
        schema="lucy",
    )
    op.create_table(
        "node_tenures",
        _uuid("id", primary=True),
        _uuid("node_id"),
        _uuid("account_id"),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        _time("starts_at"),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["node_id"], ["lucy.nodes.id"]),
        sa.ForeignKeyConstraint(["account_id"], ["lucy.tenant_accounts.id"]),
        sa.UniqueConstraint("node_id", "sequence", name="uq_node_tenure_sequence"),
        sa.UniqueConstraint("id", "node_id", name="uq_tenure_id_node"),
        sa.CheckConstraint("sequence > 0", name="ck_node_tenure_sequence"),
        sa.CheckConstraint("ends_at IS NULL OR ends_at > starts_at", name="ck_tenure_dates"),
        schema="lucy",
    )
    op.create_index(
        "uq_node_active_tenure",
        "node_tenures",
        ["node_id"],
        unique=True,
        schema="lucy",
        postgresql_where=sa.text("ends_at IS NULL"),
    )
    op.create_table(
        "security_realms",
        _uuid("id", primary=True),
        sa.Column("slug", sa.String(80), nullable=False, unique=True),
        _time("created_at"),
        schema="lucy",
    )
    op.create_table(
        "realm_bindings",
        _uuid("id", primary=True),
        _uuid("tenure_id"),
        _uuid("realm_id"),
        sa.Column("binding_version", sa.BigInteger(), nullable=False),
        _time("valid_from"),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenure_id"], ["lucy.node_tenures.id"]),
        sa.ForeignKeyConstraint(["realm_id"], ["lucy.security_realms.id"]),
        sa.UniqueConstraint("tenure_id", "binding_version", name="uq_realm_binding_version"),
        sa.CheckConstraint("binding_version > 0", name="ck_realm_binding_version"),
        sa.CheckConstraint("valid_to IS NULL OR valid_to > valid_from", name="ck_realm_dates"),
        schema="lucy",
    )
    op.create_index(
        "uq_tenure_active_realm",
        "realm_bindings",
        ["tenure_id"],
        unique=True,
        schema="lucy",
        postgresql_where=sa.text("valid_to IS NULL"),
    )
    op.create_table(
        "principals",
        _uuid("id", primary=True),
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("principal_kind", sa.String(40), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        _time("created_at"),
        sa.UniqueConstraint("issuer", "subject", name="uq_principal_subject"),
        sa.CheckConstraint(
            "principal_kind IN ('human','agent','service','runtime')",
            name="ck_principal_kind",
        ),
        schema="lucy",
    )
    op.create_table(
        "workspaces",
        _uuid("id", primary=True),
        _uuid("node_id"),
        _uuid("tenure_id"),
        sa.Column("slug", sa.String(80), nullable=False),
        sa.Column("workspace_kind", sa.String(40), nullable=False),
        _time("created_at"),
        sa.ForeignKeyConstraint(["node_id"], ["lucy.nodes.id"]),
        sa.ForeignKeyConstraint(
            ["tenure_id", "node_id"],
            ["lucy.node_tenures.id", "lucy.node_tenures.node_id"],
        ),
        sa.UniqueConstraint("tenure_id", "slug", name="uq_workspace_tenure_slug"),
        sa.UniqueConstraint("id", "node_id", "tenure_id", name="uq_workspace_scope"),
        schema="lucy",
    )
    op.create_table(
        "node_memberships",
        _uuid("id", primary=True),
        _uuid("principal_id"),
        _uuid("workspace_id"),
        sa.Column("role", sa.String(40), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        _time("granted_at"),
        sa.ForeignKeyConstraint(["principal_id"], ["lucy.principals.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["lucy.workspaces.id"]),
        sa.UniqueConstraint(
            "principal_id", "workspace_id", name="uq_membership_principal_workspace"
        ),
        sa.CheckConstraint(
            "role IN ('owner','publisher','approver','member')", name="ck_membership_role"
        ),
        sa.CheckConstraint("status IN ('active','revoked')", name="ck_membership_status"),
        schema="lucy",
    )
    op.create_table(
        "channel_bindings",
        _uuid("id", primary=True),
        sa.Column("hostname", sa.String(253), nullable=False, unique=True),
        _uuid("node_id"),
        _uuid("tenure_id"),
        _uuid("workspace_id"),
        sa.Column("channel_kind", sa.String(40), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        _time("created_at"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "node_id", "tenure_id"],
            ["lucy.workspaces.id", "lucy.workspaces.node_id", "lucy.workspaces.tenure_id"],
        ),
        sa.UniqueConstraint("id", "node_id", "tenure_id", name="uq_channel_scope"),
        sa.CheckConstraint("hostname = lower(hostname)", name="ck_channel_hostname_lower"),
        sa.CheckConstraint("channel_kind IN ('website_public','internal')", name="ck_channel_kind"),
        schema="lucy",
    )
    op.create_table(
        "lucy_instances",
        _uuid("id", primary=True),
        _uuid("node_id"),
        _uuid("tenure_id"),
        _uuid("principal_id"),
        _uuid("workspace_id"),
        sa.Column("purpose", sa.String(80), nullable=False),
        _time("created_at"),
        sa.ForeignKeyConstraint(["principal_id"], ["lucy.principals.id"]),
        sa.ForeignKeyConstraint(
            ["workspace_id", "node_id", "tenure_id"],
            ["lucy.workspaces.id", "lucy.workspaces.node_id", "lucy.workspaces.tenure_id"],
        ),
        sa.UniqueConstraint("node_id", "tenure_id", "purpose", name="uq_lucy_instance_purpose"),
        schema="lucy",
    )
    op.create_table(
        "wallet_registrations",
        _uuid("id", primary=True),
        _uuid("node_id"),
        _uuid("tenure_id"),
        sa.Column("status", sa.String(40), nullable=False),
        _time("created_at"),
        sa.ForeignKeyConstraint(
            ["tenure_id", "node_id"],
            ["lucy.node_tenures.id", "lucy.node_tenures.node_id"],
        ),
        sa.UniqueConstraint("node_id", name="uq_wallet_node"),
        sa.CheckConstraint("status = 'REGISTERED_NONSPENDABLE'", name="ck_wallet_r1_status"),
        schema="lucy",
    )
    op.create_table(
        "public_projection_candidates",
        _uuid("id", primary=True),
        _uuid("channel_binding_id"),
        sa.Column("snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("snapshot_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        _uuid("created_by"),
        _time("created_at"),
        sa.ForeignKeyConstraint(["channel_binding_id"], ["lucy.channel_bindings.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["lucy.principals.id"]),
        sa.UniqueConstraint("id", "channel_binding_id", name="uq_projection_candidate_scope"),
        sa.CheckConstraint(
            "status IN ('draft','approved','published')",
            name="ck_projection_candidate_status",
        ),
        sa.CheckConstraint("snapshot_digest ~ '^[0-9a-f]{64}$'", name="ck_projection_digest"),
        schema="lucy",
    )
    op.create_table(
        "public_projection_approvals",
        _uuid("id", primary=True),
        _uuid("candidate_id"),
        sa.Column("approved_digest", sa.String(64), nullable=False),
        _uuid("approved_by"),
        _time("approved_at"),
        sa.ForeignKeyConstraint(["candidate_id"], ["lucy.public_projection_candidates.id"]),
        sa.ForeignKeyConstraint(["approved_by"], ["lucy.principals.id"]),
        sa.UniqueConstraint("candidate_id", name="uq_projection_approval_candidate"),
        schema="lucy",
    )
    op.create_table(
        "public_projection_versions",
        _uuid("id", primary=True),
        _uuid("channel_binding_id"),
        _uuid("candidate_id"),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("snapshot_digest", sa.String(64), nullable=False),
        _time("published_at"),
        sa.ForeignKeyConstraint(["channel_binding_id"], ["lucy.channel_bindings.id"]),
        sa.ForeignKeyConstraint(
            ["candidate_id", "channel_binding_id"],
            [
                "lucy.public_projection_candidates.id",
                "lucy.public_projection_candidates.channel_binding_id",
            ],
        ),
        sa.UniqueConstraint("candidate_id", name="uq_projection_version_candidate"),
        sa.UniqueConstraint("channel_binding_id", "version", name="uq_projection_version_number"),
        sa.UniqueConstraint("id", "channel_binding_id", name="uq_projection_version_scope"),
        sa.CheckConstraint("version > 0", name="ck_projection_version_positive"),
        schema="lucy",
    )
    op.create_table(
        "public_projection_routes",
        _uuid("channel_binding_id", primary=True),
        sa.Column("active_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        _time("updated_at"),
        sa.ForeignKeyConstraint(["channel_binding_id"], ["lucy.channel_bindings.id"]),
        sa.ForeignKeyConstraint(
            ["active_version_id", "channel_binding_id"],
            [
                "lucy.public_projection_versions.id",
                "lucy.public_projection_versions.channel_binding_id",
            ],
        ),
        schema="lucy",
    )
    op.create_table(
        "public_projection_events",
        _uuid("id", primary=True),
        _uuid("channel_binding_id"),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version_id", postgresql.UUID(as_uuid=True), nullable=True),
        _uuid("actor_id"),
        _time("occurred_at"),
        sa.ForeignKeyConstraint(["channel_binding_id"], ["lucy.channel_bindings.id"]),
        sa.ForeignKeyConstraint(["candidate_id"], ["lucy.public_projection_candidates.id"]),
        sa.ForeignKeyConstraint(["version_id"], ["lucy.public_projection_versions.id"]),
        sa.ForeignKeyConstraint(["actor_id"], ["lucy.principals.id"]),
        sa.CheckConstraint(
            "event_type IN "
            "('candidate_staged','candidate_approved','published','withdrawal_blocked')",
            name="ck_projection_event_type",
        ),
        schema="lucy",
    )

    op.execute(
        "CREATE TRIGGER node_tenures_immutable BEFORE UPDATE OR DELETE ON lucy.node_tenures "
        "FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.projection_candidate_guard_v1() RETURNS trigger
        LANGUAGE plpgsql AS $function$
        BEGIN
          IF NEW.id <> OLD.id
             OR NEW.channel_binding_id <> OLD.channel_binding_id
             OR NEW.snapshot <> OLD.snapshot
             OR NEW.snapshot_digest <> OLD.snapshot_digest
             OR NEW.created_by <> OLD.created_by
             OR NEW.created_at <> OLD.created_at THEN
            RAISE EXCEPTION 'approved public projection bytes are immutable';
          END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER projection_candidate_content_immutable
        BEFORE UPDATE ON lucy.public_projection_candidates
        FOR EACH ROW EXECUTE FUNCTION lucy.projection_candidate_guard_v1();
        CREATE TRIGGER projection_candidates_no_delete
        BEFORE DELETE ON lucy.public_projection_candidates
        FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation();
        """
    )
    op.execute(
        "CREATE TRIGGER projection_versions_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.public_projection_versions FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.execute(
        "CREATE TRIGGER projection_approvals_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.public_projection_approvals FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.execute(
        "CREATE TRIGGER projection_events_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.public_projection_events FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA lucy TO lucy_app")
    op.execute(
        "REVOKE DELETE ON lucy.public_projection_candidates FROM lucy_app; "
        "REVOKE UPDATE, DELETE ON lucy.node_tenures, lucy.public_projection_approvals, "
        "lucy.public_projection_versions, lucy.public_projection_events FROM lucy_app"
    )
    op.execute(
        r"""
        GRANT USAGE ON SCHEMA lucy TO lucy_security_function_owner;
        GRANT SELECT ON lucy.channel_bindings, lucy.public_projection_routes,
          lucy.public_projection_versions TO lucy_security_function_owner;
        CREATE FUNCTION lucy.public_projection_answer_v1(p_hostname text, p_question text)
        RETURNS jsonb
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
          SELECT jsonb_build_object(
            'answer', faq.item->>'answer',
            'source', faq.item->>'source',
            'version', v.version,
            'snapshot_digest', v.snapshot_digest
          )
          FROM lucy.channel_bindings c
          JOIN lucy.public_projection_routes r ON r.channel_binding_id=c.id
          JOIN lucy.public_projection_versions v ON v.id=r.active_version_id
            AND v.channel_binding_id=c.id
          CROSS JOIN LATERAL jsonb_array_elements(v.snapshot->'faqs') AS faq(item)
          WHERE c.hostname=lower(trim(trailing '.' from btrim(p_hostname)))
            AND c.active
            AND c.channel_kind='website_public'
            AND faq.item->>'question'=
              lower(regexp_replace(btrim(p_question), E'\\s+', ' ', 'g'))
          LIMIT 1
        $function$;
        ALTER FUNCTION lucy.public_projection_answer_v1(text,text)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.public_projection_answer_v1(text,text)
          FROM PUBLIC, lucy_app;
        GRANT EXECUTE ON FUNCTION lucy.public_projection_answer_v1(text,text)
          TO lucy_public_runtime;
        """
    )


def downgrade() -> None:
    raise RuntimeError("R1 identity and publication records require a reviewed forward migration")
