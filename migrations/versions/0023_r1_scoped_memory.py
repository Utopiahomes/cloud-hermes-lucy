"""Add new-realm service bindings and execute-only scoped memory operations."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0023_r1_scoped_memory"
down_revision: str | None = "0022_r1_tenant_public"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid(name: str, *, primary: bool = False, nullable: bool = False) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), primary_key=primary, nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "realm_content_scopes_v1",
        _uuid("id", primary=True),
        _uuid("tenant_account_id"),
        _uuid("node_id"),
        _uuid("node_tenure_id"),
        sa.Column("tenure_epoch", sa.BigInteger(), nullable=False),
        _uuid("security_realm_id"),
        sa.Column("storage_epoch", sa.BigInteger(), nullable=False),
        _uuid("realm_binding_id"),
        _uuid("workspace_id"),
        _uuid("deployment_id"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_account_id"], ["lucy.tenant_accounts.id"]),
        sa.ForeignKeyConstraint(["node_id"], ["lucy.nodes.id"]),
        sa.ForeignKeyConstraint(["node_tenure_id"], ["lucy.node_tenures.id"]),
        sa.ForeignKeyConstraint(["security_realm_id"], ["lucy.security_realms.id"]),
        sa.ForeignKeyConstraint(["realm_binding_id"], ["lucy.realm_bindings.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["lucy.workspaces.id"]),
        sa.UniqueConstraint(
            "tenant_account_id",
            "node_id",
            "node_tenure_id",
            "tenure_epoch",
            "security_realm_id",
            "storage_epoch",
            "workspace_id",
            "deployment_id",
            name="uq_realm_content_scope",
        ),
        sa.CheckConstraint("tenure_epoch > 0", name="ck_content_scope_tenure_epoch"),
        sa.CheckConstraint("storage_epoch > 0", name="ck_content_scope_storage_epoch"),
        schema="lucy",
    )
    op.create_table(
        "realm_service_bindings_v1",
        _uuid("id", primary=True),
        sa.Column("session_login", sa.String(63), nullable=False, unique=True),
        _uuid("service_principal_id"),
        _uuid("content_scope_id"),
        sa.Column("service_role", sa.String(40), nullable=False),
        sa.Column("allowed_actions", postgresql.JSONB(), nullable=False),
        sa.Column("binding_generation", sa.BigInteger(), nullable=False),
        sa.Column("node_authz_epoch", sa.BigInteger(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["service_principal_id"], ["lucy.principals.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.CheckConstraint("service_role = 'realm_routine'", name="ck_realm_service_role"),
        sa.CheckConstraint(
            "jsonb_typeof(allowed_actions)='array' AND jsonb_array_length(allowed_actions)>0",
            name="ck_realm_service_actions",
        ),
        sa.CheckConstraint("binding_generation > 0", name="ck_service_binding_generation"),
        sa.CheckConstraint("node_authz_epoch > 0", name="ck_service_node_authz_epoch"),
        schema="lucy",
    )
    op.create_table(
        "scoped_memory_claims_v1",
        _uuid("id", primary=True),
        _uuid("content_scope_id"),
        _uuid("service_binding_id"),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("predicate", sa.Text(), nullable=False),
        sa.Column("object", sa.Text(), nullable=False),
        sa.Column("confidence_millionths", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(["service_binding_id"], ["lucy.realm_service_bindings_v1.id"]),
        sa.UniqueConstraint(
            "service_binding_id", "idempotency_key", name="uq_scoped_claim_idempotency"
        ),
        sa.UniqueConstraint("id", "content_scope_id", name="uq_scoped_claim_scope"),
        sa.CheckConstraint(
            "confidence_millionths BETWEEN 0 AND 1000000",
            name="ck_scoped_claim_confidence",
        ),
        sa.CheckConstraint("status IN ('provisional','accepted')", name="ck_scoped_claim_status"),
        schema="lucy",
    )
    op.create_index(
        "ix_scoped_claim_scope_created",
        "scoped_memory_claims_v1",
        ["content_scope_id", "created_at", "id"],
        schema="lucy",
    )
    op.create_table(
        "scoped_memory_events_v1",
        _uuid("id", primary=True),
        _uuid("content_scope_id"),
        _uuid("service_binding_id"),
        sa.Column("event_type", sa.String(40), nullable=False),
        _uuid("claim_id"),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["service_binding_id"], ["lucy.realm_service_bindings_v1.id"]),
        sa.ForeignKeyConstraint(
            ["claim_id", "content_scope_id"],
            ["lucy.scoped_memory_claims_v1.id", "lucy.scoped_memory_claims_v1.content_scope_id"],
        ),
        sa.CheckConstraint("event_type = 'memory.claim_written'", name="ck_scoped_event_type"),
        schema="lucy",
    )
    op.execute(
        "CREATE TRIGGER realm_content_scopes_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.realm_content_scopes_v1 FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation(); "
        "CREATE TRIGGER realm_service_bindings_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.realm_service_bindings_v1 FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation(); "
        "CREATE TRIGGER scoped_memory_claims_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_memory_claims_v1 FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation(); "
        "CREATE TRIGGER scoped_memory_events_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_memory_events_v1 FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.validate_realm_content_scope_v1() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM lucy.node_tenures t
            WHERE t.id=NEW.node_tenure_id AND t.node_id=NEW.node_id
              AND t.account_id=NEW.tenant_account_id AND t.sequence=NEW.tenure_epoch
          ) OR NOT EXISTS (
            SELECT 1 FROM lucy.realm_bindings b
            WHERE b.id=NEW.realm_binding_id AND b.tenure_id=NEW.node_tenure_id
              AND b.realm_id=NEW.security_realm_id AND b.valid_to IS NULL
          ) OR NOT EXISTS (
            SELECT 1 FROM lucy.workspaces w
            WHERE w.id=NEW.workspace_id AND w.node_id=NEW.node_id
              AND w.tenure_id=NEW.node_tenure_id
          ) THEN
            RAISE EXCEPTION 'realm content scope does not match authoritative bindings';
          END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER realm_content_scope_valid
        BEFORE INSERT ON lucy.realm_content_scopes_v1
        FOR EACH ROW EXECUTE FUNCTION lucy.validate_realm_content_scope_v1();
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.write_scoped_memory_claim_v1(
          p_idempotency_key text, p_subject text, p_predicate text, p_object text,
          p_confidence_millionths bigint
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_existing lucy.scoped_memory_claims_v1%ROWTYPE;
          v_claim_id uuid := public.gen_random_uuid();
          v_now timestamptz := clock_timestamp();
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.write"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'realm operation unavailable'; END IF;
          IF p_idempotency_key IS NULL OR btrim(p_idempotency_key)=''
             OR length(p_idempotency_key)>200 OR p_subject IS NULL OR btrim(p_subject)=''
             OR length(p_subject)>200 OR p_predicate IS NULL OR btrim(p_predicate)=''
             OR length(p_predicate)>200 OR p_object IS NULL OR btrim(p_object)=''
             OR length(p_object)>2000 OR p_confidence_millionths NOT BETWEEN 0 AND 1000000 THEN
            RAISE EXCEPTION 'scoped memory request is invalid';
          END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            v_binding.id::text || ':' || p_idempotency_key, 0));
          SELECT * INTO v_existing FROM lucy.scoped_memory_claims_v1
          WHERE service_binding_id=v_binding.id AND idempotency_key=p_idempotency_key;
          IF FOUND THEN
            IF v_existing.subject<>p_subject OR v_existing.predicate<>p_predicate
               OR v_existing.object<>p_object
               OR v_existing.confidence_millionths<>p_confidence_millionths THEN
              RAISE EXCEPTION 'scoped memory idempotency conflict';
            END IF;
            RETURN jsonb_build_object('claim_id',v_existing.id,'replayed',true);
          END IF;
          INSERT INTO lucy.scoped_memory_claims_v1(
            id,content_scope_id,service_binding_id,idempotency_key,subject,predicate,
            object,confidence_millionths,status,created_at
          ) VALUES (
            v_claim_id,v_binding.content_scope_id,v_binding.id,p_idempotency_key,
            p_subject,p_predicate,p_object,p_confidence_millionths,'accepted',v_now
          );
          INSERT INTO lucy.scoped_memory_events_v1(
            id,content_scope_id,service_binding_id,event_type,claim_id,occurred_at
          ) VALUES (
            public.gen_random_uuid(),v_binding.content_scope_id,v_binding.id,
            'memory.claim_written',v_claim_id,v_now
          );
          RETURN jsonb_build_object('claim_id',v_claim_id,'replayed',false);
        END
        $function$;

        CREATE FUNCTION lucy.search_scoped_memory_v1(p_query text, p_limit integer)
        RETURNS jsonb
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_result jsonb;
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
            'confidence_millionths',q.confidence_millionths,'status',q.status
          ) ORDER BY q.confidence_millionths DESC,q.created_at DESC,q.id), '[]'::jsonb)
          INTO v_result FROM (
            SELECT * FROM lucy.scoped_memory_claims_v1 c
            WHERE c.content_scope_id=v_binding.content_scope_id AND c.status='accepted'
              AND (c.subject ILIKE '%' || p_query || '%' OR c.predicate ILIKE '%' || p_query || '%'
                   OR c.object ILIKE '%' || p_query || '%')
            ORDER BY c.confidence_millionths DESC,c.created_at DESC,c.id LIMIT p_limit
          ) q;
          RETURN v_result;
        END
        $function$;
        """
    )
    for signature in (
        "lucy.write_scoped_memory_claim_v1(text,text,text,text,bigint)",
        "lucy.search_scoped_memory_v1(text,integer)",
    ):
        op.execute(
            f"ALTER FUNCTION {signature} OWNER TO lucy_security_function_owner; "
            f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC, lucy_app"
        )
    op.execute(
        "GRANT SELECT, INSERT ON lucy.scoped_memory_claims_v1, "
        "lucy.scoped_memory_events_v1 TO lucy_security_function_owner; "
        "GRANT SELECT ON lucy.realm_service_bindings_v1 TO lucy_security_function_owner; "
        "REVOKE ALL ON lucy.realm_content_scopes_v1, lucy.realm_service_bindings_v1, "
        "lucy.scoped_memory_claims_v1, lucy.scoped_memory_events_v1 FROM lucy_app"
    )


def downgrade() -> None:
    raise RuntimeError("R1 scoped memory requires a reviewed forward migration")
