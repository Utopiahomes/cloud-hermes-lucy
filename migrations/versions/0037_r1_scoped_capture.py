"""Add realm-scoped off-record state and per-turn capture receipts."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0037_r1_scoped_capture"
down_revision: str | None = "0036_r1_scoped_deletion_recovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid(name: str, *, primary: bool = False) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), primary_key=primary, nullable=False)


def upgrade() -> None:
    op.create_table(
        "scoped_capture_states_v1",
        _uuid("content_scope_id", primary=True),
        sa.Column("platform", sa.String(40), primary_key=True),
        sa.Column("source_conversation_id", sa.String(512), primary_key=True),
        _uuid("archive_actor_binding_id"),
        sa.Column("capture_enabled", sa.Boolean(), nullable=False),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["archive_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.CheckConstraint("platform='telegram'", name="ck_scoped_capture_platform"),
        sa.CheckConstraint("version>0", name="ck_scoped_capture_version"),
        schema="lucy",
    )
    op.create_table(
        "scoped_capture_transitions_v1",
        _uuid("id", primary=True),
        _uuid("content_scope_id"),
        _uuid("archive_actor_binding_id"),
        sa.Column("platform", sa.String(40), nullable=False),
        sa.Column("source_conversation_id", sa.String(512), nullable=False),
        sa.Column("capture_enabled", sa.Boolean(), nullable=False),
        sa.Column("capture_version", sa.BigInteger(), nullable=False),
        sa.Column("idempotency_key", sa.String(512), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["archive_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.UniqueConstraint(
            "archive_actor_binding_id", "idempotency_key", name="uq_scoped_capture_transition"
        ),
        sa.CheckConstraint("platform='telegram'", name="ck_scoped_transition_platform"),
        sa.CheckConstraint("capture_version>0", name="ck_scoped_transition_version"),
        schema="lucy",
    )
    op.create_table(
        "scoped_capture_receipts_v1",
        _uuid("content_scope_id", primary=True),
        sa.Column("platform", sa.String(40), primary_key=True),
        sa.Column("source_conversation_id", sa.String(512), primary_key=True),
        sa.Column("source_turn_id", sa.String(512), primary_key=True),
        _uuid("archive_actor_binding_id"),
        sa.Column("capture_enabled", sa.Boolean(), nullable=False),
        sa.Column("capture_version", sa.BigInteger(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["archive_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.CheckConstraint("platform='telegram'", name="ck_scoped_receipt_platform"),
        sa.CheckConstraint("capture_version>=0", name="ck_scoped_receipt_version"),
        schema="lucy",
    )
    op.execute(
        "CREATE TRIGGER scoped_capture_transitions_v1_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_capture_transitions_v1 FOR EACH ROW "
        "EXECUTE FUNCTION lucy.reject_mutation(); "
        "CREATE TRIGGER scoped_capture_receipts_v1_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_capture_receipts_v1 FOR EACH ROW "
        "EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.set_scoped_capture_mode_v1(
          p_source_conversation_id text, p_capture_enabled boolean, p_idempotency_key text
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_target lucy.realm_service_bindings_v1%ROWTYPE;
          v_existing lucy.scoped_capture_transitions_v1%ROWTYPE;
          v_state lucy.scoped_capture_states_v1%ROWTYPE;
          v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='archive_writer' AND active
            AND allowed_actions @> '["evidence.archive"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped capture authority unavailable'; END IF;
          SELECT * INTO STRICT v_target FROM lucy.realm_service_bindings_v1
          WHERE id=v_actor.target_service_binding_id AND content_scope_id=v_actor.content_scope_id
            AND active AND allowed_actions @> '["evidence.archive"]'::jsonb;
          IF v_actor.node_authz_epoch<>v_target.node_authz_epoch
             OR v_actor.policy_version<>v_target.policy_version
          THEN RAISE EXCEPTION 'scoped capture authority is stale'; END IF;
          IF p_source_conversation_id IS NULL OR btrim(p_source_conversation_id)=''
             OR length(p_source_conversation_id)>512 OR p_idempotency_key IS NULL
             OR btrim(p_idempotency_key)='' OR length(p_idempotency_key)>512
          THEN RAISE EXCEPTION 'scoped capture transition is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            v_actor.content_scope_id::text||':telegram:'||p_source_conversation_id,0));
          SELECT * INTO v_existing FROM lucy.scoped_capture_transitions_v1
          WHERE archive_actor_binding_id=v_actor.id AND idempotency_key=p_idempotency_key;
          IF FOUND THEN
            IF v_existing.source_conversation_id<>p_source_conversation_id
               OR v_existing.capture_enabled<>p_capture_enabled
            THEN RAISE EXCEPTION 'scoped capture idempotency conflict'; END IF;
            RETURN jsonb_build_object('capture_enabled',v_existing.capture_enabled,
              'version',v_existing.capture_version,'replayed',true);
          END IF;
          SELECT * INTO v_state FROM lucy.scoped_capture_states_v1
          WHERE content_scope_id=v_actor.content_scope_id AND platform='telegram'
            AND source_conversation_id=p_source_conversation_id FOR UPDATE;
          IF NOT FOUND THEN
            INSERT INTO lucy.scoped_capture_states_v1(
              content_scope_id,platform,source_conversation_id,archive_actor_binding_id,
              capture_enabled,version,updated_at
            ) VALUES (v_actor.content_scope_id,'telegram',p_source_conversation_id,v_actor.id,
              p_capture_enabled,1,v_now) RETURNING * INTO v_state;
          ELSIF v_state.archive_actor_binding_id<>v_actor.id THEN
            RAISE EXCEPTION 'scoped capture conversation authority mismatch';
          ELSIF v_state.capture_enabled<>p_capture_enabled THEN
            UPDATE lucy.scoped_capture_states_v1 SET capture_enabled=p_capture_enabled,
              version=version+1,updated_at=v_now
            WHERE content_scope_id=v_actor.content_scope_id AND platform='telegram'
              AND source_conversation_id=p_source_conversation_id RETURNING * INTO v_state;
          END IF;
          INSERT INTO lucy.scoped_capture_transitions_v1(
            id,content_scope_id,archive_actor_binding_id,platform,source_conversation_id,
            capture_enabled,capture_version,idempotency_key,recorded_at
          ) VALUES (public.gen_random_uuid(),v_actor.content_scope_id,v_actor.id,'telegram',
            p_source_conversation_id,v_state.capture_enabled,v_state.version,
            p_idempotency_key,v_now);
          RETURN jsonb_build_object('capture_enabled',v_state.capture_enabled,
            'version',v_state.version,'replayed',false);
        END
        $function$;

        CREATE FUNCTION lucy.accept_scoped_capture_turn_v1(
          p_source_conversation_id text, p_source_turn_id text
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_target lucy.realm_service_bindings_v1%ROWTYPE;
          v_state lucy.scoped_capture_states_v1%ROWTYPE;
          v_receipt lucy.scoped_capture_receipts_v1%ROWTYPE;
          v_enabled boolean; v_version bigint; v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='archive_writer' AND active
            AND allowed_actions @> '["evidence.archive"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped capture authority unavailable'; END IF;
          SELECT * INTO STRICT v_target FROM lucy.realm_service_bindings_v1
          WHERE id=v_actor.target_service_binding_id AND content_scope_id=v_actor.content_scope_id
            AND active AND allowed_actions @> '["evidence.archive"]'::jsonb;
          IF v_actor.node_authz_epoch<>v_target.node_authz_epoch
             OR v_actor.policy_version<>v_target.policy_version
          THEN RAISE EXCEPTION 'scoped capture authority is stale'; END IF;
          IF p_source_conversation_id IS NULL OR btrim(p_source_conversation_id)=''
             OR length(p_source_conversation_id)>512 OR p_source_turn_id IS NULL
             OR btrim(p_source_turn_id)='' OR length(p_source_turn_id)>512
          THEN RAISE EXCEPTION 'scoped capture turn is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            v_actor.content_scope_id::text||':telegram:'||p_source_conversation_id,0));
          SELECT * INTO v_receipt FROM lucy.scoped_capture_receipts_v1
          WHERE content_scope_id=v_actor.content_scope_id AND platform='telegram'
            AND source_conversation_id=p_source_conversation_id
            AND source_turn_id=p_source_turn_id;
          IF FOUND THEN RETURN jsonb_build_object('capture_enabled',v_receipt.capture_enabled,
            'version',v_receipt.capture_version,'replayed',true); END IF;
          SELECT * INTO v_state FROM lucy.scoped_capture_states_v1
          WHERE content_scope_id=v_actor.content_scope_id AND platform='telegram'
            AND source_conversation_id=p_source_conversation_id;
          v_enabled:=CASE WHEN FOUND THEN v_state.capture_enabled ELSE true END;
          v_version:=CASE WHEN FOUND THEN v_state.version ELSE 0 END;
          INSERT INTO lucy.scoped_capture_receipts_v1(
            content_scope_id,platform,source_conversation_id,source_turn_id,
            archive_actor_binding_id,capture_enabled,capture_version,accepted_at
          ) VALUES (v_actor.content_scope_id,'telegram',p_source_conversation_id,p_source_turn_id,
            v_actor.id,v_enabled,v_version,v_now);
          RETURN jsonb_build_object('capture_enabled',v_enabled,'version',v_version,
            'replayed',false);
        END
        $function$;

        CREATE FUNCTION lucy.register_capturable_scoped_evidence_v2(
          p_source_conversation_id text, p_source_turn_id text, p_payload jsonb,
          p_wrapper jsonb, p_content_classification text, p_lineage_refs jsonb,
          p_idempotency_key text
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_receipt lucy.scoped_capture_receipts_v1%ROWTYPE;
          v_state lucy.scoped_capture_states_v1%ROWTYPE;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='archive_writer' AND active
            AND allowed_actions @> '["evidence.archive"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped capture authority unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            v_actor.content_scope_id::text||':telegram:'||p_source_conversation_id,0));
          SELECT * INTO v_receipt FROM lucy.scoped_capture_receipts_v1
          WHERE content_scope_id=v_actor.content_scope_id AND platform='telegram'
            AND source_conversation_id=p_source_conversation_id
            AND source_turn_id=p_source_turn_id AND archive_actor_binding_id=v_actor.id;
          SELECT * INTO v_state FROM lucy.scoped_capture_states_v1
          WHERE content_scope_id=v_actor.content_scope_id AND platform='telegram'
            AND source_conversation_id=p_source_conversation_id;
          IF v_receipt.content_scope_id IS NULL OR NOT v_receipt.capture_enabled
             OR (v_state.content_scope_id IS NOT NULL AND NOT v_state.capture_enabled)
             OR v_receipt.capture_version<>
                (CASE WHEN v_state.content_scope_id IS NULL THEN 0 ELSE v_state.version END)
          THEN RAISE EXCEPTION 'scoped turn is not authorized for retention'; END IF;
          RETURN lucy.register_scoped_evidence_v2(p_payload,p_wrapper,
            p_content_classification,p_lineage_refs,p_idempotency_key);
        END
        $function$;
        """
    )
    for signature in (
        "lucy.set_scoped_capture_mode_v1(text,boolean,text)",
        "lucy.accept_scoped_capture_turn_v1(text,text)",
        "lucy.register_capturable_scoped_evidence_v2(text,text,jsonb,jsonb,text,jsonb,text)",
    ):
        op.execute(
            f"ALTER FUNCTION {signature} OWNER TO lucy_security_function_owner; "
            f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC, lucy_app"
        )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON lucy.scoped_capture_states_v1 TO "
        "lucy_security_function_owner; GRANT SELECT, INSERT ON "
        "lucy.scoped_capture_transitions_v1, lucy.scoped_capture_receipts_v1 TO "
        "lucy_security_function_owner"
    )


def downgrade() -> None:
    raise RuntimeError("R1 scoped capture history requires a reviewed forward migration")
