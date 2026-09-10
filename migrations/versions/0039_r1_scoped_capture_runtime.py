"""Expose the realm-scoped capture state to its fixed archive runtime."""

from collections.abc import Sequence

from alembic import op

revision: str = "0039_r1_scoped_capture_runtime"
down_revision: str | None = "0038_r1_archive_commit_protocol"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE FUNCTION lucy.get_scoped_capture_mode_v1(
          p_source_conversation_id text
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_target lucy.realm_service_bindings_v1%ROWTYPE;
          v_state lucy.scoped_capture_states_v1%ROWTYPE;
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
             OR length(p_source_conversation_id)>512
          THEN RAISE EXCEPTION 'scoped capture query is invalid'; END IF;
          SELECT * INTO v_state FROM lucy.scoped_capture_states_v1
          WHERE content_scope_id=v_actor.content_scope_id AND platform='telegram'
            AND source_conversation_id=p_source_conversation_id;
          IF NOT FOUND THEN
            RETURN jsonb_build_object('capture_enabled',true,'version',0,'replayed',false);
          END IF;
          IF v_state.archive_actor_binding_id<>v_actor.id
          THEN RAISE EXCEPTION 'scoped capture conversation authority mismatch'; END IF;
          RETURN jsonb_build_object('capture_enabled',v_state.capture_enabled,
            'version',v_state.version,'replayed',false);
        END
        $function$;

        ALTER FUNCTION lucy.get_scoped_capture_mode_v1(text)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.get_scoped_capture_mode_v1(text) FROM PUBLIC, lucy_app;
        """
    )


def downgrade() -> None:
    raise RuntimeError("R1 scoped capture runtime requires a reviewed forward migration")
