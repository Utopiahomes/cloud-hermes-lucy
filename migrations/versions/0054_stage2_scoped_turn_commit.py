"""Bind both encrypted messages before a Stage 2 reply may be delivered."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0054_stage2_scoped_turn_commit"
down_revision: str | None = "0053_r1_telegram_authority"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scoped_conversation_turn_commits_v1",
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_conversation_id", sa.String(512), nullable=False),
        sa.Column("source_turn_id", sa.String(512), nullable=False),
        sa.Column("user_operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assistant_operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assistant_evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint(
            "content_scope_id", "source_conversation_id", "source_turn_id"
        ),
        sa.UniqueConstraint("user_operation_id"),
        sa.UniqueConstraint("assistant_operation_id"),
        sa.UniqueConstraint("user_evidence_id"),
        sa.UniqueConstraint("assistant_evidence_id"),
        sa.ForeignKeyConstraint(
            ["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]
        ),
        sa.ForeignKeyConstraint(
            ["user_operation_id"], ["lucy.scoped_archive_intents_v1.operation_id"]
        ),
        sa.ForeignKeyConstraint(
            ["assistant_operation_id"], ["lucy.scoped_archive_intents_v1.operation_id"]
        ),
        schema="lucy",
    )
    op.execute(
        "CREATE TRIGGER scoped_conversation_turn_commits_v1_immutable "
        "BEFORE UPDATE OR DELETE ON lucy.scoped_conversation_turn_commits_v1 "
        "FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.set_and_accept_scoped_capture_turn_v1(
          p_source_conversation_id text, p_source_turn_id text,
          p_capture_enabled boolean, p_idempotency_key text
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE v_transition jsonb; v_receipt jsonb;
        BEGIN
          -- Both existing functions use the same conversation advisory lock.
          -- Calling them inside this function makes the transition and immutable
          -- control-turn receipt one PostgreSQL transaction.
          v_transition:=lucy.set_scoped_capture_mode_v1(
            p_source_conversation_id,p_capture_enabled,p_idempotency_key);
          v_receipt:=lucy.accept_scoped_capture_turn_v1(
            p_source_conversation_id,p_source_turn_id);
          IF (v_transition->>'capture_enabled')::boolean<>p_capture_enabled
             OR (v_receipt->>'capture_enabled')::boolean<>p_capture_enabled
             OR (v_transition->>'version')::bigint<>(v_receipt->>'version')::bigint
          THEN RAISE EXCEPTION 'scoped capture transition receipt mismatch'; END IF;
          RETURN v_receipt;
        END
        $function$;

        CREATE FUNCTION lucy.commit_capturable_scoped_turn_v1(
          p_assistant_operation_id uuid, p_current_input_evidence_id uuid
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_user lucy.scoped_archive_intents_v1%ROWTYPE;
          v_assistant lucy.scoped_archive_intents_v1%ROWTYPE;
          v_existing lucy.scoped_conversation_turn_commits_v1%ROWTYPE;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='archive_writer' AND active
            AND allowed_actions @> '["evidence.archive"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped turn commit unavailable'; END IF;
          SELECT * INTO v_assistant FROM lucy.scoped_archive_intents_v1
          WHERE operation_id=p_assistant_operation_id
            AND archive_actor_binding_id=v_actor.id;
          SELECT * INTO v_user FROM lucy.scoped_archive_intents_v1
          WHERE evidence_id=p_current_input_evidence_id
            AND archive_actor_binding_id=v_actor.id;
          IF v_assistant.operation_id IS NULL OR v_user.operation_id IS NULL
             OR v_assistant.operation_id=v_user.operation_id
             OR v_assistant.content_scope_id<>v_user.content_scope_id
             OR v_assistant.source_conversation_id<>v_user.source_conversation_id
             OR v_assistant.source_turn_id<>v_user.source_turn_id
             OR right(v_user.idempotency_key,5)<>chr(58)||'user'
             OR right(v_assistant.idempotency_key,10)<>chr(58)||'assistant'
             OR NOT v_assistant.lineage_refs @>
                jsonb_build_array(p_current_input_evidence_id::text)
             OR NOT EXISTS (
                SELECT 1 FROM lucy.scoped_archive_reconciliations_v1
                WHERE operation_id=v_user.operation_id)
             OR NOT EXISTS (
                SELECT 1 FROM lucy.scoped_archive_reconciliations_v1
                WHERE operation_id=v_assistant.operation_id)
          THEN RAISE EXCEPTION 'scoped turn messages are incomplete'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            v_actor.content_scope_id::text||':telegram:'||
            v_user.source_conversation_id||':'||v_user.source_turn_id,0));
          SELECT * INTO v_existing FROM lucy.scoped_conversation_turn_commits_v1
          WHERE content_scope_id=v_actor.content_scope_id
            AND source_conversation_id=v_user.source_conversation_id
            AND source_turn_id=v_user.source_turn_id;
          IF FOUND THEN
            IF v_existing.user_operation_id<>v_user.operation_id
               OR v_existing.assistant_operation_id<>v_assistant.operation_id
               OR v_existing.user_evidence_id<>v_user.evidence_id
               OR v_existing.assistant_evidence_id<>v_assistant.evidence_id
            THEN RAISE EXCEPTION 'scoped turn commit conflict'; END IF;
            RETURN jsonb_build_object('turn_committed',true,'replayed',true);
          END IF;
          INSERT INTO lucy.scoped_conversation_turn_commits_v1(
            content_scope_id,source_conversation_id,source_turn_id,
            user_operation_id,assistant_operation_id,user_evidence_id,
            assistant_evidence_id,committed_at
          ) VALUES (
            v_actor.content_scope_id,v_user.source_conversation_id,v_user.source_turn_id,
            v_user.operation_id,v_assistant.operation_id,v_user.evidence_id,
            v_assistant.evidence_id,clock_timestamp()
          );
          RETURN jsonb_build_object('turn_committed',true,'replayed',false);
        END
        $function$;

        ALTER FUNCTION lucy.set_and_accept_scoped_capture_turn_v1(text,text,boolean,text)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.commit_capturable_scoped_turn_v1(uuid,uuid)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION
          lucy.set_and_accept_scoped_capture_turn_v1(text,text,boolean,text)
          FROM PUBLIC,lucy_app;
        REVOKE ALL ON FUNCTION lucy.commit_capturable_scoped_turn_v1(uuid,uuid)
          FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.scoped_conversation_turn_commits_v1
          TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("Stage 2 turn-commit history requires a reviewed forward migration")
