"""Add a realm-bound, idempotent Workspaces task queue."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0066_workspaces_task_queue"
down_revision: str | None = "0065_memory_deletion_execution"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        ALTER FUNCTION lucy.resolve_internal_admission_v1(
          text,text,text,uuid,uuid,uuid,bigint,uuid,bigint,uuid,uuid,uuid,uuid,
          bigint,uuid,text,uuid,bigint,timestamptz)
          RENAME TO resolve_internal_admission_pre_workspaces_v1;

        CREATE FUNCTION lucy.resolve_internal_admission_v1(
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
          RETURN jsonb_set(v_result,'{authorized_action}',to_jsonb(p_action));
        END
        $function$;

        ALTER FUNCTION lucy.resolve_internal_admission_v1(
          text,text,text,uuid,uuid,uuid,bigint,uuid,bigint,uuid,uuid,uuid,uuid,
          bigint,uuid,text,uuid,bigint,timestamptz)
          OWNER TO lucy_directory_function_owner;
        REVOKE ALL ON FUNCTION lucy.resolve_internal_admission_pre_workspaces_v1(
          text,text,text,uuid,uuid,uuid,bigint,uuid,bigint,uuid,uuid,uuid,uuid,
          bigint,uuid,text,uuid,bigint,timestamptz)
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_directory_admission;
        REVOKE ALL ON FUNCTION lucy.resolve_internal_admission_v1(
          text,text,text,uuid,uuid,uuid,bigint,uuid,bigint,uuid,uuid,uuid,uuid,
          bigint,uuid,text,uuid,bigint,timestamptz)
          FROM PUBLIC,lucy_app,lucy_public_runtime;
        GRANT EXECUTE ON FUNCTION lucy.resolve_internal_admission_v1(
          text,text,text,uuid,uuid,uuid,bigint,uuid,bigint,uuid,uuid,uuid,uuid,
          bigint,uuid,text,uuid,bigint,timestamptz)
          TO lucy_directory_admission;

        ALTER TABLE lucy.realm_service_bindings_v1
          DISABLE TRIGGER realm_service_binding_monotonic;
        UPDATE lucy.realm_service_bindings_v1
        SET allowed_actions=(allowed_actions-'task.delegate'-'task.execute')||
          '["task.delegate","task.execute"]'::jsonb
        WHERE active AND allowed_actions @> '["memory.read"]'::jsonb;
        ALTER TABLE lucy.realm_service_bindings_v1
          ENABLE TRIGGER realm_service_binding_monotonic;
        """
    )
    op.create_table(
        "workspaces_tasks_v1",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("service_binding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("channel_binding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("request_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("room_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("instruction", sa.Text(), nullable=False),
        sa.Column("instruction_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("attempt_count", sa.BigInteger(), nullable=False),
        sa.Column("max_attempts", sa.BigInteger(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("lease_token", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", postgresql.JSONB(), nullable=True),
        sa.Column("result_digest", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(["service_binding_id"], ["lucy.realm_service_bindings_v1.id"]),
        sa.ForeignKeyConstraint(["workspace_id"], ["lucy.workspaces.id"]),
        sa.ForeignKeyConstraint(["channel_binding_id"], ["lucy.channel_bindings.id"]),
        sa.UniqueConstraint("service_binding_id", "request_id", name="uq_workspaces_task_request"),
        sa.CheckConstraint(
            "status IN ('queued','claimed','completed','failed')",
            name="ck_workspaces_task_status",
        ),
        sa.CheckConstraint(
            "attempt_count>=0 AND max_attempts BETWEEN 1 AND 10",
            name="ck_workspaces_task_attempts",
        ),
        sa.CheckConstraint(
            "instruction_digest~'^[0-9a-f]{64}$'",
            name="ck_workspaces_task_instruction_digest",
        ),
        sa.CheckConstraint(
            "result_digest IS NULL OR result_digest~'^[0-9a-f]{64}$'",
            name="ck_workspaces_task_result_digest",
        ),
        sa.CheckConstraint(
            "(status='queued' AND claimed_by IS NULL AND lease_token IS NULL "
            "AND lease_expires_at IS NULL AND result IS NULL AND result_digest IS NULL "
            "AND completed_at IS NULL) OR "
            "(status='claimed' AND claimed_by IS NOT NULL AND lease_token IS NOT NULL "
            "AND lease_expires_at IS NOT NULL AND result IS NULL AND result_digest IS NULL "
            "AND completed_at IS NULL) OR "
            "(status IN ('completed','failed') AND claimed_by IS NOT NULL "
            "AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL "
            "AND result IS NOT NULL AND result_digest IS NOT NULL "
            "AND completed_at IS NOT NULL)",
            name="ck_workspaces_task_lifecycle",
        ),
        schema="lucy",
    )
    op.create_index(
        "ix_workspaces_tasks_claim_v1",
        "workspaces_tasks_v1",
        ["content_scope_id", "status", "available_at", "created_at"],
        schema="lucy",
    )
    op.create_table(
        "workspaces_task_events_v1",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("task_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(30), nullable=False),
        sa.Column("attempt", sa.BigInteger(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["task_id"], ["lucy.workspaces_tasks_v1.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.CheckConstraint(
            "event_type IN "
            "('enqueued','claimed','heartbeat','completed','failed','lease_exhausted')",
            name="ck_workspaces_task_event",
        ),
        schema="lucy",
    )
    op.execute(
        r"""
        CREATE TRIGGER workspaces_task_events_immutable
        BEFORE UPDATE OR DELETE ON lucy.workspaces_task_events_v1
        FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation();

        CREATE FUNCTION lucy.enqueue_workspaces_task_v1(
          p_service_binding_id uuid,p_workspace_id uuid,p_channel_binding_id uuid,
          p_request_id uuid,p_room_id uuid,p_instruction text,p_instruction_digest text
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_existing lucy.workspaces_tasks_v1%ROWTYPE;
          v_id uuid:=gen_random_uuid(); v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE id=p_service_binding_id AND session_login=session_user AND active
            AND allowed_actions @> '["task.delegate"]'::jsonb;
          IF NOT FOUND OR coalesce(btrim(p_instruction),'')='' OR length(p_instruction)>2000
             OR octet_length(p_instruction)>8192
             OR p_instruction_digest!~'^[0-9a-f]{64}$'
             OR p_instruction_digest<>encode(
               public.digest(convert_to(p_instruction,'UTF8'),'sha256'),'hex')
             OR NOT EXISTS (
               SELECT 1 FROM lucy.realm_content_scopes_v1 cs
               JOIN lucy.channel_bindings ch ON ch.id=p_channel_binding_id
                 AND ch.workspace_id=cs.workspace_id AND ch.node_id=cs.node_id
                 AND ch.tenure_id=cs.node_tenure_id AND ch.active
               WHERE cs.id=v_binding.content_scope_id AND cs.workspace_id=p_workspace_id)
          THEN RAISE EXCEPTION 'Workspaces task enqueue unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'workspaces-task:'||p_service_binding_id::text||':'||p_request_id::text,0));
          SELECT * INTO v_existing FROM lucy.workspaces_tasks_v1
          WHERE service_binding_id=p_service_binding_id AND request_id=p_request_id;
          IF FOUND THEN
            IF v_existing.workspace_id<>p_workspace_id
               OR v_existing.channel_binding_id<>p_channel_binding_id
               OR v_existing.room_id<>p_room_id
               OR v_existing.instruction_digest<>p_instruction_digest
            THEN RAISE EXCEPTION 'Workspaces task enqueue conflict'; END IF;
            RETURN jsonb_build_object('task_id',v_existing.id,'replayed',true);
          END IF;
          INSERT INTO lucy.workspaces_tasks_v1(
            id,content_scope_id,service_binding_id,workspace_id,channel_binding_id,
            request_id,room_id,instruction,instruction_digest,status,attempt_count,
            max_attempts,available_at,created_at)
          VALUES (v_id,v_binding.content_scope_id,v_binding.id,p_workspace_id,
            p_channel_binding_id,p_request_id,p_room_id,p_instruction,p_instruction_digest,
            'queued',0,3,v_now,v_now);
          INSERT INTO lucy.workspaces_task_events_v1(
            id,task_id,content_scope_id,event_type,attempt,occurred_at)
          VALUES (gen_random_uuid(),v_id,v_binding.content_scope_id,'enqueued',0,v_now);
          RETURN jsonb_build_object('task_id',v_id,'replayed',false);
        END
        $function$;

        CREATE FUNCTION lucy.claim_workspaces_task_v1(
          p_worker_id uuid,p_lease_seconds integer
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_task lucy.workspaces_tasks_v1%ROWTYPE;
          v_token uuid:=gen_random_uuid(); v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["task.execute"]'::jsonb;
          IF NOT FOUND OR p_worker_id IS NULL OR p_lease_seconds NOT BETWEEN 15 AND 300
          THEN RAISE EXCEPTION 'Workspaces task claim unavailable'; END IF;
          WITH exhausted AS (
            UPDATE lucy.workspaces_tasks_v1 SET status='failed',completed_at=v_now,
              result=jsonb_build_object('error','attempts_exhausted'),
              result_digest=encode(public.digest(convert_to('{"error":"attempts_exhausted"}','UTF8'),'sha256'),'hex')
            WHERE content_scope_id=v_binding.content_scope_id AND status='claimed'
              AND lease_expires_at<=v_now AND attempt_count>=max_attempts
            RETURNING id,content_scope_id,attempt_count)
          INSERT INTO lucy.workspaces_task_events_v1(
            id,task_id,content_scope_id,event_type,attempt,occurred_at)
          SELECT gen_random_uuid(),id,content_scope_id,'lease_exhausted',attempt_count,v_now
          FROM exhausted;
          SELECT * INTO v_task FROM lucy.workspaces_tasks_v1
          WHERE content_scope_id=v_binding.content_scope_id
            AND ((status='queued' AND available_at<=v_now)
              OR (status='claimed' AND lease_expires_at<=v_now))
            AND attempt_count<max_attempts
          ORDER BY available_at,created_at FOR UPDATE SKIP LOCKED LIMIT 1;
          IF NOT FOUND THEN RETURN NULL; END IF;
          UPDATE lucy.workspaces_tasks_v1 SET status='claimed',claimed_by=p_worker_id,
            lease_token=v_token,lease_expires_at=v_now+make_interval(secs=>p_lease_seconds),
            attempt_count=attempt_count+1 WHERE id=v_task.id
          RETURNING * INTO v_task;
          INSERT INTO lucy.workspaces_task_events_v1(
            id,task_id,content_scope_id,event_type,attempt,occurred_at)
          VALUES (gen_random_uuid(),v_task.id,v_task.content_scope_id,'claimed',
            v_task.attempt_count,v_now);
          RETURN jsonb_build_object('task_id',v_task.id,'request_id',v_task.request_id,
            'room_id',v_task.room_id,'instruction',v_task.instruction,
            'attempt',v_task.attempt_count,'lease_token',v_task.lease_token,
            'lease_expires_at',v_task.lease_expires_at);
        END
        $function$;

        CREATE FUNCTION lucy.heartbeat_workspaces_task_v1(
          p_task_id uuid,p_lease_token uuid,p_lease_seconds integer
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_task lucy.workspaces_tasks_v1%ROWTYPE; v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["task.execute"]'::jsonb;
          IF NOT FOUND OR p_lease_seconds NOT BETWEEN 15 AND 300
          THEN RAISE EXCEPTION 'Workspaces task heartbeat unavailable'; END IF;
          UPDATE lucy.workspaces_tasks_v1
          SET lease_expires_at=v_now+make_interval(secs=>p_lease_seconds)
          WHERE id=p_task_id AND content_scope_id=v_binding.content_scope_id
            AND status='claimed' AND lease_token=p_lease_token AND lease_expires_at>v_now
          RETURNING * INTO v_task;
          IF NOT FOUND THEN RAISE EXCEPTION 'Workspaces task heartbeat unavailable'; END IF;
          INSERT INTO lucy.workspaces_task_events_v1(
            id,task_id,content_scope_id,event_type,attempt,occurred_at)
          VALUES (gen_random_uuid(),v_task.id,v_task.content_scope_id,'heartbeat',
            v_task.attempt_count,v_now);
          RETURN jsonb_build_object('task_id',v_task.id,'lease_expires_at',v_task.lease_expires_at);
        END
        $function$;

        CREATE FUNCTION lucy.complete_workspaces_task_v1(
          p_task_id uuid,p_lease_token uuid,p_outcome text,p_result jsonb
        ) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_task lucy.workspaces_tasks_v1%ROWTYPE; v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["task.execute"]'::jsonb;
          IF NOT FOUND OR p_outcome NOT IN ('completed','failed')
             OR jsonb_typeof(p_result)<>'object' OR octet_length(p_result::text)>65536
          THEN RAISE EXCEPTION 'Workspaces task completion unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended('workspaces-task:'||p_task_id::text,0));
          SELECT * INTO v_task FROM lucy.workspaces_tasks_v1
          WHERE id=p_task_id AND content_scope_id=v_binding.content_scope_id FOR UPDATE;
          IF NOT FOUND OR v_task.lease_token<>p_lease_token
          THEN RAISE EXCEPTION 'Workspaces task completion unavailable'; END IF;
          IF v_task.status IN ('completed','failed') THEN
            IF v_task.status<>p_outcome OR v_task.result<>p_result
            THEN RAISE EXCEPTION 'Workspaces task completion conflict'; END IF;
            RETURN jsonb_build_object('task_id',v_task.id,'replayed',true);
          END IF;
          IF v_task.status<>'claimed' OR v_task.lease_expires_at<=v_now
          THEN RAISE EXCEPTION 'Workspaces task completion unavailable'; END IF;
          UPDATE lucy.workspaces_tasks_v1 SET status=p_outcome,result=p_result,
            result_digest=encode(public.digest(
              convert_to(lucy.canonical_jsonb_v1(p_result),'UTF8'),'sha256'),'hex'),
            completed_at=v_now WHERE id=p_task_id;
          INSERT INTO lucy.workspaces_task_events_v1(
            id,task_id,content_scope_id,event_type,attempt,occurred_at)
          VALUES (gen_random_uuid(),v_task.id,v_task.content_scope_id,p_outcome,
            v_task.attempt_count,v_now);
          RETURN jsonb_build_object('task_id',v_task.id,'replayed',false);
        END
        $function$;

        ALTER FUNCTION lucy.enqueue_workspaces_task_v1(uuid,uuid,uuid,uuid,uuid,text,text)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.claim_workspaces_task_v1(uuid,integer)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.heartbeat_workspaces_task_v1(uuid,uuid,integer)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.complete_workspaces_task_v1(uuid,uuid,text,jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION
          lucy.enqueue_workspaces_task_v1(uuid,uuid,uuid,uuid,uuid,text,text),
          lucy.claim_workspaces_task_v1(uuid,integer),
          lucy.heartbeat_workspaces_task_v1(uuid,uuid,integer),
          lucy.complete_workspaces_task_v1(uuid,uuid,text,jsonb)
          FROM PUBLIC,lucy_app,lucy_public_runtime;
        REVOKE ALL ON lucy.workspaces_tasks_v1,lucy.workspaces_task_events_v1
          FROM PUBLIC,lucy_app,lucy_public_runtime;
        GRANT SELECT,INSERT,UPDATE ON lucy.workspaces_tasks_v1,
          lucy.workspaces_task_events_v1 TO lucy_security_function_owner;
        GRANT SELECT ON lucy.realm_service_bindings_v1,lucy.realm_content_scopes_v1,
          lucy.channel_bindings TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("Workspaces task history requires a reviewed forward migration")
