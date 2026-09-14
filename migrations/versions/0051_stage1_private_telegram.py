"""Add an execute-only, content-free private Telegram restart ledger."""

from collections.abc import Sequence

from alembic import op

revision: str = "0051_stage1_private_telegram"
down_revision: str | None = "0050_r1_recovery_ack_receiver"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE TABLE lucy.telegram_gateway_leases_v1 (
          node_id uuid PRIMARY KEY REFERENCES lucy.nodes(id),
          security_realm_id uuid NOT NULL REFERENCES lucy.security_realms(id),
          channel_binding_id uuid NOT NULL UNIQUE REFERENCES lucy.channel_bindings(id),
          bot_id bigint NOT NULL UNIQUE CHECK (bot_id > 0),
          holder_id uuid NOT NULL,
          fence bigint NOT NULL CHECK (fence > 0),
          lease_until timestamptz NOT NULL,
          updated_at timestamptz NOT NULL
        );

        CREATE TABLE lucy.telegram_channel_bindings_v1 (
          channel_binding_id uuid PRIMARY KEY REFERENCES lucy.channel_bindings(id),
          bot_id bigint NOT NULL UNIQUE CHECK (bot_id > 0),
          owner_user_id bigint NOT NULL CHECK (owner_user_id > 0),
          binding_digest text NOT NULL CHECK (binding_digest ~ '^[0-9a-f]{64}$'),
          created_at timestamptz NOT NULL
        );

        CREATE TABLE lucy.telegram_events_v1 (
          event_id uuid PRIMARY KEY,
          node_id uuid NOT NULL REFERENCES lucy.nodes(id),
          security_realm_id uuid NOT NULL REFERENCES lucy.security_realms(id),
          channel_binding_id uuid NOT NULL REFERENCES lucy.channel_bindings(id),
          bot_id bigint NOT NULL CHECK (bot_id > 0),
          update_id bigint NOT NULL CHECK (update_id >= 0),
          chat_id bigint NOT NULL,
          message_id bigint NOT NULL CHECK (message_id > 0),
          holder_id uuid NOT NULL,
          lease_fence bigint NOT NULL CHECK (lease_fence > 0),
          state text NOT NULL CHECK (state IN (
            'CLAIMED','INFERENCE_STARTED','INFERENCE_SETTLED','SEND_STARTED','SENT',
            'COMPLETED_NO_REPLY','INTERRUPTED','DELIVERY_UNCERTAIN'
          )),
          outbound_message_id bigint CHECK (outbound_message_id IS NULL OR outbound_message_id > 0),
          claimed_at timestamptz NOT NULL,
          updated_at timestamptz NOT NULL,
          UNIQUE(bot_id, update_id),
          UNIQUE(bot_id, chat_id, message_id),
          CHECK ((state = 'SENT') = (outbound_message_id IS NOT NULL))
        );

        CREATE TABLE lucy.telegram_budget_accounts_v1 (
          security_realm_id uuid PRIMARY KEY REFERENCES lucy.security_realms(id),
          daily_limit_microusd bigint NOT NULL CHECK (daily_limit_microusd > 0),
          period_date date NOT NULL,
          reserved_microusd bigint NOT NULL DEFAULT 0 CHECK (reserved_microusd >= 0),
          spent_microusd bigint NOT NULL DEFAULT 0 CHECK (spent_microusd >= 0),
          updated_at timestamptz NOT NULL,
          CHECK (reserved_microusd + spent_microusd <= daily_limit_microusd)
        );

        CREATE TABLE lucy.telegram_model_operations_v1 (
          action_id uuid PRIMARY KEY,
          event_id uuid NOT NULL REFERENCES lucy.telegram_events_v1(event_id),
          node_id uuid NOT NULL REFERENCES lucy.nodes(id),
          security_realm_id uuid NOT NULL REFERENCES lucy.security_realms(id),
          channel_binding_id uuid NOT NULL REFERENCES lucy.channel_bindings(id),
          bot_id bigint NOT NULL CHECK (bot_id > 0),
          holder_id uuid NOT NULL,
          lease_fence bigint NOT NULL CHECK (lease_fence > 0),
          model_step integer NOT NULL CHECK (model_step > 0),
          idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 500),
          model text NOT NULL,
          reserved_microusd bigint NOT NULL CHECK (reserved_microusd > 0),
          actual_microusd bigint CHECK (
            actual_microusd IS NULL OR actual_microusd BETWEEN 0 AND reserved_microusd
          ),
          state text NOT NULL CHECK (state IN ('EXECUTING','SUCCEEDED','FAILED','AMBIGUOUS')),
          created_at timestamptz NOT NULL,
          updated_at timestamptz NOT NULL,
          UNIQUE(security_realm_id, idempotency_key),
          UNIQUE(event_id, model_step),
          CHECK ((state='EXECUTING')=(actual_microusd IS NULL))
        );

        REVOKE ALL ON lucy.telegram_channel_bindings_v1,
          lucy.telegram_gateway_leases_v1, lucy.telegram_events_v1,
          lucy.telegram_budget_accounts_v1, lucy.telegram_model_operations_v1
          FROM PUBLIC, lucy_app, lucy_public_runtime;
        GRANT SELECT ON lucy.telegram_channel_bindings_v1
          TO lucy_security_function_owner;
        GRANT SELECT, INSERT, UPDATE ON lucy.telegram_gateway_leases_v1,
          lucy.telegram_events_v1, lucy.telegram_budget_accounts_v1,
          lucy.telegram_model_operations_v1 TO lucy_security_function_owner;

        CREATE FUNCTION lucy.stage1_telegram_scope_v1(
          p_node_id uuid,p_realm_id uuid,p_channel_binding_id uuid,p_bot_id bigint
        ) RETURNS uuid
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_scope uuid;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='archive_writer' AND active
            AND allowed_actions @> '["evidence.archive"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'Telegram scope unavailable'; END IF;
          SELECT cs.id INTO v_scope
          FROM lucy.realm_content_scopes_v1 cs
          JOIN lucy.realm_service_bindings_v1 sb
            ON sb.id=v_actor.target_service_binding_id
            AND sb.content_scope_id=cs.id AND sb.active
            AND sb.allowed_actions @> '["evidence.archive"]'::jsonb
          JOIN lucy.channel_bindings ch
            ON ch.id=p_channel_binding_id AND ch.node_id=cs.node_id
            AND ch.workspace_id=cs.workspace_id AND ch.tenure_id=cs.node_tenure_id
            AND ch.channel_kind='internal' AND ch.active
          JOIN lucy.telegram_channel_bindings_v1 tb
            ON tb.channel_binding_id=ch.id AND tb.bot_id=p_bot_id
          JOIN lucy.nodes n ON n.id=cs.node_id
            AND n.authz_epoch=v_actor.node_authz_epoch
            AND n.authz_epoch=sb.node_authz_epoch
          JOIN lucy.realm_bindings rb ON rb.id=cs.realm_binding_id
            AND rb.realm_id=cs.security_realm_id AND rb.tenure_id=cs.node_tenure_id
            AND rb.valid_to IS NULL
          WHERE cs.id=v_actor.content_scope_id AND cs.node_id=p_node_id
            AND cs.security_realm_id=p_realm_id
            AND v_actor.policy_version=sb.policy_version;
          IF v_scope IS NULL THEN RAISE EXCEPTION 'Telegram scope unavailable'; END IF;
          RETURN v_scope;
        END
        $function$;

        CREATE FUNCTION lucy.telegram_lease_result_v1(
          p_node_id uuid,p_acquired boolean
        ) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
          SELECT jsonb_build_object('holder_id',holder_id,'fence',fence,
            'lease_until',lease_until,'acquired',p_acquired)
          FROM lucy.telegram_gateway_leases_v1 WHERE node_id=p_node_id
        $function$;

        CREATE FUNCTION lucy.acquire_telegram_gateway_lease_v1(
          p_node_id uuid,p_realm_id uuid,p_channel_binding_id uuid,p_bot_id bigint,
          p_holder_id uuid,p_lease_seconds integer
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_existing lucy.telegram_gateway_leases_v1%ROWTYPE;
          v_now timestamptz := clock_timestamp(); v_fence bigint;
        BEGIN
          PERFORM lucy.stage1_telegram_scope_v1(
            p_node_id,p_realm_id,p_channel_binding_id,p_bot_id);
          IF p_bot_id<=0 OR p_lease_seconds<>30 THEN
            RAISE EXCEPTION 'Telegram lease unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended('telegram:'||p_node_id::text,0));
          SELECT * INTO v_existing FROM lucy.telegram_gateway_leases_v1
            WHERE node_id=p_node_id FOR UPDATE;
          IF FOUND AND v_existing.lease_until>v_now AND v_existing.holder_id<>p_holder_id
          THEN RAISE EXCEPTION 'Telegram gateway already leased'; END IF;
          IF FOUND AND (v_existing.security_realm_id<>p_realm_id
             OR v_existing.channel_binding_id<>p_channel_binding_id
             OR v_existing.bot_id<>p_bot_id)
          THEN RAISE EXCEPTION 'Telegram lease binding conflict'; END IF;
          IF FOUND AND v_existing.holder_id=p_holder_id THEN
            UPDATE lucy.telegram_gateway_leases_v1 SET lease_until=v_now+interval '30 seconds',
              updated_at=v_now WHERE node_id=p_node_id;
            RETURN lucy.telegram_lease_result_v1(p_node_id,true);
          END IF;
          IF FOUND THEN
            WITH charged AS (
              UPDATE lucy.telegram_model_operations_v1
              SET state='AMBIGUOUS',actual_microusd=reserved_microusd,updated_at=v_now
              WHERE node_id=p_node_id AND holder_id=v_existing.holder_id
                AND lease_fence=v_existing.fence AND state='EXECUTING'
              RETURNING security_realm_id,reserved_microusd
            ), totals AS (
              SELECT security_realm_id,sum(reserved_microusd)::bigint AS charged
              FROM charged GROUP BY security_realm_id
            )
            UPDATE lucy.telegram_budget_accounts_v1 a
              SET reserved_microusd=a.reserved_microusd-t.charged,
                spent_microusd=a.spent_microusd+t.charged,updated_at=v_now
            FROM totals t WHERE a.security_realm_id=t.security_realm_id;
            UPDATE lucy.telegram_events_v1 SET state=CASE
                WHEN state='SEND_STARTED' THEN 'DELIVERY_UNCERTAIN' ELSE 'INTERRUPTED' END,
              updated_at=v_now
            WHERE node_id=p_node_id AND holder_id=v_existing.holder_id
              AND lease_fence=v_existing.fence
              AND state IN ('CLAIMED','INFERENCE_STARTED','INFERENCE_SETTLED','SEND_STARTED');
            v_fence := v_existing.fence+1;
            UPDATE lucy.telegram_gateway_leases_v1 SET holder_id=p_holder_id,
              fence=v_fence,lease_until=v_now+interval '30 seconds',updated_at=v_now
              WHERE node_id=p_node_id;
          ELSE
            v_fence := 1;
            INSERT INTO lucy.telegram_gateway_leases_v1 VALUES(
              p_node_id,p_realm_id,p_channel_binding_id,p_bot_id,p_holder_id,v_fence,
              v_now+interval '30 seconds',v_now);
          END IF;
          RETURN lucy.telegram_lease_result_v1(p_node_id,true);
        END
        $function$;

        CREATE FUNCTION lucy.heartbeat_telegram_gateway_lease_v1(
          p_node_id uuid,p_realm_id uuid,p_channel_binding_id uuid,p_bot_id bigint,
          p_holder_id uuid,p_lease_seconds integer
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_now timestamptz := clock_timestamp();
        BEGIN
          PERFORM lucy.stage1_telegram_scope_v1(
            p_node_id,p_realm_id,p_channel_binding_id,p_bot_id);
          IF p_lease_seconds<>30 THEN RAISE EXCEPTION 'Telegram lease unavailable'; END IF;
          UPDATE lucy.telegram_gateway_leases_v1
            SET lease_until=v_now+interval '30 seconds',updated_at=v_now
          WHERE node_id=p_node_id AND security_realm_id=p_realm_id
            AND channel_binding_id=p_channel_binding_id AND bot_id=p_bot_id
            AND holder_id=p_holder_id AND lease_until>v_now;
          IF NOT FOUND THEN RAISE EXCEPTION 'Telegram lease unavailable'; END IF;
          RETURN lucy.telegram_lease_result_v1(p_node_id,true);
        END
        $function$;

        CREATE FUNCTION lucy.release_telegram_gateway_lease_v1(
          p_node_id uuid,p_realm_id uuid,p_channel_binding_id uuid,p_bot_id bigint,
          p_holder_id uuid
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_now timestamptz := clock_timestamp();
        BEGIN
          PERFORM lucy.stage1_telegram_scope_v1(
            p_node_id,p_realm_id,p_channel_binding_id,p_bot_id);
          UPDATE lucy.telegram_gateway_leases_v1 SET lease_until=v_now,updated_at=v_now
          WHERE node_id=p_node_id AND security_realm_id=p_realm_id
            AND channel_binding_id=p_channel_binding_id AND bot_id=p_bot_id
            AND holder_id=p_holder_id;
          IF NOT FOUND THEN RAISE EXCEPTION 'Telegram lease unavailable'; END IF;
          RETURN lucy.telegram_lease_result_v1(p_node_id,false);
        END
        $function$;

        CREATE FUNCTION lucy.telegram_event_result_v1(
          p_event_id uuid,p_admitted boolean,p_replayed boolean
        ) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
          SELECT jsonb_build_object('event_id',event_id,'state',state,
            'admitted',p_admitted,'replayed',p_replayed)
          FROM lucy.telegram_events_v1 WHERE event_id=p_event_id
        $function$;

        CREATE FUNCTION lucy.claim_telegram_event_v1(
          p_node_id uuid,p_realm_id uuid,p_channel_binding_id uuid,p_bot_id bigint,
          p_holder_id uuid,p_fence bigint,p_event_id uuid,p_update_id bigint,
          p_chat_id bigint,p_message_id bigint
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_existing lucy.telegram_events_v1%ROWTYPE;
          v_now timestamptz := clock_timestamp();
        BEGIN
          PERFORM lucy.stage1_telegram_scope_v1(
            p_node_id,p_realm_id,p_channel_binding_id,p_bot_id);
          IF p_update_id<0 OR p_message_id<=0 OR NOT EXISTS(
            SELECT 1 FROM lucy.telegram_gateway_leases_v1 l
            WHERE l.node_id=p_node_id AND l.security_realm_id=p_realm_id
              AND l.channel_binding_id=p_channel_binding_id AND l.bot_id=p_bot_id
              AND l.holder_id=p_holder_id AND l.fence=p_fence AND l.lease_until>v_now
          ) THEN RAISE EXCEPTION 'Telegram event admission unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'telegram-update:'||p_bot_id::text||':'||p_update_id::text,0));
          SELECT * INTO v_existing FROM lucy.telegram_events_v1
            WHERE bot_id=p_bot_id AND update_id=p_update_id;
          IF FOUND THEN
            IF v_existing.event_id<>p_event_id OR v_existing.node_id<>p_node_id
               OR v_existing.security_realm_id<>p_realm_id
               OR v_existing.channel_binding_id<>p_channel_binding_id
               OR v_existing.chat_id<>p_chat_id OR v_existing.message_id<>p_message_id
            THEN RAISE EXCEPTION 'Telegram event identity conflict'; END IF;
            RETURN lucy.telegram_event_result_v1(v_existing.event_id,false,true);
          END IF;
          INSERT INTO lucy.telegram_events_v1 VALUES(
            p_event_id,p_node_id,p_realm_id,p_channel_binding_id,p_bot_id,p_update_id,
            p_chat_id,p_message_id,p_holder_id,p_fence,'CLAIMED',NULL,v_now,v_now);
          RETURN lucy.telegram_event_result_v1(p_event_id,true,false);
        END
        $function$;

        CREATE FUNCTION lucy.transition_telegram_event_v1(
          p_node_id uuid,p_realm_id uuid,p_channel_binding_id uuid,p_bot_id bigint,
          p_holder_id uuid,p_fence bigint,p_event_id uuid,p_state text,
          p_outbound_message_id bigint
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_event lucy.telegram_events_v1%ROWTYPE;
          v_now timestamptz := clock_timestamp(); v_allowed boolean := false;
        BEGIN
          PERFORM lucy.stage1_telegram_scope_v1(
            p_node_id,p_realm_id,p_channel_binding_id,p_bot_id);
          IF NOT EXISTS(SELECT 1 FROM lucy.telegram_gateway_leases_v1 l
            WHERE l.node_id=p_node_id AND l.security_realm_id=p_realm_id
              AND l.channel_binding_id=p_channel_binding_id AND l.bot_id=p_bot_id
              AND l.holder_id=p_holder_id AND l.fence=p_fence AND l.lease_until>v_now)
          THEN RAISE EXCEPTION 'Telegram event transition unavailable'; END IF;
          SELECT * INTO v_event FROM lucy.telegram_events_v1
            WHERE event_id=p_event_id AND node_id=p_node_id
              AND security_realm_id=p_realm_id AND channel_binding_id=p_channel_binding_id
              AND bot_id=p_bot_id AND holder_id=p_holder_id AND lease_fence=p_fence
            FOR UPDATE;
          IF NOT FOUND THEN RAISE EXCEPTION 'Telegram event transition unavailable'; END IF;
          IF v_event.state=p_state
             AND v_event.outbound_message_id IS NOT DISTINCT FROM p_outbound_message_id
          THEN RETURN jsonb_build_object('event_id',p_event_id,'state',p_state,'replayed',true);
          END IF;
          IF v_event.state IN ('SENT','COMPLETED_NO_REPLY','INTERRUPTED','DELIVERY_UNCERTAIN')
          THEN RAISE EXCEPTION 'Telegram event is terminal'; END IF;
          v_allowed := (v_event.state='CLAIMED' AND p_state='INFERENCE_STARTED')
            OR (v_event.state='INFERENCE_STARTED' AND p_state='INFERENCE_SETTLED')
            OR (v_event.state='INFERENCE_SETTLED'
              AND p_state IN ('SEND_STARTED','COMPLETED_NO_REPLY'))
            OR (v_event.state='SEND_STARTED' AND p_state IN ('SENT','DELIVERY_UNCERTAIN'))
            OR p_state='INTERRUPTED';
          IF NOT v_allowed OR ((p_state='SENT')<>(p_outbound_message_id IS NOT NULL))
          THEN RAISE EXCEPTION 'Telegram event transition unavailable'; END IF;
          UPDATE lucy.telegram_events_v1 SET state=p_state,
            outbound_message_id=p_outbound_message_id,updated_at=v_now
            WHERE event_id=p_event_id;
          RETURN jsonb_build_object('event_id',p_event_id,'state',p_state,'replayed',false);
        END
        $function$;

        CREATE FUNCTION lucy.begin_telegram_model_operation_v1(
          p_node_id uuid,p_realm_id uuid,p_channel_binding_id uuid,p_bot_id bigint,
          p_holder_id uuid,p_fence bigint,p_event_id uuid,p_model_step integer,
          p_action_id uuid,p_idempotency_key text,p_model text,p_reservation_microusd bigint
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_now timestamptz := clock_timestamp();
          v_existing lucy.telegram_model_operations_v1%ROWTYPE;
          v_account lucy.telegram_budget_accounts_v1%ROWTYPE;
          v_expected_key text;
        BEGIN
          PERFORM lucy.stage1_telegram_scope_v1(
            p_node_id,p_realm_id,p_channel_binding_id,p_bot_id);
          v_expected_key := 'hermes-model:telegram-event:'||p_event_id::text
            ||':'||'model-step:'||p_model_step::text;
          IF p_model_step<=0 OR p_model<>'openai/gpt-oss-20b'
             OR p_reservation_microusd<>5000 OR p_idempotency_key<>v_expected_key
             OR NOT EXISTS(SELECT 1 FROM lucy.telegram_gateway_leases_v1 l
               WHERE l.node_id=p_node_id AND l.security_realm_id=p_realm_id
                 AND l.channel_binding_id=p_channel_binding_id AND l.bot_id=p_bot_id
                 AND l.holder_id=p_holder_id AND l.fence=p_fence AND l.lease_until>v_now)
             OR NOT EXISTS(SELECT 1 FROM lucy.telegram_events_v1 e
               WHERE e.event_id=p_event_id AND e.node_id=p_node_id
                 AND e.security_realm_id=p_realm_id
                 AND e.channel_binding_id=p_channel_binding_id AND e.bot_id=p_bot_id
                 AND e.holder_id=p_holder_id AND e.lease_fence=p_fence
                 AND e.state='INFERENCE_STARTED')
          THEN RAISE EXCEPTION 'Telegram model operation unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'telegram-model:'||p_realm_id::text||':'||p_idempotency_key,0));
          SELECT * INTO v_existing FROM lucy.telegram_model_operations_v1
            WHERE security_realm_id=p_realm_id AND idempotency_key=p_idempotency_key;
          IF FOUND THEN
            IF v_existing.action_id<>p_action_id OR v_existing.event_id<>p_event_id
               OR v_existing.model_step<>p_model_step OR v_existing.node_id<>p_node_id
               OR v_existing.channel_binding_id<>p_channel_binding_id
               OR v_existing.bot_id<>p_bot_id OR v_existing.model<>p_model
               OR v_existing.reserved_microusd<>p_reservation_microusd
            THEN RAISE EXCEPTION 'Telegram model idempotency conflict'; END IF;
            RETURN jsonb_build_object('action_id',v_existing.action_id,
              'status',lower(v_existing.state),'execute',false,'replayed',true);
          END IF;
          SELECT * INTO v_account FROM lucy.telegram_budget_accounts_v1
            WHERE security_realm_id=p_realm_id FOR UPDATE;
          IF NOT FOUND THEN RAISE EXCEPTION 'Telegram budget unavailable'; END IF;
          IF v_account.period_date<>v_now::date THEN
            IF v_account.reserved_microusd<>0 THEN
              RAISE EXCEPTION 'Telegram budget rollover unavailable'; END IF;
            UPDATE lucy.telegram_budget_accounts_v1 SET period_date=v_now::date,
              spent_microusd=0,updated_at=v_now WHERE security_realm_id=p_realm_id;
            v_account.spent_microusd := 0;
          END IF;
          IF v_account.reserved_microusd+v_account.spent_microusd
             +p_reservation_microusd>v_account.daily_limit_microusd
          THEN RAISE EXCEPTION 'Telegram budget exhausted'; END IF;
          INSERT INTO lucy.telegram_model_operations_v1 VALUES(
            p_action_id,p_event_id,p_node_id,p_realm_id,p_channel_binding_id,p_bot_id,
            p_holder_id,p_fence,p_model_step,p_idempotency_key,p_model,
            p_reservation_microusd,NULL,'EXECUTING',v_now,v_now);
          UPDATE lucy.telegram_budget_accounts_v1
            SET reserved_microusd=reserved_microusd+p_reservation_microusd,
              updated_at=v_now WHERE security_realm_id=p_realm_id;
          RETURN jsonb_build_object('action_id',p_action_id,'status','executing',
            'execute',true,'replayed',false);
        END
        $function$;

        CREATE FUNCTION lucy.settle_telegram_model_operation_v1(
          p_node_id uuid,p_realm_id uuid,p_channel_binding_id uuid,p_bot_id bigint,
          p_holder_id uuid,p_fence bigint,p_event_id uuid,p_model_step integer,
          p_action_id uuid,p_actual_microusd bigint,p_succeeded boolean
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_now timestamptz := clock_timestamp();
          v_operation lucy.telegram_model_operations_v1%ROWTYPE;
          v_charge bigint; v_state text;
        BEGIN
          PERFORM lucy.stage1_telegram_scope_v1(
            p_node_id,p_realm_id,p_channel_binding_id,p_bot_id);
          IF NOT EXISTS(SELECT 1 FROM lucy.telegram_gateway_leases_v1 l
            WHERE l.node_id=p_node_id AND l.security_realm_id=p_realm_id
              AND l.channel_binding_id=p_channel_binding_id AND l.bot_id=p_bot_id
              AND l.holder_id=p_holder_id AND l.fence=p_fence AND l.lease_until>v_now)
          THEN RAISE EXCEPTION 'Telegram model settlement unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.telegram_model_operations_v1
            WHERE action_id=p_action_id AND event_id=p_event_id AND model_step=p_model_step
              AND node_id=p_node_id AND security_realm_id=p_realm_id
              AND channel_binding_id=p_channel_binding_id AND bot_id=p_bot_id
              AND holder_id=p_holder_id AND lease_fence=p_fence FOR UPDATE;
          IF NOT FOUND OR p_actual_microusd<0
             OR p_actual_microusd>v_operation.reserved_microusd
          THEN RAISE EXCEPTION 'Telegram model settlement unavailable'; END IF;
          IF v_operation.state<>'EXECUTING' THEN
            RETURN jsonb_build_object('action_id',p_action_id,
              'status',lower(v_operation.state),'replayed',true);
          END IF;
          v_charge := CASE WHEN p_succeeded THEN p_actual_microusd
                           ELSE v_operation.reserved_microusd END;
          v_state := CASE WHEN p_succeeded THEN 'SUCCEEDED' ELSE 'FAILED' END;
          UPDATE lucy.telegram_budget_accounts_v1
            SET reserved_microusd=reserved_microusd-v_operation.reserved_microusd,
              spent_microusd=spent_microusd+v_charge,updated_at=v_now
            WHERE security_realm_id=p_realm_id;
          UPDATE lucy.telegram_model_operations_v1 SET state=v_state,
            actual_microusd=v_charge,updated_at=v_now WHERE action_id=p_action_id;
          RETURN jsonb_build_object('action_id',p_action_id,'status',lower(v_state),
            'replayed',false);
        END
        $function$;
        """
    )

    signatures = (
        "lucy.stage1_telegram_scope_v1(uuid,uuid,uuid,bigint)",
        "lucy.telegram_lease_result_v1(uuid,boolean)",
        "lucy.acquire_telegram_gateway_lease_v1(uuid,uuid,uuid,bigint,uuid,integer)",
        "lucy.heartbeat_telegram_gateway_lease_v1(uuid,uuid,uuid,bigint,uuid,integer)",
        "lucy.release_telegram_gateway_lease_v1(uuid,uuid,uuid,bigint,uuid)",
        "lucy.telegram_event_result_v1(uuid,boolean,boolean)",
        "lucy.claim_telegram_event_v1(uuid,uuid,uuid,bigint,uuid,bigint,uuid,bigint,bigint,bigint)",
        "lucy.transition_telegram_event_v1(uuid,uuid,uuid,bigint,uuid,bigint,uuid,text,bigint)",
        "lucy.begin_telegram_model_operation_v1(uuid,uuid,uuid,bigint,uuid,bigint,uuid,integer,uuid,text,text,bigint)",
        "lucy.settle_telegram_model_operation_v1(uuid,uuid,uuid,bigint,uuid,bigint,uuid,integer,uuid,bigint,boolean)",
    )
    for signature in signatures:
        op.execute(
            f"ALTER FUNCTION {signature} OWNER TO lucy_security_function_owner; "
            f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC, lucy_app, lucy_public_runtime"
        )


def downgrade() -> None:
    raise RuntimeError("Stage 1 Telegram delivery history requires a reviewed forward migration")
