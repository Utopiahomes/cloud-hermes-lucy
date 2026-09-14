"""Journal private Telegram channel activation and withdrawal."""

from collections.abc import Sequence

from alembic import op

revision: str = "0053_r1_telegram_authority"
down_revision: str | None = "0052_r1_public_answer_gate"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        ALTER TABLE lucy.authority_transition_events_v1
          DROP CONSTRAINT authority_transition_events_v1_event_type_check;
        ALTER TABLE lucy.authority_transition_events_v1
          ADD CONSTRAINT authority_transition_events_v1_event_type_check CHECK (
            event_type IN (
              'membership_revoked','publication_withdrawn',
              'channel_activated','channel_withdrawn'
            )
          );

        CREATE OR REPLACE FUNCTION lucy.channel_authority_guard_v1()
        RETURNS trigger LANGUAGE plpgsql
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
          IF NEW.id<>OLD.id OR NEW.hostname<>OLD.hostname OR NEW.node_id<>OLD.node_id
             OR NEW.tenure_id<>OLD.tenure_id OR NEW.workspace_id<>OLD.workspace_id
             OR NEW.channel_kind<>OLD.channel_kind OR NEW.created_at<>OLD.created_at
          THEN RAISE EXCEPTION 'channel authority transition unavailable'; END IF;
          IF current_user='lucy_authority_function_owner'
             AND NEW.active<>OLD.active AND NEW.generation=OLD.generation+1
          THEN RETURN NEW; END IF;
          IF NOT OLD.active OR NEW.active OR NEW.generation<>OLD.generation+1
          THEN RAISE EXCEPTION 'channel authority transition unavailable'; END IF;
          RETURN NEW;
        END
        $function$;

        CREATE FUNCTION lucy.guard_channel_authority_v1()
        RETURNS trigger LANGUAGE plpgsql
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
          IF current_user NOT IN ('lucy_authority_function_owner','lucy_owner')
             AND (OLD.active,OLD.generation) IS DISTINCT FROM
                 (NEW.active,NEW.generation)
          THEN RAISE EXCEPTION 'channel change requires authority transition'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER channel_binding_authority_guard_v1
          BEFORE UPDATE ON lucy.channel_bindings FOR EACH ROW
          EXECUTE FUNCTION lucy.guard_channel_authority_v1();
        ALTER FUNCTION lucy.guard_channel_authority_v1()
          OWNER TO lucy_authority_function_owner;
        REVOKE ALL ON FUNCTION lucy.guard_channel_authority_v1()
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_authority_transition,
            lucy_authority_recovery_writer;
        GRANT SELECT,UPDATE ON lucy.channel_bindings TO lucy_authority_function_owner;
        GRANT SELECT ON lucy.telegram_channel_bindings_v1
          TO lucy_authority_function_owner;

        CREATE FUNCTION lucy.stage_channel_activation_v1(
          p_channel_binding_id uuid,p_actor_id uuid,p_stream_id uuid,
          p_authority_epoch bigint,p_idempotency_key text,p_source_authority_ref text,
          p_source_authority_digest text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_existing lucy.authority_transition_events_v1%ROWTYPE;
          v_channel record; v_realm uuid;
          v_event uuid:=gen_random_uuid(); v_now timestamptz:=clock_timestamp();
          v_digest text;
        BEGIN
          IF p_authority_epoch<1 OR length(p_idempotency_key) NOT BETWEEN 1 AND 300
             OR p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR length(p_source_authority_ref) NOT BETWEEN 1 AND 512
             OR p_source_authority_ref !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR p_source_authority_digest !~ '^[0-9a-f]{64}$'
          THEN RAISE EXCEPTION 'channel activation unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(p_idempotency_key,0));
          SELECT * INTO v_existing FROM lucy.authority_transition_events_v1
            WHERE idempotency_key=p_idempotency_key;
          IF FOUND THEN
            IF v_existing.event_type<>'channel_activated'
               OR v_existing.subject_id<>p_channel_binding_id
               OR v_existing.actor_id<>p_actor_id OR v_existing.stream_id<>p_stream_id
               OR v_existing.authority_epoch<>p_authority_epoch
               OR v_existing.source_authority_ref<>p_source_authority_ref
               OR v_existing.source_authority_digest<>p_source_authority_digest
            THEN RAISE EXCEPTION 'authority transition idempotency conflict'; END IF;
            RETURN lucy.authority_transition_result_v1(v_existing.id,true); END IF;
          SELECT c.*,tb.binding_digest AS binding_digest INTO v_channel
          FROM lucy.channel_bindings c
          JOIN lucy.telegram_channel_bindings_v1 tb ON tb.channel_binding_id=c.id
          WHERE c.id=p_channel_binding_id FOR UPDATE OF c;
          IF NOT FOUND OR v_channel.active OR v_channel.channel_kind<>'internal'
             OR v_channel.binding_digest<>p_source_authority_digest
             OR EXISTS(SELECT 1 FROM lucy.authority_transition_events_v1 e
               JOIN lucy.authority_recovery_outbox_v1 o ON o.event_id=e.id
               WHERE e.subject_id=p_channel_binding_id
                 AND e.event_type='channel_activated' AND o.acknowledged_at IS NULL)
          THEN RAISE EXCEPTION 'channel activation unavailable'; END IF;
          IF NOT EXISTS(SELECT 1 FROM lucy.node_memberships a
            WHERE a.principal_id=p_actor_id AND a.workspace_id=v_channel.workspace_id
              AND a.status='active' AND a.role='owner')
          THEN RAISE EXCEPTION 'channel activation unavailable'; END IF;
          SELECT rb.realm_id INTO STRICT v_realm FROM lucy.realm_bindings rb
            WHERE rb.tenure_id=v_channel.tenure_id AND rb.valid_to IS NULL;
          v_digest:=encode(public.digest(
            'channel_activated:'||p_stream_id::text||':'||p_authority_epoch::text||':'||
            v_realm::text||':'||v_channel.workspace_id::text||':'||v_channel.id::text||':'||
            v_channel.generation::text||':'||(v_channel.generation+1)::text||':'||
            p_source_authority_digest,'sha256'),'hex');
          INSERT INTO lucy.authority_transition_events_v1 VALUES(
            v_event,p_idempotency_key,p_stream_id,p_authority_epoch,'channel_activated',
            v_realm,v_channel.workspace_id,v_channel.id,p_actor_id,v_channel.generation,
            v_channel.generation+1,p_source_authority_ref,p_source_authority_digest,
            v_digest,v_now);
          INSERT INTO lucy.authority_recovery_outbox_v1(event_id) VALUES(v_event);
          RETURN lucy.authority_transition_result_v1(v_event,false);
        END
        $function$;

        CREATE FUNCTION lucy.stage_channel_withdrawal_v1(
          p_channel_binding_id uuid,p_actor_id uuid,p_stream_id uuid,
          p_authority_epoch bigint,p_idempotency_key text,p_source_authority_ref text,
          p_source_authority_digest text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_existing lucy.authority_transition_events_v1%ROWTYPE;
          v_channel record; v_realm uuid;
          v_event uuid:=gen_random_uuid(); v_now timestamptz:=clock_timestamp();
          v_digest text;
        BEGIN
          IF p_authority_epoch<1 OR length(p_idempotency_key) NOT BETWEEN 1 AND 300
             OR p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR length(p_source_authority_ref) NOT BETWEEN 1 AND 512
             OR p_source_authority_ref !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR p_source_authority_digest !~ '^[0-9a-f]{64}$'
          THEN RAISE EXCEPTION 'channel withdrawal unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(p_idempotency_key,0));
          SELECT * INTO v_existing FROM lucy.authority_transition_events_v1
            WHERE idempotency_key=p_idempotency_key;
          IF FOUND THEN
            IF v_existing.event_type<>'channel_withdrawn'
               OR v_existing.subject_id<>p_channel_binding_id
               OR v_existing.actor_id<>p_actor_id OR v_existing.stream_id<>p_stream_id
               OR v_existing.authority_epoch<>p_authority_epoch
               OR v_existing.source_authority_ref<>p_source_authority_ref
               OR v_existing.source_authority_digest<>p_source_authority_digest
            THEN RAISE EXCEPTION 'authority transition idempotency conflict'; END IF;
            RETURN lucy.authority_transition_result_v1(v_existing.id,true); END IF;
          SELECT c.*,tb.binding_digest AS binding_digest INTO v_channel
          FROM lucy.channel_bindings c
          JOIN lucy.telegram_channel_bindings_v1 tb ON tb.channel_binding_id=c.id
          WHERE c.id=p_channel_binding_id FOR UPDATE OF c;
          IF NOT FOUND OR NOT v_channel.active OR v_channel.channel_kind<>'internal'
             OR v_channel.binding_digest<>p_source_authority_digest
          THEN RAISE EXCEPTION 'channel withdrawal unavailable'; END IF;
          IF NOT EXISTS(SELECT 1 FROM lucy.node_memberships a
            WHERE a.principal_id=p_actor_id AND a.workspace_id=v_channel.workspace_id
              AND a.status='active' AND a.role='owner')
          THEN RAISE EXCEPTION 'channel withdrawal unavailable'; END IF;
          SELECT rb.realm_id INTO STRICT v_realm FROM lucy.realm_bindings rb
            WHERE rb.tenure_id=v_channel.tenure_id AND rb.valid_to IS NULL;
          v_digest:=encode(public.digest(
            'channel_withdrawn:'||p_stream_id::text||':'||p_authority_epoch::text||':'||
            v_realm::text||':'||v_channel.workspace_id::text||':'||v_channel.id::text||':'||
            v_channel.generation::text||':'||(v_channel.generation+1)::text||':'||
            p_source_authority_digest,'sha256'),'hex');
          UPDATE lucy.channel_bindings SET active=false,generation=generation+1
            WHERE id=v_channel.id;
          INSERT INTO lucy.authority_transition_events_v1 VALUES(
            v_event,p_idempotency_key,p_stream_id,p_authority_epoch,'channel_withdrawn',
            v_realm,v_channel.workspace_id,v_channel.id,p_actor_id,v_channel.generation,
            v_channel.generation+1,p_source_authority_ref,p_source_authority_digest,
            v_digest,v_now);
          INSERT INTO lucy.authority_recovery_outbox_v1(event_id) VALUES(v_event);
          RETURN lucy.authority_transition_result_v1(v_event,false);
        END
        $function$;

        ALTER FUNCTION lucy.acknowledge_authority_event_v1(uuid,bigint,text,text)
          RENAME TO acknowledge_restrictive_authority_event_v1;
        REVOKE ALL ON FUNCTION
          lucy.acknowledge_restrictive_authority_event_v1(uuid,bigint,text,text)
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_authority_recovery_writer;
        CREATE FUNCTION lucy.acknowledge_authority_event_v1(
          p_event_id uuid,p_journal_sequence bigint,p_journal_event_digest text,
          p_journal_head_digest text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_event lucy.authority_transition_events_v1%ROWTYPE;
          v_sequence bigint; v_event_digest text; v_ack timestamptz;
          v_channel record;
          v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_event FROM lucy.authority_transition_events_v1
            WHERE id=p_event_id;
          IF NOT FOUND THEN RAISE EXCEPTION 'authority acknowledgement unavailable'; END IF;
          IF v_event.event_type<>'channel_activated' THEN
            RETURN lucy.acknowledge_restrictive_authority_event_v1(
              p_event_id,p_journal_sequence,p_journal_event_digest,p_journal_head_digest);
          END IF;
          IF p_journal_sequence<1 OR p_journal_event_digest !~ '^[0-9a-f]{64}$'
             OR p_journal_event_digest<>p_journal_head_digest
          THEN RAISE EXCEPTION 'authority acknowledgement unavailable'; END IF;
          SELECT journal_sequence,journal_event_digest,acknowledged_at
          INTO v_sequence,v_event_digest,v_ack FROM lucy.authority_recovery_outbox_v1
            WHERE event_id=p_event_id FOR UPDATE;
          IF NOT FOUND OR v_sequence IS NULL OR v_event_digest IS NULL
             OR (v_sequence,v_event_digest) IS DISTINCT FROM
                (p_journal_sequence,p_journal_event_digest)
          THEN RAISE EXCEPTION 'authority acknowledgement unavailable'; END IF;
          IF v_ack IS NOT NULL THEN
            RETURN lucy.authority_transition_result_v1(p_event_id,true); END IF;
          SELECT c.*,tb.binding_digest AS binding_digest INTO v_channel
          FROM lucy.channel_bindings c
          JOIN lucy.telegram_channel_bindings_v1 tb ON tb.channel_binding_id=c.id
          WHERE c.id=v_event.subject_id FOR UPDATE OF c;
          IF NOT FOUND OR v_channel.active OR v_channel.channel_kind<>'internal'
             OR v_channel.workspace_id<>v_event.workspace_id
             OR v_channel.generation<>v_event.previous_generation
             OR v_channel.binding_digest<>v_event.source_authority_digest
          THEN RAISE EXCEPTION 'channel activation became stale'; END IF;
          UPDATE lucy.channel_bindings SET active=true,
            generation=v_event.new_generation WHERE id=v_channel.id;
          UPDATE lucy.authority_recovery_outbox_v1 SET
            journal_head_digest=p_journal_head_digest,acknowledged_at=v_now
            WHERE event_id=p_event_id;
          RETURN lucy.authority_transition_result_v1(p_event_id,false);
        END
        $function$;

        ALTER FUNCTION lucy.apply_authority_recovery_event_v1(jsonb,jsonb)
          RENAME TO apply_restrictive_authority_recovery_event_v1;
        REVOKE ALL ON FUNCTION
          lucy.apply_restrictive_authority_recovery_event_v1(jsonb,jsonb)
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_authority_recovery_writer;
        CREATE FUNCTION lucy.apply_authority_recovery_event_v1(
          p_expected jsonb,p_event jsonb
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_head lucy.restored_recovery_heads_v1%ROWTYPE;
          v_existing jsonb; v_effect jsonb; v_transition text; v_event_id uuid;
          v_stream_id uuid; v_epoch bigint; v_store text; v_manifest text;
          v_sequence bigint; v_previous text; v_digest text; v_subject uuid;
          v_workspace uuid; v_realm uuid; v_previous_generation bigint;
          v_new_generation bigint; v_actual_workspace uuid; v_actual_realm uuid;
          v_actual_generation bigint; v_active boolean; v_kind text; v_binding_digest text;
          v_now timestamptz:=clock_timestamp();
        BEGIN
          v_transition:=p_event->'effect'->>'transition';
          IF v_transition NOT IN ('channel_activated','channel_withdrawn') THEN
            RETURN lucy.apply_restrictive_authority_recovery_event_v1(p_expected,p_event);
          END IF;
          IF NOT EXISTS(SELECT 1 FROM lucy.runtime_admission
              WHERE singleton AND state='quarantined')
             OR EXISTS(SELECT 1 FROM lucy.conversation_capture_states WHERE capture_enabled)
             OR EXISTS(SELECT 1 FROM lucy.scoped_capture_states_v1 WHERE capture_enabled)
             OR jsonb_typeof(p_expected)<>'object'
             OR (SELECT count(*) FROM jsonb_object_keys(p_expected))<>8
             OR p_expected->>'contract_version'<>'1'
             OR p_expected->>'stream_kind'<>'authority'
             OR jsonb_typeof(p_event)<>'object'
             OR (SELECT count(*) FROM jsonb_object_keys(p_event))<>17
             OR p_event->>'contract_version'<>'1'
             OR p_event->>'stream_kind'<>'authority'
             OR jsonb_typeof(p_event->'effect')<>'object'
             OR (SELECT count(*) FROM jsonb_object_keys(p_event->'effect'))<>9
             OR p_event->'effect'->>'effect_type'<>'authority'
          THEN RAISE EXCEPTION 'authority recovery event is invalid'; END IF;
          v_kind:='authority'; v_event_id:=(p_event->>'event_id')::uuid;
          v_stream_id:=(p_event->>'stream_id')::uuid;
          v_epoch:=(p_event->>'authority_epoch')::bigint;
          v_store:=p_event->>'independent_store_id';
          v_manifest:=p_event->>'binding_manifest_digest';
          v_sequence:=(p_event->>'sequence')::bigint;
          v_previous:=p_event->>'previous_digest'; v_digest:=p_event->>'event_digest';
          v_effect:=p_event->'effect'; v_subject:=(v_effect->>'subject_id')::uuid;
          v_workspace:=(v_effect->>'workspace_id')::uuid;
          v_realm:=(v_effect->>'security_realm_id')::uuid;
          v_previous_generation:=(v_effect->>'previous_generation')::bigint;
          v_new_generation:=(v_effect->>'new_generation')::bigint;
          IF v_epoch<1 OR v_sequence<1 OR v_new_generation<>v_previous_generation+1
             OR length(v_store) NOT BETWEEN 1 AND 512
             OR v_store !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR v_manifest !~ '^[0-9a-f]{64}$' OR v_previous !~ '^[0-9a-f]{64}$'
             OR v_digest !~ '^[0-9a-f]{64}$'
             OR p_event->>'operation_id'<>p_event->>'event_id'
             OR length(p_event->>'idempotency_key') NOT BETWEEN 1 AND 512
             OR p_event->>'idempotency_key' !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR length(p_event->>'source_authority_ref') NOT BETWEEN 1 AND 512
             OR p_event->>'source_authority_ref' !~
                '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR p_event->>'source_authority_digest' !~ '^[0-9a-f]{64}$'
             OR (p_event->>'source_generation')::bigint<>v_new_generation
             OR (p_event->>'occurred_at')::timestamptz IS NULL
             OR (v_transition='channel_activated' AND
               (v_effect->>'previous_state'<>'inactive' OR v_effect->>'new_state'<>'active'))
             OR (v_transition='channel_withdrawn' AND
               (v_effect->>'previous_state'<>'active' OR v_effect->>'new_state'<>'inactive'))
          THEN RAISE EXCEPTION 'authority recovery event is invalid'; END IF;
          SELECT event_body INTO v_existing FROM lucy.restored_recovery_events_v1
            WHERE event_id=v_event_id;
          IF FOUND THEN
            IF v_existing<>p_event THEN
              RAISE EXCEPTION 'authority recovery event conflicts';
            END IF;
            RETURN lucy.restored_recovery_head_v1('authority');
          END IF;
          SELECT * INTO v_head FROM lucy.restored_recovery_heads_v1
            WHERE stream_kind='authority' FOR UPDATE;
          IF NOT FOUND THEN
            IF (p_expected->>'sequence')::bigint<>0
               OR p_expected->>'event_digest'<>repeat('0',64)
            THEN RAISE EXCEPTION 'authority recovery genesis is invalid'; END IF;
            INSERT INTO lucy.restored_recovery_heads_v1 VALUES(
              'authority',v_stream_id,v_epoch,v_store,v_manifest,0,repeat('0',64),v_now
            ) RETURNING * INTO v_head;
          END IF;
          IF (v_head.stream_id,v_head.authority_epoch,v_head.independent_store_id,
              v_head.binding_manifest_digest,v_head.sequence,v_head.event_digest)
             IS DISTINCT FROM
             ((p_expected->>'stream_id')::uuid,(p_expected->>'authority_epoch')::bigint,
              p_expected->>'independent_store_id',p_expected->>'binding_manifest_digest',
              (p_expected->>'sequence')::bigint,p_expected->>'event_digest')
             OR (v_stream_id,v_epoch,v_store,v_manifest,v_sequence,v_previous)
             IS DISTINCT FROM
             (v_head.stream_id,v_head.authority_epoch,v_head.independent_store_id,
              v_head.binding_manifest_digest,v_head.sequence+1,v_head.event_digest)
          THEN RAISE EXCEPTION 'authority recovery chain is not contiguous'; END IF;
          SELECT c.workspace_id,rb.realm_id,c.generation,c.active,tb.binding_digest
          INTO v_actual_workspace,v_actual_realm,v_actual_generation,v_active,v_binding_digest
          FROM lucy.channel_bindings c
          JOIN lucy.workspaces w ON w.id=c.workspace_id
          JOIN lucy.realm_bindings rb ON rb.tenure_id=w.tenure_id AND rb.valid_to IS NULL
          JOIN lucy.telegram_channel_bindings_v1 tb ON tb.channel_binding_id=c.id
          WHERE c.id=v_subject AND c.channel_kind='internal' FOR UPDATE OF c;
          IF FOUND THEN
            IF (v_actual_workspace,v_actual_realm,v_binding_digest) IS DISTINCT FROM
               (v_workspace,v_realm,p_event->>'source_authority_digest')
            THEN RAISE EXCEPTION 'authority recovery scope differs'; END IF;
            IF v_actual_generation=v_previous_generation
               AND v_active=(v_transition='channel_withdrawn') THEN
              UPDATE lucy.channel_bindings SET
                active=(v_transition='channel_activated'),generation=v_new_generation
                WHERE id=v_subject;
            ELSIF v_actual_generation<>v_new_generation
               OR v_active<>(v_transition='channel_activated')
            THEN RAISE EXCEPTION 'authority recovery state conflicts'; END IF;
          END IF;
          INSERT INTO lucy.restored_recovery_events_v1 VALUES(
            v_event_id,v_kind,v_stream_id,v_sequence,v_previous,v_digest,p_event,v_now);
          UPDATE lucy.restored_recovery_heads_v1 SET sequence=v_sequence,
            event_digest=v_digest,updated_at=v_now WHERE stream_kind='authority';
          RETURN lucy.restored_recovery_head_v1('authority');
        END
        $function$;
        """
    )

    ownership = (
        "lucy.channel_authority_guard_v1()",
        "lucy.stage_channel_activation_v1(uuid,uuid,uuid,bigint,text,text,text)",
        "lucy.stage_channel_withdrawal_v1(uuid,uuid,uuid,bigint,text,text,text)",
        "lucy.acknowledge_authority_event_v1(uuid,bigint,text,text)",
        "lucy.apply_authority_recovery_event_v1(jsonb,jsonb)",
    )
    for signature in ownership:
        op.execute(
            f"ALTER FUNCTION {signature} OWNER TO lucy_authority_function_owner; "
            f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC,lucy_app,lucy_public_runtime"
        )
    op.execute(
        "GRANT EXECUTE ON FUNCTION "
        "lucy.stage_channel_activation_v1(uuid,uuid,uuid,bigint,text,text,text),"
        "lucy.stage_channel_withdrawal_v1(uuid,uuid,uuid,bigint,text,text,text) "
        "TO lucy_authority_transition; "
        "GRANT EXECUTE ON FUNCTION "
        "lucy.acknowledge_authority_event_v1(uuid,bigint,text,text),"
        "lucy.apply_authority_recovery_event_v1(jsonb,jsonb) "
        "TO lucy_authority_recovery_writer"
    )


def downgrade() -> None:
    raise RuntimeError("Telegram authority history requires a reviewed forward migration")
