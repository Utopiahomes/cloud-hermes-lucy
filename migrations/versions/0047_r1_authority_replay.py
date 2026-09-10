"""Replay restrictive authority events into a quarantined restore."""

from collections.abc import Sequence

from alembic import op

revision: str = "0047_r1_authority_replay"
down_revision: str | None = "0046_r1_cost_journal"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE TABLE lucy.restored_recovery_heads_v1 (
          stream_kind text PRIMARY KEY CHECK (stream_kind IN ('authority','cost')),
          stream_id uuid NOT NULL UNIQUE,
          authority_epoch bigint NOT NULL CHECK (authority_epoch>0),
          independent_store_id text NOT NULL CHECK (
            length(independent_store_id) BETWEEN 1 AND 512 AND
            independent_store_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
          ),
          binding_manifest_digest text NOT NULL CHECK (
            binding_manifest_digest ~ '^[0-9a-f]{64}$'
          ),
          sequence bigint NOT NULL CHECK (sequence>=0),
          event_digest text NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
          updated_at timestamptz NOT NULL,
          CHECK (sequence<>0 OR event_digest=repeat('0',64))
        );
        CREATE TABLE lucy.restored_recovery_events_v1 (
          event_id uuid PRIMARY KEY,
          stream_kind text NOT NULL,
          stream_id uuid NOT NULL,
          sequence bigint NOT NULL CHECK (sequence>0),
          previous_digest text NOT NULL CHECK (previous_digest ~ '^[0-9a-f]{64}$'),
          event_digest text NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
          event_body jsonb NOT NULL,
          applied_at timestamptz NOT NULL,
          UNIQUE(stream_kind,stream_id,sequence),
          UNIQUE(stream_kind,stream_id,event_digest)
        );
        CREATE TRIGGER restored_recovery_events_immutable_v1
          BEFORE UPDATE OR DELETE ON lucy.restored_recovery_events_v1
          FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation();

        REVOKE ALL ON lucy.restored_recovery_heads_v1,
          lucy.restored_recovery_events_v1
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_authority_transition,
            lucy_authority_recovery_writer,lucy_cost_admission,lucy_cost_recovery_writer;
        GRANT SELECT,INSERT,UPDATE ON lucy.restored_recovery_heads_v1
          TO lucy_authority_function_owner;
        GRANT SELECT,INSERT ON lucy.restored_recovery_events_v1
          TO lucy_authority_function_owner;
        GRANT SELECT ON lucy.runtime_admission,lucy.conversation_capture_states,
          lucy.scoped_capture_states_v1 TO lucy_authority_function_owner;

        CREATE FUNCTION lucy.restored_recovery_head_v1(p_stream_kind text)
        RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
          SELECT jsonb_build_object(
            'contract_version','1','stream_kind',stream_kind,'stream_id',stream_id,
            'authority_epoch',authority_epoch,
            'independent_store_id',independent_store_id,
            'binding_manifest_digest',binding_manifest_digest,'sequence',sequence,
            'event_digest',event_digest
          ) FROM lucy.restored_recovery_heads_v1 WHERE stream_kind=p_stream_kind
        $function$;

        CREATE FUNCTION lucy.apply_authority_recovery_event_v1(
          p_expected jsonb,p_event jsonb
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_head lucy.restored_recovery_heads_v1%ROWTYPE;
          v_existing jsonb; v_effect jsonb; v_kind text; v_event_id uuid;
          v_stream_id uuid; v_epoch bigint; v_store text; v_manifest text;
          v_sequence bigint; v_previous text; v_digest text; v_transition text;
          v_subject uuid; v_workspace uuid; v_realm uuid; v_previous_generation bigint;
          v_new_generation bigint; v_actual_workspace uuid; v_actual_realm uuid;
          v_actual_generation bigint; v_status text; v_active uuid;
          v_now timestamptz:=clock_timestamp();
        BEGIN
          IF NOT EXISTS(SELECT 1 FROM lucy.runtime_admission
              WHERE singleton AND state='quarantined')
             OR EXISTS(SELECT 1 FROM lucy.conversation_capture_states
              WHERE capture_enabled)
             OR EXISTS(SELECT 1 FROM lucy.scoped_capture_states_v1
              WHERE capture_enabled)
          THEN RAISE EXCEPTION 'authority recovery requires quarantined capture-off storage';
          END IF;
          IF jsonb_typeof(p_expected)<>'object'
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

          v_kind:=p_event->>'stream_kind'; v_event_id:=(p_event->>'event_id')::uuid;
          v_stream_id:=(p_event->>'stream_id')::uuid;
          v_epoch:=(p_event->>'authority_epoch')::bigint;
          v_store:=p_event->>'independent_store_id';
          v_manifest:=p_event->>'binding_manifest_digest';
          v_sequence:=(p_event->>'sequence')::bigint;
          v_previous:=p_event->>'previous_digest'; v_digest:=p_event->>'event_digest';
          v_effect:=p_event->'effect'; v_transition:=v_effect->>'transition';
          v_subject:=(v_effect->>'subject_id')::uuid;
          v_workspace:=(v_effect->>'workspace_id')::uuid;
          v_realm:=(v_effect->>'security_realm_id')::uuid;
          v_previous_generation:=(v_effect->>'previous_generation')::bigint;
          v_new_generation:=(v_effect->>'new_generation')::bigint;
          IF v_epoch<1 OR v_sequence<1 OR v_new_generation<>v_previous_generation+1
             OR length(v_store) NOT BETWEEN 1 AND 512
             OR v_store !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR v_manifest !~ '^[0-9a-f]{64}$'
             OR v_previous !~ '^[0-9a-f]{64}$' OR v_digest !~ '^[0-9a-f]{64}$'
             OR p_event->>'operation_id'<>p_event->>'event_id'
             OR length(p_event->>'idempotency_key') NOT BETWEEN 1 AND 512
             OR p_event->>'idempotency_key' !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR length(p_event->>'source_authority_ref') NOT BETWEEN 1 AND 512
             OR p_event->>'source_authority_ref' !~
                '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR p_event->>'source_authority_digest' !~ '^[0-9a-f]{64}$'
             OR (p_event->>'source_generation')::bigint<>v_new_generation
             OR (p_event->>'occurred_at')::timestamptz IS NULL
             OR v_transition NOT IN ('membership_revoked','publication_withdrawn')
             OR (v_transition='membership_revoked' AND
                (v_effect->>'previous_state'<>'active' OR v_effect->>'new_state'<>'revoked'))
             OR (v_transition='publication_withdrawn' AND
                (v_effect->>'previous_state'<>'published' OR
                 v_effect->>'new_state'<>'withdrawn'))
          THEN RAISE EXCEPTION 'authority recovery event is invalid'; END IF;

          SELECT event_body INTO v_existing FROM lucy.restored_recovery_events_v1
            WHERE event_id=v_event_id;
          IF FOUND THEN
            IF v_existing<>p_event THEN
              RAISE EXCEPTION 'authority recovery event conflicts';
            END IF;
            RETURN jsonb_build_object(
              'contract_version','1','stream_kind',v_kind,'stream_id',v_stream_id,
              'authority_epoch',v_epoch,'independent_store_id',v_store,
              'binding_manifest_digest',v_manifest,'sequence',v_sequence,
              'event_digest',v_digest
            );
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

          IF v_transition='membership_revoked' THEN
            SELECT m.workspace_id,rb.realm_id,m.generation,m.status
            INTO v_actual_workspace,v_actual_realm,v_actual_generation,v_status
            FROM lucy.node_memberships m JOIN lucy.workspaces w ON w.id=m.workspace_id
            JOIN lucy.realm_bindings rb ON rb.tenure_id=w.tenure_id AND rb.valid_to IS NULL
            WHERE m.id=v_subject FOR UPDATE OF m;
            IF FOUND THEN
              IF (v_actual_workspace,v_actual_realm) IS DISTINCT FROM
                 (v_workspace,v_realm)
              THEN RAISE EXCEPTION 'authority recovery scope differs'; END IF;
              IF v_status='active' AND v_actual_generation=v_previous_generation THEN
                UPDATE lucy.node_memberships SET status='revoked',generation=v_new_generation
                  WHERE id=v_subject;
              ELSIF v_status<>'revoked' OR v_actual_generation<>v_new_generation THEN
                RAISE EXCEPTION 'authority recovery state conflicts';
              END IF;
            END IF;
          ELSE
            SELECT c.workspace_id,rb.realm_id,r.authority_generation,r.active_version_id
            INTO v_actual_workspace,v_actual_realm,v_actual_generation,v_active
            FROM lucy.public_projection_routes r
            JOIN lucy.channel_bindings c ON c.id=r.channel_binding_id
            JOIN lucy.workspaces w ON w.id=c.workspace_id
            JOIN lucy.realm_bindings rb ON rb.tenure_id=w.tenure_id AND rb.valid_to IS NULL
            WHERE r.channel_binding_id=v_subject FOR UPDATE OF r;
            IF FOUND THEN
              IF (v_actual_workspace,v_actual_realm) IS DISTINCT FROM
                 (v_workspace,v_realm)
              THEN RAISE EXCEPTION 'authority recovery scope differs'; END IF;
              IF v_active IS NOT NULL AND v_actual_generation=v_previous_generation THEN
                UPDATE lucy.public_projection_routes SET active_version_id=NULL,
                  authority_generation=v_new_generation,updated_at=v_now
                  WHERE channel_binding_id=v_subject;
              ELSIF v_active IS NOT NULL OR v_actual_generation<>v_new_generation THEN
                RAISE EXCEPTION 'authority recovery state conflicts';
              END IF;
            END IF;
          END IF;

          INSERT INTO lucy.restored_recovery_events_v1 VALUES(
            v_event_id,v_kind,v_stream_id,v_sequence,v_previous,v_digest,p_event,v_now
          );
          UPDATE lucy.restored_recovery_heads_v1 SET sequence=v_sequence,
            event_digest=v_digest,updated_at=v_now WHERE stream_kind='authority';
          RETURN lucy.restored_recovery_head_v1('authority');
        END
        $function$;

        REVOKE ALL ON FUNCTION lucy.restored_recovery_head_v1(text),
          lucy.apply_authority_recovery_event_v1(jsonb,jsonb)
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_authority_transition,
            lucy_cost_admission,lucy_cost_recovery_writer;
        ALTER FUNCTION lucy.restored_recovery_head_v1(text)
          OWNER TO lucy_authority_function_owner;
        ALTER FUNCTION lucy.apply_authority_recovery_event_v1(jsonb,jsonb)
          OWNER TO lucy_authority_function_owner;
        GRANT EXECUTE ON FUNCTION lucy.restored_recovery_head_v1(text),
          lucy.apply_authority_recovery_event_v1(jsonb,jsonb)
          TO lucy_authority_recovery_writer;
        """
    )


def downgrade() -> None:
    raise RuntimeError("R1 authority replay history requires a reviewed forward migration")
