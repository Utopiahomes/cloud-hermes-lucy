"""Freeze exact cost journal events before independent persistence."""

from collections.abc import Sequence

from alembic import op

revision: str = "0046_r1_cost_journal"
down_revision: str | None = "0045_r1_authority_recovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE TABLE lucy.cost_journal_preparations_v1 (
          event_id uuid PRIMARY KEY REFERENCES lucy.cost_events_v1(id),
          journal_sequence bigint NOT NULL CHECK (journal_sequence>0),
          journal_previous_digest text NOT NULL CHECK (
            journal_previous_digest ~ '^[0-9a-f]{64}$'
          ),
          journal_event_digest text NOT NULL CHECK (
            journal_event_digest ~ '^[0-9a-f]{64}$'
          ),
          prepared_at timestamptz NOT NULL
        );
        REVOKE ALL ON lucy.cost_journal_preparations_v1
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_cost_admission,
            lucy_cost_recovery_writer;
        GRANT SELECT,INSERT ON lucy.cost_journal_preparations_v1
          TO lucy_cost_function_owner;

        CREATE FUNCTION lucy.get_pending_cost_event_v1(p_event_id uuid)
        RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
          SELECT jsonb_build_object(
            'event_id',e.id,'attempt_id',a.id,
            'idempotency_key','cost:'||e.id::text,
            'event_type',CASE e.event_type
              WHEN 'reservation_pending' THEN 'reservation'
              WHEN 'settlement_pending' THEN 'settlement'
              WHEN 'over_cap_pending' THEN 'over_cap' END,
            'node_id',a.node_id,'channel_binding_id',a.channel_binding_id,
            'policy_id',a.policy_id,'policy_version',a.policy_version,
            'rate_version',a.rate_version,'accounting_period',a.admission_period,
            'maximum_microusd',a.maximum_microusd,
            'incurred_microusd',CASE WHEN e.event_type='reservation_pending'
              THEN 0 ELSE o.pending_incurred_microusd END,
            'unresolved_microusd',CASE WHEN e.event_type='reservation_pending'
              THEN r.unresolved_microusd ELSE 0 END,
            'request_commitment',a.request_commitment,
            'provider_reference_commitment',CASE WHEN e.event_type='reservation_pending'
              THEN NULL ELSE o.pending_provider_reference_commitment END,
            'source_authority_ref','cost-policy:'||a.policy_id::text||':'||a.policy_version::text,
            'source_authority_digest',p.policy_digest,
            'occurred_at',e.occurred_at,
            'journal_sequence',j.journal_sequence,
            'journal_previous_digest',j.journal_previous_digest,
            'journal_event_digest',j.journal_event_digest
          ) FROM lucy.cost_events_v1 e
          JOIN lucy.provider_attempts_v1 a ON a.id=e.attempt_id
          JOIN lucy.provider_cost_policies_v1 p ON p.id=a.policy_id
          JOIN lucy.exposure_reservations_v1 r ON r.attempt_id=a.id
          JOIN lucy.cost_recovery_outbox_v1 o ON o.attempt_id=a.id
          LEFT JOIN lucy.cost_journal_preparations_v1 j ON j.event_id=e.id
          WHERE e.id=p_event_id AND (
            (e.event_type='reservation_pending' AND o.reservation_event_id=e.id
              AND o.acknowledged_at IS NULL)
            OR (e.event_type IN ('settlement_pending','over_cap_pending')
              AND o.outcome_event_id=e.id AND o.outcome_acknowledged_at IS NULL)
          )
        $function$;

        CREATE FUNCTION lucy.prepare_cost_journal_event_v1(
          p_event_id uuid,p_journal_sequence bigint,p_journal_previous_digest text,
          p_journal_event_digest text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_existing lucy.cost_journal_preparations_v1%ROWTYPE;
          v_pending jsonb;
        BEGIN
          IF p_journal_sequence<1
             OR p_journal_previous_digest !~ '^[0-9a-f]{64}$'
             OR p_journal_event_digest !~ '^[0-9a-f]{64}$'
          THEN RAISE EXCEPTION 'cost journal preparation unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(p_event_id::text,0));
          SELECT lucy.get_pending_cost_event_v1(p_event_id) INTO v_pending;
          IF v_pending IS NULL THEN
            RAISE EXCEPTION 'cost journal preparation unavailable'; END IF;
          SELECT * INTO v_existing FROM lucy.cost_journal_preparations_v1
            WHERE event_id=p_event_id;
          IF FOUND THEN
            IF (v_existing.journal_sequence,v_existing.journal_previous_digest,
                v_existing.journal_event_digest) IS DISTINCT FROM
               (p_journal_sequence,p_journal_previous_digest,p_journal_event_digest)
            THEN RAISE EXCEPTION 'cost journal preparation conflicts'; END IF;
          ELSE
            INSERT INTO lucy.cost_journal_preparations_v1 VALUES(
              p_event_id,p_journal_sequence,p_journal_previous_digest,
              p_journal_event_digest,clock_timestamp()
            );
          END IF;
          RETURN lucy.get_pending_cost_event_v1(p_event_id);
        END
        $function$;

        CREATE OR REPLACE FUNCTION lucy.acknowledge_provider_reservation_v1(
          p_attempt_id uuid,p_event_id uuid,p_head_digest text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_state text; v_event uuid; v_now timestamptz:=clock_timestamp();
          v_prepared text; v_stored_head text; v_ack timestamptz;
        BEGIN
          IF p_head_digest !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'cost journal acknowledgement unavailable'; END IF;
          SELECT a.state,a.reservation_event_id,j.journal_event_digest,
            o.acknowledged_head_digest,o.acknowledged_at
          INTO v_state,v_event,v_prepared,v_stored_head,v_ack
          FROM lucy.provider_attempts_v1 a
          JOIN lucy.cost_recovery_outbox_v1 o ON o.attempt_id=a.id
          LEFT JOIN lucy.cost_journal_preparations_v1 j
            ON j.event_id=o.reservation_event_id
          WHERE a.id=p_attempt_id FOR UPDATE OF a,o;
          IF NOT FOUND OR v_event<>p_event_id OR v_prepared IS NULL
             OR v_prepared<>p_head_digest
          THEN RAISE EXCEPTION 'cost journal acknowledgement unavailable'; END IF;
          IF v_ack IS NOT NULL THEN
            IF v_stored_head<>p_head_digest THEN
              RAISE EXCEPTION 'cost journal acknowledgement conflicts'; END IF;
            RETURN lucy.provider_attempt_result_v1(p_attempt_id,true); END IF;
          IF v_state<>'PERSISTENCE_PENDING' THEN
            RAISE EXCEPTION 'cost journal acknowledgement unavailable'; END IF;
          UPDATE lucy.cost_recovery_outbox_v1 SET acknowledged_head_digest=p_head_digest,
            acknowledged_at=v_now WHERE attempt_id=p_attempt_id AND acknowledged_at IS NULL;
          IF NOT FOUND THEN RAISE EXCEPTION 'cost journal acknowledgement unavailable'; END IF;
          UPDATE lucy.provider_attempts_v1 SET state='ADMITTED',admitted_at=v_now
            WHERE id=p_attempt_id;
          INSERT INTO lucy.cost_events_v1 VALUES(gen_random_uuid(),p_attempt_id,
            'reservation_acknowledged',encode(public.digest(
              'reservation_acknowledged:'||p_attempt_id::text||':'||p_head_digest,
              'sha256'),'hex'),v_now);
          RETURN lucy.provider_attempt_result_v1(p_attempt_id,false);
        END
        $function$;

        CREATE OR REPLACE FUNCTION lucy.acknowledge_provider_outcome_v1(
          p_attempt_id uuid,p_event_id uuid,p_head_digest text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_state text; v_event uuid; v_incurred bigint; v_final text;
          v_now timestamptz:=clock_timestamp(); v_prepared text;
          v_stored_head text; v_ack timestamptz;
        BEGIN
          IF p_head_digest !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'cost outcome acknowledgement unavailable'; END IF;
          SELECT a.state,o.outcome_event_id,o.pending_incurred_microusd,
            o.pending_final_state,j.journal_event_digest,o.outcome_head_digest,
            o.outcome_acknowledged_at
          INTO v_state,v_event,v_incurred,v_final,v_prepared,v_stored_head,v_ack
          FROM lucy.provider_attempts_v1 a JOIN lucy.cost_recovery_outbox_v1 o
            ON o.attempt_id=a.id LEFT JOIN lucy.cost_journal_preparations_v1 j
            ON j.event_id=o.outcome_event_id
          WHERE a.id=p_attempt_id FOR UPDATE OF a,o;
          IF NOT FOUND OR v_event<>p_event_id OR v_incurred IS NULL OR v_final IS NULL
             OR v_prepared IS NULL OR v_prepared<>p_head_digest
          THEN RAISE EXCEPTION 'cost outcome acknowledgement unavailable'; END IF;
          IF v_ack IS NOT NULL THEN
            IF v_stored_head<>p_head_digest THEN
              RAISE EXCEPTION 'cost outcome acknowledgement conflicts'; END IF;
            RETURN lucy.provider_attempt_result_v1(p_attempt_id,true); END IF;
          IF v_state NOT IN ('SETTLEMENT_PENDING','OVER_CAP_PENDING')
             OR (v_state='OVER_CAP_PENDING')<>(v_final='OVER_CAP')
          THEN RAISE EXCEPTION 'cost outcome acknowledgement unavailable'; END IF;
          UPDATE lucy.cost_recovery_outbox_v1 SET outcome_head_digest=p_head_digest,
            outcome_acknowledged_at=v_now WHERE attempt_id=p_attempt_id
            AND outcome_event_id=p_event_id AND outcome_acknowledged_at IS NULL;
          IF NOT FOUND THEN RAISE EXCEPTION 'cost outcome acknowledgement unavailable'; END IF;
          UPDATE lucy.exposure_reservations_v1 SET incurred_microusd=v_incurred,
            unresolved_microusd=0,settled_at=v_now WHERE attempt_id=p_attempt_id;
          UPDATE lucy.provider_attempts_v1 SET state=v_final,completed_at=v_now
            WHERE id=p_attempt_id;
          INSERT INTO lucy.cost_events_v1 VALUES(gen_random_uuid(),p_attempt_id,
            CASE WHEN v_final='OVER_CAP' THEN 'over_cap_acknowledged'
              ELSE 'settlement_acknowledged' END,
            encode(public.digest(lower(v_final)||'_acknowledged:'||p_attempt_id::text||':'||
              p_head_digest,'sha256'),'hex'),v_now);
          RETURN lucy.provider_attempt_result_v1(p_attempt_id,false);
        END
        $function$;

        REVOKE ALL ON FUNCTION lucy.get_pending_cost_event_v1(uuid),
          lucy.prepare_cost_journal_event_v1(uuid,bigint,text,text)
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_cost_recovery_writer;
        ALTER FUNCTION lucy.get_pending_cost_event_v1(uuid)
          OWNER TO lucy_cost_function_owner;
        ALTER FUNCTION lucy.prepare_cost_journal_event_v1(uuid,bigint,text,text)
          OWNER TO lucy_cost_function_owner;
        GRANT EXECUTE ON FUNCTION lucy.get_pending_cost_event_v1(uuid),
          lucy.prepare_cost_journal_event_v1(uuid,bigint,text,text)
          TO lucy_cost_admission;

        REVOKE ALL ON FUNCTION lucy.acknowledge_provider_reservation_v1(uuid,uuid,text),
          lucy.acknowledge_provider_outcome_v1(uuid,uuid,text)
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_cost_admission;
        ALTER FUNCTION lucy.acknowledge_provider_reservation_v1(uuid,uuid,text)
          OWNER TO lucy_cost_function_owner;
        ALTER FUNCTION lucy.acknowledge_provider_outcome_v1(uuid,uuid,text)
          OWNER TO lucy_cost_function_owner;
        GRANT EXECUTE ON FUNCTION lucy.acknowledge_provider_reservation_v1(uuid,uuid,text),
          lucy.acknowledge_provider_outcome_v1(uuid,uuid,text)
          TO lucy_cost_recovery_writer;
        """
    )


def downgrade() -> None:
    raise RuntimeError("R1 cost journal history requires a reviewed forward migration")
