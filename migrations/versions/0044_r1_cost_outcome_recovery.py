"""Keep provider exposure unresolved until independent outcome acknowledgement."""

from collections.abc import Sequence

from alembic import op

revision: str = "0044_r1_cost_outcome_recovery"
down_revision: str | None = "0043_r1_provider_cost_admission"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        ALTER TABLE lucy.provider_attempts_v1
          DROP CONSTRAINT provider_attempts_v1_state_check;
        ALTER TABLE lucy.provider_attempts_v1 ADD CHECK (state IN (
          'PERSISTENCE_PENDING','ADMITTED','SUBMITTED','UNKNOWN',
          'SETTLEMENT_PENDING','OVER_CAP_PENDING','SETTLED','OVER_CAP'
        ));
        ALTER TABLE lucy.cost_events_v1
          DROP CONSTRAINT cost_events_v1_event_type_check;
        ALTER TABLE lucy.cost_events_v1 ADD CHECK (event_type IN (
          'reservation_pending','reservation_acknowledged','submission_claimed',
          'outcome_unknown','settlement_pending','over_cap_pending',
          'settlement_acknowledged','over_cap_acknowledged'
        ));

        ALTER TABLE lucy.cost_recovery_outbox_v1
          ADD COLUMN outcome_event_id uuid UNIQUE REFERENCES lucy.cost_events_v1(id),
          ADD COLUMN pending_incurred_microusd bigint CHECK (pending_incurred_microusd>=0),
          ADD COLUMN pending_provider_reference_commitment text CHECK (
            pending_provider_reference_commitment IS NULL OR
            pending_provider_reference_commitment ~ '^[0-9a-f]{64}$'
          ),
          ADD COLUMN pending_final_state text CHECK (
            pending_final_state IS NULL OR pending_final_state IN ('SETTLED','OVER_CAP')
          ),
          ADD COLUMN outcome_head_digest text CHECK (
            outcome_head_digest IS NULL OR outcome_head_digest ~ '^[0-9a-f]{64}$'
          ),
          ADD COLUMN outcome_acknowledged_at timestamptz;

        CREATE FUNCTION lucy.reject_provider_attempt_during_pending_over_cap_v1()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
          IF EXISTS(SELECT 1 FROM lucy.provider_attempts_v1
            WHERE state='OVER_CAP_PENDING')
          THEN RAISE EXCEPTION 'provider cost admission unavailable'; END IF;
          RETURN NEW;
        END
        $function$;
        REVOKE ALL ON FUNCTION lucy.reject_provider_attempt_during_pending_over_cap_v1()
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_cost_admission,
            lucy_cost_recovery_writer;
        ALTER FUNCTION lucy.reject_provider_attempt_during_pending_over_cap_v1()
          OWNER TO lucy_cost_function_owner;
        CREATE TRIGGER provider_attempt_pending_over_cap_guard_v1
          BEFORE INSERT ON lucy.provider_attempts_v1 FOR EACH STATEMENT
          EXECUTE FUNCTION lucy.reject_provider_attempt_during_pending_over_cap_v1();

        CREATE OR REPLACE FUNCTION lucy.provider_attempt_result_v1(
          p_attempt_id uuid,p_replayed boolean
        ) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
          SELECT jsonb_build_object(
            'attempt_id',a.id,'policy_id',a.policy_id,'policy_version',a.policy_version,
            'state',a.state,'reserved_microusd',r.reserved_microusd,
            'unresolved_microusd',r.unresolved_microusd,
            'event_id',CASE WHEN o.outcome_event_id IS NOT NULL
              THEN o.outcome_event_id ELSE a.reservation_event_id END,
            'replayed',p_replayed
          )
          FROM lucy.provider_attempts_v1 a
          JOIN lucy.exposure_reservations_v1 r ON r.attempt_id=a.id
          JOIN lucy.cost_recovery_outbox_v1 o ON o.attempt_id=a.id
          WHERE a.id=p_attempt_id
        $function$;

        CREATE OR REPLACE FUNCTION lucy.settle_provider_attempt_v1(
          p_attempt_id uuid,p_incurred_microusd bigint,p_provider_reference_commitment text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_state text; v_max bigint; v_now timestamptz := clock_timestamp();
          v_pending text; v_final text; v_event_id uuid := gen_random_uuid();
          v_stored_incurred bigint; v_stored_reference text;
        BEGIN
          IF p_incurred_microusd<0 OR p_provider_reference_commitment !~ '^[0-9a-f]{64}$'
          THEN RAISE EXCEPTION 'provider settlement unavailable'; END IF;
          SELECT a.state,a.maximum_microusd,o.pending_incurred_microusd,
            o.pending_provider_reference_commitment
          INTO v_state,v_max,v_stored_incurred,v_stored_reference
          FROM lucy.provider_attempts_v1 a JOIN lucy.cost_recovery_outbox_v1 o
            ON o.attempt_id=a.id WHERE a.id=p_attempt_id FOR UPDATE OF a,o;
          IF NOT FOUND OR v_state IN ('PERSISTENCE_PENDING','ADMITTED') THEN
            RAISE EXCEPTION 'provider attempt is not submitted'; END IF;
          IF v_state IN ('SETTLEMENT_PENDING','OVER_CAP_PENDING','SETTLED','OVER_CAP') THEN
            IF v_stored_incurred<>p_incurred_microusd
               OR v_stored_reference<>p_provider_reference_commitment
            THEN RAISE EXCEPTION 'provider settlement conflicts'; END IF;
            RETURN lucy.provider_attempt_result_v1(p_attempt_id,true); END IF;
          v_final := CASE WHEN p_incurred_microusd>v_max THEN 'OVER_CAP' ELSE 'SETTLED' END;
          v_pending := CASE WHEN v_final='OVER_CAP' THEN 'OVER_CAP_PENDING'
            ELSE 'SETTLEMENT_PENDING' END;
          INSERT INTO lucy.cost_events_v1 VALUES(v_event_id,p_attempt_id,
            CASE WHEN v_final='OVER_CAP' THEN 'over_cap_pending' ELSE 'settlement_pending' END,
            encode(public.digest(lower(v_pending)||':'||p_attempt_id::text||':'||
              p_incurred_microusd::text||':'||p_provider_reference_commitment,
              'sha256'),'hex'),v_now);
          UPDATE lucy.cost_recovery_outbox_v1 SET outcome_event_id=v_event_id,
            pending_incurred_microusd=p_incurred_microusd,
            pending_provider_reference_commitment=p_provider_reference_commitment,
            pending_final_state=v_final WHERE attempt_id=p_attempt_id;
          UPDATE lucy.provider_attempts_v1 SET state=v_pending,
            provider_reference_commitment=p_provider_reference_commitment
            WHERE id=p_attempt_id;
          RETURN lucy.provider_attempt_result_v1(p_attempt_id,false);
        END
        $function$;

        CREATE FUNCTION lucy.acknowledge_provider_outcome_v1(
          p_attempt_id uuid,p_event_id uuid,p_head_digest text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_state text; v_event uuid; v_incurred bigint; v_final text;
          v_now timestamptz := clock_timestamp();
        BEGIN
          IF p_head_digest !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'cost outcome acknowledgement unavailable'; END IF;
          SELECT a.state,o.outcome_event_id,o.pending_incurred_microusd,
            o.pending_final_state INTO v_state,v_event,v_incurred,v_final
          FROM lucy.provider_attempts_v1 a JOIN lucy.cost_recovery_outbox_v1 o
            ON o.attempt_id=a.id WHERE a.id=p_attempt_id FOR UPDATE OF a,o;
          IF NOT FOUND OR v_event<>p_event_id OR v_incurred IS NULL OR v_final IS NULL THEN
            RAISE EXCEPTION 'cost outcome acknowledgement unavailable'; END IF;
          IF v_state IN ('SETTLED','OVER_CAP') THEN
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

        REVOKE ALL ON FUNCTION lucy.acknowledge_provider_outcome_v1(uuid,uuid,text)
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_cost_admission;
        ALTER FUNCTION lucy.acknowledge_provider_outcome_v1(uuid,uuid,text)
          OWNER TO lucy_cost_function_owner;
        GRANT EXECUTE ON FUNCTION lucy.acknowledge_provider_outcome_v1(uuid,uuid,text)
          TO lucy_cost_recovery_writer;

        REVOKE EXECUTE ON FUNCTION lucy.settle_provider_attempt_v1(uuid,bigint,text)
          FROM lucy_cost_recovery_writer;
        """
    )


def downgrade() -> None:
    raise RuntimeError("R1 cost recovery history requires a reviewed forward migration")
