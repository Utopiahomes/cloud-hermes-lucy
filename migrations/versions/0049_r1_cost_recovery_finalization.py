"""Fence old attempts and finalize recovered cost admission."""

from collections.abc import Sequence

from alembic import op

revision: str = "0049_r1_cost_recovery_finalize"
down_revision: str | None = "0048_r1_cost_replay"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        ALTER TABLE lucy.restored_cost_admission_v1
          ADD COLUMN paid_admission_not_before timestamptz;

        CREATE OR REPLACE FUNCTION lucy.block_provider_attempt_during_cost_recovery_v1()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_recovery lucy.restored_cost_admission_v1%ROWTYPE;
          v_policy lucy.provider_cost_policies_v1%ROWTYPE; v_period timestamptz;
          v_platform bigint; v_node bigint; v_site bigint; v_provider bigint;
          v_outstanding bigint; v_concurrency bigint;
        BEGIN
          SELECT * INTO v_recovery FROM lucy.restored_cost_admission_v1 LIMIT 1;
          IF NOT FOUND THEN RETURN NEW; END IF;
          IF v_recovery.state<>'finalized' OR v_recovery.operator_review_required
             OR v_recovery.paid_admission_not_before IS NULL
             OR clock_timestamp()<v_recovery.paid_admission_not_before
          THEN RAISE EXCEPTION 'provider cost recovery is not finalized'; END IF;
          IF EXISTS(SELECT 1 FROM lucy.restored_cost_exposures_v1
              WHERE recovery_state='over_cap')
             OR EXISTS(SELECT 1 FROM lucy.restored_cost_exposures_v1
              WHERE attempt_id=NEW.id)
          THEN RAISE EXCEPTION 'provider cost admission unavailable'; END IF;
          SELECT * INTO v_policy FROM lucy.provider_cost_policies_v1
            WHERE id=NEW.policy_id AND version=NEW.policy_version;
          IF NOT FOUND THEN RAISE EXCEPTION 'provider cost admission unavailable'; END IF;
          v_period:=date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';

          WITH effective AS (
            SELECT a.id AS attempt_id,a.node_id,a.channel_binding_id,a.provider,
              a.admission_period,r.incurred_microusd,r.unresolved_microusd,
              r.unresolved_microusd>0 AS possibly_in_flight
            FROM lucy.provider_attempts_v1 a JOIN lucy.exposure_reservations_v1 r
              ON r.attempt_id=a.id
            WHERE NOT EXISTS(SELECT 1 FROM lucy.restored_cost_exposures_v1 x
              WHERE x.attempt_id=a.id)
            UNION ALL
            SELECT x.attempt_id,x.node_id,x.channel_binding_id,p.provider,
              x.accounting_period,x.incurred_microusd,x.unresolved_microusd,
              x.recovery_state='reservation'
            FROM lucy.restored_cost_exposures_v1 x
            JOIN lucy.provider_cost_policies_v1 p ON p.id=x.policy_id
              AND p.version=x.policy_version AND p.policy_digest IS NOT NULL
            WHERE x.source_policy_verified
          )
          SELECT
            coalesce(sum(incurred_microusd+unresolved_microusd)
              FILTER (WHERE admission_period=v_period),0),
            coalesce(sum(incurred_microusd+unresolved_microusd)
              FILTER (WHERE admission_period=v_period AND node_id=NEW.node_id),0),
            coalesce(sum(incurred_microusd+unresolved_microusd)
              FILTER (WHERE admission_period=v_period
                AND channel_binding_id=NEW.channel_binding_id),0),
            coalesce(sum(incurred_microusd+unresolved_microusd)
              FILTER (WHERE admission_period=v_period AND provider=NEW.provider),0),
            coalesce(sum(unresolved_microusd),0),
            count(*) FILTER (WHERE possibly_in_flight)
          INTO v_platform,v_node,v_site,v_provider,v_outstanding,v_concurrency
          FROM effective;
          IF v_platform+NEW.maximum_microusd>v_policy.platform_daily_cap_microusd
             OR v_node+NEW.maximum_microusd>v_policy.node_daily_cap_microusd
             OR v_site+NEW.maximum_microusd>v_policy.site_daily_cap_microusd
             OR v_provider+NEW.maximum_microusd>v_policy.provider_daily_cap_microusd
             OR v_outstanding+NEW.maximum_microusd>v_policy.outstanding_cap_microusd
             OR v_concurrency>=v_policy.concurrency_limit
          THEN RAISE EXCEPTION 'provider cost limit exceeded'; END IF;
          RETURN NEW;
        END
        $function$;

        CREATE FUNCTION lucy.finalize_cost_recovery_v1(p_expected jsonb)
        RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_head lucy.restored_recovery_heads_v1%ROWTYPE;
          v_state lucy.restored_cost_admission_v1%ROWTYPE;
          v_review boolean; v_now timestamptz:=clock_timestamp();
        BEGIN
          PERFORM pg_advisory_xact_lock(hashtextextended('lucy-cost-global',0));
          IF NOT EXISTS(SELECT 1 FROM lucy.runtime_admission
              WHERE singleton AND state='quarantined')
             OR EXISTS(SELECT 1 FROM lucy.conversation_capture_states
              WHERE capture_enabled)
             OR EXISTS(SELECT 1 FROM lucy.scoped_capture_states_v1
              WHERE capture_enabled)
          THEN RAISE EXCEPTION 'cost recovery requires quarantined capture-off storage';
          END IF;
          SELECT * INTO v_head FROM lucy.restored_recovery_heads_v1
            WHERE stream_kind='cost' FOR UPDATE;
          SELECT * INTO v_state FROM lucy.restored_cost_admission_v1 FOR UPDATE;
          IF NOT FOUND OR v_head.stream_id<>v_state.stream_id
             OR jsonb_typeof(p_expected)<>'object'
             OR (SELECT count(*) FROM jsonb_object_keys(p_expected))<>8
             OR p_expected->>'contract_version'<>'1'
             OR p_expected->>'stream_kind'<>'cost'
             OR (v_head.stream_id,v_head.authority_epoch,v_head.independent_store_id,
                 v_head.binding_manifest_digest,v_head.sequence,v_head.event_digest)
                IS DISTINCT FROM
                ((p_expected->>'stream_id')::uuid,
                 (p_expected->>'authority_epoch')::bigint,
                 p_expected->>'independent_store_id',
                 p_expected->>'binding_manifest_digest',
                 (p_expected->>'sequence')::bigint,p_expected->>'event_digest')
          THEN RAISE EXCEPTION 'cost recovery finalization head differs'; END IF;
          IF v_state.state='finalized' THEN
            RETURN jsonb_build_object(
              'state',v_state.state,
              'operator_review_required',v_state.operator_review_required,
              'paid_admission_not_before',v_state.paid_admission_not_before
            );
          END IF;

          v_review:=v_state.operator_review_required
            OR EXISTS(SELECT 1 FROM lucy.provider_attempts_v1 a
              WHERE a.state NOT IN ('SETTLED','OVER_CAP')
                AND NOT EXISTS(SELECT 1 FROM lucy.restored_cost_exposures_v1 x
                  WHERE x.attempt_id=a.id))
            OR EXISTS(SELECT 1 FROM lucy.provider_attempts_v1 a
              JOIN lucy.restored_cost_exposures_v1 x ON x.attempt_id=a.id
              WHERE x.recovery_state='reservation'
                AND a.state IN ('SETTLEMENT_PENDING','OVER_CAP_PENDING','SETTLED','OVER_CAP'));

          UPDATE lucy.exposure_reservations_v1 r SET
            incurred_microusd=CASE WHEN x.recovery_state='reservation'
              THEN 0 ELSE x.incurred_microusd END,
            unresolved_microusd=CASE WHEN x.recovery_state='reservation'
              THEN x.maximum_microusd ELSE 0 END,
            settled_at=CASE WHEN x.recovery_state='reservation'
              THEN NULL ELSE x.latest_occurred_at END
          FROM lucy.restored_cost_exposures_v1 x WHERE r.attempt_id=x.attempt_id;
          UPDATE lucy.provider_attempts_v1 a SET
            state=CASE x.recovery_state WHEN 'reservation' THEN 'UNKNOWN'
              WHEN 'settlement' THEN 'SETTLED' ELSE 'OVER_CAP' END,
            provider_reference_commitment=x.provider_reference_commitment,
            completed_at=CASE WHEN x.recovery_state='reservation'
              THEN NULL ELSE x.latest_occurred_at END
          FROM lucy.restored_cost_exposures_v1 x WHERE a.id=x.attempt_id
            AND NOT (x.recovery_state='reservation' AND
              a.state IN ('SETTLEMENT_PENDING','OVER_CAP_PENDING','SETTLED','OVER_CAP'));
          UPDATE lucy.provider_attempts_v1 a SET state='UNKNOWN'
            WHERE a.state IN ('PERSISTENCE_PENDING','ADMITTED','SUBMITTED')
              AND NOT EXISTS(SELECT 1 FROM lucy.restored_cost_exposures_v1 x
                WHERE x.attempt_id=a.id);

          UPDATE lucy.restored_cost_admission_v1 SET
            state=CASE WHEN v_review THEN 'replay_in_progress' ELSE 'finalized' END,
            operator_review_required=v_review,
            paid_admission_not_before=CASE WHEN v_review THEN NULL
              ELSE v_now+interval '90 seconds' END,
            updated_at=v_now WHERE stream_id=v_head.stream_id RETURNING * INTO v_state;
          RETURN jsonb_build_object(
            'state',v_state.state,
            'operator_review_required',v_state.operator_review_required,
            'paid_admission_not_before',v_state.paid_admission_not_before
          );
        END
        $function$;
        ALTER FUNCTION lucy.finalize_cost_recovery_v1(jsonb)
          OWNER TO lucy_cost_function_owner;
        REVOKE ALL ON FUNCTION lucy.finalize_cost_recovery_v1(jsonb)
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_authority_transition,
            lucy_authority_recovery_writer,lucy_cost_admission,
            lucy_cost_recovery_writer;
        GRANT EXECUTE ON FUNCTION lucy.finalize_cost_recovery_v1(jsonb)
          TO lucy_cost_recovery_writer;
        """
    )


def downgrade() -> None:
    raise RuntimeError("R1 cost recovery finalization requires a reviewed forward migration")
