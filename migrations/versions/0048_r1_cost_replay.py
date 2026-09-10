"""Project exact cost events into a quarantined restore."""

from collections.abc import Sequence

from alembic import op

revision: str = "0048_r1_cost_replay"
down_revision: str | None = "0047_r1_authority_replay"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE TABLE lucy.restored_cost_exposures_v1 (
          attempt_id uuid PRIMARY KEY,
          node_id uuid NOT NULL,
          channel_binding_id uuid NOT NULL,
          policy_id uuid NOT NULL,
          policy_version bigint NOT NULL CHECK (policy_version>0),
          rate_version text NOT NULL CHECK (
            length(rate_version) BETWEEN 1 AND 512 AND
            rate_version ~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
          ),
          accounting_period timestamptz NOT NULL,
          maximum_microusd bigint NOT NULL CHECK (maximum_microusd>=0),
          incurred_microusd bigint NOT NULL CHECK (incurred_microusd>=0),
          unresolved_microusd bigint NOT NULL CHECK (unresolved_microusd>=0),
          request_commitment text NOT NULL CHECK (request_commitment ~ '^[0-9a-f]{64}$'),
          provider_reference_commitment text CHECK (
            provider_reference_commitment IS NULL OR
            provider_reference_commitment ~ '^[0-9a-f]{64}$'
          ),
          recovery_state text NOT NULL CHECK (
            recovery_state IN ('reservation','settlement','over_cap')
          ),
          base_attempt_present boolean NOT NULL,
          source_policy_verified boolean NOT NULL,
          latest_event_id uuid NOT NULL UNIQUE,
          latest_sequence bigint NOT NULL CHECK (latest_sequence>0),
          latest_event_digest text NOT NULL CHECK (latest_event_digest ~ '^[0-9a-f]{64}$'),
          latest_occurred_at timestamptz NOT NULL,
          updated_at timestamptz NOT NULL,
          CHECK ((recovery_state='reservation' AND incurred_microusd=0
                   AND unresolved_microusd=maximum_microusd
                   AND provider_reference_commitment IS NULL)
            OR (recovery_state='settlement' AND incurred_microusd<=maximum_microusd
                   AND unresolved_microusd=0
                   AND provider_reference_commitment IS NOT NULL)
            OR (recovery_state='over_cap' AND incurred_microusd>maximum_microusd
                   AND unresolved_microusd=0
                   AND provider_reference_commitment IS NOT NULL))
        );
        CREATE TABLE lucy.restored_cost_admission_v1 (
          stream_id uuid PRIMARY KEY,
          state text NOT NULL CHECK (state IN ('replay_in_progress','finalized')),
          operator_review_required boolean NOT NULL,
          updated_at timestamptz NOT NULL
        );
        CREATE TRIGGER restored_cost_exposure_no_delete_v1
          BEFORE DELETE ON lucy.restored_cost_exposures_v1
          FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation();

        REVOKE ALL ON lucy.restored_cost_exposures_v1,
          lucy.restored_cost_admission_v1
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_authority_transition,
            lucy_authority_recovery_writer,lucy_cost_admission,lucy_cost_recovery_writer;
        GRANT SELECT,INSERT,UPDATE ON lucy.restored_cost_exposures_v1,
          lucy.restored_cost_admission_v1 TO lucy_cost_function_owner;
        GRANT SELECT,INSERT,UPDATE ON lucy.restored_recovery_heads_v1
          TO lucy_cost_function_owner;
        GRANT SELECT,INSERT ON lucy.restored_recovery_events_v1
          TO lucy_cost_function_owner;
        GRANT SELECT ON lucy.runtime_admission,lucy.conversation_capture_states,
          lucy.scoped_capture_states_v1 TO lucy_cost_function_owner;

        CREATE FUNCTION lucy.block_provider_attempt_during_cost_recovery_v1()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
          IF EXISTS(SELECT 1 FROM lucy.restored_cost_admission_v1
            WHERE state<>'finalized' OR operator_review_required)
          THEN RAISE EXCEPTION 'provider cost recovery is not finalized'; END IF;
          RETURN NEW;
        END
        $function$;
        ALTER FUNCTION lucy.block_provider_attempt_during_cost_recovery_v1()
          OWNER TO lucy_cost_function_owner;
        REVOKE ALL ON FUNCTION lucy.block_provider_attempt_during_cost_recovery_v1()
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_cost_admission,
            lucy_cost_recovery_writer;
        CREATE TRIGGER provider_attempt_cost_recovery_guard_v1
          BEFORE INSERT ON lucy.provider_attempts_v1 FOR EACH ROW
          EXECUTE FUNCTION lucy.block_provider_attempt_during_cost_recovery_v1();

        CREATE FUNCTION lucy.restored_cost_recovery_head_v1()
        RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
          SELECT jsonb_build_object(
            'contract_version','1','stream_kind',stream_kind,'stream_id',stream_id,
            'authority_epoch',authority_epoch,
            'independent_store_id',independent_store_id,
            'binding_manifest_digest',binding_manifest_digest,'sequence',sequence,
            'event_digest',event_digest
          ) FROM lucy.restored_recovery_heads_v1 WHERE stream_kind='cost'
        $function$;

        CREATE FUNCTION lucy.apply_cost_recovery_event_v1(
          p_expected jsonb,p_event jsonb
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_head lucy.restored_recovery_heads_v1%ROWTYPE;
          v_existing jsonb; v_effect jsonb; v_event_id uuid; v_stream_id uuid;
          v_epoch bigint; v_store text; v_manifest text; v_sequence bigint;
          v_previous text; v_digest text; v_transition text; v_attempt uuid;
          v_node uuid; v_channel uuid; v_policy uuid; v_policy_version bigint;
          v_rate text; v_period timestamptz; v_maximum bigint; v_incurred bigint;
          v_unresolved bigint; v_request text; v_reference text; v_occurred timestamptz;
          v_projection lucy.restored_cost_exposures_v1%ROWTYPE;
          v_base lucy.provider_attempts_v1%ROWTYPE; v_base_present boolean:=false;
          v_policy_verified boolean:=false; v_now timestamptz:=clock_timestamp();
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
          IF jsonb_typeof(p_expected)<>'object'
             OR (SELECT count(*) FROM jsonb_object_keys(p_expected))<>8
             OR p_expected->>'contract_version'<>'1'
             OR p_expected->>'stream_kind'<>'cost'
             OR jsonb_typeof(p_event)<>'object'
             OR (SELECT count(*) FROM jsonb_object_keys(p_event))<>17
             OR p_event->>'contract_version'<>'1'
             OR p_event->>'stream_kind'<>'cost'
             OR jsonb_typeof(p_event->'effect')<>'object'
             OR (SELECT count(*) FROM jsonb_object_keys(p_event->'effect'))<>14
             OR p_event->'effect'->>'effect_type'<>'cost'
          THEN RAISE EXCEPTION 'cost recovery event is invalid'; END IF;

          v_event_id:=(p_event->>'event_id')::uuid;
          v_stream_id:=(p_event->>'stream_id')::uuid;
          v_epoch:=(p_event->>'authority_epoch')::bigint;
          v_store:=p_event->>'independent_store_id';
          v_manifest:=p_event->>'binding_manifest_digest';
          v_sequence:=(p_event->>'sequence')::bigint;
          v_previous:=p_event->>'previous_digest'; v_digest:=p_event->>'event_digest';
          v_effect:=p_event->'effect'; v_transition:=v_effect->>'transition';
          v_attempt:=(v_effect->>'attempt_id')::uuid;
          v_node:=(v_effect->>'node_id')::uuid;
          v_channel:=(v_effect->>'channel_binding_id')::uuid;
          v_policy:=(v_effect->>'policy_id')::uuid;
          v_policy_version:=(v_effect->>'policy_version')::bigint;
          v_rate:=v_effect->>'rate_version';
          v_period:=(v_effect->>'accounting_period')::timestamptz;
          v_maximum:=(v_effect->>'maximum_microusd')::bigint;
          v_incurred:=(v_effect->>'incurred_microusd')::bigint;
          v_unresolved:=(v_effect->>'unresolved_microusd')::bigint;
          v_request:=v_effect->>'request_commitment';
          v_reference:=v_effect->>'provider_reference_commitment';
          v_occurred:=(p_event->>'occurred_at')::timestamptz;
          IF v_epoch<1 OR v_sequence<1 OR v_policy_version<1
             OR length(v_store) NOT BETWEEN 1 AND 512
             OR v_store !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR v_manifest !~ '^[0-9a-f]{64}$'
             OR v_previous !~ '^[0-9a-f]{64}$' OR v_digest !~ '^[0-9a-f]{64}$'
             OR length(v_rate) NOT BETWEEN 1 AND 512
             OR v_rate !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$'
             OR v_request !~ '^[0-9a-f]{64}$'
             OR p_event->>'operation_id'<>v_attempt::text
             OR p_event->>'idempotency_key'<>'cost:'||v_event_id::text
             OR p_event->>'source_authority_ref'<>
                'cost-policy:'||v_policy::text||':'||v_policy_version::text
             OR p_event->>'source_authority_digest' !~ '^[0-9a-f]{64}$'
             OR (p_event->>'source_generation')::bigint<>v_policy_version
             OR v_transition NOT IN ('reservation','settlement','over_cap')
             OR v_maximum<0 OR v_incurred<0 OR v_unresolved<0
             OR (v_transition='reservation' AND
                (v_incurred<>0 OR v_unresolved<>v_maximum OR v_reference IS NOT NULL))
             OR (v_transition='settlement' AND
                (v_incurred>v_maximum OR v_unresolved<>0 OR
                 v_reference IS NULL OR v_reference !~ '^[0-9a-f]{64}$'))
             OR (v_transition='over_cap' AND
                (v_incurred<=v_maximum OR v_unresolved<>0 OR
                 v_reference IS NULL OR v_reference !~ '^[0-9a-f]{64}$'))
          THEN RAISE EXCEPTION 'cost recovery event is invalid'; END IF;

          SELECT event_body INTO v_existing FROM lucy.restored_recovery_events_v1
            WHERE event_id=v_event_id;
          IF FOUND THEN
            IF v_existing<>p_event THEN RAISE EXCEPTION 'cost recovery event conflicts'; END IF;
            RETURN jsonb_build_object(
              'contract_version','1','stream_kind','cost','stream_id',v_stream_id,
              'authority_epoch',v_epoch,'independent_store_id',v_store,
              'binding_manifest_digest',v_manifest,'sequence',v_sequence,
              'event_digest',v_digest
            );
          END IF;

          SELECT * INTO v_head FROM lucy.restored_recovery_heads_v1
            WHERE stream_kind='cost' FOR UPDATE;
          IF NOT FOUND THEN
            IF (p_expected->>'sequence')::bigint<>0
               OR p_expected->>'event_digest'<>repeat('0',64)
            THEN RAISE EXCEPTION 'cost recovery genesis is invalid'; END IF;
            INSERT INTO lucy.restored_recovery_heads_v1 VALUES(
              'cost',v_stream_id,v_epoch,v_store,v_manifest,0,repeat('0',64),v_now
            ) RETURNING * INTO v_head;
            INSERT INTO lucy.restored_cost_admission_v1 VALUES(
              v_stream_id,'replay_in_progress',false,v_now
            );
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
          THEN RAISE EXCEPTION 'cost recovery chain is not contiguous'; END IF;

          SELECT * INTO v_base FROM lucy.provider_attempts_v1 WHERE id=v_attempt FOR UPDATE;
          v_base_present:=FOUND;
          IF v_base_present AND
             (v_base.node_id,v_base.channel_binding_id,v_base.policy_id,
              v_base.policy_version,v_base.rate_version,v_base.admission_period,
              v_base.maximum_microusd,v_base.request_commitment) IS DISTINCT FROM
             (v_node,v_channel,v_policy,v_policy_version,v_rate,v_period,
              v_maximum,v_request)
          THEN RAISE EXCEPTION 'cost recovery base attempt differs'; END IF;
          SELECT EXISTS(SELECT 1 FROM lucy.provider_cost_policies_v1 p
            WHERE p.id=v_policy AND p.version=v_policy_version AND p.node_id=v_node
              AND p.channel_binding_id=v_channel AND p.rate_version=v_rate
              AND p.policy_digest=p_event->>'source_authority_digest')
            INTO v_policy_verified;

          SELECT * INTO v_projection FROM lucy.restored_cost_exposures_v1
            WHERE attempt_id=v_attempt FOR UPDATE;
          IF v_transition='reservation' THEN
            IF FOUND THEN RAISE EXCEPTION 'cost recovery reservation conflicts'; END IF;
            INSERT INTO lucy.restored_cost_exposures_v1 VALUES(
              v_attempt,v_node,v_channel,v_policy,v_policy_version,v_rate,v_period,
              v_maximum,v_incurred,v_unresolved,v_request,v_reference,v_transition,
              v_base_present,v_policy_verified,v_event_id,v_sequence,v_digest,
              v_occurred,v_now
            );
          ELSE
            IF NOT FOUND OR
               (v_projection.node_id,v_projection.channel_binding_id,
                v_projection.policy_id,v_projection.policy_version,
                v_projection.rate_version,v_projection.accounting_period,
                v_projection.maximum_microusd,v_projection.request_commitment) IS DISTINCT FROM
               (v_node,v_channel,v_policy,v_policy_version,v_rate,v_period,
                v_maximum,v_request)
            THEN RAISE EXCEPTION 'cost recovery outcome lacks reservation'; END IF;
            UPDATE lucy.restored_cost_exposures_v1 SET
              incurred_microusd=v_incurred,unresolved_microusd=v_unresolved,
              provider_reference_commitment=v_reference,recovery_state=v_transition,
              base_attempt_present=base_attempt_present OR v_base_present,
              source_policy_verified=source_policy_verified OR v_policy_verified,
              latest_event_id=v_event_id,latest_sequence=v_sequence,
              latest_event_digest=v_digest,latest_occurred_at=v_occurred,updated_at=v_now
              WHERE attempt_id=v_attempt;
          END IF;
          UPDATE lucy.restored_cost_admission_v1 SET
            operator_review_required=operator_review_required OR NOT v_policy_verified,
            updated_at=v_now WHERE stream_id=v_stream_id;
          INSERT INTO lucy.restored_recovery_events_v1 VALUES(
            v_event_id,'cost',v_stream_id,v_sequence,v_previous,v_digest,p_event,v_now
          );
          UPDATE lucy.restored_recovery_heads_v1 SET sequence=v_sequence,
            event_digest=v_digest,updated_at=v_now WHERE stream_kind='cost';
          RETURN lucy.restored_cost_recovery_head_v1();
        END
        $function$;

        REVOKE ALL ON FUNCTION lucy.restored_cost_recovery_head_v1(),
          lucy.apply_cost_recovery_event_v1(jsonb,jsonb)
          FROM PUBLIC,lucy_app,lucy_public_runtime,lucy_authority_transition,
            lucy_authority_recovery_writer,lucy_cost_admission,
            lucy_cost_recovery_writer;
        ALTER FUNCTION lucy.restored_cost_recovery_head_v1()
          OWNER TO lucy_cost_function_owner;
        ALTER FUNCTION lucy.apply_cost_recovery_event_v1(jsonb,jsonb)
          OWNER TO lucy_cost_function_owner;
        GRANT EXECUTE ON FUNCTION lucy.restored_cost_recovery_head_v1(),
          lucy.apply_cost_recovery_event_v1(jsonb,jsonb)
          TO lucy_cost_recovery_writer;
        """
    )


def downgrade() -> None:
    raise RuntimeError("R1 cost replay history requires a reviewed forward migration")
