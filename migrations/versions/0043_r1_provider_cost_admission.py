"""Add fail-closed public provider-cost admission and exposure accounting."""

from collections.abc import Sequence

from alembic import op

revision: str = "0043_r1_provider_cost_admission"
down_revision: str | None = "0042_r1_permit_authority"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE TABLE lucy.provider_cost_policies_v1 (
          id uuid PRIMARY KEY,
          version bigint NOT NULL CHECK (version > 0),
          node_id uuid NOT NULL REFERENCES lucy.nodes(id),
          channel_binding_id uuid NOT NULL REFERENCES lucy.channel_bindings(id),
          provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 80),
          model text NOT NULL CHECK (length(model) BETWEEN 1 AND 200),
          rate_version text NOT NULL CHECK (length(rate_version) BETWEEN 1 AND 80),
          effective_at timestamptz NOT NULL,
          kill_state text NOT NULL CHECK (kill_state IN ('enabled','disabled')),
          platform_daily_cap_microusd bigint NOT NULL CHECK (platform_daily_cap_microusd >= 0),
          node_daily_cap_microusd bigint NOT NULL CHECK (node_daily_cap_microusd >= 0),
          site_daily_cap_microusd bigint NOT NULL CHECK (site_daily_cap_microusd >= 0),
          provider_daily_cap_microusd bigint NOT NULL CHECK (provider_daily_cap_microusd >= 0),
          outstanding_cap_microusd bigint NOT NULL CHECK (outstanding_cap_microusd >= 0),
          concurrency_limit integer NOT NULL CHECK (concurrency_limit > 0),
          requests_per_minute integer NOT NULL CHECK (requests_per_minute > 0),
          session_requests_per_minute integer NOT NULL CHECK (session_requests_per_minute > 0),
          ip_requests_per_minute integer NOT NULL CHECK (ip_requests_per_minute > 0),
          per_request_cap_microusd bigint NOT NULL CHECK (per_request_cap_microusd >= 0),
          max_input_tokens integer NOT NULL CHECK (max_input_tokens > 0),
          max_output_tokens integer NOT NULL CHECK (max_output_tokens > 0),
          max_request_bytes integer NOT NULL CHECK (max_request_bytes > 0),
          timeout_seconds integer NOT NULL CHECK (timeout_seconds > 0),
          policy_digest text NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
          created_at timestamptz NOT NULL,
          UNIQUE(channel_binding_id, provider, model, version),
          CHECK (per_request_cap_microusd <= platform_daily_cap_microusd),
          CHECK (per_request_cap_microusd <= node_daily_cap_microusd),
          CHECK (per_request_cap_microusd <= site_daily_cap_microusd),
          CHECK (per_request_cap_microusd <= provider_daily_cap_microusd),
          CHECK (per_request_cap_microusd <= outstanding_cap_microusd)
        );

        CREATE TABLE lucy.provider_attempts_v1 (
          id uuid PRIMARY KEY,
          idempotency_key text NOT NULL UNIQUE CHECK (length(idempotency_key) BETWEEN 1 AND 300),
          policy_id uuid NOT NULL REFERENCES lucy.provider_cost_policies_v1(id),
          policy_version bigint NOT NULL,
          node_id uuid NOT NULL REFERENCES lucy.nodes(id),
          channel_binding_id uuid NOT NULL REFERENCES lucy.channel_bindings(id),
          provider text NOT NULL,
          model text NOT NULL,
          rate_version text NOT NULL,
          request_commitment text NOT NULL CHECK (request_commitment ~ '^[0-9a-f]{64}$'),
          session_commitment text NOT NULL CHECK (session_commitment ~ '^[0-9a-f]{64}$'),
          ip_commitment text NOT NULL CHECK (ip_commitment ~ '^[0-9a-f]{64}$'),
          maximum_microusd bigint NOT NULL CHECK (maximum_microusd >= 0),
          input_tokens integer NOT NULL CHECK (input_tokens >= 0),
          output_tokens integer NOT NULL CHECK (output_tokens >= 0),
          request_bytes integer NOT NULL CHECK (request_bytes >= 0),
          timeout_seconds integer NOT NULL CHECK (timeout_seconds > 0),
          admission_period timestamptz NOT NULL,
          state text NOT NULL CHECK (state IN (
            'PERSISTENCE_PENDING','ADMITTED','SUBMITTED','UNKNOWN','SETTLED','OVER_CAP'
          )),
          reservation_event_id uuid NOT NULL UNIQUE,
          requested_at timestamptz NOT NULL,
          admitted_at timestamptz,
          submitted_at timestamptz,
          completed_at timestamptz,
          provider_reference_commitment text CHECK (
            provider_reference_commitment IS NULL OR
            provider_reference_commitment ~ '^[0-9a-f]{64}$'
          )
        );

        CREATE TABLE lucy.exposure_reservations_v1 (
          attempt_id uuid PRIMARY KEY REFERENCES lucy.provider_attempts_v1(id),
          reserved_microusd bigint NOT NULL CHECK (reserved_microusd >= 0),
          incurred_microusd bigint NOT NULL DEFAULT 0 CHECK (incurred_microusd >= 0),
          unresolved_microusd bigint NOT NULL CHECK (unresolved_microusd >= 0),
          created_at timestamptz NOT NULL,
          settled_at timestamptz
        );

        CREATE TABLE lucy.cost_events_v1 (
          id uuid PRIMARY KEY,
          attempt_id uuid NOT NULL REFERENCES lucy.provider_attempts_v1(id),
          event_type text NOT NULL CHECK (event_type IN (
            'reservation_pending','reservation_acknowledged','submission_claimed',
            'outcome_unknown','settled','over_cap'
          )),
          event_digest text NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
          occurred_at timestamptz NOT NULL,
          UNIQUE(attempt_id, event_type)
        );

        CREATE TABLE lucy.cost_recovery_outbox_v1 (
          attempt_id uuid PRIMARY KEY REFERENCES lucy.provider_attempts_v1(id),
          reservation_event_id uuid NOT NULL UNIQUE REFERENCES lucy.cost_events_v1(id),
          acknowledged_head_digest text CHECK (
            acknowledged_head_digest IS NULL OR
            acknowledged_head_digest ~ '^[0-9a-f]{64}$'
          ),
          acknowledged_at timestamptz
        );

        CREATE INDEX ix_provider_attempts_period_scope_v1
          ON lucy.provider_attempts_v1(admission_period,node_id,channel_binding_id,provider);
        CREATE INDEX ix_provider_attempts_rate_v1
          ON lucy.provider_attempts_v1(channel_binding_id,requested_at);

        CREATE TRIGGER provider_cost_policies_immutable_v1
          BEFORE UPDATE OR DELETE ON lucy.provider_cost_policies_v1
          FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation();
        CREATE TRIGGER cost_events_immutable_v1
          BEFORE UPDATE OR DELETE ON lucy.cost_events_v1
          FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation();

        REVOKE ALL ON lucy.provider_cost_policies_v1, lucy.provider_attempts_v1,
          lucy.exposure_reservations_v1, lucy.cost_events_v1,
          lucy.cost_recovery_outbox_v1 FROM PUBLIC, lucy_app, lucy_public_runtime;
        GRANT SELECT ON lucy.channel_bindings TO lucy_cost_function_owner;
        GRANT SELECT ON lucy.provider_cost_policies_v1, lucy.provider_attempts_v1,
          lucy.exposure_reservations_v1, lucy.cost_events_v1,
          lucy.cost_recovery_outbox_v1 TO lucy_cost_function_owner;
        GRANT INSERT ON lucy.provider_attempts_v1, lucy.exposure_reservations_v1,
          lucy.cost_events_v1, lucy.cost_recovery_outbox_v1 TO lucy_cost_function_owner;
        GRANT UPDATE ON lucy.provider_attempts_v1, lucy.exposure_reservations_v1,
          lucy.cost_recovery_outbox_v1 TO lucy_cost_function_owner;

        CREATE FUNCTION lucy.provider_attempt_result_v1(p_attempt_id uuid, p_replayed boolean)
        RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
          SELECT jsonb_build_object(
            'attempt_id',a.id,'policy_id',a.policy_id,'policy_version',a.policy_version,
            'state',a.state,'reserved_microusd',r.reserved_microusd,
            'unresolved_microusd',r.unresolved_microusd,
            'event_id',a.reservation_event_id,'replayed',p_replayed
          )
          FROM lucy.provider_attempts_v1 a
          JOIN lucy.exposure_reservations_v1 r ON r.attempt_id=a.id
          WHERE a.id=p_attempt_id
        $function$;

        CREATE FUNCTION lucy.reserve_provider_attempt_v1(
          p_attempt_id uuid, p_idempotency_key text, p_node_id uuid,
          p_channel_binding_id uuid, p_provider text, p_model text, p_rate_version text,
          p_request_commitment text, p_session_commitment text, p_ip_commitment text,
          p_maximum_microusd bigint, p_input_tokens integer, p_output_tokens integer,
          p_request_bytes integer, p_timeout_seconds integer, p_requested_at timestamptz
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE
          v_existing lucy.provider_attempts_v1%ROWTYPE;
          v_policy lucy.provider_cost_policies_v1%ROWTYPE;
          v_now timestamptz := clock_timestamp();
          v_period timestamptz;
          v_event_id uuid := gen_random_uuid();
          v_platform bigint; v_node bigint; v_site bigint; v_provider bigint;
          v_outstanding bigint; v_concurrency bigint;
          v_site_rate bigint; v_session_rate bigint; v_ip_rate bigint;
        BEGIN
          IF p_idempotency_key IS NULL OR length(p_idempotency_key) NOT BETWEEN 1 AND 300
             OR p_request_commitment !~ '^[0-9a-f]{64}$'
             OR p_session_commitment !~ '^[0-9a-f]{64}$'
             OR p_ip_commitment !~ '^[0-9a-f]{64}$'
             OR p_maximum_microusd < 0 OR p_input_tokens < 0 OR p_output_tokens < 0
             OR p_request_bytes < 0 OR p_timeout_seconds < 1
             OR abs(extract(epoch FROM (v_now-p_requested_at))) > 30
          THEN RAISE EXCEPTION 'provider cost admission unavailable'; END IF;

          PERFORM pg_advisory_xact_lock(hashtextextended(p_idempotency_key,0));
          SELECT * INTO v_existing FROM lucy.provider_attempts_v1
            WHERE idempotency_key=p_idempotency_key;
          IF FOUND THEN
            IF v_existing.id<>p_attempt_id OR v_existing.node_id<>p_node_id
               OR v_existing.channel_binding_id<>p_channel_binding_id
               OR v_existing.provider<>p_provider OR v_existing.model<>p_model
               OR v_existing.rate_version<>p_rate_version
               OR v_existing.request_commitment<>p_request_commitment
               OR v_existing.session_commitment<>p_session_commitment
               OR v_existing.ip_commitment<>p_ip_commitment
               OR v_existing.maximum_microusd<>p_maximum_microusd
               OR v_existing.input_tokens<>p_input_tokens
               OR v_existing.output_tokens<>p_output_tokens
               OR v_existing.request_bytes<>p_request_bytes
               OR v_existing.timeout_seconds<>p_timeout_seconds
               OR v_existing.requested_at<>p_requested_at
            THEN RAISE EXCEPTION 'provider attempt idempotency conflict'; END IF;
            RETURN lucy.provider_attempt_result_v1(v_existing.id,true);
          END IF;

          PERFORM pg_advisory_xact_lock(hashtextextended('lucy-cost-global',0));
          SELECT p.* INTO v_policy FROM lucy.provider_cost_policies_v1 p
          JOIN lucy.channel_bindings c ON c.id=p.channel_binding_id
          WHERE p.node_id=p_node_id AND p.channel_binding_id=p_channel_binding_id
            AND p.provider=p_provider AND p.model=p_model AND p.rate_version=p_rate_version
            AND p.effective_at<=v_now AND c.node_id=p_node_id AND c.active
            AND c.channel_kind='website_public'
          ORDER BY p.version DESC LIMIT 1;
          IF NOT FOUND OR v_policy.kill_state<>'enabled'
             OR EXISTS(SELECT 1 FROM lucy.provider_attempts_v1
               WHERE state='OVER_CAP' AND completed_at>=v_policy.effective_at)
             OR p_maximum_microusd>v_policy.per_request_cap_microusd
             OR p_input_tokens>v_policy.max_input_tokens
             OR p_output_tokens>v_policy.max_output_tokens
             OR p_request_bytes>v_policy.max_request_bytes
             OR p_timeout_seconds>v_policy.timeout_seconds
          THEN RAISE EXCEPTION 'provider cost admission unavailable'; END IF;

          v_period := date_trunc('day',v_now AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
          SELECT
            coalesce(sum(r.incurred_microusd+r.unresolved_microusd),0),
            coalesce(sum(r.incurred_microusd+r.unresolved_microusd)
              FILTER (WHERE a.node_id=p_node_id),0),
            coalesce(sum(r.incurred_microusd+r.unresolved_microusd)
              FILTER (WHERE a.channel_binding_id=p_channel_binding_id),0),
            coalesce(sum(r.incurred_microusd+r.unresolved_microusd)
              FILTER (WHERE a.provider=p_provider),0)
          INTO v_platform,v_node,v_site,v_provider
          FROM lucy.provider_attempts_v1 a JOIN lucy.exposure_reservations_v1 r
            ON r.attempt_id=a.id WHERE a.admission_period=v_period;
          SELECT coalesce(sum(unresolved_microusd),0) INTO v_outstanding
            FROM lucy.exposure_reservations_v1;
          SELECT count(*) INTO v_concurrency FROM lucy.exposure_reservations_v1
            WHERE unresolved_microusd>0;
          SELECT count(*),count(*) FILTER (WHERE session_commitment=p_session_commitment),
            count(*) FILTER (WHERE ip_commitment=p_ip_commitment)
          INTO v_site_rate,v_session_rate,v_ip_rate FROM lucy.provider_attempts_v1
          WHERE channel_binding_id=p_channel_binding_id
            AND requested_at>=v_now-interval '1 minute';
          IF v_platform+p_maximum_microusd>v_policy.platform_daily_cap_microusd
             OR v_node+p_maximum_microusd>v_policy.node_daily_cap_microusd
             OR v_site+p_maximum_microusd>v_policy.site_daily_cap_microusd
             OR v_provider+p_maximum_microusd>v_policy.provider_daily_cap_microusd
             OR v_outstanding+p_maximum_microusd>v_policy.outstanding_cap_microusd
             OR v_concurrency>=v_policy.concurrency_limit
             OR v_site_rate>=v_policy.requests_per_minute
             OR v_session_rate>=v_policy.session_requests_per_minute
             OR v_ip_rate>=v_policy.ip_requests_per_minute
          THEN RAISE EXCEPTION 'provider cost limit exceeded'; END IF;

          INSERT INTO lucy.provider_attempts_v1(
            id,idempotency_key,policy_id,policy_version,node_id,channel_binding_id,
            provider,model,rate_version,request_commitment,session_commitment,ip_commitment,
            maximum_microusd,input_tokens,output_tokens,request_bytes,timeout_seconds,
            admission_period,state,reservation_event_id,requested_at
          ) VALUES (
            p_attempt_id,p_idempotency_key,v_policy.id,v_policy.version,p_node_id,
            p_channel_binding_id,p_provider,p_model,p_rate_version,p_request_commitment,
            p_session_commitment,p_ip_commitment,p_maximum_microusd,p_input_tokens,
            p_output_tokens,p_request_bytes,p_timeout_seconds,v_period,
            'PERSISTENCE_PENDING',v_event_id,p_requested_at
          );
          INSERT INTO lucy.exposure_reservations_v1(
            attempt_id,reserved_microusd,incurred_microusd,unresolved_microusd,created_at
          ) VALUES (p_attempt_id,p_maximum_microusd,0,p_maximum_microusd,v_now);
          INSERT INTO lucy.cost_events_v1(id,attempt_id,event_type,event_digest,occurred_at)
          VALUES (v_event_id,p_attempt_id,'reservation_pending',encode(public.digest(
            'reservation_pending:'||p_attempt_id::text||':'||p_maximum_microusd::text,
            'sha256'),'hex'),v_now);
          INSERT INTO lucy.cost_recovery_outbox_v1(attempt_id,reservation_event_id)
          VALUES (p_attempt_id,v_event_id);
          RETURN lucy.provider_attempt_result_v1(p_attempt_id,false);
        END
        $function$;

        CREATE FUNCTION lucy.acknowledge_provider_reservation_v1(
          p_attempt_id uuid,p_event_id uuid,p_head_digest text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_state text; v_event uuid; v_now timestamptz := clock_timestamp();
        BEGIN
          IF p_head_digest !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'cost journal acknowledgement unavailable'; END IF;
          SELECT state,reservation_event_id INTO v_state,v_event
          FROM lucy.provider_attempts_v1 WHERE id=p_attempt_id FOR UPDATE;
          IF NOT FOUND OR v_event<>p_event_id THEN
            RAISE EXCEPTION 'cost journal acknowledgement unavailable'; END IF;
          IF v_state<>'PERSISTENCE_PENDING' THEN
            RETURN lucy.provider_attempt_result_v1(p_attempt_id,true); END IF;
          UPDATE lucy.cost_recovery_outbox_v1 SET acknowledged_head_digest=p_head_digest,
            acknowledged_at=v_now WHERE attempt_id=p_attempt_id
            AND reservation_event_id=p_event_id AND acknowledged_at IS NULL;
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

        CREATE FUNCTION lucy.claim_provider_submission_v1(p_attempt_id uuid)
        RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_state text; v_now timestamptz := clock_timestamp();
        BEGIN
          SELECT state INTO v_state FROM lucy.provider_attempts_v1
            WHERE id=p_attempt_id FOR UPDATE;
          IF NOT FOUND OR v_state='PERSISTENCE_PENDING' THEN
            RAISE EXCEPTION 'provider submission is not admitted'; END IF;
          IF v_state<>'ADMITTED' THEN
            RETURN lucy.provider_attempt_result_v1(p_attempt_id,true); END IF;
          UPDATE lucy.provider_attempts_v1 SET state='SUBMITTED',submitted_at=v_now
            WHERE id=p_attempt_id;
          INSERT INTO lucy.cost_events_v1 VALUES(gen_random_uuid(),p_attempt_id,
            'submission_claimed',encode(public.digest('submission_claimed:'||p_attempt_id::text,
              'sha256'),'hex'),v_now);
          RETURN lucy.provider_attempt_result_v1(p_attempt_id,false);
        END
        $function$;

        CREATE FUNCTION lucy.mark_provider_attempt_unknown_v1(p_attempt_id uuid)
        RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_state text; v_now timestamptz := clock_timestamp();
        BEGIN
          SELECT state INTO v_state FROM lucy.provider_attempts_v1
            WHERE id=p_attempt_id FOR UPDATE;
          IF NOT FOUND OR v_state IN ('PERSISTENCE_PENDING','ADMITTED') THEN
            RAISE EXCEPTION 'provider attempt cannot become unknown'; END IF;
          IF v_state<>'SUBMITTED' THEN
            RETURN lucy.provider_attempt_result_v1(p_attempt_id,true); END IF;
          UPDATE lucy.provider_attempts_v1 SET state='UNKNOWN' WHERE id=p_attempt_id;
          INSERT INTO lucy.cost_events_v1 VALUES(gen_random_uuid(),p_attempt_id,
            'outcome_unknown',encode(public.digest('outcome_unknown:'||p_attempt_id::text,
              'sha256'),'hex'),v_now);
          RETURN lucy.provider_attempt_result_v1(p_attempt_id,false);
        END
        $function$;

        CREATE FUNCTION lucy.settle_provider_attempt_v1(
          p_attempt_id uuid,p_incurred_microusd bigint,p_provider_reference_commitment text
        ) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_state text; v_max bigint; v_now timestamptz := clock_timestamp();
          v_final text;
        BEGIN
          IF p_incurred_microusd<0 OR p_provider_reference_commitment !~ '^[0-9a-f]{64}$'
          THEN RAISE EXCEPTION 'provider settlement unavailable'; END IF;
          SELECT state,maximum_microusd INTO v_state,v_max FROM lucy.provider_attempts_v1
            WHERE id=p_attempt_id FOR UPDATE;
          IF NOT FOUND OR v_state IN ('PERSISTENCE_PENDING','ADMITTED') THEN
            RAISE EXCEPTION 'provider attempt is not submitted'; END IF;
          IF v_state IN ('SETTLED','OVER_CAP') THEN
            RETURN lucy.provider_attempt_result_v1(p_attempt_id,true); END IF;
          v_final := CASE WHEN p_incurred_microusd>v_max THEN 'OVER_CAP' ELSE 'SETTLED' END;
          UPDATE lucy.exposure_reservations_v1 SET incurred_microusd=p_incurred_microusd,
            unresolved_microusd=0,settled_at=v_now WHERE attempt_id=p_attempt_id;
          UPDATE lucy.provider_attempts_v1 SET state=v_final,completed_at=v_now,
            provider_reference_commitment=p_provider_reference_commitment
            WHERE id=p_attempt_id;
          INSERT INTO lucy.cost_events_v1 VALUES(gen_random_uuid(),p_attempt_id,
            CASE WHEN v_final='OVER_CAP' THEN 'over_cap' ELSE 'settled' END,
            encode(public.digest(lower(v_final)||':'||p_attempt_id::text||':'||
              p_incurred_microusd::text||':'||p_provider_reference_commitment,
              'sha256'),'hex'),v_now);
          RETURN lucy.provider_attempt_result_v1(p_attempt_id,false);
        END
        $function$;
        """
    )
    signatures = {
        "lucy.provider_attempt_result_v1(uuid,boolean)": (),
        (
            "lucy.reserve_provider_attempt_v1(uuid,text,uuid,uuid,text,text,text,text,"
            "text,text,bigint,integer,integer,integer,integer,timestamptz)"
        ): ("lucy_cost_admission",),
        "lucy.acknowledge_provider_reservation_v1(uuid,uuid,text)": ("lucy_cost_recovery_writer",),
        "lucy.claim_provider_submission_v1(uuid)": ("lucy_cost_admission",),
        "lucy.mark_provider_attempt_unknown_v1(uuid)": ("lucy_cost_admission",),
        "lucy.settle_provider_attempt_v1(uuid,bigint,text)": ("lucy_cost_admission",),
    }
    for signature, grantees in signatures.items():
        op.execute(
            f"ALTER FUNCTION {signature} OWNER TO lucy_cost_function_owner; "
            f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC, lucy_app, lucy_public_runtime"
        )
        for grantee in grantees:
            op.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO {grantee}")


def downgrade() -> None:
    raise RuntimeError("R1 provider cost history requires a reviewed forward migration")
