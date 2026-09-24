"""Charge Hindsight inference against the realm's existing daily model budget."""

from collections.abc import Sequence

from alembic import op

revision: str = "0074_hindsight_model_budget"
down_revision: str | None = "0073_memory_candidate_correction"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE lucy.hindsight_model_operations_v1 (
          action_id uuid PRIMARY KEY,
          security_realm_id uuid NOT NULL REFERENCES lucy.security_realms(id),
          service_binding_id uuid NOT NULL REFERENCES lucy.realm_service_bindings_v1(id),
          model text NOT NULL CHECK (model='openai/gpt-oss-20b'),
          reserved_microusd bigint NOT NULL CHECK (reserved_microusd=5000),
          actual_microusd bigint CHECK (actual_microusd BETWEEN 0 AND 5000),
          state text NOT NULL CHECK (state IN ('EXECUTING','SUCCEEDED','FAILED')),
          created_at timestamptz NOT NULL,
          updated_at timestamptz NOT NULL,
          CHECK ((state='EXECUTING')=(actual_microusd IS NULL))
        );
        REVOKE ALL ON lucy.hindsight_model_operations_v1
          FROM PUBLIC, lucy_app, lucy_public_runtime;
        GRANT SELECT,INSERT,UPDATE ON lucy.hindsight_model_operations_v1
          TO lucy_security_function_owner;
        GRANT SELECT ON lucy.realm_content_scopes_v1
          TO lucy_security_function_owner;

        CREATE FUNCTION lucy.begin_hindsight_model_operation_v1(p_action_id uuid)
        RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_now timestamptz := clock_timestamp();
          v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_realm_id uuid;
          v_account lucy.telegram_budget_accounts_v1%ROWTYPE;
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
            WHERE session_login=session_user AND active AND service_role='realm_evidence'
              AND allowed_actions @> '["memory.read"]'::jsonb;
          IF NOT FOUND OR p_action_id IS NULL THEN
            RAISE EXCEPTION 'Hindsight model operation unavailable'; END IF;
          SELECT security_realm_id INTO v_realm_id
            FROM lucy.realm_content_scopes_v1 WHERE id=v_binding.content_scope_id;
          IF v_realm_id IS NULL THEN
            RAISE EXCEPTION 'Hindsight model scope unavailable'; END IF;
          IF EXISTS (SELECT 1 FROM lucy.hindsight_model_operations_v1
            WHERE action_id=p_action_id) THEN
            RAISE EXCEPTION 'Hindsight model action already exists'; END IF;
          SELECT * INTO v_account FROM lucy.telegram_budget_accounts_v1
            WHERE security_realm_id=v_realm_id FOR UPDATE;
          IF NOT FOUND THEN RAISE EXCEPTION 'Hindsight model budget unavailable'; END IF;
          IF v_account.period_date<>v_now::date THEN
            IF v_account.reserved_microusd<>0 THEN
              RAISE EXCEPTION 'Hindsight model budget rollover unavailable'; END IF;
            UPDATE lucy.telegram_budget_accounts_v1 SET period_date=v_now::date,
              spent_microusd=0,updated_at=v_now WHERE security_realm_id=v_realm_id;
            v_account.spent_microusd := 0;
          END IF;
          IF v_account.reserved_microusd+v_account.spent_microusd+5000
             >v_account.daily_limit_microusd THEN
            RAISE EXCEPTION 'Hindsight model budget exhausted'; END IF;
          INSERT INTO lucy.hindsight_model_operations_v1 VALUES
            (p_action_id,v_realm_id,v_binding.id,'openai/gpt-oss-20b',
             5000,NULL,'EXECUTING',v_now,v_now);
          UPDATE lucy.telegram_budget_accounts_v1
            SET reserved_microusd=reserved_microusd+5000,updated_at=v_now
            WHERE security_realm_id=v_realm_id;
          RETURN jsonb_build_object('action_id',p_action_id,'execute',true);
        END $function$;

        CREATE FUNCTION lucy.settle_hindsight_model_operation_v1(
          p_action_id uuid,p_actual_microusd bigint,p_succeeded boolean)
        RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_now timestamptz := clock_timestamp();
          v_operation lucy.hindsight_model_operations_v1%ROWTYPE;
          v_charge bigint;
          v_state text;
        BEGIN
          SELECT * INTO v_operation FROM lucy.hindsight_model_operations_v1
            WHERE action_id=p_action_id FOR UPDATE;
          IF NOT FOUND OR NOT EXISTS (
            SELECT 1 FROM lucy.realm_service_bindings_v1 b
            WHERE b.id=v_operation.service_binding_id AND b.session_login=session_user
              AND b.active AND b.service_role='realm_evidence'
          ) OR p_actual_microusd IS NULL OR p_actual_microusd NOT BETWEEN 0 AND 5000
             OR p_succeeded IS NULL THEN
            RAISE EXCEPTION 'Hindsight model settlement unavailable'; END IF;
          IF v_operation.state<>'EXECUTING' THEN
            RETURN jsonb_build_object('action_id',p_action_id,
              'status',lower(v_operation.state),'replayed',true); END IF;
          v_charge := CASE WHEN p_succeeded THEN p_actual_microusd ELSE 5000 END;
          v_state := CASE WHEN p_succeeded THEN 'SUCCEEDED' ELSE 'FAILED' END;
          UPDATE lucy.telegram_budget_accounts_v1
            SET reserved_microusd=reserved_microusd-5000,
              spent_microusd=spent_microusd+v_charge,updated_at=v_now
            WHERE security_realm_id=v_operation.security_realm_id;
          UPDATE lucy.hindsight_model_operations_v1 SET state=v_state,
            actual_microusd=v_charge,updated_at=v_now WHERE action_id=p_action_id;
          RETURN jsonb_build_object('action_id',p_action_id,
            'status',lower(v_state),'replayed',false);
        END $function$;
    """)
    op.execute("""
        DO $grant$ BEGIN
          IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='lucy_raymond_routine') THEN
            GRANT EXECUTE ON FUNCTION lucy.begin_hindsight_model_operation_v1(uuid),
              lucy.settle_hindsight_model_operation_v1(uuid,bigint,boolean)
              TO lucy_raymond_routine;
          END IF;
        END $grant$;
    """)
    for signature in (
        "lucy.begin_hindsight_model_operation_v1(uuid)",
        "lucy.settle_hindsight_model_operation_v1(uuid,bigint,boolean)",
    ):
        op.execute(
            f"ALTER FUNCTION {signature} OWNER TO lucy_security_function_owner; "
            f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC, lucy_app, lucy_public_runtime"
        )


def downgrade() -> None:
    raise RuntimeError("Hindsight spending history requires a reviewed forward migration")
