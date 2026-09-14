"""Add receipt-only realm-scoped operation reconciliation."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0029_r1_receipt_reconcile"
down_revision: str | None = "0028_r1_executor_receipt"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("ck_v2_sensitive_initial_state", "sensitive_operations_v2", schema="lucy")
    op.add_column(
        "sensitive_operations_v2",
        sa.Column("receipt_attestation_id", postgresql.UUID(as_uuid=True), nullable=True),
        schema="lucy",
    )
    op.add_column(
        "sensitive_operations_v2",
        sa.Column("executor_receipt_digest", sa.String(64), nullable=True),
        schema="lucy",
    )
    op.add_column(
        "sensitive_operations_v2",
        sa.Column("executor_result", sa.String(40), nullable=True),
        schema="lucy",
    )
    op.add_column(
        "sensitive_operations_v2",
        sa.Column("reconciled_at", sa.DateTime(timezone=True), nullable=True),
        schema="lucy",
    )
    op.create_foreign_key(
        "fk_v2_operation_receipt_attestation",
        "sensitive_operations_v2",
        "executor_receipt_attestations_v2",
        ["receipt_attestation_id"],
        ["id"],
        source_schema="lucy",
        referent_schema="lucy",
    )
    op.create_check_constraint(
        "ck_v2_sensitive_operation_state",
        "sensitive_operations_v2",
        "(state='CLAIMED' AND receipt_attestation_id IS NULL "
        "AND executor_receipt_digest IS NULL AND executor_result IS NULL "
        "AND reconciled_at IS NULL) OR "
        "(state IN ('RECONCILED','REJECTED') AND receipt_attestation_id IS NOT NULL "
        "AND executor_receipt_digest IS NOT NULL AND executor_result IS NOT NULL "
        "AND reconciled_at IS NOT NULL)",
        schema="lucy",
    )
    op.execute(
        r"""
        DROP TRIGGER sensitive_operations_v2_immutable ON lucy.sensitive_operations_v2;
        CREATE FUNCTION lucy.sensitive_operation_guard_v2() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
        AS $function$
        BEGIN
          IF TG_OP='DELETE' OR NEW.id<>OLD.id OR NEW.permit_id<>OLD.permit_id
             OR NEW.content_scope_id<>OLD.content_scope_id
             OR NEW.workflow_actor_binding_id<>OLD.workflow_actor_binding_id
             OR NEW.target_service_binding_id<>OLD.target_service_binding_id
             OR NEW.action<>OLD.action OR NEW.resource_object_id<>OLD.resource_object_id
             OR NEW.resource_object_version<>OLD.resource_object_version
             OR NEW.claim_idempotency_key<>OLD.claim_idempotency_key
             OR NEW.claimed_at<>OLD.claimed_at OR OLD.state<>'CLAIMED'
             OR NEW.state NOT IN ('RECONCILED','REJECTED')
             OR OLD.receipt_attestation_id IS NOT NULL
             OR NEW.receipt_attestation_id IS NULL
             OR OLD.executor_receipt_digest IS NOT NULL
             OR NEW.executor_receipt_digest IS NULL
             OR OLD.executor_result IS NOT NULL OR NEW.executor_result IS NULL
             OR OLD.reconciled_at IS NOT NULL OR NEW.reconciled_at IS NULL
          THEN RAISE EXCEPTION 'sensitive operation mutation unavailable'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER sensitive_operations_v2_monotonic BEFORE UPDATE OR DELETE
        ON lucy.sensitive_operations_v2 FOR EACH ROW
        EXECUTE FUNCTION lucy.sensitive_operation_guard_v2();
        """
    )
    op.drop_constraint(
        "ck_v2_sensitive_event_type", "sensitive_operation_events_v2", schema="lucy"
    )
    op.create_check_constraint(
        "ck_v2_sensitive_event_type",
        "sensitive_operation_events_v2",
        "event_type IN ('sensitive.permit_issued','sensitive.operation_claimed',"
        "'sensitive.execution_granted','sensitive.executor_receipt_attested',"
        "'sensitive.operation_reconciled')",
        schema="lucy",
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.reconcile_sensitive_operation_v2(p_operation_id uuid)
        RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_now timestamptz:=clock_timestamp();
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_receipt lucy.executor_receipt_attestations_v2%ROWTYPE;
          v_state text;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='sensitive_workflow' AND active
            AND allowed_actions @> '["sensitive.operation.reconcile"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'sensitive reconciliation unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id FOR UPDATE;
          IF NOT FOUND OR v_operation.workflow_actor_binding_id<>v_actor.id
          THEN RAISE EXCEPTION 'sensitive reconciliation unavailable'; END IF;
          IF v_operation.state IN ('RECONCILED','REJECTED') THEN
            RETURN jsonb_build_object('operation_id',v_operation.id,
              'state',v_operation.state,'result',v_operation.executor_result,
              'receipt_digest',v_operation.executor_receipt_digest,'replayed',true);
          END IF;
          SELECT * INTO v_receipt FROM lucy.executor_receipt_attestations_v2
          WHERE operation_id=v_operation.id AND content_scope_id=v_operation.content_scope_id;
          IF NOT FOUND THEN RAISE EXCEPTION 'policy receipt attestation unavailable'; END IF;
          v_state:=CASE WHEN v_receipt.result='rejected' THEN 'REJECTED' ELSE 'RECONCILED' END;
          UPDATE lucy.sensitive_operations_v2 SET state=v_state,
            receipt_attestation_id=v_receipt.id,
            executor_receipt_digest=v_receipt.receipt_digest,
            executor_result=v_receipt.result,reconciled_at=v_now
          WHERE id=v_operation.id;
          INSERT INTO lucy.sensitive_operation_events_v2(
            id,content_scope_id,operation_id,event_type,details,occurred_at
          ) VALUES (gen_random_uuid(),v_operation.content_scope_id,v_operation.id,
            'sensitive.operation_reconciled',jsonb_build_object(
              'receipt_attestation_id',v_receipt.id,
              'receipt_digest',v_receipt.receipt_digest,'result',v_receipt.result,
              'state',v_state),v_now);
          RETURN jsonb_build_object('operation_id',v_operation.id,'state',v_state,
            'result',v_receipt.result,'receipt_digest',v_receipt.receipt_digest,
            'replayed',false);
        END
        $function$;
        ALTER FUNCTION lucy.reconcile_sensitive_operation_v2(uuid)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.reconcile_sensitive_operation_v2(uuid)
          FROM PUBLIC,lucy_app;
        GRANT UPDATE ON lucy.sensitive_operations_v2 TO lucy_security_function_owner;
        GRANT SELECT ON lucy.executor_receipt_attestations_v2
          TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("R1 receipt-only reconciliation requires a reviewed forward migration")
