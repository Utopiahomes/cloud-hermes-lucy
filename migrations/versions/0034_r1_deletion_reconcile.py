"""Reconcile scoped deletion receipts to operational effect and finality pending."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0034_r1_deletion_reconcile"
down_revision: str | None = "0033_r1_deletion_receipt"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scoped_deletion_effects_v2",
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("manifest_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column(
            "receipt_attestation_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            unique=True,
        ),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finality_not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finality_status", sa.String(30), nullable=False),
        sa.ForeignKeyConstraint(["operation_id"], ["lucy.sensitive_operations_v2.id"]),
        sa.ForeignKeyConstraint(["manifest_id"], ["lucy.scoped_deletion_manifests_v2.id"]),
        sa.ForeignKeyConstraint(
            ["receipt_attestation_id"], ["lucy.executor_receipt_attestations_v2.id"]
        ),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.CheckConstraint("finality_status='PENDING'", name="ck_scoped_finality_initial"),
        schema="lucy",
    )
    op.execute(
        "CREATE TRIGGER scoped_deletion_effects_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_deletion_effects_v2 FOR EACH ROW "
        "EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.drop_constraint(
        "ck_v2_sensitive_operation_state", "sensitive_operations_v2", schema="lucy"
    )
    op.create_check_constraint(
        "ck_v2_sensitive_operation_state",
        "sensitive_operations_v2",
        "(state='CLAIMED' AND receipt_attestation_id IS NULL "
        "AND executor_receipt_digest IS NULL AND executor_result IS NULL "
        "AND reconciled_at IS NULL) OR "
        "(state IN ('RECONCILED','REJECTED','FINALITY_PENDING') "
        "AND receipt_attestation_id IS NOT NULL "
        "AND executor_receipt_digest IS NOT NULL AND executor_result IS NOT NULL "
        "AND reconciled_at IS NOT NULL)",
        schema="lucy",
    )
    op.drop_constraint(
        "ck_v2_sensitive_event_type", "sensitive_operation_events_v2", schema="lucy"
    )
    op.create_check_constraint(
        "ck_v2_sensitive_event_type",
        "sensitive_operation_events_v2",
        "event_type IN ('sensitive.permit_issued','sensitive.operation_claimed',"
        "'sensitive.execution_granted','sensitive.executor_receipt_attested',"
        "'sensitive.operation_reconciled','sensitive.deletion_manifest_frozen',"
        "'sensitive.deletion_effective')",
        schema="lucy",
    )
    op.execute(
        r"""
        CREATE OR REPLACE FUNCTION lucy.sensitive_operation_guard_v2() RETURNS trigger
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
             OR NEW.state NOT IN ('RECONCILED','REJECTED','FINALITY_PENDING')
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

        CREATE OR REPLACE FUNCTION lucy.reconcile_sensitive_operation_v2(
          p_operation_id uuid
        ) RETURNS jsonb
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
             OR v_operation.action<>'evidence.retrieve'
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

        CREATE FUNCTION lucy.reconcile_scoped_deletion_v2(p_operation_id uuid)
        RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_now timestamptz:=clock_timestamp();
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_receipt lucy.executor_receipt_attestations_v2%ROWTYPE;
          v_manifest lucy.scoped_deletion_manifests_v2%ROWTYPE;
          v_state text; v_finality_not_before timestamptz;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='sensitive_workflow' AND active
            AND allowed_actions @> '["sensitive.operation.reconcile"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped deletion reconciliation unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id FOR UPDATE;
          IF NOT FOUND OR v_operation.workflow_actor_binding_id<>v_actor.id
             OR v_operation.action<>'evidence.delete'
          THEN RAISE EXCEPTION 'scoped deletion reconciliation unavailable'; END IF;
          IF v_operation.state IN ('FINALITY_PENDING','REJECTED') THEN
            RETURN jsonb_build_object('operation_id',v_operation.id,
              'state',v_operation.state,'result',v_operation.executor_result,
              'receipt_digest',v_operation.executor_receipt_digest,
              'finality_not_before',(SELECT finality_not_before
                FROM lucy.scoped_deletion_effects_v2 WHERE operation_id=v_operation.id),
              'replayed',true);
          END IF;
          SELECT * INTO v_receipt FROM lucy.executor_receipt_attestations_v2
          WHERE operation_id=v_operation.id AND content_scope_id=v_operation.content_scope_id;
          IF NOT FOUND THEN RAISE EXCEPTION 'policy deletion receipt unavailable'; END IF;
          SELECT * INTO STRICT v_manifest FROM lucy.scoped_deletion_manifests_v2
          WHERE operation_id=v_operation.id AND id=
            (v_receipt.serialized_receipt->>'deletion_manifest_id')::uuid;
          IF v_receipt.result='rejected' THEN
            v_state:='REJECTED'; v_finality_not_before:=NULL;
          ELSE
            IF v_receipt.result NOT IN ('deletion_succeeded','idempotent_replay')
               OR v_receipt.serialized_receipt->>'finality_state'<>'operationally_deleted'
            THEN RAISE EXCEPTION 'policy deletion receipt is not effective'; END IF;
            v_state:='FINALITY_PENDING';
            v_finality_not_before:=v_now+interval '30 days';
            INSERT INTO lucy.scoped_deletion_effects_v2(
              operation_id,manifest_id,receipt_attestation_id,content_scope_id,
              effective_at,finality_not_before,finality_status
            ) VALUES (v_operation.id,v_manifest.id,v_receipt.id,v_operation.content_scope_id,
              v_now,v_finality_not_before,'PENDING');
          END IF;
          UPDATE lucy.sensitive_operations_v2 SET state=v_state,
            receipt_attestation_id=v_receipt.id,
            executor_receipt_digest=v_receipt.receipt_digest,
            executor_result=v_receipt.result,reconciled_at=v_now
          WHERE id=v_operation.id;
          INSERT INTO lucy.sensitive_operation_events_v2(
            id,content_scope_id,operation_id,event_type,details,occurred_at
          ) VALUES (gen_random_uuid(),v_operation.content_scope_id,v_operation.id,
            CASE WHEN v_state='REJECTED' THEN 'sensitive.operation_reconciled'
                 ELSE 'sensitive.deletion_effective' END,
            jsonb_build_object('receipt_attestation_id',v_receipt.id,
              'receipt_digest',v_receipt.receipt_digest,'manifest_id',v_manifest.id,
              'result',v_receipt.result,'state',v_state,
              'finality_not_before',v_finality_not_before),v_now);
          RETURN jsonb_build_object('operation_id',v_operation.id,'state',v_state,
            'result',v_receipt.result,'receipt_digest',v_receipt.receipt_digest,
            'finality_not_before',v_finality_not_before,'replayed',false);
        END
        $function$;
        ALTER FUNCTION lucy.reconcile_scoped_deletion_v2(uuid)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.reconcile_scoped_deletion_v2(uuid)
          FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.scoped_deletion_effects_v2
          TO lucy_security_function_owner;
        GRANT SELECT ON lucy.scoped_deletion_manifests_v2
          TO lucy_security_function_owner;
        """
    )
    op.execute(
        r"""
        CREATE OR REPLACE FUNCTION lucy.search_scoped_memory_v1(
          p_query text,p_limit integer
        ) RETURNS jsonb
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_result jsonb;
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.read"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'realm operation unavailable'; END IF;
          IF p_query IS NULL OR btrim(p_query)='' OR length(p_query)>200
             OR p_limit NOT BETWEEN 1 AND 50
          THEN RAISE EXCEPTION 'scoped memory request is invalid'; END IF;
          SELECT coalesce(jsonb_agg(jsonb_build_object(
            'claim_id',q.id,'subject',q.subject,'predicate',q.predicate,'object',q.object,
            'confidence_millionths',q.confidence_millionths,'status',q.status
          ) ORDER BY q.confidence_millionths DESC,q.created_at DESC,q.id),'[]'::jsonb)
          INTO v_result FROM (
            SELECT * FROM lucy.scoped_memory_claims_v1 c
            WHERE c.content_scope_id=v_binding.content_scope_id AND c.status='accepted'
              AND NOT EXISTS (
                SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                JOIN lucy.scoped_evidence_deletion_fences_v2 f
                  ON f.evidence_id=s.evidence_id AND f.content_scope_id=s.content_scope_id
                WHERE s.claim_id=c.id AND s.content_scope_id=c.content_scope_id
              )
              AND (c.subject ILIKE '%'||p_query||'%'
                OR c.predicate ILIKE '%'||p_query||'%'
                OR c.object ILIKE '%'||p_query||'%')
            ORDER BY c.confidence_millionths DESC,c.created_at DESC,c.id LIMIT p_limit
          ) q;
          RETURN v_result;
        END
        $function$;

        CREATE FUNCTION lucy.reject_fenced_retrieval_package_v2() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
        AS $function$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
            WHERE f.evidence_id=NEW.evidence_id AND f.content_scope_id=NEW.content_scope_id
          ) THEN RAISE EXCEPTION 'scoped evidence is deletion fenced'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER scoped_retrieval_package_not_fenced
        BEFORE INSERT ON lucy.sensitive_operation_packages_v2 FOR EACH ROW
        EXECUTE FUNCTION lucy.reject_fenced_retrieval_package_v2();

        CREATE FUNCTION lucy.reject_fenced_retrieval_grant_v2() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
        AS $function$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM lucy.sensitive_operations_v2 o
            JOIN lucy.sensitive_operation_packages_v2 p ON p.operation_id=o.id
            JOIN lucy.scoped_evidence_deletion_fences_v2 f
              ON f.evidence_id=p.evidence_id AND f.content_scope_id=p.content_scope_id
            WHERE o.id=NEW.operation_id AND o.action='evidence.retrieve'
          ) THEN RAISE EXCEPTION 'scoped evidence is deletion fenced'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER scoped_retrieval_grant_not_fenced
        BEFORE INSERT ON lucy.sensitive_execution_grants_v2 FOR EACH ROW
        EXECUTE FUNCTION lucy.reject_fenced_retrieval_grant_v2();
        """
    )


def downgrade() -> None:
    raise RuntimeError("scoped deletion reconciliation requires a reviewed forward migration")
