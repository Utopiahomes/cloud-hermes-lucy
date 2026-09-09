"""Add realm-scoped executor receipt attestation."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0028_r1_executor_receipt"
down_revision: str | None = "0027_r1_execution_grant"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid(name: str, *, primary: bool = False, unique: bool = False) -> sa.Column:
    return sa.Column(
        name,
        postgresql.UUID(as_uuid=True),
        primary_key=primary,
        nullable=False,
        unique=unique,
    )


def upgrade() -> None:
    op.execute(
        "DROP TRIGGER realm_executor_bindings_v2_immutable "
        "ON lucy.realm_executor_bindings_v2; "
        "CREATE FUNCTION lucy.realm_executor_binding_guard_v2() RETURNS trigger "
        "LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$ "
        "BEGIN IF TG_OP='DELETE' OR NEW.id<>OLD.id "
        "OR NEW.content_scope_id<>OLD.content_scope_id OR NEW.action<>OLD.action "
        "OR NEW.caller_identity<>OLD.caller_identity "
        "OR NEW.executor_identity<>OLD.executor_identity "
        "OR NEW.executor_alias_arn<>OLD.executor_alias_arn "
        "OR NEW.executor_version<>OLD.executor_version "
        "OR NEW.receipt_key_id<>OLD.receipt_key_id "
        "OR NEW.node_authz_epoch<>OLD.node_authz_epoch "
        "OR NEW.policy_version<>OLD.policy_version OR NEW.created_at<>OLD.created_at "
        "OR NOT OLD.active OR NEW.active "
        "OR NEW.binding_generation<>OLD.binding_generation+1 "
        "THEN RAISE EXCEPTION 'realm executor binding mutation unavailable'; END IF; "
        "RETURN NEW; END $function$; "
        "CREATE TRIGGER realm_executor_bindings_v2_monotonic BEFORE UPDATE OR DELETE "
        "ON lucy.realm_executor_bindings_v2 FOR EACH ROW "
        "EXECUTE FUNCTION lucy.realm_executor_binding_guard_v2()"
    )
    op.create_table(
        "executor_receipt_attestations_v2",
        _uuid("id", primary=True),
        _uuid("operation_id", unique=True),
        _uuid("execution_grant_id", unique=True),
        _uuid("content_scope_id"),
        _uuid("policy_actor_binding_id"),
        _uuid("executor_binding_id"),
        sa.Column("receipt_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("result", sa.String(40), nullable=False),
        sa.Column("serialized_receipt", postgresql.JSONB(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["operation_id"], ["lucy.sensitive_operations_v2.id"]),
        sa.ForeignKeyConstraint(
            ["execution_grant_id"], ["lucy.sensitive_execution_grants_v2.id"]
        ),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["policy_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.ForeignKeyConstraint(
            ["executor_binding_id"], ["lucy.realm_executor_bindings_v2.id"]
        ),
        sa.CheckConstraint(
            "result IN ('retrieval_succeeded','deletion_succeeded','idempotent_replay','rejected')",
            name="ck_v2_receipt_result",
        ),
        schema="lucy",
    )
    op.execute(
        "CREATE TRIGGER executor_receipt_attestations_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.executor_receipt_attestations_v2 FOR EACH ROW "
        "EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.drop_constraint(
        "ck_v2_sensitive_event_type", "sensitive_operation_events_v2", schema="lucy"
    )
    op.create_check_constraint(
        "ck_v2_sensitive_event_type",
        "sensitive_operation_events_v2",
        "event_type IN ('sensitive.permit_issued','sensitive.operation_claimed',"
        "'sensitive.execution_granted','sensitive.executor_receipt_attested')",
        schema="lucy",
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.attest_executor_receipt_v2(
          p_operation_id uuid, p_receipt jsonb
        ) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_now timestamptz:=clock_timestamp();
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v3%ROWTYPE;
          v_grant lucy.sensitive_execution_grants_v2%ROWTYPE;
          v_executor lucy.realm_executor_bindings_v2%ROWTYPE;
          v_existing lucy.executor_receipt_attestations_v2%ROWTYPE;
          v_receipt_id uuid; v_digest text; v_completed_at timestamptz; v_result text;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.receipt.attest"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'executor receipt attestation unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id;
          IF NOT FOUND THEN RAISE EXCEPTION 'executor receipt attestation unavailable'; END IF;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v3
          WHERE id=v_operation.permit_id;
          SELECT * INTO STRICT v_grant FROM lucy.sensitive_execution_grants_v2
          WHERE operation_id=v_operation.id AND permit_id=v_permit.id;
          SELECT * INTO STRICT v_executor FROM lucy.realm_executor_bindings_v2
          WHERE id=v_grant.executor_binding_id;
          SELECT * INTO v_existing FROM lucy.executor_receipt_attestations_v2
          WHERE operation_id=p_operation_id;
          IF FOUND THEN
            IF v_existing.serialized_receipt=p_receipt
            THEN RETURN v_existing.receipt_digest; END IF;
            RAISE EXCEPTION 'executor receipt attestation replay differs';
          END IF;
          IF jsonb_typeof(p_receipt)<>'object' OR p_receipt-ARRAY[
            'canonicalization_version','signature_algorithm','signing_key_purpose','key_id',
            'issuer','environment','issued_at','signature','contract_version','object_type',
            'receipt_id','action','executor_identity','executor_alias_arn','executor_version',
            'caller_identity','target_scope','execution_binding','operation_id','permit_id',
            'permit_digest','execution_grant_id','execution_grant_digest',
            'deletion_manifest_id','deletion_manifest_digest','package_digest','result',
            'lambda_request_id','kms_request_id','transaction_client_token',
            'execution_completion_deadline','completed_at','record_version','journal_ref',
            'finality_state'
          ]<>'{}'::jsonb THEN RAISE EXCEPTION 'V2 executor receipt contains unknown fields'; END IF;
          v_receipt_id:=(p_receipt->>'receipt_id')::uuid;
          v_completed_at:=(p_receipt->>'completed_at')::timestamptz;
          v_result:=p_receipt->>'result';
          v_digest:=lucy.security_contract_digest_v2(p_receipt);
          IF p_receipt->>'contract_version'<>'2'
             OR p_receipt->>'object_type'<>'lucy.executor-receipt.v2'
             OR p_receipt->>'canonicalization_version'<>'lucy-cjson-1'
             OR p_receipt->>'signature_algorithm'<>'ECDSA_SHA_256'
             OR p_receipt->>'signing_key_purpose'<>'retrieval_receipt_v13'
             OR p_receipt->>'key_id'<>v_executor.receipt_key_id
             OR coalesce(p_receipt->>'signature','')=''
             OR (p_receipt->>'issued_at')::timestamptz
                NOT BETWEEN v_completed_at-interval '5 seconds'
                    AND v_completed_at+interval '5 seconds'
             OR v_completed_at>v_grant.execution_completion_deadline+interval '5 seconds'
             OR p_receipt->>'action'<>v_operation.action
             OR p_receipt->>'executor_identity'<>v_executor.executor_identity
             OR p_receipt->>'executor_alias_arn'<>v_executor.executor_alias_arn
             OR (p_receipt->>'executor_version')::bigint<>v_executor.executor_version
             OR p_receipt->>'caller_identity'<>v_executor.caller_identity
             OR p_receipt->'target_scope'<>v_grant.serialized_grant->'target_scope'
             OR p_receipt->'execution_binding'<>v_grant.serialized_grant->'execution_binding'
             OR (p_receipt->>'operation_id')::uuid<>v_operation.id
             OR (p_receipt->>'permit_id')::uuid<>v_permit.id
             OR p_receipt->>'permit_digest'<>v_permit.permit_digest
             OR (p_receipt->>'execution_grant_id')::uuid<>v_grant.id
             OR p_receipt->>'execution_grant_digest'<>v_grant.grant_digest
             OR (p_receipt->>'deletion_manifest_id') IS NOT NULL
             OR (p_receipt->>'deletion_manifest_digest') IS NOT NULL
             OR p_receipt->>'package_digest'<>v_grant.package_digest
             OR v_result NOT IN ('retrieval_succeeded','idempotent_replay','rejected')
             OR (p_receipt->>'kms_request_id') IS NULL
             OR (p_receipt->>'transaction_client_token') IS NOT NULL
             OR (p_receipt->>'execution_completion_deadline')::timestamptz
                <>v_grant.execution_completion_deadline
             OR (p_receipt->>'record_version')::bigint<>v_operation.resource_object_version
             OR p_receipt->>'finality_state'<>'not_applicable'
          THEN RAISE EXCEPTION 'verified executor receipt differs from stored grant'; END IF;
          INSERT INTO lucy.executor_receipt_attestations_v2(
            id,operation_id,execution_grant_id,content_scope_id,policy_actor_binding_id,
            executor_binding_id,receipt_digest,result,serialized_receipt,completed_at,verified_at
          ) VALUES (v_receipt_id,v_operation.id,v_grant.id,v_operation.content_scope_id,
            v_actor.id,v_executor.id,v_digest,v_result,p_receipt,v_completed_at,v_now);
          INSERT INTO lucy.sensitive_operation_events_v2(
            id,content_scope_id,operation_id,event_type,details,occurred_at
          ) VALUES (gen_random_uuid(),v_operation.content_scope_id,v_operation.id,
            'sensitive.executor_receipt_attested',jsonb_build_object(
              'receipt_id',v_receipt_id,'receipt_digest',v_digest,'result',v_result),v_now);
          RETURN v_digest;
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR not_null_violation OR check_violation
          THEN RAISE EXCEPTION 'malformed V2 executor receipt';
        END
        $function$;
        ALTER FUNCTION lucy.attest_executor_receipt_v2(uuid,jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.attest_executor_receipt_v2(uuid,jsonb)
          FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.executor_receipt_attestations_v2
          TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("R1 scoped executor receipts require a reviewed forward migration")
