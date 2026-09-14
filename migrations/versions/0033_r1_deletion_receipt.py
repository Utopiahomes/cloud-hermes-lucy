"""Attest deletion receipts against exact scoped manifests and grants."""

from collections.abc import Sequence

from alembic import op

revision: str = "0033_r1_deletion_receipt"
down_revision: str | None = "0032_r1_deletion_grant"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        r"""
        CREATE FUNCTION lucy.attest_deletion_executor_receipt_v2(
          p_operation_id uuid,p_receipt jsonb
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
          v_manifest lucy.scoped_deletion_manifests_v2%ROWTYPE;
          v_executor lucy.realm_executor_bindings_v2%ROWTYPE;
          v_existing lucy.executor_receipt_attestations_v2%ROWTYPE;
          v_receipt_id uuid; v_digest text; v_completed_at timestamptz; v_result text;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.receipt.attest"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'deletion receipt attestation unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id;
          IF NOT FOUND OR v_operation.action<>'evidence.delete'
          THEN RAISE EXCEPTION 'deletion receipt attestation unavailable'; END IF;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v3
          WHERE id=v_operation.permit_id;
          SELECT * INTO STRICT v_grant FROM lucy.sensitive_execution_grants_v2
          WHERE operation_id=v_operation.id AND permit_id=v_permit.id;
          SELECT * INTO STRICT v_manifest FROM lucy.scoped_deletion_manifests_v2
          WHERE id=v_grant.deletion_manifest_id AND operation_id=v_operation.id;
          SELECT * INTO STRICT v_executor FROM lucy.realm_executor_bindings_v2
          WHERE id=v_grant.executor_binding_id;
          SELECT * INTO v_existing FROM lucy.executor_receipt_attestations_v2
          WHERE operation_id=p_operation_id;
          IF FOUND THEN
            IF v_existing.serialized_receipt=p_receipt
            THEN RETURN v_existing.receipt_digest; END IF;
            RAISE EXCEPTION 'deletion receipt attestation replay differs';
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
          ]<>'{}'::jsonb THEN RAISE EXCEPTION 'V2 deletion receipt contains unknown fields'; END IF;
          v_receipt_id:=(p_receipt->>'receipt_id')::uuid;
          v_completed_at:=(p_receipt->>'completed_at')::timestamptz;
          v_result:=p_receipt->>'result';
          v_digest:=lucy.security_contract_digest_v2(p_receipt);
          IF p_receipt->>'contract_version'<>'2'
             OR p_receipt->>'object_type'<>'lucy.executor-receipt.v2'
             OR p_receipt->>'canonicalization_version'<>'lucy-cjson-1'
             OR p_receipt->>'signature_algorithm'<>'ECDSA_SHA_256'
             OR p_receipt->>'signing_key_purpose'<>'deletion_receipt_v13'
             OR p_receipt->>'key_id'<>v_executor.receipt_key_id
             OR coalesce(p_receipt->>'signature','')=''
             OR (p_receipt->>'issued_at')::timestamptz
                NOT BETWEEN v_completed_at-interval '5 seconds'
                    AND v_completed_at+interval '5 seconds'
             OR v_completed_at>v_grant.execution_completion_deadline+interval '5 seconds'
             OR p_receipt->>'action'<>'evidence.delete'
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
             OR (p_receipt->>'deletion_manifest_id')::uuid<>v_manifest.id
             OR p_receipt->>'deletion_manifest_digest'<>v_manifest.manifest_digest
             OR p_receipt->>'package_digest'<>v_grant.package_digest
             OR v_result NOT IN ('deletion_succeeded','idempotent_replay','rejected')
             OR (p_receipt->>'kms_request_id') IS NOT NULL
             OR coalesce(p_receipt->>'transaction_client_token','')=''
             OR (p_receipt->>'execution_completion_deadline')::timestamptz
                <>v_grant.execution_completion_deadline
             OR (p_receipt->>'record_version')::bigint<>v_operation.resource_object_version
             OR (v_result='rejected' AND p_receipt->>'finality_state'<>'not_applicable')
             OR (v_result<>'rejected'
                AND p_receipt->>'finality_state'<>'operationally_deleted')
          THEN RAISE EXCEPTION 'verified deletion receipt differs from stored grant'; END IF;
          INSERT INTO lucy.executor_receipt_attestations_v2(
            id,operation_id,execution_grant_id,content_scope_id,policy_actor_binding_id,
            executor_binding_id,receipt_digest,result,serialized_receipt,completed_at,verified_at
          ) VALUES (v_receipt_id,v_operation.id,v_grant.id,v_operation.content_scope_id,
            v_actor.id,v_executor.id,v_digest,v_result,p_receipt,v_completed_at,v_now);
          INSERT INTO lucy.sensitive_operation_events_v2(
            id,content_scope_id,operation_id,event_type,details,occurred_at
          ) VALUES (gen_random_uuid(),v_operation.content_scope_id,v_operation.id,
            'sensitive.executor_receipt_attested',jsonb_build_object(
              'receipt_id',v_receipt_id,'receipt_digest',v_digest,'result',v_result,
              'manifest_id',v_manifest.id),v_now);
          RETURN v_digest;
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR not_null_violation OR check_violation
          THEN RAISE EXCEPTION 'malformed V2 deletion executor receipt';
        END
        $function$;
        ALTER FUNCTION lucy.attest_deletion_executor_receipt_v2(uuid,jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.attest_deletion_executor_receipt_v2(uuid,jsonb)
          FROM PUBLIC,lucy_app;
        """
    )


def downgrade() -> None:
    raise RuntimeError("scoped deletion receipts require a reviewed forward migration")
