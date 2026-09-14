"""Bind, attest, and reconcile V3 imported-memory deletions."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0065_memory_deletion_execution"
down_revision: str | None = "0064_memory_deletion_authority"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "scoped_deletion_execution_grants_v3",
        sa.Column("grant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("manifest_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("manifest_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["grant_id"], ["lucy.sensitive_execution_grants_v2.id"]),
        sa.ForeignKeyConstraint(["operation_id"], ["lucy.sensitive_operations_v2.id"]),
        sa.ForeignKeyConstraint(["manifest_id"], ["lucy.scoped_deletion_manifests_v3.id"]),
        schema="lucy",
    )
    op.create_table(
        "scoped_memory_candidate_tombstones_v3",
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("candidate_version", sa.BigInteger(), primary_key=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("manifest_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tombstoned_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["candidate_id", "candidate_version"],
            [
                "lucy.scoped_memory_candidate_versions_v1.candidate_id",
                "lucy.scoped_memory_candidate_versions_v1.candidate_version",
            ],
        ),
        sa.ForeignKeyConstraint(["operation_id"], ["lucy.sensitive_operations_v2.id"]),
        sa.ForeignKeyConstraint(["manifest_id"], ["lucy.scoped_deletion_manifests_v3.id"]),
        schema="lucy",
    )
    op.create_table(
        "memory_import_outcome_tombstones_v3",
        sa.Column("extraction_job_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("record_version", sa.BigInteger(), primary_key=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("manifest_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("representation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("wrapped_key_ref", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key_registry_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tombstoned_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["extraction_job_id"], ["lucy.memory_import_extraction_jobs_v1.id"]
        ),
        sa.ForeignKeyConstraint(["operation_id"], ["lucy.sensitive_operations_v2.id"]),
        sa.ForeignKeyConstraint(["manifest_id"], ["lucy.scoped_deletion_manifests_v3.id"]),
        schema="lucy",
    )
    op.create_table(
        "scoped_deletion_effects_v3",
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
        sa.ForeignKeyConstraint(["manifest_id"], ["lucy.scoped_deletion_manifests_v3.id"]),
        sa.ForeignKeyConstraint(
            ["receipt_attestation_id"], ["lucy.executor_receipt_attestations_v2.id"]
        ),
        sa.CheckConstraint("finality_status='PENDING'", name="ck_v3_finality_initial"),
        schema="lucy",
    )
    op.execute(
        r"""
        CREATE TRIGGER scoped_deletion_execution_grants_v3_immutable BEFORE UPDATE OR DELETE
        ON lucy.scoped_deletion_execution_grants_v3 FOR EACH ROW
        EXECUTE FUNCTION lucy.reject_mutation();
        CREATE TRIGGER scoped_memory_candidate_tombstones_v3_immutable BEFORE UPDATE OR DELETE
        ON lucy.scoped_memory_candidate_tombstones_v3 FOR EACH ROW
        EXECUTE FUNCTION lucy.reject_mutation();
        CREATE TRIGGER memory_import_outcome_tombstones_v3_immutable BEFORE UPDATE OR DELETE
        ON lucy.memory_import_outcome_tombstones_v3 FOR EACH ROW
        EXECUTE FUNCTION lucy.reject_mutation();
        CREATE TRIGGER scoped_deletion_effects_v3_immutable BEFORE UPDATE OR DELETE
        ON lucy.scoped_deletion_effects_v3 FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation();

        CREATE FUNCTION lucy.read_claimed_sensitive_authority_v2(p_operation_id uuid)
        RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v3%ROWTYPE;
          v_executor lucy.realm_executor_bindings_v2%ROWTYPE;
          v_manifest lucy.scoped_deletion_manifests_v3%ROWTYPE;
          v_existing lucy.sensitive_execution_grants_v2%ROWTYPE;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.grant.issue"]'::jsonb;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id
            AND action='evidence.delete' AND state='CLAIMED';
          IF v_actor.id IS NULL OR v_operation.id IS NULL
          THEN RAISE EXCEPTION 'V3 grant authority unavailable'; END IF;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v3
          WHERE id=v_operation.permit_id AND state='CLAIMED';
          SELECT * INTO STRICT v_manifest FROM lucy.scoped_deletion_manifests_v3
          WHERE operation_id=v_operation.id AND permit_id=v_permit.id;
          SELECT * INTO STRICT v_executor FROM lucy.realm_executor_bindings_v2
          WHERE content_scope_id=v_actor.content_scope_id AND action='evidence.delete' AND active
            AND node_authz_epoch=v_actor.node_authz_epoch AND policy_version=v_actor.policy_version;
          SELECT g.* INTO v_existing FROM lucy.sensitive_execution_grants_v2 g
          JOIN lucy.scoped_deletion_execution_grants_v3 b ON b.grant_id=g.id
          WHERE b.operation_id=v_operation.id;
          RETURN jsonb_build_object('operation_id',v_operation.id,'action',v_operation.action,
            'claimed_at',v_operation.claimed_at,
            'claim_idempotency_key',v_operation.claim_idempotency_key,
            'permit',v_permit.serialized_permit,'permit_id',v_permit.id,
            'permit_digest',v_permit.permit_digest,
            'package_digest',v_manifest.manifest_digest,
            'package_size_bytes',octet_length(convert_to(
              lucy.canonical_jsonb_v1(v_manifest.serialized_manifest),'UTF8')),
            'executor_binding_id',v_executor.id,'caller_identity',v_executor.caller_identity,
            'executor_identity',v_executor.executor_identity,
            'executor_alias_arn',v_executor.executor_alias_arn,
            'executor_version',v_executor.executor_version,'receipt_key_id',v_executor.receipt_key_id,
            'deletion_manifest_id',v_manifest.id,
            'deletion_manifest_digest',v_manifest.manifest_digest,
            'existing_grant',v_existing.serialized_grant);
        END $function$;

        CREATE FUNCTION lucy.store_deletion_execution_grant_v3(p_operation_id uuid,p_grant jsonb)
        RETURNS text LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_authority jsonb; v_manifest lucy.scoped_deletion_manifests_v3%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v3%ROWTYPE;
          v_executor lucy.realm_executor_bindings_v2%ROWTYPE;
          v_scope lucy.realm_content_scopes_v1%ROWTYPE;
          v_existing lucy.sensitive_execution_grants_v2%ROWTYPE;
          v_id uuid; v_digest text; v_now timestamptz:=clock_timestamp();
          v_issued timestamptz; v_package_size bigint;
        BEGIN
          v_authority:=lucy.read_claimed_sensitive_authority_v2(p_operation_id);
          SELECT * INTO STRICT v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v3
          WHERE id=v_operation.permit_id AND state='CLAIMED';
          SELECT * INTO STRICT v_manifest FROM lucy.scoped_deletion_manifests_v3
          WHERE operation_id=p_operation_id;
          SELECT * INTO STRICT v_executor FROM lucy.realm_executor_bindings_v2
          WHERE id=(v_authority->>'executor_binding_id')::uuid;
          SELECT * INTO STRICT v_scope FROM lucy.realm_content_scopes_v1
          WHERE id=v_operation.content_scope_id;
          SELECT g.* INTO v_existing FROM lucy.sensitive_execution_grants_v2 g
          JOIN lucy.scoped_deletion_execution_grants_v3 b ON b.grant_id=g.id
          WHERE b.operation_id=p_operation_id;
          IF FOUND THEN
            IF v_existing.serialized_grant=p_grant THEN RETURN v_existing.grant_digest; END IF;
            RAISE EXCEPTION 'V3 deletion grant replay differs';
          END IF;
          IF jsonb_typeof(p_grant)<>'object' OR p_grant-ARRAY[
            'canonicalization_version','signature_algorithm','signing_key_purpose','key_id',
            'issuer','environment','issued_at','signature','contract_version','object_type',
            'grant_id','action','permit_id','permit_digest','operation_id','caller_identity',
            'target_scope','workspace_id','resource_selector','execution_binding',
            'restore_mapping_id','deletion_manifest_id','deletion_manifest_digest',
            'encrypted_package_digest','package_size_bytes','idempotency_key',
            'executor_identity','executor_alias_arn','executor_version','permit_claimed_at',
            'permit_claim_deadline','execution_completion_deadline','max_records','max_bytes','nonce'
          ]<>'{}'::jsonb THEN RAISE EXCEPTION 'V3 deletion grant contains unknown fields'; END IF;
          v_id:=(p_grant->>'grant_id')::uuid;
          v_digest:=lucy.security_contract_digest_v2(p_grant);
          v_issued:=(p_grant->>'issued_at')::timestamptz;
          v_package_size:=(v_authority->>'package_size_bytes')::bigint;
          IF p_grant->>'contract_version'<>'2'
             OR p_grant->>'object_type'<>'lucy.sensitive-execution-grant.v2'
             OR p_grant->>'canonicalization_version'<>'lucy-cjson-1'
             OR p_grant->>'signature_algorithm'<>'Ed25519'
             OR p_grant->>'signing_key_purpose'<>'policy_notary_v13'
             OR coalesce(p_grant->>'signature','')=''
             OR v_issued>v_now+interval '5 seconds'
             OR v_issued>v_permit.permit_claim_deadline+interval '5 seconds'
             OR v_now>v_permit.execution_completion_deadline
             OR (p_grant->>'permit_claimed_at')::timestamptz<>v_operation.claimed_at
             OR (p_grant->>'permit_claim_deadline')::timestamptz
                <>v_permit.permit_claim_deadline
             OR (p_grant->>'execution_completion_deadline')::timestamptz
                <>v_permit.execution_completion_deadline
             OR p_grant->>'action'<>'evidence.delete'
             OR (p_grant->>'operation_id')::uuid<>p_operation_id
             OR (p_grant->>'permit_id')::uuid<>(v_authority->>'permit_id')::uuid
             OR p_grant->>'permit_digest'<>v_authority->>'permit_digest'
             OR (p_grant->>'deletion_manifest_id')::uuid<>v_manifest.id
             OR p_grant->>'deletion_manifest_digest'<>v_manifest.manifest_digest
             OR p_grant->>'encrypted_package_digest'<>v_manifest.manifest_digest
             OR (p_grant->>'package_size_bytes')::bigint<>
                (v_authority->>'package_size_bytes')::bigint
             OR p_grant->>'idempotency_key'<>v_authority->>'claim_idempotency_key'
             OR p_grant->>'caller_identity'<>v_authority->>'caller_identity'
             OR p_grant->>'executor_identity'<>v_authority->>'executor_identity'
             OR p_grant->>'executor_alias_arn'<>v_authority->>'executor_alias_arn'
             OR (p_grant->>'executor_version')::bigint<>(v_authority->>'executor_version')::bigint
             OR p_grant->'target_scope'<>v_authority->'permit'->'target_scope'
             OR p_grant->'execution_binding'<>v_authority->'permit'->'execution_binding'
             OR p_grant->'resource_selector'<>v_authority->'permit'->'resource_selector'
             OR (p_grant->>'workspace_id')::uuid<>(v_authority->'permit'->>'workspace_id')::uuid
             OR (p_grant->>'restore_mapping_id') IS NOT NULL
             OR (p_grant->>'package_size_bytes')::bigint<>v_package_size
             OR (p_grant->>'package_size_bytes')::bigint>(p_grant->>'max_bytes')::bigint
             OR (p_grant->>'max_records')::bigint<1
             OR (p_grant->>'max_records')::bigint
                <>(v_authority->'permit'->>'max_records')::bigint
             OR (p_grant->>'max_bytes')::bigint
                <>(v_authority->'permit'->>'max_bytes')::bigint
          THEN RAISE EXCEPTION 'V3 deletion grant differs from authority'; END IF;
          IF NOT EXISTS (
            SELECT 1 FROM lucy.principals p
            JOIN lucy.node_memberships m ON m.principal_id=p.id
              AND m.workspace_id=v_scope.workspace_id
            JOIN lucy.channel_bindings ch ON ch.id=v_permit.channel_binding_id
              AND ch.workspace_id=v_scope.workspace_id
            JOIN lucy.nodes n ON n.id=v_scope.node_id
            JOIN lucy.node_tenures nt ON nt.id=v_scope.node_tenure_id
            JOIN lucy.realm_bindings rb ON rb.id=v_scope.realm_binding_id
            JOIN lucy.realm_service_bindings_v1 sb
              ON sb.id=v_operation.target_service_binding_id
            WHERE p.id=v_permit.principal_id AND p.status='active'
              AND m.status='active' AND m.role='owner'
              AND m.generation=(v_permit.serialized_permit->>'membership_generation')::bigint
              AND ch.active AND ch.channel_kind='internal'
              AND ch.generation=(v_permit.serialized_permit->>'channel_generation')::bigint
              AND n.authz_epoch=v_executor.node_authz_epoch
              AND nt.ends_at IS NULL AND nt.sequence=v_scope.tenure_epoch
              AND rb.valid_to IS NULL AND rb.binding_version=
                (v_permit.serialized_permit->'execution_binding'
                  ->>'realm_binding_generation')::bigint
              AND sb.active AND sb.content_scope_id=v_scope.id
              AND sb.binding_generation=
                (v_permit.serialized_permit->>'service_binding_generation')::bigint
              AND sb.node_authz_epoch=v_executor.node_authz_epoch
              AND sb.policy_version=v_executor.policy_version
          ) THEN RAISE EXCEPTION 'V3 deletion grant current authority is unavailable'; END IF;
          INSERT INTO lucy.sensitive_execution_grants_v2(
            id,operation_id,permit_id,content_scope_id,policy_actor_binding_id,
            executor_binding_id,package_digest,grant_digest,serialized_grant,issued_at,
            execution_completion_deadline,created_at)
          SELECT v_id,o.id,o.permit_id,o.content_scope_id,a.id,e.id,v_manifest.manifest_digest,
            v_digest,p_grant,v_issued,v_permit.execution_completion_deadline,v_now
          FROM lucy.sensitive_operations_v2 o
          JOIN lucy.realm_sensitive_actor_bindings_v1 a ON a.content_scope_id=o.content_scope_id
            AND a.session_login=session_user AND a.actor_role='policy_notary' AND a.active
          JOIN lucy.realm_executor_bindings_v2 e ON e.content_scope_id=o.content_scope_id
            AND e.action='evidence.delete' AND e.active WHERE o.id=p_operation_id;
          INSERT INTO lucy.scoped_deletion_execution_grants_v3(
            grant_id,operation_id,manifest_id,manifest_digest,created_at)
          VALUES(v_id,p_operation_id,v_manifest.id,v_manifest.manifest_digest,v_now);
          INSERT INTO lucy.sensitive_operation_events_v2(
            id,content_scope_id,operation_id,event_type,details,occurred_at)
          VALUES(gen_random_uuid(),v_operation.content_scope_id,p_operation_id,
            'sensitive.execution_granted',jsonb_build_object(
              'grant_id',v_id,'grant_digest',v_digest,'manifest_id',v_manifest.id),v_now);
          RETURN v_digest;
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR not_null_violation OR check_violation
          THEN RAISE EXCEPTION 'malformed V3 deletion grant';
        END $function$;

        CREATE FUNCTION lucy.attest_deletion_executor_receipt_v3(
          p_operation_id uuid,p_receipt jsonb) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_grant lucy.sensitive_execution_grants_v2%ROWTYPE;
          v_binding lucy.scoped_deletion_execution_grants_v3%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v3%ROWTYPE;
          v_executor lucy.realm_executor_bindings_v2%ROWTYPE;
          v_existing lucy.executor_receipt_attestations_v2%ROWTYPE;
          v_digest text; v_id uuid; v_completed timestamptz; v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.receipt.attest"]'::jsonb;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id
            AND action='evidence.delete';
          SELECT * INTO STRICT v_binding FROM lucy.scoped_deletion_execution_grants_v3
          WHERE operation_id=p_operation_id;
          SELECT * INTO STRICT v_grant FROM lucy.sensitive_execution_grants_v2
          WHERE id=v_binding.grant_id;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v3
          WHERE id=v_grant.permit_id;
          SELECT * INTO STRICT v_executor FROM lucy.realm_executor_bindings_v2
          WHERE id=v_grant.executor_binding_id;
          SELECT * INTO v_existing FROM lucy.executor_receipt_attestations_v2
          WHERE operation_id=p_operation_id;
          IF FOUND THEN
            IF v_existing.serialized_receipt=p_receipt
            THEN RETURN v_existing.receipt_digest; END IF;
            RAISE EXCEPTION 'V3 deletion receipt replay differs';
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
          ]<>'{}'::jsonb THEN RAISE EXCEPTION 'V3 deletion receipt contains unknown fields'; END IF;
          v_id:=(p_receipt->>'receipt_id')::uuid;
          v_completed:=(p_receipt->>'completed_at')::timestamptz;
          v_digest:=lucy.security_contract_digest_v2(p_receipt);
          IF p_receipt->>'contract_version'<>'2'
             OR p_receipt->>'object_type'<>'lucy.executor-receipt.v2'
             OR p_receipt->>'canonicalization_version'<>'lucy-cjson-1'
             OR p_receipt->>'signature_algorithm'<>'ECDSA_SHA_256'
             OR p_receipt->>'signing_key_purpose'<>'deletion_receipt_v13'
             OR coalesce(p_receipt->>'signature','')=''
             OR (p_receipt->>'issued_at')::timestamptz
                NOT BETWEEN v_completed-interval '5 seconds'
                    AND v_completed+interval '5 seconds'
             OR (p_receipt->>'operation_id')::uuid<>p_operation_id
             OR p_receipt->>'action'<>'evidence.delete'
             OR p_receipt->>'executor_identity'<>v_executor.executor_identity
             OR (p_receipt->>'executor_version')::bigint<>v_executor.executor_version
             OR p_receipt->>'caller_identity'<>v_executor.caller_identity
             OR p_receipt->'target_scope'<>v_grant.serialized_grant->'target_scope'
             OR p_receipt->'execution_binding'<>v_grant.serialized_grant->'execution_binding'
             OR (p_receipt->>'permit_id')::uuid<>v_permit.id
             OR p_receipt->>'permit_digest'<>v_permit.permit_digest
             OR (p_receipt->>'execution_grant_id')::uuid<>v_grant.id
             OR p_receipt->>'execution_grant_digest'<>v_grant.grant_digest
             OR (p_receipt->>'deletion_manifest_id')::uuid<>v_binding.manifest_id
             OR p_receipt->>'deletion_manifest_digest'<>v_binding.manifest_digest
             OR p_receipt->>'package_digest'<>v_grant.package_digest
             OR p_receipt->>'executor_alias_arn'<>v_executor.executor_alias_arn
             OR p_receipt->>'key_id'<>v_executor.receipt_key_id
             OR p_receipt->>'result' NOT IN ('deletion_succeeded','idempotent_replay','rejected')
             OR (p_receipt->>'kms_request_id') IS NOT NULL
             OR coalesce(p_receipt->>'transaction_client_token','')=''
             OR (p_receipt->>'execution_completion_deadline')::timestamptz
                <>v_grant.execution_completion_deadline
             OR (p_receipt->>'record_version')::bigint<>v_operation.resource_object_version
             OR v_completed>v_grant.execution_completion_deadline+interval '5 seconds'
             OR p_receipt->>'finality_state'<>(CASE
                  WHEN p_receipt->>'result'='rejected' THEN 'not_applicable'
                  ELSE 'operationally_deleted' END)
          THEN RAISE EXCEPTION 'V3 deletion receipt differs from grant'; END IF;
          INSERT INTO lucy.executor_receipt_attestations_v2(
            id,operation_id,execution_grant_id,content_scope_id,policy_actor_binding_id,
            executor_binding_id,receipt_digest,result,serialized_receipt,completed_at,verified_at)
          VALUES(v_id,p_operation_id,v_grant.id,v_operation.content_scope_id,v_actor.id,
            v_executor.id,v_digest,p_receipt->>'result',p_receipt,v_completed,v_now);
          INSERT INTO lucy.sensitive_operation_events_v2(
            id,content_scope_id,operation_id,event_type,details,occurred_at)
          VALUES(gen_random_uuid(),v_operation.content_scope_id,p_operation_id,
            'sensitive.executor_receipt_attested',jsonb_build_object(
              'receipt_id',v_id,'receipt_digest',v_digest,
              'result',p_receipt->>'result'),v_now);
          RETURN v_digest;
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR not_null_violation OR check_violation
          THEN RAISE EXCEPTION 'malformed V3 deletion receipt';
        END $function$;

        CREATE FUNCTION lucy.reconcile_scoped_deletion_v3(p_operation_id uuid)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_manifest lucy.scoped_deletion_manifests_v3%ROWTYPE;
          v_receipt lucy.executor_receipt_attestations_v2%ROWTYPE;
          v_now timestamptz:=clock_timestamp(); v_finality timestamptz;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='sensitive_workflow' AND active
            AND allowed_actions @> '["sensitive.operation.reconcile"]'::jsonb;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id FOR UPDATE;
          IF v_operation.id IS NULL OR v_operation.action<>'evidence.delete'
          THEN RAISE EXCEPTION 'V3 deletion reconciliation unavailable'; END IF;
          IF v_operation.state IN ('FINALITY_PENDING','REJECTED') THEN
            RETURN jsonb_build_object('operation_id',v_operation.id,'state',v_operation.state,
              'result',v_operation.executor_result,'receipt_digest',v_operation.executor_receipt_digest,
              'finality_not_before',(SELECT finality_not_before
                FROM lucy.scoped_deletion_effects_v3 WHERE operation_id=v_operation.id),
              'replayed',true);
          END IF;
          SELECT * INTO STRICT v_manifest FROM lucy.scoped_deletion_manifests_v3
          WHERE operation_id=p_operation_id;
          SELECT * INTO STRICT v_receipt FROM lucy.executor_receipt_attestations_v2
          WHERE operation_id=p_operation_id AND execution_grant_id=(
            SELECT grant_id FROM lucy.scoped_deletion_execution_grants_v3
            WHERE operation_id=p_operation_id);
          IF v_receipt.result='rejected' THEN
            UPDATE lucy.sensitive_operations_v2 SET state='REJECTED',
              receipt_attestation_id=v_receipt.id,executor_receipt_digest=v_receipt.receipt_digest,
              executor_result=v_receipt.result,reconciled_at=v_now WHERE id=p_operation_id;
          ELSE
            IF v_receipt.result NOT IN ('deletion_succeeded','idempotent_replay')
               OR v_receipt.serialized_receipt->>'finality_state'<>'operationally_deleted'
            THEN RAISE EXCEPTION 'V3 deletion receipt is not effective'; END IF;
            INSERT INTO lucy.scoped_memory_candidate_tombstones_v3
            SELECT t.artifact_id,t.artifact_version,v_manifest.content_scope_id,
              p_operation_id,v_manifest.id,v_now
            FROM lucy.scoped_deletion_manifest_targets_v3 t
            WHERE t.manifest_id=v_manifest.id AND t.artifact_class='memory_candidate'
            ON CONFLICT (candidate_id,candidate_version,content_scope_id) DO NOTHING;
            INSERT INTO lucy.memory_import_outcome_tombstones_v3
            SELECT t.artifact_id,t.artifact_version,v_manifest.content_scope_id,p_operation_id,
              v_manifest.id,t.representation_id,t.wrapped_key_ref,t.key_registry_id,v_now
            FROM lucy.scoped_deletion_manifest_targets_v3 t
            WHERE t.manifest_id=v_manifest.id
              AND t.artifact_class='memory_import_provider_outcome'
            ON CONFLICT (extraction_job_id,record_version,content_scope_id) DO NOTHING;
            IF EXISTS (
              SELECT 1 FROM lucy.scoped_deletion_manifest_targets_v3 t
              LEFT JOIN lucy.scoped_memory_candidate_tombstones_v3 c
                ON c.candidate_id=t.artifact_id
                AND c.candidate_version=t.artifact_version
                AND c.content_scope_id=v_manifest.content_scope_id
              LEFT JOIN lucy.memory_import_outcome_tombstones_v3 o
                ON o.extraction_job_id=t.artifact_id
                AND o.record_version=t.artifact_version
                AND o.content_scope_id=v_manifest.content_scope_id
              WHERE t.manifest_id=v_manifest.id AND (
                (t.artifact_class='memory_candidate' AND c.candidate_id IS NULL) OR
                (t.artifact_class='memory_import_provider_outcome' AND (
                  o.extraction_job_id IS NULL OR o.representation_id<>t.representation_id
                  OR o.wrapped_key_ref<>t.wrapped_key_ref
                  OR o.key_registry_id<>t.key_registry_id)))
            ) THEN RAISE EXCEPTION 'V3 deletion tombstone reconciliation differs'; END IF;
            v_finality:=v_now+interval '30 days';
            INSERT INTO lucy.scoped_deletion_effects_v3 VALUES(
              p_operation_id,v_manifest.id,v_receipt.id,v_manifest.content_scope_id,
              v_now,v_finality,'PENDING');
            UPDATE lucy.sensitive_operations_v2 SET state='FINALITY_PENDING',
              receipt_attestation_id=v_receipt.id,executor_receipt_digest=v_receipt.receipt_digest,
              executor_result=v_receipt.result,reconciled_at=v_now WHERE id=p_operation_id;
          END IF;
          INSERT INTO lucy.sensitive_operation_events_v2(
            id,content_scope_id,operation_id,event_type,details,occurred_at)
          VALUES(gen_random_uuid(),v_operation.content_scope_id,p_operation_id,
            'sensitive.operation_reconciled',jsonb_build_object(
              'receipt_attestation_id',v_receipt.id,
              'receipt_digest',v_receipt.receipt_digest,'result',v_receipt.result,
              'state',(SELECT state FROM lucy.sensitive_operations_v2
                WHERE id=p_operation_id)),v_now);
          RETURN jsonb_build_object('operation_id',v_operation.id,
            'state',(SELECT state FROM lucy.sensitive_operations_v2 WHERE id=p_operation_id),
            'result',v_receipt.result,'receipt_digest',v_receipt.receipt_digest,
            'finality_not_before',v_finality,'replayed',false);
        END $function$;

        CREATE FUNCTION lucy.reject_tombstoned_memory_import_outcome_v3() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM lucy.memory_import_extraction_jobs_v1 j
            JOIN lucy.memory_import_campaigns_v1 c
              ON c.id=j.campaign_id AND c.content_scope_id=j.content_scope_id
            JOIN jsonb_array_elements_text(j.source_record_ids) source(source_record_id)
              ON true
            JOIN jsonb_array_elements(c.serialized_manifest->'records') record
              ON record->>'source_record_id'=source.source_record_id
            JOIN lucy.scoped_evidence_records_v2 e
              ON e.content_scope_id=j.content_scope_id
              AND e.idempotency_key='memory-import'||chr(58)||c.manifest_digest||chr(58)||
                (record->>'source_record_id')||chr(58)||'r'||(record->>'source_revision')
            JOIN lucy.scoped_evidence_deletion_fences_v2 f ON f.evidence_id=e.id
            WHERE j.id=NEW.extraction_job_id AND j.content_scope_id=NEW.content_scope_id
              AND coalesce((record->>'included')::boolean,false)
          )
          THEN RAISE EXCEPTION 'memory import outcome is deletion fenced'; END IF;
          RETURN NEW;
        END $function$;
        CREATE TRIGGER memory_import_outcome_v3_deletion_gate BEFORE INSERT
        ON lucy.memory_import_provider_outcomes_v1 FOR EACH ROW
        EXECUTE FUNCTION lucy.reject_tombstoned_memory_import_outcome_v3();

        ALTER FUNCTION lucy.read_claimed_sensitive_authority_v2(uuid)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.store_deletion_execution_grant_v3(uuid,jsonb)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.attest_deletion_executor_receipt_v3(uuid,jsonb)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.reconcile_scoped_deletion_v3(uuid)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.reject_tombstoned_memory_import_outcome_v3()
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.read_claimed_sensitive_authority_v2(uuid),
          lucy.store_deletion_execution_grant_v3(uuid,jsonb),
          lucy.attest_deletion_executor_receipt_v3(uuid,jsonb),
          lucy.reconcile_scoped_deletion_v3(uuid) FROM PUBLIC,lucy_app;
        REVOKE ALL ON lucy.scoped_deletion_execution_grants_v3,
          lucy.scoped_memory_candidate_tombstones_v3,
          lucy.memory_import_outcome_tombstones_v3,lucy.scoped_deletion_effects_v3
          FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.scoped_deletion_execution_grants_v3,
          lucy.scoped_memory_candidate_tombstones_v3,
          lucy.memory_import_outcome_tombstones_v3,lucy.scoped_deletion_effects_v3
          TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("memory deletion execution V3 requires a reviewed forward migration")
