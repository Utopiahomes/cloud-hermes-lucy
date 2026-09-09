"""Add realm-scoped post-claim execution grant admission."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0027_r1_execution_grant"
down_revision: str | None = "0026_r1_scoped_archive_package"
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
    op.create_table(
        "realm_executor_bindings_v2",
        _uuid("id", primary=True),
        _uuid("content_scope_id"),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("caller_identity", sa.String(512), nullable=False),
        sa.Column("executor_identity", sa.String(512), nullable=False),
        sa.Column("executor_alias_arn", sa.String(300), nullable=False),
        sa.Column("executor_version", sa.BigInteger(), nullable=False),
        sa.Column("receipt_key_id", sa.String(512), nullable=False),
        sa.Column("binding_generation", sa.BigInteger(), nullable=False),
        sa.Column("node_authz_epoch", sa.BigInteger(), nullable=False),
        sa.Column("policy_version", sa.BigInteger(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.CheckConstraint(
            "action IN ('evidence.retrieve','evidence.delete')", name="ck_v2_executor_action"
        ),
        sa.CheckConstraint("executor_version>0", name="ck_v2_executor_version"),
        sa.CheckConstraint("binding_generation>0", name="ck_v2_executor_generation"),
        sa.CheckConstraint("node_authz_epoch>0", name="ck_v2_executor_node_epoch"),
        sa.CheckConstraint("policy_version>0", name="ck_v2_executor_policy_version"),
        schema="lucy",
    )
    op.create_index(
        "uq_v2_active_realm_executor",
        "realm_executor_bindings_v2",
        ["content_scope_id", "action"],
        unique=True,
        postgresql_where=sa.text("active"),
        schema="lucy",
    )
    op.create_table(
        "sensitive_execution_grants_v2",
        _uuid("id", primary=True),
        _uuid("operation_id", unique=True),
        _uuid("permit_id", unique=True),
        _uuid("content_scope_id"),
        _uuid("policy_actor_binding_id"),
        _uuid("executor_binding_id"),
        sa.Column("package_digest", sa.String(64), nullable=False),
        sa.Column("grant_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("serialized_grant", postgresql.JSONB(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("execution_completion_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["operation_id"], ["lucy.sensitive_operations_v2.id"]),
        sa.ForeignKeyConstraint(["permit_id"], ["lucy.sensitive_action_permits_v3.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["policy_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.ForeignKeyConstraint(
            ["executor_binding_id"], ["lucy.realm_executor_bindings_v2.id"]
        ),
        schema="lucy",
    )
    op.execute(
        "CREATE TRIGGER realm_executor_bindings_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.realm_executor_bindings_v2 FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation(); "
        "CREATE TRIGGER sensitive_execution_grants_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.sensitive_execution_grants_v2 FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.drop_constraint(
        "ck_v2_sensitive_event_type", "sensitive_operation_events_v2", schema="lucy"
    )
    op.create_check_constraint(
        "ck_v2_sensitive_event_type",
        "sensitive_operation_events_v2",
        "event_type IN ('sensitive.permit_issued','sensitive.operation_claimed',"
        "'sensitive.execution_granted')",
        schema="lucy",
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.store_sensitive_execution_grant_v2(
          p_operation_id uuid, p_grant jsonb
        ) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_now timestamptz:=clock_timestamp();
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v3%ROWTYPE;
          v_package lucy.sensitive_operation_packages_v2%ROWTYPE;
          v_executor lucy.realm_executor_bindings_v2%ROWTYPE;
          v_existing lucy.sensitive_execution_grants_v2%ROWTYPE;
          v_scope lucy.realm_content_scopes_v1%ROWTYPE;
          v_grant_id uuid; v_digest text; v_issued_at timestamptz; v_package_size bigint;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.grant.issue"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'execution grant admission unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id;
          IF NOT FOUND OR v_operation.state<>'CLAIMED'
          THEN RAISE EXCEPTION 'execution grant admission unavailable'; END IF;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v3
          WHERE id=v_operation.permit_id AND state='CLAIMED';
          SELECT * INTO STRICT v_package FROM lucy.sensitive_operation_packages_v2
          WHERE operation_id=v_operation.id AND permit_id=v_permit.id;
          SELECT * INTO STRICT v_scope FROM lucy.realm_content_scopes_v1
          WHERE id=v_operation.content_scope_id;
          SELECT * INTO v_executor FROM lucy.realm_executor_bindings_v2
          WHERE content_scope_id=v_scope.id AND action=v_operation.action AND active;
          IF NOT FOUND OR v_executor.node_authz_epoch<>v_actor.node_authz_epoch
             OR v_executor.policy_version<>v_actor.policy_version
          THEN RAISE EXCEPTION 'qualified executor binding unavailable'; END IF;
          SELECT * INTO v_existing FROM lucy.sensitive_execution_grants_v2
          WHERE operation_id=p_operation_id;
          IF FOUND THEN
            IF v_existing.serialized_grant=p_grant THEN RETURN v_existing.grant_digest; END IF;
            RAISE EXCEPTION 'execution grant replay differs';
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
          ]<>'{}'::jsonb THEN RAISE EXCEPTION 'V2 execution grant contains unknown fields'; END IF;
          v_grant_id:=(p_grant->>'grant_id')::uuid;
          v_issued_at:=(p_grant->>'issued_at')::timestamptz;
          v_digest:=lucy.security_contract_digest_v2(p_grant);
          v_package_size:=octet_length(convert_to(
            lucy.canonical_jsonb_v1(v_package.serialized_package),'UTF8'));
          IF p_grant->>'contract_version'<>'2'
             OR p_grant->>'object_type'<>'lucy.sensitive-execution-grant.v2'
             OR p_grant->>'canonicalization_version'<>'lucy-cjson-1'
             OR p_grant->>'signature_algorithm'<>'Ed25519'
             OR p_grant->>'signing_key_purpose'<>'policy_notary_v13'
             OR coalesce(p_grant->>'signature','')=''
             OR v_issued_at>v_now+interval '5 seconds'
             OR v_issued_at>v_permit.permit_claim_deadline+interval '5 seconds'
             OR v_now>v_permit.execution_completion_deadline
             OR (p_grant->>'permit_claimed_at')::timestamptz<>v_operation.claimed_at
             OR (p_grant->>'permit_claim_deadline')::timestamptz<>v_permit.permit_claim_deadline
             OR (p_grant->>'execution_completion_deadline')::timestamptz
                <>v_permit.execution_completion_deadline
             OR (p_grant->>'grant_id') IS NULL OR p_grant->>'action'<>v_operation.action
             OR (p_grant->>'permit_id')::uuid<>v_permit.id
             OR p_grant->>'permit_digest'<>v_permit.permit_digest
             OR (p_grant->>'operation_id')::uuid<>v_operation.id
             OR p_grant->>'caller_identity'<>v_executor.caller_identity
             OR (p_grant->>'workspace_id')::uuid<>v_scope.workspace_id
             OR p_grant->'target_scope'<>v_permit.serialized_permit->'target_scope'
             OR p_grant->'resource_selector'<>v_permit.serialized_permit->'resource_selector'
             OR p_grant->'execution_binding'<>v_permit.serialized_permit->'execution_binding'
             OR (p_grant->>'restore_mapping_id') IS NOT NULL
             OR (p_grant->>'deletion_manifest_id') IS NOT NULL
             OR (p_grant->>'deletion_manifest_digest') IS NOT NULL
             OR p_grant->>'encrypted_package_digest'<>v_package.package_digest
             OR (p_grant->>'package_size_bytes')::bigint<>v_package_size
             OR (p_grant->>'package_size_bytes')::bigint>(p_grant->>'max_bytes')::bigint
             OR p_grant->>'idempotency_key'<>v_operation.claim_idempotency_key
             OR p_grant->>'executor_identity'<>v_executor.executor_identity
             OR p_grant->>'executor_alias_arn'<>v_executor.executor_alias_arn
             OR (p_grant->>'executor_version')::bigint<>v_executor.executor_version
             OR (p_grant->>'max_records')::bigint<>1
             OR (p_grant->>'max_bytes')::bigint<>(v_permit.serialized_permit->>'max_bytes')::bigint
          THEN RAISE EXCEPTION 'execution grant differs from claimed authority'; END IF;
          IF NOT EXISTS (
            SELECT 1 FROM lucy.principals p
            JOIN lucy.node_memberships m ON m.principal_id=p.id
              AND m.workspace_id=v_scope.workspace_id
            JOIN lucy.channel_bindings ch ON ch.id=v_permit.channel_binding_id
              AND ch.workspace_id=v_scope.workspace_id
            JOIN lucy.nodes n ON n.id=v_scope.node_id
            JOIN lucy.node_tenures nt ON nt.id=v_scope.node_tenure_id
            JOIN lucy.realm_bindings rb ON rb.id=v_scope.realm_binding_id
            JOIN lucy.realm_service_bindings_v1 sb ON sb.id=v_operation.target_service_binding_id
            WHERE p.id=v_permit.principal_id AND p.status='active'
              AND m.status='active' AND m.role='owner'
              AND m.generation=(v_permit.serialized_permit->>'membership_generation')::bigint
              AND ch.active AND ch.channel_kind='internal'
              AND ch.generation=(v_permit.serialized_permit->>'channel_generation')::bigint
              AND n.authz_epoch=v_actor.node_authz_epoch
              AND nt.ends_at IS NULL AND nt.sequence=v_scope.tenure_epoch
              AND rb.valid_to IS NULL AND rb.binding_version=
                (v_permit.serialized_permit->'execution_binding'->>'realm_binding_generation')::bigint
              AND sb.active AND sb.content_scope_id=v_scope.id
              AND sb.binding_generation=
                (v_permit.serialized_permit->>'service_binding_generation')::bigint
              AND sb.node_authz_epoch=v_actor.node_authz_epoch
              AND sb.policy_version=v_actor.policy_version
          ) THEN RAISE EXCEPTION 'execution grant current authority is unavailable'; END IF;
          INSERT INTO lucy.sensitive_execution_grants_v2(
            id,operation_id,permit_id,content_scope_id,policy_actor_binding_id,
            executor_binding_id,package_digest,grant_digest,serialized_grant,issued_at,
            execution_completion_deadline,created_at
          ) VALUES (v_grant_id,v_operation.id,v_permit.id,v_scope.id,v_actor.id,
            v_executor.id,v_package.package_digest,v_digest,p_grant,v_issued_at,
            v_permit.execution_completion_deadline,v_now);
          INSERT INTO lucy.sensitive_operation_events_v2(
            id,content_scope_id,operation_id,event_type,details,occurred_at
          ) VALUES (gen_random_uuid(),v_scope.id,v_operation.id,'sensitive.execution_granted',
            jsonb_build_object('grant_id',v_grant_id,'grant_digest',v_digest,
              'executor_binding_id',v_executor.id),v_now);
          RETURN v_digest;
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR not_null_violation OR check_violation
          THEN RAISE EXCEPTION 'malformed V2 execution grant';
        END
        $function$;
        ALTER FUNCTION lucy.store_sensitive_execution_grant_v2(uuid,jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.store_sensitive_execution_grant_v2(uuid,jsonb)
          FROM PUBLIC, lucy_app;
        GRANT SELECT ON lucy.realm_executor_bindings_v2,
          lucy.sensitive_execution_grants_v2 TO lucy_security_function_owner;
        GRANT INSERT ON lucy.sensitive_execution_grants_v2 TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("R1 scoped execution grants require a reviewed forward migration")
