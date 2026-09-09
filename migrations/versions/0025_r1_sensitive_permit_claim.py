"""Add realm-scoped sensitive permit issuance and workflow claim gates."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0025_r1_sensitive_permit_claim"
down_revision: str | None = "0024_r1_internal_admission"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid(
    name: str, *, primary: bool = False, nullable: bool = False, unique: bool = False
) -> sa.Column:
    return sa.Column(
        name,
        postgresql.UUID(as_uuid=True),
        primary_key=primary,
        nullable=nullable,
        unique=unique,
    )


def upgrade() -> None:
    op.drop_constraint("ck_realm_service_role", "realm_service_bindings_v1", schema="lucy")
    op.create_check_constraint(
        "ck_realm_service_role",
        "realm_service_bindings_v1",
        "service_role IN ('realm_routine','realm_evidence','realm_deletion')",
        schema="lucy",
    )
    op.create_table(
        "realm_sensitive_actor_bindings_v1",
        _uuid("id", primary=True),
        sa.Column("session_login", sa.String(63), nullable=False, unique=True),
        _uuid("actor_principal_id"),
        _uuid("target_service_binding_id"),
        _uuid("content_scope_id"),
        sa.Column("actor_role", sa.String(40), nullable=False),
        sa.Column("allowed_actions", postgresql.JSONB(), nullable=False),
        sa.Column("binding_generation", sa.BigInteger(), nullable=False),
        sa.Column("node_authz_epoch", sa.BigInteger(), nullable=False),
        sa.Column("policy_version", sa.BigInteger(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["actor_principal_id"], ["lucy.principals.id"]),
        sa.ForeignKeyConstraint(
            ["target_service_binding_id"], ["lucy.realm_service_bindings_v1.id"]
        ),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.CheckConstraint(
            "actor_role IN ('policy_notary','sensitive_workflow')",
            name="ck_sensitive_actor_role",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(allowed_actions)='array' AND jsonb_array_length(allowed_actions)>0",
            name="ck_sensitive_actor_actions",
        ),
        sa.CheckConstraint("binding_generation > 0", name="ck_sensitive_actor_generation"),
        sa.CheckConstraint("node_authz_epoch > 0", name="ck_sensitive_actor_node_epoch"),
        sa.CheckConstraint("policy_version > 0", name="ck_sensitive_actor_policy_version"),
        schema="lucy",
    )
    op.create_table(
        "sensitive_action_permits_v3",
        _uuid("id", primary=True),
        _uuid("operation_id", unique=True),
        _uuid("content_scope_id"),
        _uuid("policy_actor_binding_id"),
        _uuid("target_service_binding_id"),
        _uuid("principal_id"),
        _uuid("channel_binding_id"),
        sa.Column("action", sa.String(40), nullable=False),
        _uuid("resource_object_id"),
        sa.Column("resource_object_version", sa.BigInteger(), nullable=False),
        sa.Column("permit_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("serialized_permit", postgresql.JSONB(), nullable=False),
        sa.Column("nonce", sa.String(128), nullable=False, unique=True),
        sa.Column("issuance_idempotency_key", sa.String(512), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("permit_claim_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("execution_completion_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("claim_idempotency_key", sa.String(512)),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["policy_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.ForeignKeyConstraint(
            ["target_service_binding_id"], ["lucy.realm_service_bindings_v1.id"]
        ),
        sa.ForeignKeyConstraint(["principal_id"], ["lucy.principals.id"]),
        sa.ForeignKeyConstraint(["channel_binding_id"], ["lucy.channel_bindings.id"]),
        sa.UniqueConstraint(
            "policy_actor_binding_id",
            "issuance_idempotency_key",
            name="uq_v3_permit_issuance_replay",
        ),
        sa.CheckConstraint(
            "action IN ('evidence.retrieve','evidence.delete')", name="ck_v3_permit_action"
        ),
        sa.CheckConstraint("resource_object_version > 0", name="ck_v3_permit_resource_version"),
        sa.CheckConstraint("state IN ('ISSUED','CLAIMED')", name="ck_v3_permit_state"),
        sa.CheckConstraint(
            "(state='ISSUED' AND claim_idempotency_key IS NULL AND claimed_at IS NULL) OR "
            "(state='CLAIMED' AND claim_idempotency_key IS NOT NULL AND claimed_at IS NOT NULL)",
            name="ck_v3_permit_claim_state",
        ),
        schema="lucy",
    )
    op.create_table(
        "sensitive_operations_v2",
        _uuid("id", primary=True),
        _uuid("permit_id", unique=True),
        _uuid("content_scope_id"),
        _uuid("workflow_actor_binding_id"),
        _uuid("target_service_binding_id"),
        sa.Column("action", sa.String(40), nullable=False),
        _uuid("resource_object_id"),
        sa.Column("resource_object_version", sa.BigInteger(), nullable=False),
        sa.Column("claim_idempotency_key", sa.String(512), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["permit_id"], ["lucy.sensitive_action_permits_v3.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["workflow_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.ForeignKeyConstraint(
            ["target_service_binding_id"], ["lucy.realm_service_bindings_v1.id"]
        ),
        sa.UniqueConstraint(
            "workflow_actor_binding_id",
            "claim_idempotency_key",
            name="uq_v2_sensitive_operation_claim_replay",
        ),
        sa.CheckConstraint(
            "action IN ('evidence.retrieve','evidence.delete')", name="ck_v2_sensitive_action"
        ),
        sa.CheckConstraint("resource_object_version > 0", name="ck_v2_sensitive_resource_version"),
        sa.CheckConstraint("state = 'CLAIMED'", name="ck_v2_sensitive_initial_state"),
        schema="lucy",
    )
    op.create_table(
        "sensitive_operation_events_v2",
        _uuid("id", primary=True),
        _uuid("content_scope_id"),
        _uuid("operation_id"),
        sa.Column("event_type", sa.String(60), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.CheckConstraint(
            "event_type IN ('sensitive.permit_issued','sensitive.operation_claimed')",
            name="ck_v2_sensitive_event_type",
        ),
        sa.CheckConstraint("jsonb_typeof(details)='object'", name="ck_v2_sensitive_event_details"),
        schema="lucy",
    )
    op.create_index(
        "ix_v2_sensitive_events_operation",
        "sensitive_operation_events_v2",
        ["operation_id", "occurred_at", "id"],
        schema="lucy",
    )
    op.execute(
        r"""
        CREATE TRIGGER sensitive_operation_events_v2_immutable BEFORE UPDATE OR DELETE
        ON lucy.sensitive_operation_events_v2 FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation();

        CREATE FUNCTION lucy.sensitive_actor_binding_guard_v1() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
          IF TG_OP='DELETE' OR NEW.id<>OLD.id OR NEW.session_login<>OLD.session_login
             OR NEW.actor_principal_id<>OLD.actor_principal_id
             OR NEW.target_service_binding_id<>OLD.target_service_binding_id
             OR NEW.content_scope_id<>OLD.content_scope_id OR NEW.actor_role<>OLD.actor_role
             OR NEW.allowed_actions<>OLD.allowed_actions
             OR NEW.node_authz_epoch<>OLD.node_authz_epoch
             OR NEW.policy_version<>OLD.policy_version OR NEW.created_at<>OLD.created_at
             OR NOT OLD.active OR NEW.active OR NEW.binding_generation<>OLD.binding_generation+1
          THEN RAISE EXCEPTION 'sensitive actor binding mutation unavailable'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER sensitive_actor_binding_monotonic BEFORE UPDATE OR DELETE
        ON lucy.realm_sensitive_actor_bindings_v1
        FOR EACH ROW EXECUTE FUNCTION lucy.sensitive_actor_binding_guard_v1();

        CREATE FUNCTION lucy.sensitive_permit_guard_v3() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
          IF TG_OP='DELETE' OR NEW.id<>OLD.id OR NEW.operation_id<>OLD.operation_id
             OR NEW.content_scope_id<>OLD.content_scope_id
             OR NEW.policy_actor_binding_id<>OLD.policy_actor_binding_id
             OR NEW.target_service_binding_id<>OLD.target_service_binding_id
             OR NEW.principal_id<>OLD.principal_id
             OR NEW.channel_binding_id<>OLD.channel_binding_id OR NEW.action<>OLD.action
             OR NEW.resource_object_id<>OLD.resource_object_id
             OR NEW.resource_object_version<>OLD.resource_object_version
             OR NEW.permit_digest<>OLD.permit_digest
             OR NEW.serialized_permit<>OLD.serialized_permit OR NEW.nonce<>OLD.nonce
             OR NEW.issuance_idempotency_key<>OLD.issuance_idempotency_key
             OR NEW.issued_at<>OLD.issued_at
             OR NEW.permit_claim_deadline<>OLD.permit_claim_deadline
             OR NEW.execution_completion_deadline<>OLD.execution_completion_deadline
             OR NEW.created_at<>OLD.created_at OR OLD.state<>'ISSUED' OR NEW.state<>'CLAIMED'
             OR OLD.claim_idempotency_key IS NOT NULL OR NEW.claim_idempotency_key IS NULL
             OR OLD.claimed_at IS NOT NULL OR NEW.claimed_at IS NULL
          THEN RAISE EXCEPTION 'sensitive permit mutation unavailable'; END IF;
          RETURN NEW;
        END
        $function$;
        CREATE TRIGGER sensitive_permit_monotonic BEFORE UPDATE OR DELETE
        ON lucy.sensitive_action_permits_v3
        FOR EACH ROW EXECUTE FUNCTION lucy.sensitive_permit_guard_v3();

        CREATE TRIGGER sensitive_operations_v2_immutable BEFORE UPDATE OR DELETE
        ON lucy.sensitive_operations_v2 FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation();
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.normalize_security_contract_v2(p_contract jsonb) RETURNS jsonb
        LANGUAGE plpgsql IMMUTABLE STRICT
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE v_result jsonb := p_contract; v_name text; v_timestamp timestamptz;
        BEGIN
          FOREACH v_name IN ARRAY ARRAY[
            'issued_at','expires_at','permit_claim_deadline','execution_completion_deadline',
            'completed_at','auth_time'
          ] LOOP
            IF v_result ? v_name THEN
              IF jsonb_typeof(v_result->v_name) <> 'string' THEN
                RAISE EXCEPTION 'canonical contract timestamp must be a string';
              END IF;
              v_timestamp := (v_result->>v_name)::timestamptz;
              v_result := jsonb_set(v_result,ARRAY[v_name],to_jsonb(to_char(
                v_timestamp AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')));
            END IF;
          END LOOP;
          RETURN v_result;
        END
        $function$;

        CREATE FUNCTION lucy.security_contract_digest_v2(p_contract jsonb) RETURNS text
        LANGUAGE sql IMMUTABLE STRICT
        SET search_path = pg_catalog, pg_temp
        AS $function$
          SELECT encode(public.digest(
            convert_to('LUCY-SIGNED-CONTRACT','UTF8') || decode('00','hex') ||
            convert_to(lucy.canonical_jsonb_v1(
              lucy.normalize_security_contract_v2(p_contract) - 'signature'),'UTF8'),
            'sha256'),'hex')
        $function$;
        """
    )
    for signature in (
        "lucy.normalize_security_contract_v2(jsonb)",
        "lucy.security_contract_digest_v2(jsonb)",
    ):
        op.execute(
            f"ALTER FUNCTION {signature} OWNER TO lucy_security_function_owner; "
            f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC, lucy_app"
        )
    op.execute(
        r"""
        CREATE FUNCTION lucy.issue_sensitive_action_permit_v3(
          p_permit jsonb, p_issuance_idempotency_key text
        ) RETURNS uuid
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_now timestamptz := clock_timestamp();
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_target lucy.realm_service_bindings_v1%ROWTYPE;
          v_scope lucy.realm_content_scopes_v1%ROWTYPE;
          v_existing lucy.sensitive_action_permits_v3%ROWTYPE;
          v_permit_id uuid; v_operation_id uuid; v_principal_id uuid;
          v_channel_id uuid; v_resource_id uuid; v_action text; v_reason text;
          v_issued_at timestamptz; v_claim_deadline timestamptz;
          v_execution_deadline timestamptz; v_digest text;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["sensitive.permit.issue"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'sensitive permit issuance unavailable'; END IF;
          SELECT * INTO STRICT v_target FROM lucy.realm_service_bindings_v1
          WHERE id=v_actor.target_service_binding_id AND content_scope_id=v_actor.content_scope_id;
          SELECT * INTO STRICT v_scope FROM lucy.realm_content_scopes_v1
          WHERE id=v_actor.content_scope_id;
          IF p_issuance_idempotency_key IS NULL OR btrim(p_issuance_idempotency_key)=''
             OR length(p_issuance_idempotency_key)>512 OR jsonb_typeof(p_permit)<>'object'
          THEN RAISE EXCEPTION 'invalid v1.3 permit issuance request'; END IF;
          IF p_permit - ARRAY[
            'canonicalization_version','signature_algorithm','signing_key_purpose','key_id',
            'issuer','environment','issued_at','signature','contract_version','object_type',
            'permit_id','action','reason','principal_id','service_principal_id',
            'service_binding_id','service_binding_generation','operation_id','target_scope',
            'workspace_id','resource_selector',
            'execution_binding','restore_mapping_id','owner_assertion_id',
            'owner_assertion_digest','approval_digest','policy_version','membership_generation',
            'channel_binding_id','channel_generation','grant_generation','permit_claim_deadline',
            'execution_completion_deadline','max_records','max_bytes','nonce'
          ] <> '{}'::jsonb THEN RAISE EXCEPTION 'V3 permit contains unknown fields'; END IF;
          IF p_permit->>'contract_version'<>'3'
             OR p_permit->>'object_type'<>'lucy.sensitive-action-permit.v3'
             OR p_permit->>'canonicalization_version'<>'lucy-cjson-1'
             OR p_permit->>'signature_algorithm'<>'Ed25519'
             OR p_permit->>'signing_key_purpose'<>'policy_notary_v13'
             OR coalesce(p_permit->>'signature','')=''
             OR length(p_permit->>'nonce') NOT BETWEEN 32 AND 128
          THEN RAISE EXCEPTION 'invalid V3 permit contract domain'; END IF;

          v_permit_id := (p_permit->>'permit_id')::uuid;
          v_operation_id := (p_permit->>'operation_id')::uuid;
          v_principal_id := (p_permit->>'principal_id')::uuid;
          v_channel_id := (p_permit->>'channel_binding_id')::uuid;
          v_resource_id := (p_permit->'resource_selector'->>'object_id')::uuid;
          v_action := p_permit->>'action'; v_reason := p_permit->>'reason';
          v_issued_at := (p_permit->>'issued_at')::timestamptz;
          v_claim_deadline := (p_permit->>'permit_claim_deadline')::timestamptz;
          v_execution_deadline := (p_permit->>'execution_completion_deadline')::timestamptz;
          v_digest := lucy.security_contract_digest_v2(p_permit);

          IF NOT v_actor.active OR NOT v_target.active
             OR v_actor.node_authz_epoch<>v_target.node_authz_epoch
             OR v_actor.policy_version<>v_target.policy_version
             OR (p_permit->>'service_principal_id')::uuid<>v_target.service_principal_id
             OR (p_permit->>'service_binding_id')::uuid<>v_target.id
             OR (p_permit->>'service_binding_generation')::bigint<>v_target.binding_generation
             OR NOT v_target.allowed_actions @> jsonb_build_array(v_action)
             OR (p_permit->>'workspace_id')::uuid<>v_scope.workspace_id
             OR (p_permit->'target_scope'->>'tenant_account_id')::uuid<>v_scope.tenant_account_id
             OR (p_permit->'target_scope'->>'node_id')::uuid<>v_scope.node_id
             OR (p_permit->'target_scope'->>'node_tenure_id')::uuid<>v_scope.node_tenure_id
             OR (p_permit->'target_scope'->>'tenure_epoch')::bigint<>v_scope.tenure_epoch
             OR (p_permit->'target_scope'->>'security_realm_id')::uuid<>v_scope.security_realm_id
             OR (p_permit->'target_scope'->>'storage_epoch')::bigint<>v_scope.storage_epoch
             OR (p_permit->'execution_binding'->>'deployment_id')::uuid<>v_scope.deployment_id
             OR (p_permit->'execution_binding'->>'active_realm_id')::uuid<>v_scope.security_realm_id
             OR (p_permit->'execution_binding'->>'active_storage_epoch')::bigint
                <>v_scope.storage_epoch
             OR (p_permit->>'restore_mapping_id') IS NOT NULL
             OR (p_permit->'resource_selector'->>'selector_type')<>'exact_object'
             OR (p_permit->'resource_selector'->>'object_version')::bigint<1
          THEN RAISE EXCEPTION 'V3 permit scope is unavailable'; END IF;
          IF NOT EXISTS (
            SELECT 1 FROM lucy.principals p
            JOIN lucy.node_memberships m
              ON m.principal_id=p.id AND m.workspace_id=v_scope.workspace_id
            JOIN lucy.channel_bindings ch
              ON ch.id=v_channel_id AND ch.workspace_id=v_scope.workspace_id
            JOIN lucy.nodes n ON n.id=v_scope.node_id
            JOIN lucy.node_tenures nt ON nt.id=v_scope.node_tenure_id
            JOIN lucy.realm_bindings rb ON rb.id=v_scope.realm_binding_id
            WHERE p.id=v_principal_id AND p.status='active' AND m.status='active' AND m.role='owner'
              AND m.generation=(p_permit->>'membership_generation')::bigint
              AND ch.active AND ch.channel_kind='internal'
              AND ch.generation=(p_permit->>'channel_generation')::bigint
              AND n.authz_epoch=(p_permit->'execution_binding'->>'node_authz_epoch')::bigint
              AND n.authz_epoch=v_target.node_authz_epoch
              AND nt.sequence=v_scope.tenure_epoch AND nt.ends_at IS NULL
              AND rb.valid_to IS NULL
              AND rb.binding_version=
                  (p_permit->'execution_binding'->>'realm_binding_generation')::bigint
              AND v_target.policy_version=(p_permit->>'policy_version')::bigint
          ) THEN RAISE EXCEPTION 'V3 permit authority is unavailable'; END IF;
          IF v_issued_at>v_now+interval '30 seconds' OR v_claim_deadline<=v_now
             OR v_claim_deadline>v_issued_at+interval '60 seconds'
             OR v_execution_deadline<=v_claim_deadline
             OR v_execution_deadline>v_issued_at+interval '10 minutes'
          THEN RAISE EXCEPTION 'V3 permit deadline is unavailable'; END IF;
          IF v_action='evidence.retrieve' THEN
            IF v_reason NOT IN (
              'verify_exact_wording','resolve_ambiguity','recover_missing_context','owner_review'
            )
               OR (p_permit->>'max_records')::int<>1
               OR (p_permit->>'max_bytes')::int NOT BETWEEN 1 AND 65536
            THEN RAISE EXCEPTION 'V3 retrieval permit is invalid'; END IF;
          ELSIF v_action='evidence.delete' THEN
            IF v_reason NOT IN ('owner_request','sensitive_data','retention_expired')
               OR (p_permit->>'max_records')::int NOT BETWEEN 1 AND 90
               OR (p_permit->>'max_bytes')::int NOT BETWEEN 1 AND 131072
            THEN RAISE EXCEPTION 'V3 deletion permit is invalid'; END IF;
          ELSE RAISE EXCEPTION 'unsupported V3 sensitive action'; END IF;

          PERFORM pg_advisory_xact_lock(hashtextextended(
            v_actor.id::text||':'||p_issuance_idempotency_key,0));
          SELECT * INTO v_existing FROM lucy.sensitive_action_permits_v3
          WHERE policy_actor_binding_id=v_actor.id
            AND issuance_idempotency_key=p_issuance_idempotency_key;
          IF FOUND THEN
            IF v_existing.id<>v_permit_id OR v_existing.serialized_permit<>p_permit
            THEN RAISE EXCEPTION 'V3 permit issuance idempotency conflict'; END IF;
            RETURN v_existing.id;
          END IF;
          INSERT INTO lucy.sensitive_action_permits_v3(
            id,operation_id,content_scope_id,policy_actor_binding_id,target_service_binding_id,
            principal_id,channel_binding_id,action,resource_object_id,resource_object_version,
            permit_digest,serialized_permit,nonce,issuance_idempotency_key,issued_at,
            permit_claim_deadline,execution_completion_deadline,state,created_at
          ) VALUES (
            v_permit_id,v_operation_id,v_scope.id,v_actor.id,v_target.id,v_principal_id,
            v_channel_id,v_action,v_resource_id,
            (p_permit->'resource_selector'->>'object_version')::bigint,v_digest,p_permit,
            p_permit->>'nonce',p_issuance_idempotency_key,v_issued_at,v_claim_deadline,
            v_execution_deadline,'ISSUED',v_now
          );
          INSERT INTO lucy.sensitive_operation_events_v2(
            id,content_scope_id,operation_id,event_type,details,occurred_at
          ) VALUES (public.gen_random_uuid(),v_scope.id,v_operation_id,'sensitive.permit_issued',
            jsonb_build_object('permit_id',v_permit_id,'permit_digest',v_digest,'action',v_action),v_now);
          RETURN v_permit_id;
        EXCEPTION WHEN invalid_text_representation OR not_null_violation OR check_violation
          THEN RAISE EXCEPTION 'malformed V3 permit contract';
        END
        $function$;

        CREATE FUNCTION lucy.claim_sensitive_operation_v2(
          p_permit_id uuid, p_claim_idempotency_key text
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_now timestamptz := clock_timestamp();
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_target lucy.realm_service_bindings_v1%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v3%ROWTYPE;
          v_existing lucy.sensitive_operations_v2%ROWTYPE;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='sensitive_workflow' AND active
            AND allowed_actions @> '["sensitive.operation.claim"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'sensitive operation claim unavailable'; END IF;
          IF p_claim_idempotency_key IS NULL OR btrim(p_claim_idempotency_key)=''
             OR length(p_claim_idempotency_key)>512
          THEN RAISE EXCEPTION 'invalid sensitive operation claim'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            v_actor.id::text||':'||p_permit_id::text,0));
          SELECT * INTO v_permit FROM lucy.sensitive_action_permits_v3
          WHERE id=p_permit_id FOR UPDATE;
          IF NOT FOUND OR v_permit.content_scope_id<>v_actor.content_scope_id
             OR v_permit.target_service_binding_id<>v_actor.target_service_binding_id
          THEN RAISE EXCEPTION 'sensitive operation claim unavailable'; END IF;
          SELECT * INTO STRICT v_target FROM lucy.realm_service_bindings_v1
          WHERE id=v_actor.target_service_binding_id AND content_scope_id=v_actor.content_scope_id;
          SELECT * INTO v_existing FROM lucy.sensitive_operations_v2 WHERE permit_id=p_permit_id;
          IF FOUND THEN
            IF v_existing.workflow_actor_binding_id<>v_actor.id
               OR v_existing.claim_idempotency_key<>p_claim_idempotency_key
            THEN RAISE EXCEPTION 'sensitive operation claim idempotency conflict'; END IF;
            RETURN jsonb_build_object('operation_id',v_existing.id,'replayed',true);
          END IF;
          IF NOT v_target.active OR v_actor.node_authz_epoch<>v_target.node_authz_epoch
             OR v_actor.policy_version<>v_target.policy_version
             OR (v_permit.serialized_permit->>'service_binding_generation')::bigint
                <>v_target.binding_generation
             OR NOT v_target.allowed_actions @> jsonb_build_array(v_permit.action)
             OR v_now>v_permit.permit_claim_deadline
          THEN RAISE EXCEPTION 'sensitive operation claim authority is stale'; END IF;
          IF NOT EXISTS (
            SELECT 1 FROM lucy.realm_content_scopes_v1 cs
            JOIN lucy.principals p
              ON p.id=v_permit.principal_id AND p.status='active'
            JOIN lucy.node_memberships m
              ON m.principal_id=p.id AND m.workspace_id=cs.workspace_id
            JOIN lucy.channel_bindings ch
              ON ch.id=v_permit.channel_binding_id AND ch.workspace_id=cs.workspace_id
            JOIN lucy.nodes n ON n.id=cs.node_id
            JOIN lucy.node_tenures nt ON nt.id=cs.node_tenure_id
            JOIN lucy.realm_bindings rb ON rb.id=cs.realm_binding_id
            WHERE cs.id=v_permit.content_scope_id AND m.status='active' AND m.role='owner'
              AND m.generation=
                  (v_permit.serialized_permit->>'membership_generation')::bigint
              AND ch.active AND ch.channel_kind='internal'
              AND ch.generation=
                  (v_permit.serialized_permit->>'channel_generation')::bigint
              AND n.authz_epoch=
                  (v_permit.serialized_permit->'execution_binding'->>'node_authz_epoch')::bigint
              AND nt.sequence=cs.tenure_epoch AND nt.ends_at IS NULL
              AND rb.valid_to IS NULL
              AND rb.binding_version=(v_permit.serialized_permit->'execution_binding'
                  ->>'realm_binding_generation')::bigint
          ) THEN RAISE EXCEPTION 'sensitive operation claim authority is stale'; END IF;
          IF v_permit.state<>'ISSUED' THEN
            RAISE EXCEPTION 'sensitive permit is not claimable';
          END IF;
          INSERT INTO lucy.sensitive_operations_v2(
            id,permit_id,content_scope_id,workflow_actor_binding_id,target_service_binding_id,
            action,resource_object_id,resource_object_version,claim_idempotency_key,state,claimed_at
          ) VALUES (
            v_permit.operation_id,v_permit.id,v_permit.content_scope_id,v_actor.id,
            v_permit.target_service_binding_id,v_permit.action,v_permit.resource_object_id,
            v_permit.resource_object_version,p_claim_idempotency_key,'CLAIMED',v_now
          );
          UPDATE lucy.sensitive_action_permits_v3 SET state='CLAIMED',
            claim_idempotency_key=p_claim_idempotency_key,claimed_at=v_now
          WHERE id=v_permit.id;
          INSERT INTO lucy.sensitive_operation_events_v2(
            id,content_scope_id,operation_id,event_type,details,occurred_at
          ) VALUES (public.gen_random_uuid(),v_permit.content_scope_id,v_permit.operation_id,
            'sensitive.operation_claimed',jsonb_build_object(
              'permit_id',v_permit.id,'workflow_actor_binding_id',v_actor.id),v_now);
          RETURN jsonb_build_object('operation_id',v_permit.operation_id,'replayed',false);
        END
        $function$;
        """
    )
    for signature in (
        "lucy.issue_sensitive_action_permit_v3(jsonb,text)",
        "lucy.claim_sensitive_operation_v2(uuid,text)",
    ):
        op.execute(
            f"ALTER FUNCTION {signature} OWNER TO lucy_security_function_owner; "
            f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC, lucy_app"
        )
    op.execute(
        "GRANT SELECT ON lucy.realm_content_scopes_v1, lucy.realm_service_bindings_v1, "
        "lucy.realm_sensitive_actor_bindings_v1, lucy.principals, lucy.node_memberships, "
        "lucy.channel_bindings, lucy.nodes, lucy.node_tenures, lucy.realm_bindings "
        "TO lucy_security_function_owner; "
        "GRANT SELECT, INSERT, UPDATE ON lucy.sensitive_action_permits_v3 "
        "TO lucy_security_function_owner; "
        "GRANT SELECT, INSERT ON lucy.sensitive_operations_v2, lucy.sensitive_operation_events_v2 "
        "TO lucy_security_function_owner; "
        "REVOKE ALL ON lucy.realm_sensitive_actor_bindings_v1, lucy.sensitive_action_permits_v3, "
        "lucy.sensitive_operations_v2, lucy.sensitive_operation_events_v2 FROM lucy_app"
    )


def downgrade() -> None:
    raise RuntimeError("R1 sensitive permit claims require a reviewed forward migration")
