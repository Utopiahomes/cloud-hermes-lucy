"""Add durable intent/outcome/reconciliation for realm archive capture."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0038_r1_archive_commit_protocol"
down_revision: str | None = "0037_r1_scoped_capture"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid(name: str, *, primary: bool = False) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), primary_key=primary, nullable=False)


def upgrade() -> None:
    op.create_table(
        "scoped_archive_intents_v1",
        _uuid("operation_id", primary=True),
        _uuid("content_scope_id"),
        _uuid("archive_actor_binding_id"),
        sa.Column("source_conversation_id", sa.String(512), nullable=False),
        sa.Column("source_turn_id", sa.String(512), nullable=False),
        sa.Column("idempotency_key", sa.String(512), nullable=False),
        sa.Column("request_commitment", sa.CHAR(64), nullable=False),
        _uuid("evidence_id"),
        _uuid("representation_id"),
        _uuid("wrapped_key_ref"),
        sa.Column("content_classification", sa.String(200), nullable=False),
        sa.Column("lineage_refs", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["archive_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.UniqueConstraint(
            "archive_actor_binding_id", "idempotency_key", name="uq_scoped_archive_intent_replay"
        ),
        sa.UniqueConstraint("evidence_id", name="uq_scoped_archive_intent_evidence"),
        sa.UniqueConstraint("representation_id", name="uq_scoped_archive_intent_representation"),
        sa.UniqueConstraint("wrapped_key_ref", name="uq_scoped_archive_intent_key_ref"),
        sa.CheckConstraint(
            "request_commitment ~ '^[0-9a-f]{64}$'", name="ck_scoped_archive_request_digest"
        ),
        schema="lucy",
    )
    op.create_table(
        "scoped_archive_aws_outcomes_v1",
        _uuid("operation_id", primary=True),
        sa.Column("envelope", postgresql.JSONB(), nullable=False),
        sa.Column("envelope_digest", sa.CHAR(64), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["operation_id"], ["lucy.scoped_archive_intents_v1.operation_id"]
        ),
        sa.CheckConstraint(
            "envelope_digest ~ '^[0-9a-f]{64}$'", name="ck_scoped_archive_envelope_digest"
        ),
        schema="lucy",
    )
    op.create_table(
        "scoped_archive_reconciliations_v1",
        _uuid("operation_id", primary=True),
        sa.Column("result", postgresql.JSONB(), nullable=False),
        sa.Column("result_digest", sa.CHAR(64), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["operation_id"], ["lucy.scoped_archive_intents_v1.operation_id"]
        ),
        sa.CheckConstraint(
            "result_digest ~ '^[0-9a-f]{64}$'", name="ck_scoped_archive_result_digest"
        ),
        schema="lucy",
    )
    for table in (
        "scoped_archive_intents_v1",
        "scoped_archive_aws_outcomes_v1",
        "scoped_archive_reconciliations_v1",
    ):
        op.execute(
            f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON lucy.{table} "
            f"FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
        )

    op.execute(
        r"""
        CREATE FUNCTION lucy.claim_capturable_scoped_archive_v1(
          p_source_conversation_id text, p_source_turn_id text,
          p_idempotency_key text, p_request_commitment text,
          p_content_classification text, p_lineage_refs jsonb
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_receipt lucy.scoped_capture_receipts_v1%ROWTYPE;
          v_state lucy.scoped_capture_states_v1%ROWTYPE;
          v_intent lucy.scoped_archive_intents_v1%ROWTYPE;
          v_stage text;
          v_replayed boolean:=false;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='archive_writer' AND active
            AND allowed_actions @> '["evidence.archive"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped archive claim unavailable'; END IF;
          IF p_source_conversation_id IS NULL OR btrim(p_source_conversation_id)=''
             OR length(p_source_conversation_id)>512 OR p_source_turn_id IS NULL
             OR btrim(p_source_turn_id)='' OR length(p_source_turn_id)>512
             OR p_idempotency_key IS NULL OR btrim(p_idempotency_key)=''
             OR length(p_idempotency_key)>512
             OR p_request_commitment !~ '^[0-9a-f]{64}$'
             OR p_content_classification IS NULL OR btrim(p_content_classification)=''
             OR length(p_content_classification)>200
             OR jsonb_typeof(p_lineage_refs)<>'array'
             OR jsonb_array_length(p_lineage_refs)>32
             OR (SELECT count(*) FROM jsonb_array_elements_text(p_lineage_refs))
                <>(SELECT count(DISTINCT value) FROM jsonb_array_elements_text(p_lineage_refs))
          THEN RAISE EXCEPTION 'scoped archive claim is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            v_actor.id::text||':'||p_idempotency_key,0));
          SELECT * INTO v_intent FROM lucy.scoped_archive_intents_v1
          WHERE archive_actor_binding_id=v_actor.id AND idempotency_key=p_idempotency_key;
          IF FOUND THEN
            v_replayed:=true;
            IF v_intent.source_conversation_id<>p_source_conversation_id
               OR v_intent.source_turn_id<>p_source_turn_id
               OR v_intent.request_commitment<>p_request_commitment
               OR v_intent.content_classification<>p_content_classification
               OR v_intent.lineage_refs<>p_lineage_refs
            THEN RAISE EXCEPTION 'scoped archive idempotency conflict'; END IF;
          ELSE
            SELECT * INTO v_receipt FROM lucy.scoped_capture_receipts_v1
            WHERE content_scope_id=v_actor.content_scope_id AND platform='telegram'
              AND source_conversation_id=p_source_conversation_id
              AND source_turn_id=p_source_turn_id AND archive_actor_binding_id=v_actor.id;
            SELECT * INTO v_state FROM lucy.scoped_capture_states_v1
            WHERE content_scope_id=v_actor.content_scope_id AND platform='telegram'
              AND source_conversation_id=p_source_conversation_id;
            IF v_receipt.content_scope_id IS NULL OR NOT v_receipt.capture_enabled
               OR (v_state.content_scope_id IS NOT NULL AND NOT v_state.capture_enabled)
               OR v_receipt.capture_version<>
                  (CASE WHEN v_state.content_scope_id IS NULL THEN 0 ELSE v_state.version END)
            THEN RAISE EXCEPTION 'scoped turn is not authorized for retention'; END IF;
            INSERT INTO lucy.scoped_archive_intents_v1(
              operation_id,content_scope_id,archive_actor_binding_id,
              source_conversation_id,source_turn_id,idempotency_key,request_commitment,
              evidence_id,representation_id,wrapped_key_ref,content_classification,
              lineage_refs,created_at
            ) VALUES (gen_random_uuid(),v_actor.content_scope_id,v_actor.id,
              p_source_conversation_id,p_source_turn_id,p_idempotency_key,
              p_request_commitment,gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),
              p_content_classification,p_lineage_refs,clock_timestamp())
            RETURNING * INTO v_intent;
          END IF;
          v_stage:=CASE
            WHEN EXISTS (SELECT 1 FROM lucy.scoped_archive_reconciliations_v1
                         WHERE operation_id=v_intent.operation_id) THEN 'RECONCILED'
            WHEN EXISTS (SELECT 1 FROM lucy.scoped_archive_aws_outcomes_v1
                         WHERE operation_id=v_intent.operation_id) THEN 'AWS_COMMITTED'
            ELSE 'INTENT_RECORDED' END;
          RETURN jsonb_build_object('operation_id',v_intent.operation_id,
            'evidence_id',v_intent.evidence_id,
            'representation_id',v_intent.representation_id,
            'wrapped_key_ref',v_intent.wrapped_key_ref,'stage',v_stage,
            'replayed',v_replayed);
        END
        $function$;
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.record_scoped_archive_aws_outcome_v1(
          p_operation_id uuid, p_envelope jsonb, p_envelope_digest text
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_intent lucy.scoped_archive_intents_v1%ROWTYPE;
          v_existing lucy.scoped_archive_aws_outcomes_v1%ROWTYPE;
          v_scope lucy.realm_content_scopes_v1%ROWTYPE;
          v_digest text;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='archive_writer' AND active
            AND allowed_actions @> '["evidence.archive"]'::jsonb;
          SELECT * INTO v_intent FROM lucy.scoped_archive_intents_v1
          WHERE operation_id=p_operation_id AND archive_actor_binding_id=v_actor.id;
          IF v_actor.id IS NULL OR NOT FOUND
          THEN RAISE EXCEPTION 'scoped archive outcome unavailable'; END IF;
          SELECT * INTO STRICT v_scope FROM lucy.realm_content_scopes_v1
          WHERE id=v_intent.content_scope_id;
          v_digest:=encode(public.digest(
            convert_to(lucy.canonical_jsonb_v1(p_envelope),'UTF8'),'sha256'),'hex');
          IF p_envelope-ARRAY['contract_version','object_type','payload_binding',
                'wrapper_binding','keyed_commitment','request_commitment','kms_request_id']
                <>'{}'::jsonb
             OR p_envelope_digest<>v_digest
             OR p_envelope->>'contract_version'<>'1'
             OR p_envelope->>'object_type'<>'lucy.realm-archive-envelope.v1'
             OR p_envelope->>'request_commitment'<>v_intent.request_commitment
             OR (p_envelope->'payload_binding'->>'evidence_id')::uuid<>v_intent.evidence_id
             OR (p_envelope->'wrapper_binding'->>'representation_id')::uuid
                <>v_intent.representation_id
             OR (p_envelope->'wrapper_binding'->>'wrapped_key_ref')::uuid
                <>v_intent.wrapped_key_ref
             OR p_envelope->'payload_binding'->'original_scope'
                <>p_envelope->'wrapper_binding'->'wrapping_scope'
             OR p_envelope->'wrapper_binding'->'wrapping_scope'<>jsonb_build_object(
                'tenant_account_id',v_scope.tenant_account_id,
                'node_id',v_scope.node_id,'node_tenure_id',v_scope.node_tenure_id,
                'tenure_epoch',v_scope.tenure_epoch,
                'security_realm_id',v_scope.security_realm_id,
                'storage_epoch',v_scope.storage_epoch)
          THEN RAISE EXCEPTION 'scoped archive outcome binding is invalid'; END IF;
          SELECT * INTO v_existing FROM lucy.scoped_archive_aws_outcomes_v1
          WHERE operation_id=p_operation_id;
          IF FOUND THEN
            IF v_existing.envelope_digest<>v_digest OR v_existing.envelope<>p_envelope
            THEN RAISE EXCEPTION 'scoped archive outcome conflict'; END IF;
            RETURN jsonb_build_object('operation_id',p_operation_id,
              'envelope_digest',v_digest,'replayed',true);
          END IF;
          INSERT INTO lucy.scoped_archive_aws_outcomes_v1(
            operation_id,envelope,envelope_digest,recorded_at
          ) VALUES (p_operation_id,p_envelope,v_digest,clock_timestamp());
          RETURN jsonb_build_object('operation_id',p_operation_id,
            'envelope_digest',v_digest,'replayed',false);
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR not_null_violation OR check_violation
          THEN RAISE EXCEPTION 'malformed scoped archive outcome';
        END
        $function$;
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.reconcile_capturable_scoped_archive_v1(
          p_operation_id uuid
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_intent lucy.scoped_archive_intents_v1%ROWTYPE;
          v_outcome lucy.scoped_archive_aws_outcomes_v1%ROWTYPE;
          v_existing lucy.scoped_archive_reconciliations_v1%ROWTYPE;
          v_result jsonb; v_digest text;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='archive_writer' AND active
            AND allowed_actions @> '["evidence.archive"]'::jsonb;
          SELECT * INTO v_intent FROM lucy.scoped_archive_intents_v1
          WHERE operation_id=p_operation_id AND archive_actor_binding_id=v_actor.id;
          SELECT * INTO v_outcome FROM lucy.scoped_archive_aws_outcomes_v1
          WHERE operation_id=p_operation_id;
          IF v_actor.id IS NULL OR v_intent.operation_id IS NULL
             OR v_outcome.operation_id IS NULL
          THEN RAISE EXCEPTION 'scoped archive reconciliation unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            v_actor.id::text||':'||v_intent.idempotency_key,0));
          SELECT * INTO v_existing FROM lucy.scoped_archive_reconciliations_v1
          WHERE operation_id=p_operation_id;
          IF FOUND THEN
            RETURN v_existing.result||jsonb_build_object('replayed',true);
          END IF;
          v_result:=lucy.register_capturable_scoped_evidence_v2(
            v_intent.source_conversation_id,v_intent.source_turn_id,
            v_outcome.envelope->'payload_binding',v_outcome.envelope->'wrapper_binding',
            v_intent.content_classification,v_intent.lineage_refs,v_intent.idempotency_key);
          v_result:=v_result||jsonb_build_object('operation_id',p_operation_id);
          v_digest:=encode(public.digest(
            convert_to(lucy.canonical_jsonb_v1(v_result),'UTF8'),'sha256'),'hex');
          INSERT INTO lucy.scoped_archive_reconciliations_v1(
            operation_id,result,result_digest,recorded_at
          ) VALUES (p_operation_id,v_result,v_digest,clock_timestamp());
          RETURN v_result||jsonb_build_object('replayed',false);
        END
        $function$;
        """
    )
    for signature in (
        "lucy.claim_capturable_scoped_archive_v1(text,text,text,text,text,jsonb)",
        "lucy.record_scoped_archive_aws_outcome_v1(uuid,jsonb,text)",
        "lucy.reconcile_capturable_scoped_archive_v1(uuid)",
    ):
        op.execute(
            f"ALTER FUNCTION {signature} OWNER TO lucy_security_function_owner; "
            f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC, lucy_app"
        )
    op.execute(
        "GRANT SELECT, INSERT ON lucy.scoped_archive_intents_v1, "
        "lucy.scoped_archive_aws_outcomes_v1, lucy.scoped_archive_reconciliations_v1 "
        "TO lucy_security_function_owner"
    )


def downgrade() -> None:
    raise RuntimeError("R1 archive commit history requires a reviewed forward migration")
