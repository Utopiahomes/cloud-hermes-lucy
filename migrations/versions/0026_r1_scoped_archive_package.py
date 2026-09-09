"""Add realm-scoped encrypted archive records and exact claimed packages."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0026_r1_scoped_archive_package"
down_revision: str | None = "0025_r1_sensitive_permit_claim"
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
    op.drop_constraint(
        "ck_sensitive_actor_role", "realm_sensitive_actor_bindings_v1", schema="lucy"
    )
    op.create_check_constraint(
        "ck_sensitive_actor_role",
        "realm_sensitive_actor_bindings_v1",
        "actor_role IN ('archive_writer','policy_notary','sensitive_workflow')",
        schema="lucy",
    )
    op.create_table(
        "scoped_evidence_records_v2",
        _uuid("id", primary=True),
        _uuid("content_scope_id"),
        _uuid("archive_actor_binding_id"),
        sa.Column("content_classification", sa.String(200), nullable=False),
        sa.Column("lineage_refs", postgresql.JSONB(), nullable=False),
        sa.Column("idempotency_key", sa.String(512), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["archive_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.UniqueConstraint(
            "archive_actor_binding_id", "idempotency_key", name="uq_scoped_evidence_replay"
        ),
        sa.CheckConstraint("jsonb_typeof(lineage_refs)='array'", name="ck_scoped_lineage_array"),
        sa.CheckConstraint("status='active'", name="ck_scoped_evidence_initial_status"),
        schema="lucy",
    )
    op.create_table(
        "scoped_evidence_payloads_v2",
        _uuid("evidence_id", primary=True),
        sa.Column("record_version", sa.BigInteger(), nullable=False),
        sa.Column("payload_ciphertext_digest", sa.String(64), nullable=False),
        sa.Column("serialized_payload", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["lucy.scoped_evidence_records_v2.id"]),
        sa.CheckConstraint("record_version>0", name="ck_scoped_payload_version"),
        schema="lucy",
    )
    op.create_table(
        "scoped_evidence_wrappers_v2",
        _uuid("representation_id", primary=True),
        _uuid("evidence_id"),
        _uuid("content_scope_id"),
        _uuid("wrapped_key_ref"),
        sa.Column("payload_ciphertext_digest", sa.String(64), nullable=False),
        sa.Column("serialized_wrapper", postgresql.JSONB(), nullable=False),
        sa.Column("current", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["lucy.scoped_evidence_records_v2.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.UniqueConstraint("wrapped_key_ref", name="uq_scoped_wrapper_key_ref"),
        schema="lucy",
    )
    op.create_index(
        "uq_scoped_current_wrapper",
        "scoped_evidence_wrappers_v2",
        ["evidence_id"],
        unique=True,
        postgresql_where=sa.text("current"),
        schema="lucy",
    )
    op.create_table(
        "sensitive_operation_packages_v2",
        _uuid("operation_id", primary=True),
        _uuid("permit_id", unique=True),
        _uuid("content_scope_id"),
        _uuid("workflow_actor_binding_id"),
        _uuid("evidence_id"),
        _uuid("representation_id"),
        sa.Column("package_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("serialized_package", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["operation_id"], ["lucy.sensitive_operations_v2.id"]),
        sa.ForeignKeyConstraint(["permit_id"], ["lucy.sensitive_action_permits_v3.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["workflow_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.ForeignKeyConstraint(["evidence_id"], ["lucy.scoped_evidence_records_v2.id"]),
        sa.ForeignKeyConstraint(
            ["representation_id"], ["lucy.scoped_evidence_wrappers_v2.representation_id"]
        ),
        schema="lucy",
    )
    op.execute(
        "CREATE TRIGGER scoped_evidence_records_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_evidence_records_v2 FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation(); "
        "CREATE TRIGGER scoped_evidence_payloads_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_evidence_payloads_v2 FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation(); "
        "CREATE TRIGGER scoped_evidence_wrappers_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_evidence_wrappers_v2 FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation(); "
        "CREATE TRIGGER sensitive_operation_packages_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.sensitive_operation_packages_v2 FOR EACH ROW "
        "EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.evidence_package_digest_v2(p_package jsonb) RETURNS text
        LANGUAGE sql IMMUTABLE STRICT
        SET search_path = pg_catalog, pg_temp
        AS $function$
          SELECT encode(public.digest(
            convert_to('LUCY-ENCRYPTED-EVIDENCE-PACKAGE-V2','UTF8') || decode('00','hex') ||
            convert_to(lucy.canonical_jsonb_v1(p_package),'UTF8'),'sha256'),'hex')
        $function$;
        ALTER FUNCTION lucy.evidence_package_digest_v2(jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.evidence_package_digest_v2(jsonb) FROM PUBLIC, lucy_app;
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.register_scoped_evidence_v2(
          p_payload jsonb, p_wrapper jsonb, p_content_classification text,
          p_lineage_refs jsonb, p_idempotency_key text
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_target lucy.realm_service_bindings_v1%ROWTYPE;
          v_scope lucy.realm_content_scopes_v1%ROWTYPE;
          v_existing lucy.scoped_evidence_records_v2%ROWTYPE;
          v_evidence_id uuid; v_representation_id uuid; v_key_ref uuid;
          v_ciphertext bytea; v_payload_digest text; v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='archive_writer' AND active
            AND allowed_actions @> '["evidence.archive"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped evidence archive unavailable'; END IF;
          SELECT * INTO STRICT v_target FROM lucy.realm_service_bindings_v1
          WHERE id=v_actor.target_service_binding_id AND content_scope_id=v_actor.content_scope_id
            AND active AND allowed_actions @> '["evidence.archive"]'::jsonb;
          SELECT * INTO STRICT v_scope FROM lucy.realm_content_scopes_v1
          WHERE id=v_actor.content_scope_id;
          IF jsonb_typeof(p_payload)<>'object' OR jsonb_typeof(p_wrapper)<>'object'
             OR jsonb_typeof(p_lineage_refs)<>'array'
             OR jsonb_array_length(p_lineage_refs)>32
             OR p_content_classification IS NULL OR btrim(p_content_classification)=''
             OR length(p_content_classification)>200 OR p_idempotency_key IS NULL
             OR btrim(p_idempotency_key)='' OR length(p_idempotency_key)>512
          THEN RAISE EXCEPTION 'scoped evidence archive request is invalid'; END IF;
          IF p_payload-ARRAY['evidence_id','original_scope','record_version','cipher_suite',
             'ciphertext_b64','content_nonce_b64','authenticated_header_b64',
             'payload_ciphertext_digest']<>'{}'::jsonb
             OR p_wrapper-ARRAY['representation_id','wrapping_scope','wrapped_key_ref',
             'encryption_context','encryption_context_version','payload_ciphertext_digest',
             'migration_receipt_id']<>'{}'::jsonb
             OR (p_payload->'original_scope')-ARRAY['tenant_account_id','node_id',
             'node_tenure_id','tenure_epoch','security_realm_id','storage_epoch']<>'{}'::jsonb
             OR (p_wrapper->'wrapping_scope')-ARRAY['tenant_account_id','node_id',
             'node_tenure_id','tenure_epoch','security_realm_id','storage_epoch']<>'{}'::jsonb
             OR (p_wrapper->'encryption_context')-ARRAY['contract_version','tenant_account_id',
             'node_id','node_tenure_id','tenure_epoch','security_realm_id','storage_epoch',
             'evidence_id','purpose']<>'{}'::jsonb
          THEN RAISE EXCEPTION 'scoped evidence bindings contain unknown fields'; END IF;
          v_evidence_id:=(p_payload->>'evidence_id')::uuid;
          v_representation_id:=(p_wrapper->>'representation_id')::uuid;
          v_key_ref:=(p_wrapper->>'wrapped_key_ref')::uuid;
          v_ciphertext:=decode(p_payload->>'ciphertext_b64','base64');
          v_payload_digest:=encode(public.digest(v_ciphertext,'sha256'),'hex');
          IF p_payload->>'cipher_suite'<>'AES-256-GCM'
             OR (p_payload->>'record_version')::bigint<1 OR octet_length(v_ciphertext)>65552
             OR octet_length(decode(p_payload->>'content_nonce_b64','base64'))<>12
             OR p_payload->>'payload_ciphertext_digest'<>v_payload_digest
             OR p_wrapper->>'payload_ciphertext_digest'<>v_payload_digest
             OR p_wrapper->>'encryption_context_version'<>'KmsEncryptionContextV2'
             OR p_wrapper->'encryption_context'->>'contract_version'<>'KmsEncryptionContextV2'
             OR p_wrapper->'encryption_context'->>'purpose'<>'EVIDENCE_DEK'
             OR (p_wrapper->'encryption_context'->>'evidence_id')::uuid<>v_evidence_id
             OR (p_wrapper->>'migration_receipt_id') IS NOT NULL
          THEN RAISE EXCEPTION 'scoped evidence cryptographic binding is invalid'; END IF;
          IF p_payload->'original_scope'<>p_wrapper->'wrapping_scope'
             OR (p_wrapper->'wrapping_scope'->>'tenant_account_id')::uuid<>v_scope.tenant_account_id
             OR (p_wrapper->'wrapping_scope'->>'node_id')::uuid<>v_scope.node_id
             OR (p_wrapper->'wrapping_scope'->>'node_tenure_id')::uuid<>v_scope.node_tenure_id
             OR (p_wrapper->'wrapping_scope'->>'tenure_epoch')::bigint<>v_scope.tenure_epoch
             OR (p_wrapper->'wrapping_scope'->>'security_realm_id')::uuid<>v_scope.security_realm_id
             OR (p_wrapper->'wrapping_scope'->>'storage_epoch')::bigint<>v_scope.storage_epoch
             OR (p_wrapper->'encryption_context')-'contract_version'-'evidence_id'-'purpose'
                <>p_wrapper->'wrapping_scope'
             OR v_actor.node_authz_epoch<>v_target.node_authz_epoch
             OR v_actor.policy_version<>v_target.policy_version
          THEN RAISE EXCEPTION 'scoped evidence realm binding is unavailable'; END IF;
          IF EXISTS (
            SELECT value FROM jsonb_array_elements_text(p_lineage_refs) refs(value)
            WHERE value::uuid=v_evidence_id
          ) OR (SELECT count(*) FROM jsonb_array_elements_text(p_lineage_refs))
             <>(SELECT count(DISTINCT value) FROM jsonb_array_elements_text(p_lineage_refs))
          THEN RAISE EXCEPTION 'scoped evidence lineage is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            v_actor.id::text||':'||p_idempotency_key,0));
          SELECT * INTO v_existing FROM lucy.scoped_evidence_records_v2
          WHERE archive_actor_binding_id=v_actor.id AND idempotency_key=p_idempotency_key;
          IF FOUND THEN
            IF v_existing.id<>v_evidence_id
               OR (SELECT serialized_payload FROM lucy.scoped_evidence_payloads_v2
                   WHERE evidence_id=v_evidence_id)<>p_payload
               OR (SELECT serialized_wrapper FROM lucy.scoped_evidence_wrappers_v2
                   WHERE representation_id=v_representation_id)<>p_wrapper
            THEN RAISE EXCEPTION 'scoped evidence archive idempotency conflict'; END IF;
            RETURN jsonb_build_object('evidence_id',v_evidence_id,
              'representation_id',v_representation_id,'replayed',true);
          END IF;
          INSERT INTO lucy.scoped_evidence_records_v2(
            id,content_scope_id,archive_actor_binding_id,content_classification,
            lineage_refs,idempotency_key,status,created_at
          ) VALUES (v_evidence_id,v_scope.id,v_actor.id,p_content_classification,
            p_lineage_refs,p_idempotency_key,'active',v_now);
          INSERT INTO lucy.scoped_evidence_payloads_v2(
            evidence_id,record_version,payload_ciphertext_digest,serialized_payload,created_at
          ) VALUES (v_evidence_id,(p_payload->>'record_version')::bigint,
            v_payload_digest,p_payload,v_now);
          INSERT INTO lucy.scoped_evidence_wrappers_v2(
            representation_id,evidence_id,content_scope_id,wrapped_key_ref,
            payload_ciphertext_digest,serialized_wrapper,current,created_at
          ) VALUES (v_representation_id,v_evidence_id,v_scope.id,v_key_ref,
            v_payload_digest,p_wrapper,true,v_now);
          RETURN jsonb_build_object('evidence_id',v_evidence_id,
            'representation_id',v_representation_id,'replayed',false);
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR not_null_violation OR check_violation
          THEN RAISE EXCEPTION 'malformed scoped evidence binding';
        END
        $function$;
        """
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.freeze_claimed_evidence_package_v2(p_operation_id uuid)
        RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_permit lucy.sensitive_action_permits_v3%ROWTYPE;
          v_record lucy.scoped_evidence_records_v2%ROWTYPE;
          v_payload lucy.scoped_evidence_payloads_v2%ROWTYPE;
          v_wrapper lucy.scoped_evidence_wrappers_v2%ROWTYPE;
          v_existing lucy.sensitive_operation_packages_v2%ROWTYPE;
          v_package jsonb; v_digest text; v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='sensitive_workflow' AND active
            AND allowed_actions @> '["sensitive.operation.claim"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'claimed evidence package unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2 WHERE id=p_operation_id;
          IF NOT FOUND OR v_operation.workflow_actor_binding_id<>v_actor.id
             OR v_operation.content_scope_id<>v_actor.content_scope_id
             OR v_operation.action<>'evidence.retrieve' OR v_operation.state<>'CLAIMED'
          THEN RAISE EXCEPTION 'claimed evidence package unavailable'; END IF;
          SELECT * INTO v_existing FROM lucy.sensitive_operation_packages_v2
          WHERE operation_id=p_operation_id;
          IF FOUND THEN RETURN jsonb_build_object('package',v_existing.serialized_package,
            'package_digest',v_existing.package_digest,'replayed',true); END IF;
          SELECT * INTO STRICT v_permit FROM lucy.sensitive_action_permits_v3
          WHERE id=v_operation.permit_id;
          SELECT * INTO v_record FROM lucy.scoped_evidence_records_v2
          WHERE id=v_operation.resource_object_id
            AND content_scope_id=v_operation.content_scope_id AND status='active';
          IF NOT FOUND THEN RAISE EXCEPTION 'claimed evidence record unavailable'; END IF;
          SELECT * INTO STRICT v_payload FROM lucy.scoped_evidence_payloads_v2
          WHERE evidence_id=v_record.id AND record_version=v_operation.resource_object_version;
          SELECT * INTO STRICT v_wrapper FROM lucy.scoped_evidence_wrappers_v2
          WHERE evidence_id=v_record.id AND content_scope_id=v_record.content_scope_id AND current;
          IF v_now>v_permit.execution_completion_deadline
          THEN RAISE EXCEPTION 'claimed evidence package deadline expired'; END IF;
          v_package:=jsonb_build_object(
            'contract_version','2','canonicalization_version','lucy-cjson-1',
            'object_type','lucy.encrypted-evidence-package.v2',
            'operation_id',v_operation.id,'permit_id',v_permit.id,
            'action','evidence.retrieve','payload_binding',v_payload.serialized_payload,
            'wrapper_binding',v_wrapper.serialized_wrapper,
            'content_classification',v_record.content_classification,
            'lineage_refs',v_record.lineage_refs);
          v_digest:=lucy.evidence_package_digest_v2(v_package);
          INSERT INTO lucy.sensitive_operation_packages_v2(
            operation_id,permit_id,content_scope_id,workflow_actor_binding_id,evidence_id,
            representation_id,package_digest,serialized_package,created_at
          ) VALUES (v_operation.id,v_permit.id,v_record.content_scope_id,v_actor.id,
            v_record.id,v_wrapper.representation_id,v_digest,v_package,v_now);
          RETURN jsonb_build_object('package',v_package,'package_digest',v_digest,'replayed',false);
        END
        $function$;
        """
    )
    for signature in (
        "lucy.register_scoped_evidence_v2(jsonb,jsonb,text,jsonb,text)",
        "lucy.freeze_claimed_evidence_package_v2(uuid)",
    ):
        op.execute(
            f"ALTER FUNCTION {signature} OWNER TO lucy_security_function_owner; "
            f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC, lucy_app"
        )
    op.execute(
        "GRANT SELECT ON lucy.realm_content_scopes_v1, lucy.realm_service_bindings_v1, "
        "lucy.realm_sensitive_actor_bindings_v1, lucy.sensitive_action_permits_v3, "
        "lucy.sensitive_operations_v2 TO lucy_security_function_owner; "
        "GRANT SELECT, INSERT ON lucy.scoped_evidence_records_v2, "
        "lucy.scoped_evidence_payloads_v2, lucy.scoped_evidence_wrappers_v2, "
        "lucy.sensitive_operation_packages_v2 TO lucy_security_function_owner; "
        "REVOKE ALL ON lucy.scoped_evidence_records_v2, lucy.scoped_evidence_payloads_v2, "
        "lucy.scoped_evidence_wrappers_v2, lucy.sensitive_operation_packages_v2 FROM lucy_app"
    )


def downgrade() -> None:
    raise RuntimeError("R1 scoped archive packages require a reviewed forward migration")
