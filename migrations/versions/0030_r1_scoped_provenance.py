"""Add scoped evidence-derived memory provenance and deletion fencing."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0030_r1_scoped_provenance"
down_revision: str | None = "0029_r1_receipt_reconcile"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scoped_memory_claims_v1",
        sa.Column(
            "origin_class",
            sa.String(30),
            nullable=False,
            server_default=sa.text("'direct_input'"),
        ),
        schema="lucy",
    )
    op.create_check_constraint(
        "ck_scoped_claim_origin",
        "scoped_memory_claims_v1",
        "origin_class IN ('direct_input','evidence_derived')",
        schema="lucy",
    )
    op.create_unique_constraint(
        "uq_scoped_evidence_scope",
        "scoped_evidence_records_v2",
        ["id", "content_scope_id"],
        schema="lucy",
    )
    op.create_table(
        "scoped_memory_claim_sources_v2",
        sa.Column("claim_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["claim_id", "content_scope_id"],
            ["lucy.scoped_memory_claims_v1.id", "lucy.scoped_memory_claims_v1.content_scope_id"],
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id", "content_scope_id"],
            [
                "lucy.scoped_evidence_records_v2.id",
                "lucy.scoped_evidence_records_v2.content_scope_id",
            ],
        ),
        schema="lucy",
    )
    op.create_index(
        "ix_scoped_claim_sources_evidence",
        "scoped_memory_claim_sources_v2",
        ["evidence_id", "content_scope_id"],
        schema="lucy",
    )
    op.create_table(
        "scoped_evidence_deletion_fences_v2",
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["evidence_id", "content_scope_id"],
            [
                "lucy.scoped_evidence_records_v2.id",
                "lucy.scoped_evidence_records_v2.content_scope_id",
            ],
        ),
        sa.ForeignKeyConstraint(["operation_id"], ["lucy.sensitive_operations_v2.id"]),
        schema="lucy",
    )
    op.execute(
        "CREATE TRIGGER scoped_memory_claim_sources_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_memory_claim_sources_v2 FOR EACH ROW "
        "EXECUTE FUNCTION lucy.reject_mutation(); "
        "CREATE TRIGGER scoped_evidence_deletion_fences_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_evidence_deletion_fences_v2 FOR EACH ROW "
        "EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.write_evidence_derived_memory_claim_v2(
          p_idempotency_key text,p_subject text,p_predicate text,p_object text,
          p_confidence_millionths bigint,p_source_evidence_ids uuid[]
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_existing lucy.scoped_memory_claims_v1%ROWTYPE;
          v_sources uuid[]; v_source uuid; v_claim_id uuid:=gen_random_uuid();
          v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.write"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'realm operation unavailable'; END IF;
          SELECT array_agg(DISTINCT source ORDER BY source) INTO v_sources
          FROM unnest(p_source_evidence_ids) source;
          IF p_source_evidence_ids IS NULL OR v_sources IS NULL
             OR p_idempotency_key IS NULL OR btrim(p_idempotency_key)=''
             OR length(p_idempotency_key)>200 OR p_subject IS NULL OR btrim(p_subject)=''
             OR length(p_subject)>200 OR p_predicate IS NULL OR btrim(p_predicate)=''
             OR length(p_predicate)>200 OR p_object IS NULL OR btrim(p_object)=''
             OR length(p_object)>2000 OR p_confidence_millionths NOT BETWEEN 0 AND 1000000
             OR cardinality(v_sources) NOT BETWEEN 1 AND 16
             OR cardinality(v_sources)<>cardinality(p_source_evidence_ids)
          THEN RAISE EXCEPTION 'scoped derived memory request is invalid'; END IF;
          FOREACH v_source IN ARRAY v_sources LOOP
            PERFORM pg_advisory_xact_lock(hashtextextended('evidence-derive:'||v_source::text,0));
          END LOOP;
          IF (SELECT count(*) FROM lucy.scoped_evidence_records_v2 e
              WHERE e.id=ANY(v_sources) AND e.content_scope_id=v_binding.content_scope_id
                AND e.status='active')<>cardinality(v_sources)
             OR EXISTS (SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
                        WHERE f.evidence_id=ANY(v_sources))
          THEN RAISE EXCEPTION 'scoped evidence derivation unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            v_binding.id::text||':'||p_idempotency_key,0));
          SELECT * INTO v_existing FROM lucy.scoped_memory_claims_v1
          WHERE service_binding_id=v_binding.id AND idempotency_key=p_idempotency_key;
          IF FOUND THEN
            IF v_existing.origin_class<>'evidence_derived'
               OR v_existing.subject<>p_subject OR v_existing.predicate<>p_predicate
               OR v_existing.object<>p_object
               OR v_existing.confidence_millionths<>p_confidence_millionths
               OR (SELECT array_agg(evidence_id ORDER BY evidence_id)
                   FROM lucy.scoped_memory_claim_sources_v2
                   WHERE claim_id=v_existing.id)<>v_sources
            THEN RAISE EXCEPTION 'scoped memory idempotency conflict'; END IF;
            RETURN jsonb_build_object('claim_id',v_existing.id,'replayed',true);
          END IF;
          INSERT INTO lucy.scoped_memory_claims_v1(
            id,content_scope_id,service_binding_id,idempotency_key,subject,predicate,
            object,confidence_millionths,status,origin_class,created_at
          ) VALUES (v_claim_id,v_binding.content_scope_id,v_binding.id,p_idempotency_key,
            p_subject,p_predicate,p_object,p_confidence_millionths,'accepted',
            'evidence_derived',v_now);
          INSERT INTO lucy.scoped_memory_claim_sources_v2(
            claim_id,evidence_id,content_scope_id,created_at
          ) SELECT v_claim_id,source,v_binding.content_scope_id,v_now FROM unnest(v_sources) source;
          INSERT INTO lucy.scoped_memory_events_v1(
            id,content_scope_id,service_binding_id,event_type,claim_id,occurred_at
          ) VALUES (gen_random_uuid(),v_binding.content_scope_id,v_binding.id,
            'memory.claim_written',v_claim_id,v_now);
          RETURN jsonb_build_object('claim_id',v_claim_id,'replayed',false);
        END
        $function$;
        ALTER FUNCTION lucy.write_evidence_derived_memory_claim_v2(
          text,text,text,text,bigint,uuid[]
        ) OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.write_evidence_derived_memory_claim_v2(
          text,text,text,text,bigint,uuid[]
        ) FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.scoped_memory_claim_sources_v2
          TO lucy_security_function_owner;
        GRANT SELECT ON lucy.scoped_evidence_records_v2,
          lucy.scoped_evidence_deletion_fences_v2 TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("scoped provenance requires a reviewed forward migration")
