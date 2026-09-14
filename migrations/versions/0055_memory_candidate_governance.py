"""Govern exact scoped memory candidates, promotion, and protected recall."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0055_memory_candidate_governance"
down_revision: str | None = "0054_stage2_scoped_turn_commit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scoped_memory_candidate_versions_v1",
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("candidate_version", sa.BigInteger(), primary_key=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("extractor_binding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("candidate_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("protection_class", sa.String(30), nullable=False),
        sa.Column("memory_kind", sa.String(30), nullable=False),
        sa.Column("assertion_status", sa.String(40), nullable=False),
        sa.Column("epistemic_status", sa.String(30), nullable=False),
        sa.Column("serialized_candidate", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["extractor_binding_id"], ["lucy.realm_service_bindings_v1.id"]
        ),
        sa.CheckConstraint("candidate_version > 0", name="ck_memory_candidate_version"),
        sa.CheckConstraint(
            "protection_class IN ('ordinary_private','protected')",
            name="ck_memory_candidate_protection",
        ),
        sa.CheckConstraint(
            "memory_kind IN ('episode','assertion','project_state','entity','procedure')",
            name="ck_memory_candidate_kind",
        ),
        sa.CheckConstraint(
            "assertion_status IN ('report','preference','proposal','hypothesis','decision',"
            "'assistant_recommendation','attributed_interpretation')",
            name="ck_memory_candidate_assertion",
        ),
        sa.CheckConstraint(
            "epistemic_status IN ('uncertain','disputed','current','historical',"
            "'contradicted','superseded')",
            name="ck_memory_candidate_epistemic",
        ),
        schema="lucy",
    )
    op.create_table(
        "scoped_memory_candidate_sources_v1",
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("candidate_version", sa.BigInteger(), primary_key=True),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("record_version", sa.BigInteger(), primary_key=True),
        sa.Column("byte_start", sa.BigInteger(), primary_key=True),
        sa.Column("byte_end", sa.BigInteger(), nullable=False),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["candidate_id", "candidate_version"],
            [
                "lucy.scoped_memory_candidate_versions_v1.candidate_id",
                "lucy.scoped_memory_candidate_versions_v1.candidate_version",
            ],
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id", "content_scope_id"],
            [
                "lucy.scoped_evidence_records_v2.id",
                "lucy.scoped_evidence_records_v2.content_scope_id",
            ],
        ),
        sa.CheckConstraint("record_version > 0", name="ck_memory_source_version"),
        sa.CheckConstraint(
            "byte_start >= 0 AND byte_end > byte_start", name="ck_memory_source_span"
        ),
        schema="lucy",
    )
    op.create_table(
        "scoped_memory_candidate_approvals_v1",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("candidate_version", sa.BigInteger(), nullable=False),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_actor_binding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("candidate_digest", sa.String(64), nullable=False),
        sa.Column("owner_approval_ref", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("owner_actor_id", sa.String(512), nullable=False),
        sa.Column("policy_version", sa.BigInteger(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["candidate_id", "candidate_version"],
            [
                "lucy.scoped_memory_candidate_versions_v1.candidate_id",
                "lucy.scoped_memory_candidate_versions_v1.candidate_version",
            ],
        ),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["policy_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.UniqueConstraint(
            "candidate_id", "candidate_version", name="uq_memory_candidate_approval"
        ),
        schema="lucy",
    )
    op.create_table(
        "scoped_memory_promotions_v1",
        sa.Column("approval_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("candidate_version", sa.BigInteger(), nullable=False),
        sa.Column("claim_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["approval_id"], ["lucy.scoped_memory_candidate_approvals_v1.id"]
        ),
        sa.ForeignKeyConstraint(
            ["candidate_id", "candidate_version"],
            [
                "lucy.scoped_memory_candidate_versions_v1.candidate_id",
                "lucy.scoped_memory_candidate_versions_v1.candidate_version",
            ],
        ),
        sa.ForeignKeyConstraint(["claim_id"], ["lucy.scoped_memory_claims_v1.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.UniqueConstraint(
            "candidate_id", "candidate_version", name="uq_memory_candidate_promotion"
        ),
        schema="lucy",
    )
    op.create_table(
        "scoped_protected_memory_accesses_v1",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_actor_binding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owner_interaction_ref", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("query_commitment", sa.String(64), nullable=False),
        sa.Column("returned_claim_ids", postgresql.JSONB(), nullable=False),
        sa.Column("reason_code", sa.String(60), nullable=False),
        sa.Column("accessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["policy_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        schema="lucy",
    )
    for name in (
        "scoped_memory_candidate_versions_v1",
        "scoped_memory_candidate_sources_v1",
        "scoped_memory_candidate_approvals_v1",
        "scoped_memory_promotions_v1",
        "scoped_protected_memory_accesses_v1",
    ):
        op.execute(
            f"CREATE TRIGGER {name}_immutable BEFORE UPDATE OR DELETE ON lucy.{name} "
            "FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
        )

    op.add_column(
        "scoped_memory_claims_v1",
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True)),
        schema="lucy",
    )
    op.add_column(
        "scoped_memory_claims_v1",
        sa.Column("candidate_version", sa.BigInteger()),
        schema="lucy",
    )
    op.add_column(
        "scoped_memory_claims_v1",
        sa.Column("protection_class", sa.String(30)),
        schema="lucy",
    )
    op.add_column(
        "scoped_memory_claims_v1",
        sa.Column("memory_kind", sa.String(30)),
        schema="lucy",
    )
    op.add_column(
        "scoped_memory_claims_v1",
        sa.Column("assertion_status", sa.String(40)),
        schema="lucy",
    )
    op.add_column(
        "scoped_memory_claims_v1",
        sa.Column("epistemic_status", sa.String(30)),
        schema="lucy",
    )
    op.add_column(
        "scoped_memory_claims_v1",
        sa.Column("domain_tags", postgresql.JSONB()),
        schema="lucy",
    )
    op.add_column(
        "scoped_memory_claims_v1",
        sa.Column("event_time", sa.DateTime(timezone=True)),
        schema="lucy",
    )
    op.add_column(
        "scoped_memory_claims_v1",
        sa.Column("valid_from", sa.DateTime(timezone=True)),
        schema="lucy",
    )
    op.add_column(
        "scoped_memory_claims_v1",
        sa.Column("valid_to", sa.DateTime(timezone=True)),
        schema="lucy",
    )
    op.create_foreign_key(
        "fk_scoped_claim_candidate",
        "scoped_memory_claims_v1",
        "scoped_memory_candidate_versions_v1",
        ["candidate_id", "candidate_version"],
        ["candidate_id", "candidate_version"],
        source_schema="lucy",
        referent_schema="lucy",
    )
    op.create_check_constraint(
        "ck_scoped_claim_governed_fields",
        "scoped_memory_claims_v1",
        "(candidate_id IS NULL AND candidate_version IS NULL AND protection_class IS NULL) OR "
        "(candidate_id IS NOT NULL AND candidate_version > 0 AND protection_class IN "
        "('ordinary_private','protected') AND memory_kind IS NOT NULL AND "
        "assertion_status IS NOT NULL AND epistemic_status IS NOT NULL)",
        schema="lucy",
    )

    op.execute(
        r"""
        ALTER TABLE lucy.realm_service_bindings_v1 DISABLE TRIGGER realm_service_binding_monotonic;
        UPDATE lucy.realm_service_bindings_v1
        SET allowed_actions=(allowed_actions-'memory.write')||'["memory.propose"]'::jsonb
        WHERE allowed_actions @> '["memory.write"]'::jsonb;
        ALTER TABLE lucy.realm_service_bindings_v1 ENABLE TRIGGER realm_service_binding_monotonic;

        ALTER TABLE lucy.realm_sensitive_actor_bindings_v1
          DISABLE TRIGGER sensitive_actor_binding_monotonic;
        UPDATE lucy.realm_sensitive_actor_bindings_v1
        SET allowed_actions=allowed_actions||
          '["memory.candidate.approve","memory.candidate.promote","memory.protected.read"]'::jsonb
        WHERE actor_role='policy_notary';
        ALTER TABLE lucy.realm_sensitive_actor_bindings_v1
          ENABLE TRIGGER sensitive_actor_binding_monotonic;

        DO $revoke$
        DECLARE v_login text;
        BEGIN
          FOR v_login IN SELECT session_login FROM lucy.realm_service_bindings_v1 LOOP
            EXECUTE format(
              'REVOKE EXECUTE ON FUNCTION '
              'lucy.write_scoped_memory_claim_v1(text,text,text,text,bigint),'
              'lucy.write_evidence_derived_memory_claim_v2(text,text,text,text,bigint,uuid[]) '
              'FROM %I',v_login);
          END LOOP;
        END
        $revoke$;

        CREATE FUNCTION lucy.memory_candidate_digest_v1(p_candidate jsonb) RETURNS text
        LANGUAGE sql IMMUTABLE STRICT
        SET search_path=pg_catalog,pg_temp
        AS $function$
          SELECT encode(public.digest(
            convert_to('LUCY-MEMORY-CANDIDATE-V1','UTF8')||decode('00','hex')||
            convert_to(lucy.canonical_jsonb_v1(p_candidate),'UTF8'),'sha256'),'hex')
        $function$;

        CREATE FUNCTION lucy.stage_scoped_memory_candidate_v1(p_candidate jsonb)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_binding lucy.realm_service_bindings_v1%ROWTYPE;
          v_existing lucy.scoped_memory_candidate_versions_v1%ROWTYPE;
          v_source jsonb; v_digest text; v_source_count bigint;
          v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.propose"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory candidate staging unavailable'; END IF;
          IF jsonb_typeof(p_candidate)<>'object' OR p_candidate-ARRAY[
            'contract_version','candidate_id','candidate_version','destination_content_scope_id',
            'campaign_id','manifest_digest','extraction_job_id','extractor_version',
            'prompt_version','model_route',
            'subject','predicate','object','confidence_millionths','memory_kind',
            'assertion_status','epistemic_status','protection_class','domain_tags','event_time',
            'valid_from','valid_to','sources','supersedes_candidate_id']<>'{}'::jsonb
             OR p_candidate->>'contract_version'<>'1'
             OR (p_candidate->>'destination_content_scope_id')::uuid<>v_binding.content_scope_id
             OR (p_candidate->>'candidate_version')::bigint<1
             OR p_candidate->>'manifest_digest'!~'^[0-9a-f]{64}$'
             OR coalesce(btrim(p_candidate->>'extractor_version'),'')=''
             OR length(p_candidate->>'extractor_version')>100
             OR coalesce(btrim(p_candidate->>'prompt_version'),'')=''
             OR length(p_candidate->>'prompt_version')>100
             OR coalesce(btrim(p_candidate->>'model_route'),'')=''
             OR length(p_candidate->>'model_route')>200
             OR coalesce(btrim(p_candidate->>'subject'),'')=''
             OR length(p_candidate->>'subject')>200
             OR coalesce(btrim(p_candidate->>'predicate'),'')=''
             OR length(p_candidate->>'predicate')>200
             OR coalesce(btrim(p_candidate->>'object'),'')='' OR length(p_candidate->>'object')>4000
             OR (p_candidate->>'confidence_millionths')::bigint NOT BETWEEN 0 AND 1000000
             OR p_candidate->>'protection_class' NOT IN ('ordinary_private','protected')
             OR p_candidate->>'memory_kind' NOT IN
                ('episode','assertion','project_state','entity','procedure')
             OR p_candidate->>'assertion_status' NOT IN
                ('report','preference','proposal','hypothesis','decision',
                 'assistant_recommendation','attributed_interpretation')
             OR p_candidate->>'epistemic_status' NOT IN
                ('uncertain','disputed','current','historical','contradicted','superseded')
             OR jsonb_typeof(p_candidate->'sources')<>'array'
             OR jsonb_array_length(p_candidate->'sources') NOT BETWEEN 1 AND 32
          THEN RAISE EXCEPTION 'memory candidate is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-candidate:'||(p_candidate->>'candidate_id')||':'||
            (p_candidate->>'candidate_version'),0));
          FOR v_source IN SELECT value FROM jsonb_array_elements(p_candidate->'sources') LOOP
            IF jsonb_typeof(v_source)<>'object' OR v_source-ARRAY[
              'source_record_id','evidence_id','record_version','byte_start','byte_end']<>'{}'::jsonb
               OR coalesce(btrim(v_source->>'source_record_id'),'')=''
               OR length(v_source->>'source_record_id')>512
               OR (v_source->>'record_version')::bigint<1
               OR (v_source->>'byte_start')::bigint<0
               OR (v_source->>'byte_end')::bigint<=(v_source->>'byte_start')::bigint
            THEN RAISE EXCEPTION 'memory candidate source is invalid'; END IF;
            PERFORM pg_advisory_xact_lock(hashtextextended(
              'evidence-derive:'||(v_source->>'evidence_id'),0));
            IF NOT EXISTS (
              SELECT 1 FROM lucy.scoped_evidence_records_v2 e
              JOIN lucy.scoped_evidence_payloads_v2 p ON p.evidence_id=e.id
              WHERE e.id=(v_source->>'evidence_id')::uuid
                AND e.content_scope_id=v_binding.content_scope_id AND e.status='active'
                AND p.record_version=(v_source->>'record_version')::bigint
                AND octet_length(decode(p.serialized_payload->>'ciphertext_b64','base64'))-16
                    >=(v_source->>'byte_end')::bigint
            ) OR EXISTS (
              SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
              WHERE f.evidence_id=(v_source->>'evidence_id')::uuid
            ) THEN RAISE EXCEPTION 'memory candidate source is unavailable'; END IF;
          END LOOP;
          SELECT count(DISTINCT (value->>'source_record_id',value->>'evidence_id',
            value->>'record_version',value->>'byte_start',value->>'byte_end'))
          INTO v_source_count
          FROM jsonb_array_elements(p_candidate->'sources');
          IF v_source_count<>jsonb_array_length(p_candidate->'sources')
          THEN RAISE EXCEPTION 'memory candidate sources must be unique'; END IF;
          v_digest:=lucy.memory_candidate_digest_v1(p_candidate);
          SELECT * INTO v_existing FROM lucy.scoped_memory_candidate_versions_v1
          WHERE candidate_id=(p_candidate->>'candidate_id')::uuid
            AND candidate_version=(p_candidate->>'candidate_version')::bigint;
          IF FOUND THEN
            IF v_existing.candidate_digest<>v_digest OR v_existing.serialized_candidate<>p_candidate
            THEN RAISE EXCEPTION 'memory candidate version conflict'; END IF;
            RETURN jsonb_build_object('candidate_id',v_existing.candidate_id,
              'candidate_version',v_existing.candidate_version,
              'candidate_digest',v_existing.candidate_digest,'replayed',true);
          END IF;
          INSERT INTO lucy.scoped_memory_candidate_versions_v1(
            candidate_id,candidate_version,content_scope_id,extractor_binding_id,
            candidate_digest,protection_class,memory_kind,assertion_status,
            epistemic_status,serialized_candidate,created_at)
          VALUES ((p_candidate->>'candidate_id')::uuid,
            (p_candidate->>'candidate_version')::bigint,v_binding.content_scope_id,v_binding.id,
            v_digest,p_candidate->>'protection_class',p_candidate->>'memory_kind',
            p_candidate->>'assertion_status',p_candidate->>'epistemic_status',p_candidate,v_now);
          INSERT INTO lucy.scoped_memory_candidate_sources_v1(
            candidate_id,candidate_version,evidence_id,record_version,byte_start,byte_end,
            content_scope_id)
          SELECT (p_candidate->>'candidate_id')::uuid,
            (p_candidate->>'candidate_version')::bigint,(value->>'evidence_id')::uuid,
            (value->>'record_version')::bigint,(value->>'byte_start')::bigint,
            (value->>'byte_end')::bigint,v_binding.content_scope_id
          FROM jsonb_array_elements(p_candidate->'sources');
          RETURN jsonb_build_object('candidate_id',p_candidate->>'candidate_id',
            'candidate_version',(p_candidate->>'candidate_version')::bigint,
            'candidate_digest',v_digest,'replayed',false);
        EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
          OR not_null_violation OR check_violation THEN
          RAISE EXCEPTION 'malformed memory candidate';
        END
        $function$;

        CREATE FUNCTION lucy.approve_scoped_memory_candidate_v1(
          p_candidate_id uuid,p_candidate_version bigint,p_expected_digest text,
          p_owner_approval_ref uuid,p_owner_actor_id text)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_candidate lucy.scoped_memory_candidate_versions_v1%ROWTYPE;
          v_existing lucy.scoped_memory_candidate_approvals_v1%ROWTYPE;
          v_id uuid:=gen_random_uuid(); v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["memory.candidate.approve"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory candidate approval unavailable'; END IF;
          IF p_candidate_version<1 OR p_expected_digest!~'^[0-9a-f]{64}$'
             OR coalesce(btrim(p_owner_actor_id),'')='' OR length(p_owner_actor_id)>512
          THEN RAISE EXCEPTION 'memory candidate approval is invalid'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-candidate:'||p_candidate_id::text||':'||p_candidate_version::text,0));
          SELECT * INTO v_candidate FROM lucy.scoped_memory_candidate_versions_v1
          WHERE candidate_id=p_candidate_id AND candidate_version=p_candidate_version
            AND content_scope_id=v_actor.content_scope_id;
          IF NOT FOUND OR v_candidate.candidate_digest<>p_expected_digest
             OR lucy.memory_candidate_digest_v1(v_candidate.serialized_candidate)<>p_expected_digest
          THEN RAISE EXCEPTION 'memory candidate approval does not match reviewed bytes'; END IF;
          SELECT * INTO v_existing FROM lucy.scoped_memory_candidate_approvals_v1
          WHERE candidate_id=p_candidate_id AND candidate_version=p_candidate_version;
          IF FOUND THEN
            IF v_existing.candidate_digest<>p_expected_digest
               OR v_existing.owner_approval_ref<>p_owner_approval_ref
               OR v_existing.owner_actor_id<>p_owner_actor_id
            THEN RAISE EXCEPTION 'memory candidate approval conflict'; END IF;
            RETURN jsonb_build_object('approval_id',v_existing.id,'replayed',true);
          END IF;
          INSERT INTO lucy.scoped_memory_candidate_approvals_v1(
            id,candidate_id,candidate_version,content_scope_id,policy_actor_binding_id,
            candidate_digest,owner_approval_ref,owner_actor_id,policy_version,revoked,approved_at)
          VALUES (v_id,p_candidate_id,p_candidate_version,v_actor.content_scope_id,v_actor.id,
            p_expected_digest,p_owner_approval_ref,p_owner_actor_id,v_actor.policy_version,false,v_now);
          RETURN jsonb_build_object('approval_id',v_id,'replayed',false);
        END
        $function$;

        CREATE FUNCTION lucy.promote_scoped_memory_candidate_v1(
          p_approval_id uuid,p_expected_digest text)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_approval lucy.scoped_memory_candidate_approvals_v1%ROWTYPE;
          v_candidate lucy.scoped_memory_candidate_versions_v1%ROWTYPE;
          v_existing lucy.scoped_memory_promotions_v1%ROWTYPE;
          v_source lucy.scoped_memory_candidate_sources_v1%ROWTYPE;
          v_claim_id uuid:=gen_random_uuid(); v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["memory.candidate.promote"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'memory candidate promotion unavailable'; END IF;
          PERFORM pg_advisory_xact_lock(hashtextextended(
            'memory-approval:'||p_approval_id::text,0));
          SELECT * INTO v_approval FROM lucy.scoped_memory_candidate_approvals_v1
          WHERE id=p_approval_id AND content_scope_id=v_actor.content_scope_id;
          IF NOT FOUND OR v_approval.revoked OR v_approval.candidate_digest<>p_expected_digest
          THEN RAISE EXCEPTION 'memory candidate approval is unavailable'; END IF;
          SELECT * INTO v_candidate FROM lucy.scoped_memory_candidate_versions_v1
          WHERE candidate_id=v_approval.candidate_id
            AND candidate_version=v_approval.candidate_version
            AND content_scope_id=v_actor.content_scope_id;
          IF NOT FOUND OR v_candidate.candidate_digest<>p_expected_digest
             OR lucy.memory_candidate_digest_v1(v_candidate.serialized_candidate)<>p_expected_digest
          THEN RAISE EXCEPTION 'memory candidate changed after approval'; END IF;
          SELECT * INTO v_existing FROM lucy.scoped_memory_promotions_v1
          WHERE approval_id=p_approval_id;
          IF FOUND THEN
            RETURN jsonb_build_object('claim_id',v_existing.claim_id,'replayed',true);
          END IF;
          FOR v_source IN SELECT * FROM lucy.scoped_memory_candidate_sources_v1
            WHERE candidate_id=v_candidate.candidate_id
              AND candidate_version=v_candidate.candidate_version ORDER BY evidence_id
          LOOP
            PERFORM pg_advisory_xact_lock(hashtextextended(
              'evidence-derive:'||v_source.evidence_id::text,0));
            IF NOT EXISTS (
              SELECT 1 FROM lucy.scoped_evidence_records_v2 e
              JOIN lucy.scoped_evidence_payloads_v2 p ON p.evidence_id=e.id
              WHERE e.id=v_source.evidence_id AND e.content_scope_id=v_actor.content_scope_id
                AND e.status='active' AND p.record_version=v_source.record_version
            ) OR EXISTS (
              SELECT 1 FROM lucy.scoped_evidence_deletion_fences_v2 f
              WHERE f.evidence_id=v_source.evidence_id
            ) THEN RAISE EXCEPTION 'memory candidate source became unavailable'; END IF;
          END LOOP;
          INSERT INTO lucy.scoped_memory_claims_v1(
            id,content_scope_id,service_binding_id,idempotency_key,subject,predicate,object,
            confidence_millionths,status,origin_class,created_at,candidate_id,candidate_version,
            protection_class,memory_kind,assertion_status,epistemic_status,domain_tags,
            event_time,valid_from,valid_to)
          VALUES (v_claim_id,v_actor.content_scope_id,v_actor.target_service_binding_id,
            'memory-candidate:'||v_candidate.candidate_id::text||':'||v_candidate.candidate_version,
            v_candidate.serialized_candidate->>'subject',
            v_candidate.serialized_candidate->>'predicate',
            v_candidate.serialized_candidate->>'object',
            (v_candidate.serialized_candidate->>'confidence_millionths')::bigint,
            'accepted','evidence_derived',v_now,v_candidate.candidate_id,
            v_candidate.candidate_version,v_candidate.protection_class,v_candidate.memory_kind,
            v_candidate.assertion_status,v_candidate.epistemic_status,
            v_candidate.serialized_candidate->'domain_tags',
            (v_candidate.serialized_candidate->>'event_time')::timestamptz,
            (v_candidate.serialized_candidate->>'valid_from')::timestamptz,
            (v_candidate.serialized_candidate->>'valid_to')::timestamptz);
          INSERT INTO lucy.scoped_memory_claim_sources_v2(
            claim_id,evidence_id,content_scope_id,created_at)
          SELECT v_claim_id,evidence_id,v_actor.content_scope_id,v_now
          FROM lucy.scoped_memory_candidate_sources_v1
          WHERE candidate_id=v_candidate.candidate_id
            AND candidate_version=v_candidate.candidate_version
          GROUP BY evidence_id;
          INSERT INTO lucy.scoped_memory_events_v1(
            id,content_scope_id,service_binding_id,event_type,claim_id,occurred_at)
          VALUES (gen_random_uuid(),v_actor.content_scope_id,v_actor.target_service_binding_id,
            'memory.claim_written',v_claim_id,v_now);
          INSERT INTO lucy.scoped_memory_promotions_v1(
            approval_id,candidate_id,candidate_version,claim_id,content_scope_id,promoted_at)
          VALUES (v_approval.id,v_candidate.candidate_id,v_candidate.candidate_version,
            v_claim_id,v_actor.content_scope_id,v_now);
          RETURN jsonb_build_object('claim_id',v_claim_id,'replayed',false);
        END
        $function$;

        CREATE FUNCTION lucy.search_governed_scoped_memory_v1(p_query text,p_limit integer)
        RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_binding lucy.realm_service_bindings_v1%ROWTYPE; v_result jsonb;
        BEGIN
          SELECT * INTO v_binding FROM lucy.realm_service_bindings_v1
          WHERE session_login=session_user AND active
            AND allowed_actions @> '["memory.read"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'realm operation unavailable'; END IF;
          IF coalesce(btrim(p_query),'')='' OR length(p_query)>200 OR p_limit NOT BETWEEN 1 AND 50
          THEN RAISE EXCEPTION 'scoped memory request is invalid'; END IF;
          SELECT coalesce(jsonb_agg(jsonb_build_object(
            'claim_id',q.id,'candidate_id',q.candidate_id,
            'candidate_version',q.candidate_version,'subject',q.subject,
            'predicate',q.predicate,'object',q.object,
            'confidence_millionths',q.confidence_millionths,'status',q.status,
            'protection_class',coalesce(q.protection_class,'ordinary_private'),
            'memory_kind',q.memory_kind,'assertion_status',q.assertion_status,
            'epistemic_status',q.epistemic_status,'domain_tags',coalesce(q.domain_tags,'[]'::jsonb),
            'source_evidence_ids',coalesce((SELECT jsonb_agg(s.evidence_id ORDER BY s.evidence_id)
              FROM lucy.scoped_memory_claim_sources_v2 s WHERE s.claim_id=q.id),'[]'::jsonb)
          ) ORDER BY q.confidence_millionths DESC,q.created_at DESC,q.id),'[]'::jsonb)
          INTO v_result FROM (
            SELECT * FROM lucy.scoped_memory_claims_v1 c
            WHERE c.content_scope_id=v_binding.content_scope_id AND c.status='accepted'
              AND coalesce(c.protection_class,'ordinary_private')='ordinary_private'
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                JOIN lucy.scoped_evidence_deletion_fences_v2 f ON f.evidence_id=s.evidence_id
                WHERE s.claim_id=c.id)
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                WHERE s.claim_id=c.id AND NOT EXISTS (
                  SELECT 1 FROM lucy.scoped_evidence_records_v2 e
                  JOIN lucy.scoped_evidence_payloads_v2 p ON p.evidence_id=e.id
                  WHERE e.id=s.evidence_id AND e.status='active'))
              AND (c.subject ILIKE '%'||p_query||'%' OR c.predicate ILIKE '%'||p_query||'%'
                   OR c.object ILIKE '%'||p_query||'%')
            ORDER BY c.confidence_millionths DESC,c.created_at DESC,c.id LIMIT p_limit
          ) q;
          RETURN v_result;
        END
        $function$;

        CREATE FUNCTION lucy.search_protected_scoped_memory_v1(
          p_query text,p_limit integer,p_owner_interaction_ref uuid,p_reason_code text)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_result jsonb; v_ids jsonb; v_commitment text;
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='policy_notary' AND active
            AND allowed_actions @> '["memory.protected.read"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'protected memory recall unavailable'; END IF;
          IF coalesce(btrim(p_query),'')='' OR length(p_query)>200 OR p_limit NOT BETWEEN 1 AND 20
             OR coalesce(btrim(p_reason_code),'')='' OR length(p_reason_code)>60
          THEN RAISE EXCEPTION 'protected memory recall is invalid'; END IF;
          SELECT coalesce(jsonb_agg(jsonb_build_object(
            'claim_id',q.id,'candidate_id',q.candidate_id,'candidate_version',q.candidate_version,
            'subject',q.subject,'predicate',q.predicate,'object',q.object,
            'confidence_millionths',q.confidence_millionths,'status',q.status,
            'protection_class',q.protection_class,'memory_kind',q.memory_kind,
            'assertion_status',q.assertion_status,'epistemic_status',q.epistemic_status,
            'domain_tags',q.domain_tags,'source_evidence_ids',
              (SELECT jsonb_agg(s.evidence_id ORDER BY s.evidence_id)
               FROM lucy.scoped_memory_claim_sources_v2 s WHERE s.claim_id=q.id)
          ) ORDER BY q.confidence_millionths DESC,q.created_at DESC,q.id),'[]'::jsonb),
          coalesce(jsonb_agg(to_jsonb(q.id) ORDER BY q.id),'[]'::jsonb)
          INTO v_result,v_ids FROM (
            SELECT * FROM lucy.scoped_memory_claims_v1 c
            WHERE c.content_scope_id=v_actor.content_scope_id AND c.status='accepted'
              AND c.protection_class='protected'
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                JOIN lucy.scoped_evidence_deletion_fences_v2 f ON f.evidence_id=s.evidence_id
                WHERE s.claim_id=c.id)
              AND NOT EXISTS (SELECT 1 FROM lucy.scoped_memory_claim_sources_v2 s
                WHERE s.claim_id=c.id AND NOT EXISTS (
                  SELECT 1 FROM lucy.scoped_evidence_records_v2 e
                  JOIN lucy.scoped_evidence_payloads_v2 p ON p.evidence_id=e.id
                  WHERE e.id=s.evidence_id AND e.status='active'))
              AND (c.subject ILIKE '%'||p_query||'%' OR c.predicate ILIKE '%'||p_query||'%'
                   OR c.object ILIKE '%'||p_query||'%')
            ORDER BY c.confidence_millionths DESC,c.created_at DESC,c.id LIMIT p_limit
          ) q;
          v_commitment:=encode(public.digest(convert_to(p_query,'UTF8'),'sha256'),'hex');
          INSERT INTO lucy.scoped_protected_memory_accesses_v1(
            id,content_scope_id,policy_actor_binding_id,owner_interaction_ref,
            query_commitment,returned_claim_ids,reason_code,accessed_at)
          VALUES (gen_random_uuid(),v_actor.content_scope_id,v_actor.id,p_owner_interaction_ref,
            v_commitment,v_ids,p_reason_code,clock_timestamp());
          RETURN v_result;
        END
        $function$;

        ALTER FUNCTION lucy.memory_candidate_digest_v1(jsonb)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.stage_scoped_memory_candidate_v1(jsonb)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.approve_scoped_memory_candidate_v1(uuid,bigint,text,uuid,text)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.promote_scoped_memory_candidate_v1(uuid,text)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.search_governed_scoped_memory_v1(text,integer)
          OWNER TO lucy_security_function_owner;
        ALTER FUNCTION lucy.search_protected_scoped_memory_v1(text,integer,uuid,text)
          OWNER TO lucy_security_function_owner;

        REVOKE ALL ON FUNCTION lucy.memory_candidate_digest_v1(jsonb),
          lucy.stage_scoped_memory_candidate_v1(jsonb),
          lucy.approve_scoped_memory_candidate_v1(uuid,bigint,text,uuid,text),
          lucy.promote_scoped_memory_candidate_v1(uuid,text),
          lucy.search_governed_scoped_memory_v1(text,integer),
          lucy.search_protected_scoped_memory_v1(text,integer,uuid,text)
          FROM PUBLIC,lucy_app;
        REVOKE ALL ON lucy.scoped_memory_candidate_versions_v1,
          lucy.scoped_memory_candidate_sources_v1,lucy.scoped_memory_candidate_approvals_v1,
          lucy.scoped_memory_promotions_v1,lucy.scoped_protected_memory_accesses_v1
          FROM PUBLIC,lucy_app;
        REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON lucy.scoped_memory_claims_v1,
          lucy.scoped_memory_claim_sources_v2,lucy.scoped_memory_events_v1
          FROM lucy_app;
        GRANT SELECT,INSERT ON lucy.scoped_memory_candidate_versions_v1,
          lucy.scoped_memory_candidate_sources_v1,lucy.scoped_memory_candidate_approvals_v1,
          lucy.scoped_memory_promotions_v1,lucy.scoped_protected_memory_accesses_v1,
          lucy.scoped_memory_claims_v1,lucy.scoped_memory_claim_sources_v2,
          lucy.scoped_memory_events_v1 TO lucy_security_function_owner;
        GRANT SELECT ON lucy.realm_service_bindings_v1,lucy.realm_sensitive_actor_bindings_v1,
          lucy.scoped_evidence_records_v2,lucy.scoped_evidence_payloads_v2,
          lucy.scoped_evidence_deletion_fences_v2 TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("governed memory history requires a reviewed forward migration")
