"""Record metadata-only scoped deletion finality observations."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0035_r1_scoped_finality"
down_revision: str | None = "0034_r1_deletion_reconcile"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        "ck_sensitive_actor_role", "realm_sensitive_actor_bindings_v1", schema="lucy"
    )
    op.create_check_constraint(
        "ck_sensitive_actor_role",
        "realm_sensitive_actor_bindings_v1",
        "actor_role IN ('archive_writer','policy_notary','sensitive_workflow',"
        "'finality_verifier')",
        schema="lucy",
    )
    op.create_table(
        "scoped_finality_observations_v2",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("content_scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finality_actor_binding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("metadata_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("inventory_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("serialized_inventory", postgresql.JSONB(), nullable=False),
        sa.Column("recoverable_copy_count", sa.BigInteger(), nullable=False),
        sa.Column("finality_not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finality_status", sa.String(30), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["operation_id"], ["lucy.sensitive_operations_v2.id"]),
        sa.ForeignKeyConstraint(["content_scope_id"], ["lucy.realm_content_scopes_v1.id"]),
        sa.ForeignKeyConstraint(
            ["finality_actor_binding_id"], ["lucy.realm_sensitive_actor_bindings_v1.id"]
        ),
        sa.UniqueConstraint(
            "operation_id", "metadata_observed_at", name="uq_scoped_finality_observed"
        ),
        sa.CheckConstraint("recoverable_copy_count>=0", name="ck_scoped_recovery_count"),
        sa.CheckConstraint(
            "finality_status IN ('EXTENDED','VERIFIED')", name="ck_scoped_finality_status"
        ),
        schema="lucy",
    )
    op.execute(
        "CREATE TRIGGER scoped_finality_observations_v2_immutable BEFORE UPDATE OR DELETE "
        "ON lucy.scoped_finality_observations_v2 FOR EACH ROW "
        "EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.execute(
        r"""
        CREATE FUNCTION lucy.record_scoped_finality_inventory_v2(
          p_operation_id uuid,p_inventory jsonb
        ) RETURNS jsonb
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp
        AS $function$
        DECLARE
          v_actor lucy.realm_sensitive_actor_bindings_v1%ROWTYPE;
          v_operation lucy.sensitive_operations_v2%ROWTYPE;
          v_effect lucy.scoped_deletion_effects_v2%ROWTYPE;
          v_latest lucy.scoped_finality_observations_v2%ROWTYPE;
          v_observed timestamptz; v_pitr_earliest timestamptz;
          v_pitr_latest timestamptz; v_exceptional_earliest timestamptz;
          v_exceptional_latest timestamptz; v_not_before timestamptz;
          v_count bigint; v_exceptional_count bigint; v_status text; v_digest text;
          v_now timestamptz:=clock_timestamp();
        BEGIN
          SELECT * INTO v_actor FROM lucy.realm_sensitive_actor_bindings_v1
          WHERE session_login=session_user AND actor_role='finality_verifier' AND active
            AND allowed_actions @> '["sensitive.finality.record"]'::jsonb;
          IF NOT FOUND THEN RAISE EXCEPTION 'scoped finality verification unavailable'; END IF;
          SELECT * INTO v_operation FROM lucy.sensitive_operations_v2
          WHERE id=p_operation_id AND content_scope_id=v_actor.content_scope_id;
          IF NOT FOUND OR v_operation.action<>'evidence.delete'
             OR v_operation.state<>'FINALITY_PENDING'
          THEN RAISE EXCEPTION 'scoped finality operation unavailable'; END IF;
          SELECT * INTO STRICT v_effect FROM lucy.scoped_deletion_effects_v2
          WHERE operation_id=v_operation.id AND content_scope_id=v_operation.content_scope_id;
          IF jsonb_typeof(p_inventory)<>'object'
             OR (SELECT count(*) FROM jsonb_object_keys(p_inventory))<>18
             OR p_inventory-ARRAY[
            'contract_version','object_type','operation_id','metadata_observed_at',
            'pitr_status','pitr_recovery_period_days','pitr_earliest_restorable_at',
            'pitr_latest_restorable_at','on_demand_backup_count',
            'aws_backup_recovery_point_count','export_count','import_count',
            'global_replica_count','quarantine_table_count','stream_enabled',
            'exceptional_earliest_restorable_at','exceptional_latest_restorable_at',
            'metadata_inventory_digest']<>'{}'::jsonb
          THEN RAISE EXCEPTION 'invalid scoped finality inventory'; END IF;
          IF p_inventory->>'contract_version'<>'1'
             OR p_inventory->>'object_type'<>'lucy.deletion-recovery-inventory.v1'
             OR (p_inventory->>'operation_id')::uuid<>v_operation.id
             OR p_inventory->>'metadata_inventory_digest' !~ '^[0-9a-f]{64}$'
             OR p_inventory->>'pitr_status' NOT IN ('ENABLED','DISABLED')
          THEN RAISE EXCEPTION 'scoped finality inventory domain is invalid'; END IF;
          v_observed:=(p_inventory->>'metadata_observed_at')::timestamptz;
          v_pitr_earliest:=nullif(p_inventory->>'pitr_earliest_restorable_at','')::timestamptz;
          v_pitr_latest:=nullif(p_inventory->>'pitr_latest_restorable_at','')::timestamptz;
          v_exceptional_earliest:=
            nullif(p_inventory->>'exceptional_earliest_restorable_at','')::timestamptz;
          v_exceptional_latest:=
            nullif(p_inventory->>'exceptional_latest_restorable_at','')::timestamptz;
          v_exceptional_count:=(p_inventory->>'on_demand_backup_count')::bigint
            +(p_inventory->>'aws_backup_recovery_point_count')::bigint
            +(p_inventory->>'export_count')::bigint
            +(p_inventory->>'import_count')::bigint
            +(p_inventory->>'global_replica_count')::bigint
            +(p_inventory->>'quarantine_table_count')::bigint;
          v_digest:=p_inventory->>'metadata_inventory_digest';
          SELECT * INTO v_latest FROM lucy.scoped_finality_observations_v2
          WHERE operation_id=v_operation.id ORDER BY metadata_observed_at DESC LIMIT 1;
          IF FOUND AND v_latest.inventory_digest=v_digest
             AND v_latest.serialized_inventory=p_inventory
          THEN RETURN jsonb_build_object('status',v_latest.finality_status,
            'recoverable_copy_count',v_latest.recoverable_copy_count,
            'finality_not_before',v_latest.finality_not_before,'replayed',true); END IF;
          IF FOUND AND v_latest.finality_status='VERIFIED'
          THEN RAISE EXCEPTION 'scoped deletion finality is already verified'; END IF;
          IF v_observed<v_effect.effective_at OR v_observed>v_now+interval '5 minutes'
             OR (v_latest.id IS NOT NULL AND v_observed<=v_latest.metadata_observed_at)
             OR v_exceptional_count<0
             OR (p_inventory->>'on_demand_backup_count')::bigint<0
             OR (p_inventory->>'aws_backup_recovery_point_count')::bigint<0
             OR (p_inventory->>'export_count')::bigint<0
             OR (p_inventory->>'import_count')::bigint<0
             OR (p_inventory->>'global_replica_count')::bigint<0
             OR (p_inventory->>'quarantine_table_count')::bigint<0
             OR (p_inventory->>'stream_enabled')::boolean IS NULL
             OR (v_pitr_earliest IS NULL)<>(v_pitr_latest IS NULL)
             OR (v_pitr_earliest IS NOT NULL AND v_pitr_earliest>v_pitr_latest)
             OR (v_exceptional_earliest IS NULL)<>(v_exceptional_latest IS NULL)
             OR (v_exceptional_earliest IS NOT NULL
                AND v_exceptional_earliest>v_exceptional_latest)
             OR (v_exceptional_count=0 AND v_exceptional_earliest IS NOT NULL)
          THEN RAISE EXCEPTION 'scoped finality inventory is not monotonic'; END IF;
          IF p_inventory->>'pitr_status'='ENABLED' THEN
            IF (p_inventory->>'pitr_recovery_period_days')::bigint<>30
               OR v_pitr_earliest IS NULL
            THEN RAISE EXCEPTION 'scoped finality PITR inventory is invalid'; END IF;
          ELSIF (p_inventory->>'pitr_recovery_period_days') IS NOT NULL
             OR v_pitr_earliest IS NOT NULL
          THEN RAISE EXCEPTION 'scoped finality PITR inventory is invalid'; END IF;
          v_count:=v_exceptional_count+
            CASE WHEN (p_inventory->>'stream_enabled')::boolean THEN 1 ELSE 0 END;
          IF p_inventory->>'pitr_status'<>'ENABLED'
             OR (p_inventory->>'pitr_recovery_period_days')::bigint<>30
          THEN v_count:=v_count+1;
          ELSIF v_pitr_earliest<=v_effect.effective_at THEN
            v_count:=v_count+1;
          END IF;
          v_not_before:=greatest(v_effect.finality_not_before,
            coalesce(v_latest.finality_not_before,v_effect.finality_not_before),
            coalesce(v_exceptional_latest,v_effect.finality_not_before));
          v_status:=CASE WHEN v_observed>=v_not_before AND v_count=0
            THEN 'VERIFIED' ELSE 'EXTENDED' END;
          INSERT INTO lucy.scoped_finality_observations_v2(
            id,operation_id,content_scope_id,finality_actor_binding_id,
            metadata_observed_at,inventory_digest,serialized_inventory,
            recoverable_copy_count,finality_not_before,finality_status,created_at
          ) VALUES (gen_random_uuid(),v_operation.id,v_operation.content_scope_id,v_actor.id,
            v_observed,v_digest,p_inventory,v_count,v_not_before,v_status,v_now);
          RETURN jsonb_build_object('status',v_status,'recoverable_copy_count',v_count,
            'finality_not_before',v_not_before,'replayed',false);
        EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value
          OR not_null_violation OR check_violation
          THEN RAISE EXCEPTION 'malformed scoped finality inventory';
        END
        $function$;
        ALTER FUNCTION lucy.record_scoped_finality_inventory_v2(uuid,jsonb)
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.record_scoped_finality_inventory_v2(uuid,jsonb)
          FROM PUBLIC,lucy_app;
        GRANT SELECT,INSERT ON lucy.scoped_finality_observations_v2
          TO lucy_security_function_owner;
        GRANT SELECT ON lucy.scoped_deletion_effects_v2
          TO lucy_security_function_owner;
        """
    )


def downgrade() -> None:
    raise RuntimeError("scoped deletion finality requires a reviewed forward migration")
