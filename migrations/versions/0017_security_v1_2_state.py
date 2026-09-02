"""Create the Security Baseline v1.2 PostgreSQL state boundary."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0017_security_v1_2_state"
down_revision: str | None = "0016_deletion_journal"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute(
        """
        DO $bootstrap$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM pg_roles WHERE rolname = 'lucy_security_function_owner'
          ) THEN
            RAISE EXCEPTION
              'Security Baseline v1.2 bootstrap missing: lucy_security_function_owner';
          END IF;
          IF NOT pg_has_role(current_user, 'lucy_security_function_owner', 'MEMBER') THEN
            RAISE EXCEPTION
              'migration identity is not authorized to install v1.2 security functions';
          END IF;
        END
        $bootstrap$
        """
    )
    op.execute(
        "GRANT USAGE, CREATE ON SCHEMA lucy TO lucy_security_function_owner"
    )

    op.add_column(
        "evidence_payloads",
        sa.Column(
            "encryption_context_version",
            sa.SmallInteger(),
            nullable=False,
            server_default="1",
        ),
        schema="lucy",
    )
    for column in ("record_version", "storage_epoch", "registry_epoch", "key_epoch"):
        op.add_column(
            "evidence_payloads",
            sa.Column(column, sa.BigInteger(), nullable=False, server_default="1"),
            schema="lucy",
        )
        op.create_check_constraint(
            f"ck_evidence_payload_{column}",
            "evidence_payloads",
            f"{column} >= 1",
            schema="lucy",
        )
    op.create_check_constraint(
        "ck_evidence_payload_context_version",
        "evidence_payloads",
        "encryption_context_version IN (1,2)",
        schema="lucy",
    )

    op.create_table(
        "security_contract_epochs",
        sa.Column("singleton", sa.Boolean(), primary_key=True),
        sa.Column("storage_epoch", sa.BigInteger(), nullable=False),
        sa.Column("registry_epoch", sa.BigInteger(), nullable=False),
        sa.Column("key_epoch", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("singleton", name="ck_security_epochs_singleton"),
        sa.CheckConstraint(
            "storage_epoch >= 1 AND registry_epoch >= 1 AND key_epoch >= 1",
            name="ck_security_epochs_positive",
        ),
        schema="lucy",
    )
    op.execute(
        "INSERT INTO lucy.security_contract_epochs VALUES (true,1,1,1,clock_timestamp())"
    )

    op.create_table(
        "owner_interaction_assertions_v1",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("nonce", sa.Text(), nullable=False, unique=True),
        sa.Column("anti_replay_id", sa.Text(), nullable=False, unique=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("owner_subject", sa.Text(), nullable=False),
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("environment", sa.Text(), nullable=False),
        sa.Column("assertion_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("serialized_assertion", postgresql.JSONB(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("storage_epoch", sa.BigInteger(), nullable=False),
        sa.Column("registry_epoch", sa.BigInteger(), nullable=False),
        sa.Column("key_epoch", sa.BigInteger(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["lucy.evidence.id"]),
        sa.CheckConstraint(
            "action IN ('evidence.retrieve','evidence.delete')",
            name="ck_owner_assertion_action",
        ),
        sa.CheckConstraint(
            "environment IN ('development','test','production')",
            name="ck_owner_assertion_environment",
        ),
        sa.CheckConstraint(
            "expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'",
            name="ck_owner_assertion_lifetime",
        ),
        schema="lucy",
    )

    op.create_table(
        "sensitive_action_permits_v2",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("nonce", sa.Text(), nullable=False, unique=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("owner_subject", sa.Text(), nullable=False),
        sa.Column(
            "owner_assertion_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.owner_interaction_assertions_v1.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "evidence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.evidence.id"),
            nullable=False,
        ),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("max_records", sa.Integer(), nullable=False),
        sa.Column("max_bytes", sa.Integer(), nullable=False),
        sa.Column("record_version", sa.BigInteger(), nullable=False),
        sa.Column("permit_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("serialized_permit", postgresql.JSONB(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("permit_claim_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("storage_epoch", sa.BigInteger(), nullable=False),
        sa.Column("registry_epoch", sa.BigInteger(), nullable=False),
        sa.Column("key_epoch", sa.BigInteger(), nullable=False),
        sa.Column("issuance_idempotency_key", sa.Text(), nullable=False, unique=True),
        sa.Column(
            "issued_operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.operations.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_operation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("claimed_idempotency_key", sa.Text(), nullable=True, unique=True),
        sa.Column("claimed_session_user", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "action IN ('evidence.retrieve','evidence.delete')",
            name="ck_sensitive_permit_v2_action",
        ),
        sa.CheckConstraint(
            "reason IN ('verify_exact_wording','resolve_ambiguity','recover_missing_context',"
            "'owner_review','owner_request','sensitive_data','retention_expired')",
            name="ck_sensitive_permit_v2_reason",
        ),
        sa.CheckConstraint(
            "max_records BETWEEN 1 AND 90 AND max_bytes BETWEEN 1 AND 131072",
            name="ck_sensitive_permit_v2_limits",
        ),
        sa.CheckConstraint(
            "permit_claim_deadline > issued_at AND "
            "permit_claim_deadline <= issued_at + interval '5 minutes'",
            name="ck_sensitive_permit_v2_lifetime",
        ),
        sa.CheckConstraint(
            "state IN ('ISSUED','CLAIMED','EXPIRED','BULK_REQUIRED')",
            name="ck_sensitive_permit_v2_state",
        ),
        schema="lucy",
    )

    op.create_table(
        "deletion_target_manifests_v1",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "permit_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.sensitive_action_permits_v2.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("root_evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=False, unique=True),
        sa.Column("scope_version", sa.BigInteger(), nullable=False),
        sa.Column("target_count", sa.Integer(), nullable=False),
        sa.Column("targets_digest", sa.String(64), nullable=True),
        sa.Column("unsigned_manifest_digest", sa.String(64), nullable=True),
        sa.Column("unsigned_manifest", postgresql.JSONB(), nullable=True),
        sa.Column("signed_manifest_digest", sa.String(64), nullable=True, unique=True),
        sa.Column("signed_manifest", postgresql.JSONB(), nullable=True),
        sa.Column("permit_claim_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("execution_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["root_evidence_id"], ["lucy.evidence.id"]),
        sa.CheckConstraint("scope_version >= 1", name="ck_deletion_manifest_scope_version"),
        sa.CheckConstraint(
            "target_count >= 1", name="ck_deletion_manifest_target_count_positive"
        ),
        sa.CheckConstraint(
            "state IN ('PREPARED','SIGNED','CLAIMED','BULK_REQUIRED')",
            name="ck_deletion_manifest_state",
        ),
        schema="lucy",
    )

    op.create_table(
        "deletion_manifest_targets_v1",
        sa.Column(
            "manifest_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.deletion_target_manifests_v1.id"),
            primary_key=True,
        ),
        sa.Column(
            "evidence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.evidence.id"),
            primary_key=True,
        ),
        sa.Column("key_ref", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("record_version", sa.BigInteger(), nullable=False),
        sa.Column("key_epoch", sa.BigInteger(), nullable=False),
        sa.UniqueConstraint("manifest_id", "key_ref", name="uq_manifest_target_key_ref"),
        schema="lucy",
    )

    op.create_table(
        "executor_bindings_v1",
        sa.Column("action", sa.Text(), primary_key=True),
        sa.Column("environment", sa.Text(), primary_key=True),
        sa.Column("executor_identity", sa.Text(), nullable=False),
        sa.Column("executor_alias_arn", sa.Text(), nullable=False, unique=True),
        sa.Column("executor_version", sa.BigInteger(), nullable=False),
        sa.Column("receipt_key_id", sa.Text(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("configured_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "action IN ('evidence.retrieve','evidence.delete')",
            name="ck_executor_binding_action",
        ),
        sa.CheckConstraint(
            "environment IN ('development','test','production')",
            name="ck_executor_binding_environment",
        ),
        sa.CheckConstraint("executor_version >= 1", name="ck_executor_binding_version"),
        schema="lucy",
    )

    op.create_table(
        "sensitive_operations_v1",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "permit_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.sensitive_action_permits_v2.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "manifest_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.deletion_target_manifests_v1.id"),
            nullable=True,
            unique=True,
        ),
        sa.Column("idempotency_key", sa.Text(), nullable=False, unique=True),
        sa.Column("caller_session_user", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("encrypted_package", postgresql.JSONB(), nullable=False),
        sa.Column("package_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("package_size_bytes", sa.Integer(), nullable=False),
        sa.Column("record_version", sa.BigInteger(), nullable=False),
        sa.Column("storage_epoch", sa.BigInteger(), nullable=False),
        sa.Column("registry_epoch", sa.BigInteger(), nullable=False),
        sa.Column("key_epoch", sa.BigInteger(), nullable=False),
        sa.Column("permit_claim_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("execution_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("executor_receipt_digest", sa.String(64), nullable=True),
        sa.CheckConstraint(
            "action IN ('evidence.retrieve','evidence.delete')",
            name="ck_sensitive_operation_action",
        ),
        sa.CheckConstraint(
            "state IN ('CLAIMED','EXECUTING','EXECUTOR_RECEIPTED','DELIVERY_CONFIRMED',"
            "'DELIVERY_UNKNOWN','EFFECTIVE','FINALITY_PENDING','FINALITY_EXTENDED',"
            "'FINALITY_VERIFIED','EXPIRED','BULK_REQUIRED','FAILED_RETRYABLE','FAILED_FINAL')",
            name="ck_sensitive_operation_state",
        ),
        sa.CheckConstraint(
            "package_size_bytes BETWEEN 1 AND 131072",
            name="ck_sensitive_operation_package_size",
        ),
        schema="lucy",
    )
    op.create_index(
        "ix_sensitive_operation_evidence",
        "sensitive_operations_v1",
        ["evidence_id", "state"],
        schema="lucy",
    )

    op.create_table(
        "sensitive_execution_grants_v1",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.sensitive_operations_v1.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("grant_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("serialized_grant", postgresql.JSONB(), nullable=False),
        sa.Column("executor_identity", sa.Text(), nullable=False),
        sa.Column("executor_alias_arn", sa.Text(), nullable=False),
        sa.Column("executor_version", sa.BigInteger(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("execution_deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stored_at", sa.DateTime(timezone=True), nullable=False),
        schema="lucy",
    )

    op.create_table(
        "executor_receipt_attestations_v1",
        sa.Column("receipt_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.sensitive_operations_v1.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("execution_grant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("receipt_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("result", sa.Text(), nullable=False),
        sa.Column("receipt_key_id", sa.Text(), nullable=False),
        sa.Column("executor_identity", sa.Text(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_session_user", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "result IN ('retrieval_succeeded','deletion_succeeded','idempotent_replay','rejected')",
            name="ck_executor_attestation_result",
        ),
        schema="lucy",
    )

    op.create_table(
        "evidence_deletion_fences_v1",
        sa.Column(
            "evidence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.evidence.id"),
            primary_key=True,
        ),
        sa.Column("permit_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("fenced_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('CLAIMED','BULK_REQUIRED','EFFECTIVE')",
            name="ck_evidence_deletion_fence_state",
        ),
        schema="lucy",
    )

    op.create_table(
        "deletion_finality_v1",
        sa.Column(
            "operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.sensitive_operations_v1.id"),
            primary_key=True,
        ),
        sa.Column("deletion_effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finality_not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finality_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finality_status", sa.Text(), nullable=False),
        sa.Column("metadata_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("earliest_restorable_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("latest_restorable_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recoverable_copy_count", sa.Integer(), nullable=True),
        sa.Column("metadata_inventory_digest", sa.String(64), nullable=True),
        sa.CheckConstraint(
            "finality_not_before >= deletion_effective_at",
            name="ck_deletion_finality_lower_bound",
        ),
        sa.CheckConstraint(
            "finality_status IN ('PENDING','EXTENDED','VERIFIED')",
            name="ck_deletion_finality_status",
        ),
        schema="lucy",
    )

    op.create_table(
        "sensitive_operation_events_v1",
        sa.Column("sequence", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        schema="lucy",
    )

    immutable_tables = (
        "owner_interaction_assertions_v1",
        "deletion_manifest_targets_v1",
        "sensitive_execution_grants_v1",
        "executor_receipt_attestations_v1",
        "sensitive_operation_events_v1",
    )
    protected_tables = (
        "security_contract_epochs",
        "owner_interaction_assertions_v1",
        "sensitive_action_permits_v2",
        "deletion_target_manifests_v1",
        "deletion_manifest_targets_v1",
        "executor_bindings_v1",
        "sensitive_operations_v1",
        "sensitive_execution_grants_v1",
        "executor_receipt_attestations_v1",
        "evidence_deletion_fences_v1",
        "deletion_finality_v1",
        "sensitive_operation_events_v1",
    )
    for table in protected_tables:
        op.execute(f"REVOKE ALL ON lucy.{table} FROM PUBLIC, lucy_app")
    for table in immutable_tables:
        op.execute(
            f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON lucy.{table} "
            "FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
        )

    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA lucy "
        "TO lucy_security_function_owner"
    )
    op.execute(
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA lucy "
        "TO lucy_security_function_owner"
    )
    op.execute("UPDATE lucy.runtime_admission SET state='quarantined', updated_at=now()")


def downgrade() -> None:
    raise RuntimeError(
        "Security Baseline v1.2 state is recovery authority; use a reviewed forward migration"
    )
