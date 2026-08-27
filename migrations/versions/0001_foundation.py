"""Foundational evidence, memory, control, budget, and audit tables."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_foundation"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS lucy")
    op.create_table(
        "operations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("idempotency_key", sa.Text(), nullable=False, unique=True),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("result", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "outcome IN ('pending','succeeded','failed','ambiguous')",
            name="ck_operations_outcome",
        ),
        schema="lucy",
    )
    op.create_table(
        "evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("source_conversation_id", sa.Text(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content", postgresql.JSONB(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(["operation_id"], ["lucy.operations.id"]),
        schema="lucy",
    )
    op.create_table(
        "memory_claims",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("predicate", sa.Text(), nullable=False),
        sa.Column("object", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("supersedes_claim_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["lucy.evidence.id"]),
        sa.ForeignKeyConstraint(["supersedes_claim_id"], ["lucy.memory_claims.id"]),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_claim_confidence"),
        sa.CheckConstraint(
            "status IN ('provisional','accepted','superseded')", name="ck_claim_status"
        ),
        schema="lucy",
    )
    op.create_table(
        "lifecycle",
        sa.Column("singleton", sa.Boolean(), primary_key=True, server_default=sa.true()),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("version", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("singleton", name="ck_lifecycle_singleton"),
        schema="lucy",
    )
    op.create_table(
        "budget_accounts",
        sa.Column("name", sa.Text(), primary_key=True),
        sa.Column("limit_microusd", sa.BigInteger(), nullable=False),
        sa.Column("reserved_microusd", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("spent_microusd", sa.BigInteger(), nullable=False, server_default="0"),
        sa.CheckConstraint("limit_microusd >= 0", name="ck_budget_limit"),
        sa.CheckConstraint("reserved_microusd >= 0", name="ck_budget_reserved"),
        sa.CheckConstraint("spent_microusd >= 0", name="ck_budget_spent"),
        schema="lucy",
    )
    op.create_table(
        "budget_reservations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("budget_name", sa.Text(), nullable=False),
        sa.Column("reserved_microusd", sa.BigInteger(), nullable=False),
        sa.Column("settled_microusd", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("settled_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["operation_id"], ["lucy.operations.id"]),
        sa.ForeignKeyConstraint(["budget_name"], ["lucy.budget_accounts.name"]),
        schema="lucy",
    )
    op.create_table(
        "audit_head",
        sa.Column("singleton", sa.Boolean(), primary_key=True, server_default=sa.true()),
        sa.Column("last_sequence", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_hash", sa.String(64), nullable=False),
        sa.CheckConstraint("singleton", name="ck_audit_head_singleton"),
        schema="lucy",
    )
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sequence", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False, unique=True),
        sa.ForeignKeyConstraint(["operation_id"], ["lucy.operations.id"]),
        schema="lucy",
    )
    op.execute(
        "INSERT INTO lucy.lifecycle (singleton, state, version, updated_at) "
        "VALUES (true, 'offline', 0, now())"
    )
    op.execute(
        "INSERT INTO lucy.audit_head (singleton, last_sequence, last_hash) "
        "VALUES (true, 0, repeat('0', 64))"
    )
    op.execute(
        "INSERT INTO lucy.budget_accounts "
        "(name, limit_microusd, reserved_microusd, spent_microusd) "
        "VALUES ('model.daily', 1000000, 0, 0)"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA lucy TO lucy_app")
    op.execute("REVOKE UPDATE, DELETE ON lucy.evidence, lucy.audit_events FROM lucy_app")
    op.execute(
        "CREATE FUNCTION lucy.reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN RAISE EXCEPTION 'append-only table % cannot be mutated', TG_TABLE_NAME; END $$"
    )
    op.execute(
        "CREATE TRIGGER evidence_append_only BEFORE UPDATE OR DELETE ON lucy.evidence "
        "FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
    )
    op.execute(
        "CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON lucy.audit_events "
        "FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS lucy.reject_mutation() CASCADE")
    for table in (
        "audit_events",
        "audit_head",
        "budget_reservations",
        "budget_accounts",
        "lifecycle",
        "memory_claims",
        "evidence",
        "operations",
    ):
        op.drop_table(table, schema="lucy")
