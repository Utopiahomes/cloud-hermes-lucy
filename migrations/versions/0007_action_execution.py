"""Add durable policy and budget-gated action execution journal."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_action_execution"
down_revision: str | None = "0006_memory_write_proposals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "INSERT INTO lucy.budget_accounts "
        "(name, limit_microusd, reserved_microusd, spent_microusd) "
        "VALUES ('action.daily', 1000000, 0, 0) ON CONFLICT (name) DO NOTHING"
    )
    op.create_table(
        "action_executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("idempotency_key", sa.Text(), nullable=False, unique=True),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("action_payload", postgresql.JSONB(), nullable=False),
        sa.Column("estimated_microusd", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("disposition", sa.Text(), nullable=False),
        sa.Column(
            "control_operation_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            unique=True,
        ),
        sa.Column("approval_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reservation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "execution_operation_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
            unique=True,
        ),
        sa.Column("result", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["control_operation_id"], ["lucy.operations.id"]),
        sa.ForeignKeyConstraint(["approval_id"], ["lucy.approval_requests.id"]),
        sa.ForeignKeyConstraint(["reservation_id"], ["lucy.budget_reservations.id"]),
        sa.ForeignKeyConstraint(["execution_operation_id"], ["lucy.operations.id"]),
        sa.CheckConstraint("estimated_microusd >= 0", name="ck_action_estimate"),
        sa.CheckConstraint(
            "status IN ('denied','awaiting_approval','reserved','executing',"
            "'succeeded','failed','ambiguous')", name="ck_action_status"
        ),
        sa.CheckConstraint(
            "disposition IN ('allow','require_approval','deny')", name="ck_action_disposition"
        ),
        schema="lucy",
    )
    op.execute("GRANT SELECT, INSERT, UPDATE ON lucy.action_executions TO lucy_app")


def downgrade() -> None:
    op.drop_table("action_executions", schema="lucy")
    op.execute("DELETE FROM lucy.budget_accounts WHERE name = 'action.daily'")
