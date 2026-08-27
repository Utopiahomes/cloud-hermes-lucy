"""Add human-only approval requests."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_approvals"
down_revision: str | None = "0001_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "approval_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "request_operation_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True
        ),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("action_payload", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_by", sa.Text(), nullable=True),
        sa.Column("actor_type", sa.Text(), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("version", sa.BigInteger(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["request_operation_id"], ["lucy.operations.id"]),
        sa.CheckConstraint(
            "status IN ('pending','approved','denied','expired')", name="ck_approval_status"
        ),
        sa.CheckConstraint(
            "actor_type IS NULL OR actor_type IN ('human_owner','human_delegate')",
            name="ck_approval_human_actor",
        ),
        schema="lucy",
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON lucy.approval_requests TO lucy_app; "
        "REVOKE DELETE ON lucy.approval_requests FROM lucy_app"
    )


def downgrade() -> None:
    op.drop_table("approval_requests", schema="lucy")

