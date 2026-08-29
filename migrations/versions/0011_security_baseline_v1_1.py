"""Add single-use sensitive-action permits for Security Baseline v1.1."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_security_v1_1"
down_revision: str | None = "0010_aws_kms_backend"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sensitive_action_permits",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("nonce", sa.Text(), nullable=False, unique=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("owner_subject", sa.Text(), nullable=False),
        sa.Column("owner_interaction_id", sa.Text(), nullable=False),
        sa.Column("serialized_permit", postgresql.JSONB(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "issued_operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.operations.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("consumed_by_idempotency_key", sa.Text(), unique=True),
        sa.CheckConstraint(
            "action IN ('evidence.retrieve','evidence.delete')",
            name="ck_sensitive_action_permit_action",
        ),
        sa.CheckConstraint(
            "expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'",
            name="ck_sensitive_action_permit_lifetime",
        ),
        schema="lucy",
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON lucy.sensitive_action_permits TO lucy_app"
    )


def downgrade() -> None:
    op.drop_table("sensitive_action_permits", schema="lucy")
