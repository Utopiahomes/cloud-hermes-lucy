"""Track authoritative committed conversation turns."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_turn_commits"
down_revision: str | None = "0008_encrypted_archive"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "conversation_turns",
        sa.Column("platform", sa.Text(), primary_key=True),
        sa.Column("source_conversation_id", sa.Text(), primary_key=True),
        sa.Column("source_turn_id", sa.Text(), primary_key=True),
        sa.Column("user_evidence_id", postgresql.UUID(as_uuid=True), unique=True),
        sa.Column("assistant_evidence_id", postgresql.UUID(as_uuid=True), unique=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("committed_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_evidence_id"], ["lucy.evidence.id"]),
        sa.ForeignKeyConstraint(["assistant_evidence_id"], ["lucy.evidence.id"]),
        sa.CheckConstraint(
            "status IN ('capturing','committed','redacted')",
            name="ck_conversation_turn_status",
        ),
        schema="lucy",
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON lucy.conversation_turns TO lucy_app"
    )


def downgrade() -> None:
    op.drop_table("conversation_turns", schema="lucy")
