"""Add governed memory correction proposals."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_memory_corrections"
down_revision: str | None = "0004_startup_runs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "memory_corrections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("idempotency_key", sa.Text(), nullable=False, unique=True),
        sa.Column("old_claim_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("new_evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("replacement_object", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("approval_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("new_claim_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["old_claim_id"], ["lucy.memory_claims.id"]),
        sa.ForeignKeyConstraint(["new_evidence_id"], ["lucy.evidence.id"]),
        sa.ForeignKeyConstraint(["approval_id"], ["lucy.approval_requests.id"]),
        sa.ForeignKeyConstraint(["new_claim_id"], ["lucy.memory_claims.id"]),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_correction_confidence"),
        sa.CheckConstraint("status IN ('pending','applied','rejected')", name="ck_correction_status"),
        schema="lucy",
    )
    op.execute("GRANT SELECT, INSERT, UPDATE ON lucy.memory_corrections TO lucy_app")


def downgrade() -> None:
    op.drop_table("memory_corrections", schema="lucy")
