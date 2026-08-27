"""Add versioned graph and disposable working context layers."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_memory_graph"
down_revision: str | None = "0002_approvals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "memory_entities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("canonical_name", sa.Text(), nullable=False),
        sa.Column("entity_type", sa.Text(), nullable=False),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("entity_type", "canonical_name", name="uq_memory_entity_name"),
        schema="lucy",
    )
    op.create_table(
        "memory_relationships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("subject_entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("object_entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("predicate", sa.Text(), nullable=False),
        sa.Column("claim_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(["subject_entity_id"], ["lucy.memory_entities.id"]),
        sa.ForeignKeyConstraint(["object_entity_id"], ["lucy.memory_entities.id"]),
        sa.ForeignKeyConstraint(["claim_id"], ["lucy.memory_claims.id"]),
        sa.ForeignKeyConstraint(["evidence_id"], ["lucy.evidence.id"]),
        schema="lucy",
    )
    op.create_table(
        "working_contexts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("projection", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        schema="lucy",
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON lucy.memory_entities, "
        "lucy.memory_relationships TO lucy_app; "
        "GRANT SELECT, INSERT, DELETE ON lucy.working_contexts TO lucy_app"
    )


def downgrade() -> None:
    op.drop_table("working_contexts", schema="lucy")
    op.drop_table("memory_relationships", schema="lucy")
    op.drop_table("memory_entities", schema="lucy")
