"""Add durable Rejoining startup diagnostics."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_startup_runs"
down_revision: str | None = "0003_memory_graph"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "startup_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("outcome_state", sa.Text(), nullable=False),
        sa.Column("checks", postgresql.JSONB(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "outcome_state IN ('ready','degraded')", name="ck_startup_outcome_state"
        ),
        schema="lucy",
    )
    op.execute("GRANT SELECT, INSERT ON lucy.startup_runs TO lucy_app")


def downgrade() -> None:
    op.drop_table("startup_runs", schema="lucy")
