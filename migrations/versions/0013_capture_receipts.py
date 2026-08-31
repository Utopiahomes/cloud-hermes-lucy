"""Persist content-free, immutable per-turn consent decisions."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_capture_receipts"
down_revision: str | None = "0012_commitment_name"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "capture_receipts",
        sa.Column("platform", sa.Text(), primary_key=True),
        sa.Column("source_conversation_id", sa.Text(), primary_key=True),
        sa.Column("source_turn_id", sa.Text(), primary_key=True),
        sa.Column("capture_enabled", sa.Boolean(), nullable=False),
        sa.Column("capture_version", sa.BigInteger(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("capture_version >= 0", name="ck_capture_receipt_version"),
        schema="lucy",
    )
    # Existing runtime history has no trustworthy per-turn consent snapshot.
    # Do not infer consent or backfill receipts from today's capture mode.
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON lucy.capture_receipts FROM lucy_app")
    op.execute("GRANT SELECT, INSERT ON lucy.capture_receipts TO lucy_app")


def downgrade() -> None:
    raise RuntimeError("consent receipts must not be dropped; use a forward migration")
