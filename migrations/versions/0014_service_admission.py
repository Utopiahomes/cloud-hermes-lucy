"""Separate operator-owned storage admission from service startup."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014_service_admission"
down_revision: str | None = "0013_capture_receipts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "runtime_admission",
        sa.Column("singleton", sa.Boolean(), primary_key=True),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("storage_epoch", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("singleton", name="ck_admission_singleton"),
        sa.CheckConstraint("state IN ('quarantined','ready')", name="ck_admission_state"),
        sa.CheckConstraint("state != 'ready' OR storage_epoch IS NOT NULL",
                           name="ck_admission_ready_epoch"),
        schema="lucy",
    )
    op.execute("INSERT INTO lucy.runtime_admission VALUES (true, 'quarantined', NULL, now())")
    op.execute("REVOKE ALL ON lucy.runtime_admission FROM PUBLIC, lucy_app")
    op.execute("GRANT SELECT ON lucy.runtime_admission TO lucy_app")
    op.execute("GRANT SELECT ON public.alembic_version TO lucy_app")


def downgrade() -> None:
    raise RuntimeError("storage admission must not be bypassed by a downgrade")
