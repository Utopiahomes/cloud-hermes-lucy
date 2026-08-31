"""Independent deletion journal binding and append-only completion receipts."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0016_deletion_journal"
down_revision: str | None = "0015_derivation_sources"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "deletion_journal_binding",
        sa.Column("singleton", sa.Boolean(), primary_key=True),
        sa.Column("journal_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("registry_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.CheckConstraint("singleton", name="ck_deletion_binding_singleton"),
        schema="lucy",
    )
    op.create_table(
        "deletion_journal_receipts",
        sa.Column("sequence", sa.BigInteger(), primary_key=True),
        sa.Column("intent_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column(
            "operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.operations.id"),
            nullable=False,
            unique=True,
        ),
        sa.CheckConstraint("sequence > 0", name="ck_deletion_receipt_sequence"),
        schema="lucy",
    )
    for table in ("deletion_journal_binding", "deletion_journal_receipts"):
        op.execute(f"REVOKE ALL ON lucy.{table} FROM PUBLIC, lucy_app")
        op.execute(f"GRANT SELECT ON lucy.{table} TO lucy_app")
        op.execute(
            f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON lucy.{table} "
            "FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
        )
    op.execute("GRANT INSERT ON lucy.deletion_journal_receipts TO lucy_app")
    op.execute("UPDATE lucy.runtime_admission SET state='quarantined', updated_at=now()")


def downgrade() -> None:
    raise RuntimeError("deletion receipts must not be erased by downgrade")
