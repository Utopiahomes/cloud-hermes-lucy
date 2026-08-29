"""Name the evidence commitment according to its keyed production semantics."""

from collections.abc import Sequence

from alembic import op

revision: str = "0012_commitment_name"
down_revision: str | None = "0011_security_v1_1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "evidence",
        "content_sha256",
        new_column_name="content_commitment",
        schema="lucy",
    )
    op.execute(
        "ALTER TABLE lucy.evidence RENAME CONSTRAINT evidence_content_sha256_key "
        "TO evidence_content_commitment_key"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE lucy.evidence RENAME CONSTRAINT evidence_content_commitment_key "
        "TO evidence_content_sha256_key"
    )
    op.alter_column(
        "evidence",
        "content_commitment",
        new_column_name="content_sha256",
        schema="lucy",
    )
