"""Add the immutable database-owned Tiamat ledger identity.

Revision ID: 0005_ledger_identity
Revises: 0004_idempotency_digest_aliases
Create Date: 2026-09-18
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005_ledger_identity"
down_revision: str | None = "0004_idempotency_digest_aliases"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # PostgreSQL 16 provides gen_random_uuid() as a built-in function. The identity is created in
    # the ledger itself, never supplied by a serving process or deployment environment variable.
    op.execute(
        """
        CREATE TABLE tiamat.ledger_identity (
            singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
            ledger_id uuid NOT NULL UNIQUE,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp()
        )
        """
    )
    op.execute(
        "INSERT INTO tiamat.ledger_identity (singleton, ledger_id) "
        "VALUES (true, gen_random_uuid())"
    )


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger identity downgrades are intentionally unsupported")
