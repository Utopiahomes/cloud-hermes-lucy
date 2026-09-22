"""Record a digest of each completed response, and nothing of its content.

RC1 section 15 allows request and response content only in volatile process memory, for at most
ten minutes from admission, and forbids it in any database. Replay is therefore served from a
volatile cache in the serving process, and a replay that finds the body gone returns
``idempotency_recovery_unavailable`` from the durable completion record, as RC1 already defines.

What the ledger gains is only the digest that lets a volatile body be checked against the durable
record before it is served. The digest is one-way and carries no content, so accounting and
deduplication remain content-free.

An earlier draft of this revision (pushed in 29eee01 and d8c85a4) also created a PostgreSQL
response table. That breached section 15. It was only ever applied to the disposable test
database, where the table was dropped and this revision re-applied; it is not part of this
revision, and no other database ever ran it.

Revision ID: 0015_replay_cache
Revises: 0014_attestation_expiry
Create Date: 2026-09-22
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0015_replay_cache"
down_revision: str | None = "0014_attestation_expiry"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE tiamat.execution_records
          ADD COLUMN response_body_sha256 text
            CHECK (response_body_sha256 ~ '^[0-9a-f]{64}$')
        """
    )


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
