"""Hold replayable output beside the ledger without putting it in the ledger.

RC1 requires the response ``output`` on every reply, including a replayed one, while the
execution ledger is deliberately content-free. Serving replays from durable state therefore needs
somewhere to keep the minimum material RC1 needs to reproduce a response, and nowhere else.

This is a cache, not a second system of record:

* it holds only what RC1 reproduces - the response body, its digest, its execution and idempotency keys,
  and an expiry. No prompt, no transcript, no memory, no tool trace, no caller profile;
* it expires with the replay guarantee itself, after which the response body disappears while the
  ledger's accounting remains;
* it takes no part in recovery. It is not in a recovery checkpoint, not under the anchor, not in
  any continuity proof, and not in the day-zero emptiness check, because its contents are not
  authority. Losing it degrades replay; it does not make what Tiamat did, or what it spent,
  uncertain.

``execution_records`` gains the digest that binds the two: the ledger states what the response was,
the cache holds it, and a replay is served only when they agree.

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
    op.execute(
        """
        CREATE TABLE tiamat.replay_cache (
          environment text NOT NULL
            CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
          caller_id text NOT NULL CHECK (length(caller_id) BETWEEN 1 AND 255),
          idempotency_key_digest text NOT NULL
            CHECK (idempotency_key_digest ~ '^[0-9a-f]{64}$'),
          execution_id uuid NOT NULL,
          response_body_sha256 text NOT NULL
            CHECK (response_body_sha256 ~ '^[0-9a-f]{64}$'),
          response_body jsonb NOT NULL,
          created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
          expires_at timestamptz NOT NULL,
          PRIMARY KEY (environment, caller_id, idempotency_key_digest),
          CHECK (expires_at > created_at)
        )
        """
    )
    op.execute(
        """
        CREATE INDEX replay_cache_expiry ON tiamat.replay_cache (expires_at)
        """
    )
    op.execute("ALTER TABLE tiamat.replay_cache ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tiamat.replay_cache FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY replay_cache_scope ON tiamat.replay_cache
        FOR ALL TO PUBLIC
        USING (
          environment = current_setting('tiamat.environment', true)
          AND caller_id = current_setting('tiamat.caller_id', true)
        )
        WITH CHECK (
          environment = current_setting('tiamat.environment', true)
          AND caller_id = current_setting('tiamat.caller_id', true)
        )
        """
    )
    op.execute(
        """
        CREATE POLICY replay_cache_offline_recovery ON tiamat.replay_cache
        FOR ALL TO PUBLIC
        USING (current_user = 'tiamat_recovery')
        WITH CHECK (current_user = 'tiamat_recovery')
        """
    )


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
