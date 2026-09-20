"""Persist the immutable recovery checkpoint a generation was authorized under.

Draft 0.5 section 4 requires the checkpoint object and anchor to be retained separately from live
accounting, so a restart recomputes its digest from the retained checkpoint rather than from
today's changing balances. Rows are append-only: a trigger rejects every update and delete, so a
bound generation cannot be rewritten later by any role which can reach the table.

Revision ID: 0011_recovery_checkpoint
Revises: 0010_attestation_database_clock
Create Date: 2026-09-20
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0011_recovery_checkpoint"
down_revision: str | None = "0010_attestation_database_clock"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE tiamat.recovery_checkpoints (
          environment text NOT NULL
            CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
          recovery_generation bigint NOT NULL CHECK (recovery_generation >= 1),
          ledger_id uuid NOT NULL,
          storage_epoch uuid NOT NULL,
          checkpoint_sha256 text NOT NULL
            CHECK (checkpoint_sha256 ~ '^[0-9a-f]{64}$'),
          release_heads_sha256 text NOT NULL
            CHECK (release_heads_sha256 ~ '^[0-9a-f]{64}$'),
          settlement_position_sha256 text NOT NULL
            CHECK (settlement_position_sha256 ~ '^[0-9a-f]{64}$'),
          checkpoint jsonb NOT NULL,
          bound_at timestamptz NOT NULL DEFAULT clock_timestamp(),
          PRIMARY KEY (environment, recovery_generation)
        )
        """
    )
    op.execute("ALTER TABLE tiamat.recovery_checkpoints ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tiamat.recovery_checkpoints FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY recovery_checkpoints_offline_recovery
        ON tiamat.recovery_checkpoints FOR ALL TO PUBLIC
        USING (current_user = 'tiamat_recovery')
        WITH CHECK (current_user = 'tiamat_recovery')
        """
    )
    op.execute(
        """
        CREATE FUNCTION tiamat.reject_recovery_checkpoint_rewrite()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY INVOKER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
          RAISE EXCEPTION USING ERRCODE = 'ZX107',
            MESSAGE = 'recovery_checkpoint_is_immutable';
        END;
        $function$
        """
    )
    op.execute(
        """
        CREATE TRIGGER recovery_checkpoints_append_only
        BEFORE UPDATE OR DELETE ON tiamat.recovery_checkpoints
        FOR EACH ROW EXECUTE FUNCTION tiamat.reject_recovery_checkpoint_rewrite()
        """
    )


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
