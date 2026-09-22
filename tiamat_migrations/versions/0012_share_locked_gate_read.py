"""Let the non-writing roles take the restore gate's shared lock.

Migration 0007 revoked the runtime's direct UPDATE on ``tiamat.restore_gate`` so that only the
definer functions may acquire a fence or block dispatch. PostgreSQL requires more than SELECT to
take a row lock, so that revoke also removed the runtime's ability to run the ledger's
``SELECT ... FOR SHARE`` gate reads, which exist to stop a quarantine committing between the gate
check and the write it authorizes. Integration exposed this: the durable ledger could no longer
admit an execution at all. The release manager reads the gate the same way and holds SELECT only,
so its authority transitions have the same problem.

A SECURITY DEFINER function runs inside the caller's transaction, so the lock it takes is held for
that transaction exactly as the inline statement was. Both non-writing roles therefore keep the
same concurrency protection with no write privilege of their own.

The scope comes from the session setting rather than an argument, matching the other definer
functions. Inside a definer the current user is its owner, whose policy sees every row, so an
argument would let a caller name an environment its own row-level security policy hides.

Revision ID: 0012_share_locked_gate_read
Revises: 0011_recovery_checkpoint
Create Date: 2026-09-22
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0012_share_locked_gate_read"
down_revision: str | None = "0011_recovery_checkpoint"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION tiamat.share_locked_restore_gate()
        RETURNS TABLE (
          storage_epoch uuid,
          recovery_generation bigint,
          coordinator_generation bigint,
          dispatch_blocked boolean
        )
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          scoped_environment text := pg_catalog.current_setting('tiamat.environment', true);
        BEGIN
          IF scoped_environment IS NULL OR scoped_environment = '' THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX108',
              MESSAGE = 'restore_gate_scope_missing';
          END IF;
          RETURN QUERY
            SELECT gate.storage_epoch, gate.recovery_generation,
                   gate.coordinator_generation, gate.dispatch_blocked
            FROM tiamat.restore_gate AS gate
            WHERE gate.environment = scoped_environment
            FOR SHARE;
        END;
        $function$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION tiamat.share_locked_restore_gate() FROM PUBLIC")


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
