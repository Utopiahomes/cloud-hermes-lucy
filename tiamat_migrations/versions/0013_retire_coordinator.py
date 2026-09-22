"""Separate ending a coordinator's fence from quarantining the environment.

An executor shutting down cleanly must invalidate its own fence: a consumed claimant is only
retired when ``coordinator_generation`` moves, and the row itself cannot be superseded once
consumed. Until now the only way to move it was ``block_dispatch``, which also sets
``dispatch_blocked``. That leaves the ledger quarantined after an ordinary stop, and the launcher
refuses to issue a claimant against a blocked gate, so nothing could start again without a
recovery-role unblock. Integration exposed this: an ordinary restart was impossible.

``retire_coordinator`` therefore ends the fence and nothing else. It is one-way in the sense that
matters: it only ever advances the generation, and it can neither clear a block nor set one. A
quarantine remains ``block_dispatch``'s job, and a blocked gate stays blocked through this call.

Revision ID: 0013_retire_coordinator
Revises: 0012_share_locked_gate_read
Create Date: 2026-09-22
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0013_retire_coordinator"
down_revision: str | None = "0012_share_locked_gate_read"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION tiamat.retire_coordinator(
          expected_coordinator_generation bigint
        ) RETURNS bigint
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          scoped_environment text := pg_catalog.current_setting('tiamat.environment', true);
          retired bigint;
        BEGIN
          IF scoped_environment IS NULL OR scoped_environment = ''
             OR expected_coordinator_generation IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX109',
              MESSAGE = 'coordinator_retirement_scope_missing';
          END IF;
          -- Only the current coordinator may retire itself, so a stale process cannot advance the
          -- fence out from under a newer one.
          UPDATE tiamat.restore_gate
          SET coordinator_generation = coordinator_generation + 1,
              updated_at = pg_catalog.clock_timestamp()
          WHERE environment = scoped_environment
            AND coordinator_generation = expected_coordinator_generation
          RETURNING coordinator_generation INTO retired;
          IF retired IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX109',
              MESSAGE = 'coordinator_retirement_stale';
          END IF;
          RETURN retired;
        END;
        $function$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION tiamat.retire_coordinator(bigint) FROM PUBLIC")


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
