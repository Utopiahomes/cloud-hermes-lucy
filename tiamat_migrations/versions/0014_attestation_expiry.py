"""Stop a consumed claimant authorizing dispatch after it has expired.

``verify_attestation_current`` checked cluster identity, timeline, durable WAL position and the
composite fence, but not the claimant's own expiry. A process that kept running therefore kept
dispatching after its authority lapsed, which Draft 0.5 section 5 forbids: expiry blocks new
dispatch, including admitted work which has not been sent.

The claimant's ``expires_at`` is set by the issuer to no later than the signed witness's
``not_after``, so it is the conservative signal that authority has lapsed. Enforcing it here puts
the check inside the same statement the dispatch transaction already makes, rather than relying on
a process to notice its own expiry.

This replaces a function which finalization may already have transferred to
``tiamat_recovery``. On a fresh ledger the migration owner still owns it and this runs
normally. On a finalized ledger the migration owner can no longer replace it, so
``deploy/postgres/apply_tiamat_definer_migration_v1.py`` applies the same statement through a
temporary ownership handoff and advances Alembic in the same transaction. The statement is
exported so that runner applies exactly this text rather than a copy of it.

Revision ID: 0014_attestation_expiry
Revises: 0013_retire_coordinator
Create Date: 2026-09-22
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0014_attestation_expiry"
down_revision: str | None = "0013_retire_coordinator"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


DEFINER_STATEMENT = """
        CREATE OR REPLACE FUNCTION tiamat.verify_attestation_current(
          expected_coordinator_generation bigint
        ) RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          requested_environment text := pg_catalog.current_setting('tiamat.environment', true);
          attested tiamat.startup_attestations%ROWTYPE;
          gate_record record;
          live_identifier text;
          live_timeline bigint;
          live_lsn pg_lsn;
        BEGIN
          IF requested_environment IS NULL OR requested_environment = ''
             OR expected_coordinator_generation IS NULL THEN
            RETURN false;
          END IF;
          SELECT * INTO attested FROM tiamat.startup_attestations
          WHERE environment = requested_environment
            AND consumed_coordinator_generation = expected_coordinator_generation
            AND consumed_at IS NOT NULL AND superseded_at IS NULL;
          IF NOT FOUND THEN RETURN false; END IF;
          -- Expiry blocks new dispatch, including work already admitted but not yet sent.
          IF attested.expires_at <= pg_catalog.clock_timestamp() THEN
            RETURN false;
          END IF;
          SELECT gate.storage_epoch, gate.recovery_generation,
                 gate.coordinator_generation, gate.dispatch_blocked,
                 gate.anchor_floor_version, gate.anchor_floor_sha256,
                 identity.ledger_id
            INTO gate_record
          FROM tiamat.restore_gate AS gate
          CROSS JOIN tiamat.ledger_identity AS identity
          WHERE gate.environment = requested_environment AND identity.singleton;
          IF NOT FOUND THEN RETURN false; END IF;
          IF gate_record.dispatch_blocked OR
             gate_record.coordinator_generation <> expected_coordinator_generation OR
             gate_record.anchor_floor_version = 0 OR
             gate_record.anchor_floor_version > attested.anchor_transition_version OR
             (gate_record.anchor_floor_version = attested.anchor_transition_version AND
              gate_record.anchor_floor_sha256 <> attested.anchor_transition_sha256) OR
             gate_record.ledger_id <> attested.ledger_id OR
             gate_record.storage_epoch <> attested.storage_epoch OR
             gate_record.recovery_generation <> attested.recovery_generation THEN
            RETURN false;
          END IF;
          SELECT (pg_catalog.pg_control_system()).system_identifier::text,
                 (pg_catalog.pg_control_checkpoint()).timeline_id::bigint,
                 pg_catalog.pg_current_wal_flush_lsn()
            INTO live_identifier, live_timeline, live_lsn;
          RETURN COALESCE(
            live_identifier = attested.system_identifier AND
            live_timeline = attested.timeline_id AND
            live_lsn >= attested.flushed_lsn,
            false
          );
        END;
        $function$
        """


def upgrade() -> None:
    op.execute(DEFINER_STATEMENT)


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
