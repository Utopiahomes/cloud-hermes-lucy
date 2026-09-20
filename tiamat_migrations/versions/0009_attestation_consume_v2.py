"""Install the post-gate-expiry-safe D1 consume function.

The original D1 function may already be recovery-owned on an older finalized
ledger, so this is a new function rather than a mutation of migration 0007.
The finalizer transfers the new function before any runtime call can use it.

Revision ID: 0009_attestation_consume_v2
Revises: 0008_attestation_expiry
Create Date: 2026-09-20
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0009_attestation_consume_v2"
down_revision: str | None = "0008_attestation_expiry"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION tiamat.consume_startup_attestation_v2(
          requested_anchor_sha256 text
        ) RETURNS bigint
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
          next_generation bigint;
        BEGIN
          IF requested_environment IS NULL OR
             requested_anchor_sha256 IS NULL OR
             requested_anchor_sha256 !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX101', MESSAGE = 'startup_attestation_absent';
          END IF;
          SELECT * INTO attested FROM tiamat.startup_attestations
          WHERE environment = requested_environment
            AND anchor_transition_sha256 = requested_anchor_sha256
            AND consumed_at IS NULL AND superseded_at IS NULL
            AND expires_at > pg_catalog.clock_timestamp()
          FOR UPDATE;
          IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX101', MESSAGE = 'startup_attestation_absent';
          END IF;
          SELECT gate.environment, gate.storage_epoch, gate.recovery_generation,
                 gate.coordinator_generation, gate.dispatch_blocked,
                 gate.anchor_floor_version, gate.anchor_floor_sha256,
                 identity.ledger_id
            INTO gate_record
          FROM tiamat.restore_gate AS gate
          CROSS JOIN tiamat.ledger_identity AS identity
          WHERE gate.environment = requested_environment AND identity.singleton
          FOR UPDATE OF gate;
          IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX102', MESSAGE = 'startup_authority_mismatch';
          END IF;
          IF attested.expires_at <= pg_catalog.clock_timestamp() THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX101', MESSAGE = 'startup_attestation_absent';
          END IF;
          IF gate_record.dispatch_blocked OR
             gate_record.anchor_floor_version = 0 OR
             gate_record.anchor_floor_version > attested.anchor_transition_version OR
             (gate_record.anchor_floor_version = attested.anchor_transition_version AND
              gate_record.anchor_floor_sha256 <> attested.anchor_transition_sha256) OR
             gate_record.ledger_id <> attested.ledger_id OR
             gate_record.storage_epoch <> attested.storage_epoch OR
             gate_record.recovery_generation <> attested.recovery_generation THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX102', MESSAGE = 'startup_authority_mismatch';
          END IF;
          SELECT (pg_catalog.pg_control_system()).system_identifier::text,
                 (pg_catalog.pg_control_checkpoint()).timeline_id::bigint,
                 pg_catalog.pg_current_wal_flush_lsn()
            INTO live_identifier, live_timeline, live_lsn;
          IF live_identifier IS NULL OR live_timeline IS NULL OR
             live_identifier <> attested.system_identifier OR
             live_timeline <> attested.timeline_id THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX103', MESSAGE = 'startup_cluster_mismatch';
          END IF;
          IF live_lsn IS NULL OR live_lsn < attested.flushed_lsn THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX104', MESSAGE = 'startup_wal_behind';
          END IF;
          UPDATE tiamat.restore_gate
          SET coordinator_generation = coordinator_generation + 1,
              updated_at = pg_catalog.clock_timestamp()
          WHERE environment = requested_environment
          RETURNING coordinator_generation INTO next_generation;
          UPDATE tiamat.startup_attestations
          SET consumed_at = pg_catalog.clock_timestamp(),
              consumed_coordinator_generation = next_generation
          WHERE attestation_id = attested.attestation_id;
          RETURN next_generation;
        END;
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION tiamat.consume_startup_attestation_v2(text) FROM PUBLIC"
    )


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
