"""Install the fail-closed startup-attestation boundary.

The migration runs before service roles exist on a fresh ledger. Functions are
therefore created without PUBLIC execution and are not granted to the runtime.
The separate, transactional role-finalization step transfers their ownership to
tiamat_recovery and grants the runtime only the narrow function calls.

Revision ID: 0007_startup_attestation
Revises: 0006_render_recovery_rls
Create Date: 2026-09-19
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0007_startup_attestation"
down_revision: str | None = "0006_render_recovery_rls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE tiamat.restore_gate
          ADD COLUMN anchor_floor_version bigint NOT NULL DEFAULT 0
            CHECK (anchor_floor_version >= 0),
          ADD COLUMN anchor_floor_sha256 text
            CHECK (anchor_floor_sha256 ~ '^[0-9a-f]{64}$'),
          ADD CONSTRAINT restore_gate_anchor_floor_pair CHECK (
            (anchor_floor_version = 0 AND anchor_floor_sha256 IS NULL) OR
            (anchor_floor_version > 0 AND anchor_floor_sha256 IS NOT NULL)
          )
        """
    )
    op.execute(
        """
        CREATE TABLE tiamat.startup_attestations (
          attestation_id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
          environment text NOT NULL
            CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
          anchor_transition_sha256 text NOT NULL
            CHECK (anchor_transition_sha256 ~ '^[0-9a-f]{64}$'),
          anchor_transition_version bigint NOT NULL
            CHECK (anchor_transition_version >= 1),
          system_identifier text NOT NULL CHECK (system_identifier ~ '^[0-9]+$'),
          timeline_id bigint NOT NULL CHECK (timeline_id >= 1),
          flushed_lsn pg_lsn NOT NULL,
          checkpoint_digest text NOT NULL
            CHECK (checkpoint_digest ~ '^[0-9a-f]{64}$'),
          ledger_id uuid NOT NULL,
          storage_epoch uuid NOT NULL,
          recovery_generation bigint NOT NULL CHECK (recovery_generation >= 1),
          expires_at timestamptz NOT NULL,
          consumed_at timestamptz,
          consumed_coordinator_generation bigint
            CHECK (consumed_coordinator_generation >= 1),
          superseded_at timestamptz,
          CHECK ((consumed_at IS NULL) = (consumed_coordinator_generation IS NULL)),
          CHECK (consumed_at IS NULL OR superseded_at IS NULL)
        )
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX startup_attestations_active_claimant
        ON tiamat.startup_attestations (environment)
        WHERE consumed_at IS NULL AND superseded_at IS NULL
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX startup_attestations_consumed_generation
        ON tiamat.startup_attestations
          (environment, consumed_coordinator_generation)
        WHERE consumed_coordinator_generation IS NOT NULL
        """
    )
    op.execute("ALTER TABLE tiamat.startup_attestations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tiamat.startup_attestations FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY startup_attestations_offline_recovery
        ON tiamat.startup_attestations FOR ALL TO PUBLIC
        USING (current_user = 'tiamat_recovery')
        WITH CHECK (current_user = 'tiamat_recovery')
        """
    )
    op.execute(
        """
        CREATE FUNCTION tiamat.consume_startup_attestation(
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
          -- The claimant was locked before the gate. Recheck expiry after any
          -- gate-lock wait so a short-lived attestation cannot be consumed late.
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
        """
        CREATE FUNCTION tiamat.verify_attestation_current(
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
          IF requested_environment IS NULL OR
             expected_coordinator_generation IS NULL THEN
            RETURN false;
          END IF;
          SELECT * INTO attested FROM tiamat.startup_attestations
          WHERE environment = requested_environment
            AND consumed_coordinator_generation = expected_coordinator_generation
            AND consumed_at IS NOT NULL AND superseded_at IS NULL;
          IF NOT FOUND THEN RETURN false; END IF;
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
    )
    op.execute(
        """
        CREATE FUNCTION tiamat.block_dispatch(reason text) RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          requested_environment text := pg_catalog.current_setting('tiamat.environment', true);
        BEGIN
          IF requested_environment IS NULL OR reason IS NULL OR
             reason !~ '^[a-z][a-z0-9_]{0,63}$' THEN
            RAISE EXCEPTION 'invalid dispatch block request';
          END IF;
          UPDATE tiamat.restore_gate
          SET dispatch_blocked = true, block_reason = reason, verified_at = NULL,
              coordinator_generation = coordinator_generation + 1,
              updated_at = pg_catalog.clock_timestamp()
          WHERE environment = requested_environment;
          IF NOT FOUND THEN RAISE EXCEPTION 'restore gate is not initialized'; END IF;
        END;
        $function$
        """
    )
    for signature in (
        "consume_startup_attestation(text)",
        "verify_attestation_current(bigint)",
        "block_dispatch(text)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION tiamat.{signature} FROM PUBLIC")


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
