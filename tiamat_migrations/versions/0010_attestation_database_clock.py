"""Make post-M2 claimant issuance time database-authoritative.

Existing rows intentionally retain a NULL issuance time because their original
timestamp cannot be reconstructed safely. New claimants receive the database's
own clock value even if a recovery-role caller supplies ``created_at``.

Revision ID: 0010_attestation_database_clock
Revises: 0009_attestation_consume_v2
Create Date: 2026-09-20
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0010_attestation_database_clock"
down_revision: str | None = "0009_attestation_consume_v2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION tiamat.enforce_startup_attestation_expiry_bound()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY INVOKER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
          database_now timestamptz := pg_catalog.clock_timestamp();
        BEGIN
          IF TG_OP = 'INSERT' THEN
            NEW.created_at := database_now;
          ELSIF NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX106',
              MESSAGE = 'startup_attestation_created_at_immutable';
          END IF;
          IF NEW.created_at IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX106',
              MESSAGE = 'startup_attestation_created_at_required';
          END IF;
          IF NEW.expires_at <= database_now THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX105',
              MESSAGE = 'startup_attestation_expired';
          END IF;
          IF NEW.expires_at > NEW.created_at + interval '10 minutes' THEN
            RAISE EXCEPTION USING ERRCODE = 'ZX106',
              MESSAGE = 'startup_attestation_expiry_not_issuer_bounded';
          END IF;
          RETURN NEW;
        END;
        $function$
        """
    )


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
