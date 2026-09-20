"""Enforce the launcher-issued D1 attestation lifetime at the database boundary.

Revision ID: 0008_attestation_expiry
Revises: 0007_startup_attestation
Create Date: 2026-09-20
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0008_attestation_expiry"
down_revision: str | None = "0007_startup_attestation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE tiamat.startup_attestations
          ADD COLUMN created_at timestamptz
        """
    )
    op.execute(
        """
        ALTER TABLE tiamat.startup_attestations
          ALTER COLUMN created_at SET DEFAULT clock_timestamp(),
          ADD CONSTRAINT startup_attestations_expiry_bound CHECK (
            created_at IS NULL OR (
              expires_at > created_at
              AND expires_at <= created_at + interval '10 minutes'
            )
          )
        """
    )
    # Existing D1 rows have no trustworthy issuance timestamp. Keep their
    # ``created_at`` NULL as historical evidence rather than inventing one, but
    # make a missing/bad timestamp impossible for every post-M2 INSERT or expiry
    # update. This avoids a forced-RLS migration-owner bypass.
    op.execute(
        """
        CREATE FUNCTION tiamat.enforce_startup_attestation_expiry_bound()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY INVOKER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
          IF NEW.created_at IS NULL OR NEW.expires_at <= NEW.created_at
             OR NEW.expires_at > NEW.created_at + interval '10 minutes' THEN
            RAISE EXCEPTION 'startup attestation expiry is not issuer-bounded';
          END IF;
          RETURN NEW;
        END;
        $function$
        """
    )
    op.execute(
        """
        CREATE TRIGGER startup_attestations_expiry_bound_insert
        BEFORE INSERT OR UPDATE OF created_at, expires_at
        ON tiamat.startup_attestations
        FOR EACH ROW EXECUTE FUNCTION tiamat.enforce_startup_attestation_expiry_bound()
        """
    )


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
