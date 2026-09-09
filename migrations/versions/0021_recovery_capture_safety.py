"""Centralize the capture-off boundary used during deletion recovery."""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0021_recovery_capture_safety"
down_revision: str | None = "0020_authorized_delete_recovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_OLD_RECOVERY_GATE = """IF NOT EXISTS (
               SELECT 1 FROM lucy.runtime_admission WHERE singleton AND state='quarantined'
             ) OR EXISTS (
               SELECT 1 FROM lucy.conversation_capture_states WHERE capture_enabled
             ) OR EXISTS (
               SELECT 1 FROM lucy.capture_receipts WHERE capture_enabled
             ) THEN"""

_NEW_RECOVERY_GATE = """IF NOT EXISTS (
               SELECT 1 FROM lucy.runtime_admission WHERE singleton AND state='quarantined'
             ) OR NOT lucy.capture_boundary_safe_v1() THEN"""


def upgrade() -> None:
    op.execute("GRANT USAGE, CREATE ON SCHEMA lucy TO lucy_security_function_owner")
    op.execute(
        r"""
        CREATE FUNCTION lucy.capture_boundary_safe_v1()
        RETURNS boolean
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
          SELECT
            NOT EXISTS (
              SELECT 1
              FROM lucy.conversation_capture_states
              WHERE capture_enabled
            )
            AND NOT EXISTS (
              SELECT 1
              FROM lucy.capture_receipts r
              WHERE r.capture_enabled
                AND NOT (
                  r.platform = 'telegram'
                  AND r.source_conversation_id ~
                    '^cloud-acceptance-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
                  AND r.source_turn_id = regexp_replace(
                    r.source_conversation_id,
                    '^cloud-acceptance-',
                    'turn-'
                  )
                  AND EXISTS (
                    SELECT 1
                    FROM lucy.evidence e
                    WHERE e.source = 'hermes'
                      AND e.source_conversation_id =
                        'telegram:' || r.source_conversation_id
                  )
                )
            )
        $function$;
        ALTER FUNCTION lucy.capture_boundary_safe_v1()
          OWNER TO lucy_security_function_owner;
        REVOKE ALL ON FUNCTION lucy.capture_boundary_safe_v1()
          FROM PUBLIC, lucy_app;
        GRANT EXECUTE ON FUNCTION lucy.capture_boundary_safe_v1()
          TO lucy_migration;
        """
    )

    connection = op.get_bind()
    definition = connection.execute(
        text(
            "SELECT pg_get_functiondef("
            "'lucy.apply_authorized_deletion_recovery_v1(jsonb)'::regprocedure)"
        )
    ).scalar_one()
    if definition.count(_OLD_RECOVERY_GATE) != 1:
        raise RuntimeError(
            "authorized deletion recovery capture gate did not match reviewed revision 0020"
        )
    op.execute(definition.replace(_OLD_RECOVERY_GATE, _NEW_RECOVERY_GATE))
    op.execute("REVOKE CREATE ON SCHEMA lucy FROM lucy_security_function_owner")


def downgrade() -> None:
    raise RuntimeError(
        "The centralized recovery capture boundary is a durable security control; "
        "use a reviewed forward migration"
    )
