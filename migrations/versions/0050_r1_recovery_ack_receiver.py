"""Permit recovery identities to read only exact pending acknowledgement metadata."""

from collections.abc import Sequence

from alembic import op

revision: str = "0050_r1_recovery_ack_receiver"
down_revision: str | None = "0049_r1_cost_recovery_finalize"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "GRANT EXECUTE ON FUNCTION lucy.get_pending_authority_event_v1(uuid) "
        "TO lucy_authority_recovery_writer"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION lucy.get_pending_cost_event_v1(uuid) "
        "TO lucy_cost_recovery_writer"
    )


def downgrade() -> None:
    raise RuntimeError("R1 acknowledgement receiver requires a reviewed forward migration")
