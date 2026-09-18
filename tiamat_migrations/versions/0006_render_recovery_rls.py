"""Grant the offline recovery login an explicit Render-compatible RLS path.

Render's managed database owner cannot create a ``BYPASSRLS`` role.  The recovery login therefore
receives a narrowly named policy on every existing RLS-protected Tiamat table instead.  It remains
a non-owner, non-serving login; ordinary serving policies continue to constrain every other role.

Revision ID: 0006_render_recovery_rls
Revises: 0005_ledger_identity
Create Date: 2026-09-18
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0006_render_recovery_rls"
down_revision: str | None = "0005_ledger_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RECOVERY_POLICY_TABLES = (
    "restore_gate",
    "jti_replay",
    "spending_partitions",
    "execution_records",
    "grant_releases",
    "route_rate_quarantines",
    "financial_events",
    "trust_inventories",
    "signed_releases",
    "release_heads",
    "execution_idempotency_aliases",
)


def upgrade() -> None:
    for table in RECOVERY_POLICY_TABLES:
        # The migration runs before the login is created, so the predicate is deliberately
        # role-name based rather than ``TO tiamat_recovery``. ``current_user`` cannot be forged,
        # and the policy is permissive only for that separately held recovery login.
        op.execute(
            f"""
            CREATE POLICY {table}_offline_recovery
            ON tiamat.{table}
            FOR ALL TO PUBLIC
            USING (current_user = 'tiamat_recovery')
            WITH CHECK (current_user = 'tiamat_recovery')
            """
        )


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
