"""Count revocations per authority subject, and pin the count at admission.

0016 decided eligibility from the pinned releases' state and their subject's head state. That
state can be overwritten: once B succeeds A and is revoked, activating C sets the head active
again, and an execution pinned to A no longer shows that its subject was revoked while it ran.

A revocation generation per subject cannot be overwritten. apply_revocation increments it and
nothing else does, so routine activation still lets an admitted execution finish, while any
revocation of the subject since admission is visible as a mismatch. Records carry the generation
of each pinned subject at admission. Records admitted before this revision carry none and are
treated as ineligible: their accounting stands, but they are not dispatched or delivered.

Revision ID: 0017_revocation_generation
Revises: 0016_privacy_policy_pin
Create Date: 2026-09-22
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0017_revocation_generation"
down_revision: str | None = "0016_privacy_policy_pin"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE tiamat.release_heads
          ADD COLUMN revocation_generation bigint NOT NULL DEFAULT 0
            CHECK (revocation_generation >= 0)
        """
    )
    op.execute(
        """
        ALTER TABLE tiamat.execution_records
          ADD COLUMN profile_revocation_generation bigint
            CHECK (profile_revocation_generation >= 0),
          ADD COLUMN privacy_policy_revocation_generation bigint
            CHECK (privacy_policy_revocation_generation >= 0)
        """
    )


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
