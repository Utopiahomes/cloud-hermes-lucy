"""Pin the privacy-policy release an execution was admitted under.

RC1 section 11 requires the completed commit to recheck the current security/privacy eligibility
atomically, and section 13 requires the same recheck before dispatch. A revocation can target the
execution profile or the privacy policy, so both admitted releases must be known to the record.
The profile release was already pinned; this adds the privacy policy. Both columns are nullable
because records admitted before this revision carry no policy pin, and are checked against their
profile alone.

Revision ID: 0016_privacy_policy_pin
Revises: 0015_replay_cache
Create Date: 2026-09-22
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0016_privacy_policy_pin"
down_revision: str | None = "0015_replay_cache"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE tiamat.execution_records
          ADD COLUMN privacy_policy_id text
            CHECK (length(privacy_policy_id) BETWEEN 1 AND 128),
          ADD COLUMN privacy_policy_release_id text
            CHECK (length(privacy_policy_release_id) BETWEEN 1 AND 128),
          ADD CONSTRAINT execution_records_privacy_policy_pin_pair
            CHECK ((privacy_policy_id IS NULL) = (privacy_policy_release_id IS NULL))
        """
    )


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
