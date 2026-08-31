"""Immutable evidence ancestry and multi-source memory provenance."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015_derivation_sources"
down_revision: str | None = "0014_service_admission"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_derivations",
        sa.Column(
            "parent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.evidence.id"),
            primary_key=True,
        ),
        sa.Column(
            "child_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("lucy.evidence.id"),
            primary_key=True,
        ),
        sa.CheckConstraint("parent_id <> child_id", name="ck_derivation_not_self"),
        schema="lucy",
    )
    op.create_index("ix_derivation_child", "evidence_derivations", ["child_id"], schema="lucy")
    for table, field, target in (
        ("claim_sources", "claim_id", "memory_claims"),
        ("proposal_sources", "proposal_id", "memory_write_proposals"),
        ("correction_sources", "correction_id", "memory_corrections"),
    ):
        op.create_table(
            table,
            sa.Column(
                field,
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey(f"lucy.{target}.id"),
                primary_key=True,
            ),
            sa.Column(
                "evidence_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("lucy.evidence.id"),
                primary_key=True,
            ),
            schema="lucy",
        )
        op.create_index(f"ix_{table}_evidence", table, ["evidence_id"], schema="lucy")
    # Preserve only known legacy support. Do not invent missing assistant/history
    # provenance: maintenance must reject legacy encrypted records separately.
    op.execute("INSERT INTO lucy.claim_sources SELECT id,evidence_id FROM lucy.memory_claims")
    op.execute("""
        WITH RECURSIVE support(claim_id,evidence_id) AS (
          SELECT id,evidence_id FROM lucy.memory_claims
          UNION
          SELECT c.id,s.evidence_id FROM lucy.memory_claims c
          JOIN support s ON c.supersedes_claim_id=s.claim_id
        ) INSERT INTO lucy.claim_sources SELECT * FROM support ON CONFLICT DO NOTHING
    """)
    op.execute(
        "INSERT INTO lucy.proposal_sources SELECT id,evidence_id FROM lucy.memory_write_proposals"
    )
    op.execute(
        "INSERT INTO lucy.correction_sources SELECT id,new_evidence_id FROM lucy.memory_corrections"
    )
    op.execute(
        "INSERT INTO lucy.correction_sources SELECT c.id,s.evidence_id "
        "FROM lucy.memory_corrections c JOIN lucy.claim_sources s "
        "ON s.claim_id=c.old_claim_id ON CONFLICT DO NOTHING"
    )
    for table in (
        "evidence_derivations",
        "claim_sources",
        "proposal_sources",
        "correction_sources",
    ):
        op.execute(f"REVOKE ALL ON lucy.{table} FROM PUBLIC, lucy_app")
        op.execute(f"GRANT SELECT, INSERT ON lucy.{table} TO lucy_app")
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON lucy.{table} "
            "FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
        )
    # One authorized root deletion can tombstone several derived evidence records.
    op.drop_constraint(
        "evidence_tombstones_deletion_operation_id_key",
        "evidence_tombstones",
        schema="lucy",
        type_="unique",
    )
    op.create_index(
        "ix_tombstone_operation", "evidence_tombstones", ["deletion_operation_id"], schema="lucy"
    )
    op.execute("UPDATE lucy.runtime_admission SET state='quarantined', updated_at=now()")


def downgrade() -> None:
    raise RuntimeError("provenance must not be erased by downgrade; use a forward migration")
