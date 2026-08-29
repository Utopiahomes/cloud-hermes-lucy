"""Add encrypted evidence payloads, tombstones, and capture state."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_encrypted_archive"
down_revision: str | None = "0007_action_execution"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_payloads",
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("content_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("key_ref", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("algorithm", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["lucy.evidence.id"]),
        sa.CheckConstraint(
            "algorithm = 'AES-256-GCM+AES-KW-GCM'",
            name="ck_evidence_payload_algorithm",
        ),
        schema="lucy",
    )
    op.create_table(
        "evidence_tombstones",
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "deletion_operation_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            unique=True,
        ),
        sa.Column("reason_category", sa.Text(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("derived_summary", postgresql.JSONB(), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["lucy.evidence.id"]),
        sa.ForeignKeyConstraint(
            ["deletion_operation_id"], ["lucy.operations.id"]
        ),
        sa.CheckConstraint(
            "reason_category IN ('owner_request','sensitive_data','retention_expired')",
            name="ck_evidence_tombstone_reason",
        ),
        schema="lucy",
    )
    op.create_table(
        "conversation_capture_states",
        sa.Column("platform", sa.Text(), primary_key=True),
        sa.Column("source_conversation_id", sa.Text(), primary_key=True),
        sa.Column("capture_enabled", sa.Boolean(), nullable=False),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema="lucy",
    )
    op.drop_constraint("ck_claim_status", "memory_claims", schema="lucy", type_="check")
    op.create_check_constraint(
        "ck_claim_status",
        "memory_claims",
        "status IN ('provisional','accepted','superseded','invalidated')",
        schema="lucy",
    )
    op.execute(
        "GRANT SELECT, INSERT, DELETE ON lucy.evidence_payloads TO lucy_app; "
        "GRANT SELECT, INSERT ON lucy.evidence_tombstones TO lucy_app; "
        "GRANT SELECT, INSERT, UPDATE ON lucy.conversation_capture_states TO lucy_app"
    )
    op.execute(
        "CREATE TRIGGER evidence_tombstones_append_only "
        "BEFORE UPDATE OR DELETE ON lucy.evidence_tombstones "
        "FOR EACH ROW EXECUTE FUNCTION lucy.reject_mutation()"
    )


def downgrade() -> None:
    op.execute(
        "UPDATE lucy.memory_claims SET status = 'superseded' "
        "WHERE status = 'invalidated'"
    )
    op.drop_constraint("ck_claim_status", "memory_claims", schema="lucy", type_="check")
    op.create_check_constraint(
        "ck_claim_status",
        "memory_claims",
        "status IN ('provisional','accepted','superseded')",
        schema="lucy",
    )
    op.drop_table("conversation_capture_states", schema="lucy")
    op.drop_table("evidence_tombstones", schema="lucy")
    op.drop_table("evidence_payloads", schema="lucy")
