"""Permit the AWS KMS production envelope algorithm."""

from collections.abc import Sequence

from alembic import op

revision: str = "0010_aws_kms_backend"
down_revision: str | None = "0009_turn_commits"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        "ck_evidence_payload_algorithm",
        "evidence_payloads",
        schema="lucy",
        type_="check",
    )
    op.create_check_constraint(
        "ck_evidence_payload_algorithm",
        "evidence_payloads",
        "algorithm IN ('AES-256-GCM+AES-KW-GCM','AES-256-GCM+AWS-KMS')",
        schema="lucy",
    )


def downgrade() -> None:
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM lucy.evidence_payloads "
        "WHERE algorithm = 'AES-256-GCM+AWS-KMS') THEN "
        "RAISE EXCEPTION 'cannot downgrade while AWS KMS payloads exist'; "
        "END IF; END $$"
    )
    op.drop_constraint(
        "ck_evidence_payload_algorithm",
        "evidence_payloads",
        schema="lucy",
        type_="check",
    )
    op.create_check_constraint(
        "ck_evidence_payload_algorithm",
        "evidence_payloads",
        "algorithm = 'AES-256-GCM+AES-KW-GCM'",
        schema="lucy",
    )
