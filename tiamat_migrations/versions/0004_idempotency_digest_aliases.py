"""Add rotation-safe keyed idempotency digest aliases.

Revision ID: 0004_idempotency_digest_aliases
Revises: 0003_signed_release_authority
Create Date: 2026-09-18
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0004_idempotency_digest_aliases"
down_revision: str | None = "0003_signed_release_authority"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE tiamat.execution_idempotency_aliases (
            issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 255),
            caller_id text NOT NULL CHECK (length(caller_id) BETWEEN 1 AND 255),
            realm text NOT NULL CHECK (realm ~ '^[a-z][a-z0-9-]{0,63}$'),
            environment text NOT NULL CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
            operation text NOT NULL CHECK (operation ~ '^[a-z][a-z0-9.]{0,63}$'),
            contract_major integer NOT NULL CHECK (contract_major >= 1),
            idempotency_key_digest text NOT NULL CHECK (
                idempotency_key_digest ~ '^[0-9a-f]{64}$'
            ),
            digest_key_version text NOT NULL CHECK (length(digest_key_version) BETWEEN 1 AND 128),
            execution_id uuid NOT NULL REFERENCES tiamat.execution_records(execution_id)
                ON DELETE CASCADE,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (
                issuer, caller_id, realm, environment, operation,
                contract_major, idempotency_key_digest
            )
        );
        CREATE INDEX execution_idempotency_alias_version_idx
        ON tiamat.execution_idempotency_aliases (
            environment, caller_id, realm, digest_key_version
        )
        """
    )
    op.execute(
        """
        INSERT INTO tiamat.execution_idempotency_aliases (
            issuer, caller_id, realm, environment, operation, contract_major,
            idempotency_key_digest, digest_key_version, execution_id
        )
        SELECT issuer, caller_id, realm, environment, operation, contract_major,
               idempotency_key_digest, digest_key_version, execution_id
        FROM tiamat.execution_records
        """
    )
    op.execute("ALTER TABLE tiamat.execution_idempotency_aliases ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tiamat.execution_idempotency_aliases FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY execution_idempotency_aliases_scope
        ON tiamat.execution_idempotency_aliases
        USING (
            caller_id = current_setting('tiamat.caller_id', true)
            AND realm = current_setting('tiamat.realm', true)
            AND environment = current_setting('tiamat.environment', true)
        )
        WITH CHECK (
            caller_id = current_setting('tiamat.caller_id', true)
            AND realm = current_setting('tiamat.realm', true)
            AND environment = current_setting('tiamat.environment', true)
        )
        """
    )


def downgrade() -> None:
    raise RuntimeError("Tiamat idempotency alias downgrades are intentionally unsupported")
