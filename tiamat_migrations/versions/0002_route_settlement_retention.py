"""Pin provider economics and retain content-free settlement evidence.

Revision ID: 0002_route_settlement_retention
Revises: 0001_execution_ledger
Create Date: 2026-09-17
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002_route_settlement_retention"
down_revision: str | None = "0001_execution_ledger"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE tiamat.execution_records
          ADD COLUMN provider_route_id text,
          ADD COLUMN rate_release_id text;
        UPDATE tiamat.execution_records
        SET provider_route_id = 'legacy-unpinned', rate_release_id = 'legacy-unpinned'
        WHERE provider_route_id IS NULL OR rate_release_id IS NULL;
        ALTER TABLE tiamat.execution_records
          ALTER COLUMN provider_route_id SET NOT NULL,
          ALTER COLUMN rate_release_id SET NOT NULL,
          ADD CONSTRAINT execution_provider_route_length
            CHECK (length(provider_route_id) BETWEEN 1 AND 128),
          ADD CONSTRAINT execution_rate_release_length
            CHECK (length(rate_release_id) BETWEEN 1 AND 128)
        """
    )
    op.execute(
        """
        ALTER TABLE tiamat.spending_partitions
          ADD COLUMN external_liability_microusd bigint NOT NULL DEFAULT 0
            CHECK (external_liability_microusd >= 0)
        """
    )
    op.execute(
        """
        CREATE TABLE tiamat.route_rate_quarantines (
            environment text NOT NULL,
            caller_id text NOT NULL,
            realm text NOT NULL,
            partition_id text NOT NULL,
            provider_route_id text NOT NULL CHECK (length(provider_route_id) BETWEEN 1 AND 128),
            rate_release_id text NOT NULL CHECK (length(rate_release_id) BETWEEN 1 AND 128),
            reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
            source_execution_id uuid NOT NULL,
            activated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            cleared_at timestamptz,
            PRIMARY KEY (
                environment, caller_id, realm, partition_id,
                provider_route_id, rate_release_id
            ),
            FOREIGN KEY (environment, caller_id, realm, partition_id)
                REFERENCES tiamat.spending_partitions (
                    environment, caller_id, realm, partition_id
                ),
            CHECK (cleared_at IS NULL OR cleared_at >= activated_at)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE tiamat.financial_events (
            event_id uuid PRIMARY KEY,
            environment text NOT NULL,
            caller_id text NOT NULL,
            realm text NOT NULL,
            partition_id text NOT NULL,
            execution_id uuid NOT NULL,
            event_type text NOT NULL CHECK (
                event_type IN ('settled', 'reservation_forfeited', 'settlement_overrun')
            ),
            actual_microusd bigint NOT NULL CHECK (actual_microusd >= 0),
            reservation_microusd bigint NOT NULL CHECK (reservation_microusd >= 1),
            contingency_microusd bigint NOT NULL DEFAULT 0 CHECK (contingency_microusd >= 0),
            provider_route_id text NOT NULL CHECK (length(provider_route_id) BETWEEN 1 AND 128),
            rate_release_id text NOT NULL CHECK (length(rate_release_id) BETWEEN 1 AND 128),
            provider_cost_reference_digest text CHECK (
                provider_cost_reference_digest IS NULL
                OR provider_cost_reference_digest ~ '^[0-9a-f]{64}$'
            ),
            occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (execution_id, event_type),
            FOREIGN KEY (environment, caller_id, realm, partition_id)
                REFERENCES tiamat.spending_partitions (
                    environment, caller_id, realm, partition_id
                )
        )
        """
    )
    for table in ("route_rate_quarantines", "financial_events"):
        op.execute(f"ALTER TABLE tiamat.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE tiamat.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {table}_scope ON tiamat.{table}
            USING (
                environment = current_setting('tiamat.environment', true)
                AND caller_id = current_setting('tiamat.caller_id', true)
                AND realm = current_setting('tiamat.realm', true)
                AND partition_id = current_setting('tiamat.partition_id', true)
            )
            WITH CHECK (
                environment = current_setting('tiamat.environment', true)
                AND caller_id = current_setting('tiamat.caller_id', true)
                AND realm = current_setting('tiamat.realm', true)
                AND partition_id = current_setting('tiamat.partition_id', true)
            )
            """
        )


def downgrade() -> None:
    raise RuntimeError("Tiamat ledger downgrades are intentionally unsupported")
