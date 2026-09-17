"""Create the content-free Tiamat execution ledger.

Revision ID: 0001_execution_ledger
Revises: None
Create Date: 2026-09-17
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0001_execution_ledger"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS tiamat")
    op.execute(
        """
        CREATE TABLE tiamat.restore_gate (
            environment text PRIMARY KEY CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
            storage_epoch uuid NOT NULL,
            recovery_generation bigint NOT NULL CHECK (recovery_generation >= 1),
            coordinator_generation bigint NOT NULL CHECK (coordinator_generation >= 1),
            dispatch_blocked boolean NOT NULL DEFAULT true,
            block_reason text CHECK (
                block_reason IS NULL OR block_reason ~ '^[a-z][a-z0-9_]{0,63}$'
            ),
            verified_at timestamptz,
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            CHECK (dispatch_blocked OR (block_reason IS NULL AND verified_at IS NOT NULL)),
            CHECK (NOT dispatch_blocked OR block_reason IS NOT NULL)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE tiamat.jti_replay (
            issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 255),
            subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
            realm text NOT NULL CHECK (realm ~ '^[a-z][a-z0-9-]{0,63}$'),
            environment text NOT NULL CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
            jti uuid NOT NULL,
            expires_at timestamptz NOT NULL,
            consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (issuer, subject, realm, environment, jti)
        )
        """
    )
    op.execute("CREATE INDEX jti_replay_expiry_idx ON tiamat.jti_replay (expires_at)")
    op.execute(
        """
        CREATE TABLE tiamat.spending_partitions (
            environment text NOT NULL CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
            caller_id text NOT NULL CHECK (length(caller_id) BETWEEN 1 AND 255),
            realm text NOT NULL CHECK (realm ~ '^[a-z][a-z0-9-]{0,63}$'),
            partition_id text NOT NULL CHECK (partition_id ~ '^[a-z][a-z0-9-]{0,127}$'),
            active_grant_release_id text CHECK (length(active_grant_release_id) BETWEEN 1 AND 128),
            budget_period_id text CHECK (length(budget_period_id) BETWEEN 1 AND 128),
            allowance_microusd bigint NOT NULL DEFAULT 0 CHECK (allowance_microusd >= 0),
            period_spend_microusd bigint NOT NULL DEFAULT 0 CHECK (period_spend_microusd >= 0),
            contingency_reserve_microusd bigint NOT NULL DEFAULT 0
                CHECK (contingency_reserve_microusd >= 0),
            contingency_spend_microusd bigint NOT NULL DEFAULT 0
                CHECK (contingency_spend_microusd >= 0),
            maximum_concurrency integer NOT NULL DEFAULT 0 CHECK (maximum_concurrency >= 0),
            largest_per_call_microusd bigint NOT NULL DEFAULT 0
                CHECK (largest_per_call_microusd >= 0),
            blocked boolean NOT NULL DEFAULT true,
            block_reason text CHECK (
                block_reason IS NULL OR block_reason ~ '^[a-z][a-z0-9_]{0,63}$'
            ),
            generation bigint NOT NULL DEFAULT 1 CHECK (generation >= 1),
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (environment, caller_id, realm, partition_id),
            CHECK (NOT blocked OR block_reason IS NOT NULL)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE tiamat.execution_records (
            execution_id uuid PRIMARY KEY,
            issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 255),
            caller_id text NOT NULL CHECK (length(caller_id) BETWEEN 1 AND 255),
            realm text NOT NULL CHECK (realm ~ '^[a-z][a-z0-9-]{0,63}$'),
            environment text NOT NULL CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
            operation text NOT NULL CHECK (operation ~ '^[a-z][a-z0-9.]{0,63}$'),
            contract_major integer NOT NULL CHECK (contract_major >= 1),
            partition_id text NOT NULL CHECK (partition_id ~ '^[a-z][a-z0-9-]{0,127}$'),
            idempotency_key_digest text NOT NULL CHECK (
                idempotency_key_digest ~ '^[0-9a-f]{64}$'
            ),
            identity_digest text NOT NULL CHECK (identity_digest ~ '^[0-9a-f]{64}$'),
            digest_key_version text NOT NULL CHECK (length(digest_key_version) BETWEEN 1 AND 128),
            execution_profile_id text NOT NULL CHECK (
                length(execution_profile_id) BETWEEN 1 AND 128
            ),
            profile_release_id text NOT NULL CHECK (
                length(profile_release_id) BETWEEN 1 AND 128
            ),
            state text NOT NULL CHECK (
                state IN ('admitted', 'dispatched', 'completed', 'failed', 'outcome_unknown')
            ),
            coordinator_generation bigint NOT NULL CHECK (coordinator_generation >= 1),
            record_generation bigint NOT NULL DEFAULT 1 CHECK (record_generation >= 1),
            lease_owner_id uuid NOT NULL,
            lease_expires_at timestamptz NOT NULL,
            execution_deadline timestamptz NOT NULL,
            eligibility_generation bigint NOT NULL CHECK (eligibility_generation >= 1),
            reserved_microusd bigint NOT NULL CHECK (reserved_microusd >= 1),
            settled_microusd bigint,
            settlement_status text NOT NULL CHECK (
                settlement_status IN (
                    'settled', 'pending_reconciliation',
                    'reservation_forfeited', 'settlement_overrun'
                )
            ),
            provider_cost_reference_digest text CHECK (
                provider_cost_reference_digest IS NULL
                OR provider_cost_reference_digest ~ '^[0-9a-f]{64}$'
            ),
            failure_code text CHECK (
                failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9_]{0,63}$'
            ),
            admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            dispatched_at timestamptz,
            terminal_at timestamptz,
            reconciliation_deadline timestamptz NOT NULL,
            tombstone_until timestamptz NOT NULL,
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (
                issuer, caller_id, realm, environment, operation,
                contract_major, idempotency_key_digest
            ),
            FOREIGN KEY (environment, caller_id, realm, partition_id)
                REFERENCES tiamat.spending_partitions (
                    environment, caller_id, realm, partition_id
                ),
            CHECK (settled_microusd IS NULL OR settled_microusd >= 0),
            CHECK (
                (settlement_status = 'pending_reconciliation' AND settled_microusd IS NULL)
                OR (settlement_status <> 'pending_reconciliation' AND settled_microusd IS NOT NULL)
            ),
            CHECK (execution_deadline > admitted_at),
            CHECK (reconciliation_deadline >= execution_deadline),
            CHECK (tombstone_until >= admitted_at)
        )
        """
    )
    op.execute(
        """
        CREATE INDEX execution_reaper_idx
        ON tiamat.execution_records (environment, state, lease_expires_at)
        WHERE state IN ('admitted', 'dispatched')
        """
    )
    op.execute(
        """
        CREATE INDEX execution_reconciliation_idx
        ON tiamat.execution_records (environment, settlement_status, reconciliation_deadline)
        WHERE settlement_status = 'pending_reconciliation'
        """
    )
    op.execute(
        """
        CREATE INDEX execution_exposure_idx
        ON tiamat.execution_records (
            environment, caller_id, realm, partition_id, state, settlement_status
        )
        """
    )
    op.execute(
        """
        CREATE TABLE tiamat.grant_releases (
            release_id text PRIMARY KEY CHECK (length(release_id) BETWEEN 1 AND 128),
            environment text NOT NULL CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
            caller_id text NOT NULL CHECK (length(caller_id) BETWEEN 1 AND 255),
            realm text NOT NULL CHECK (realm ~ '^[a-z][a-z0-9-]{0,63}$'),
            partition_id text NOT NULL CHECK (partition_id ~ '^[a-z][a-z0-9-]{0,127}$'),
            budget_period_id text NOT NULL CHECK (length(budget_period_id) BETWEEN 1 AND 128),
            predecessor_release_id text CHECK (length(predecessor_release_id) BETWEEN 1 AND 128),
            not_before timestamptz NOT NULL,
            not_after timestamptz NOT NULL,
            period_start timestamptz NOT NULL,
            period_end timestamptz NOT NULL,
            allowance_microusd bigint NOT NULL CHECK (allowance_microusd >= 1),
            maximum_concurrency integer NOT NULL CHECK (maximum_concurrency >= 1),
            largest_per_call_microusd bigint NOT NULL CHECK (largest_per_call_microusd >= 1),
            contingency_reserve_microusd bigint NOT NULL
                CHECK (contingency_reserve_microusd >= 1),
            signed_artifact_digest text NOT NULL CHECK (
                signed_artifact_digest ~ '^[0-9a-f]{64}$'
            ),
            activated_at timestamptz,
            revoked_at timestamptz,
            CHECK (not_before < not_after),
            CHECK (period_start < period_end),
            CHECK (
                contingency_reserve_microusd
                >= 2 * maximum_concurrency::bigint * largest_per_call_microusd
            ),
            FOREIGN KEY (environment, caller_id, realm, partition_id)
                REFERENCES tiamat.spending_partitions (
                    environment, caller_id, realm, partition_id
                )
        )
        """
    )
    for table in (
        "restore_gate",
        "jti_replay",
        "spending_partitions",
        "execution_records",
        "grant_releases",
    ):
        op.execute(f"ALTER TABLE tiamat.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE tiamat.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY restore_gate_scope ON tiamat.restore_gate
        USING (environment = current_setting('tiamat.environment', true))
        WITH CHECK (environment = current_setting('tiamat.environment', true))
        """
    )
    op.execute(
        """
        CREATE POLICY jti_replay_scope ON tiamat.jti_replay
        USING (
            subject = current_setting('tiamat.caller_id', true)
            AND realm = current_setting('tiamat.realm', true)
            AND environment = current_setting('tiamat.environment', true)
        )
        WITH CHECK (
            subject = current_setting('tiamat.caller_id', true)
            AND realm = current_setting('tiamat.realm', true)
            AND environment = current_setting('tiamat.environment', true)
        )
        """
    )
    for table in ("execution_records",):
        op.execute(
            f"""
            CREATE POLICY {table}_scope ON tiamat.{table}
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
    for table in ("spending_partitions", "grant_releases"):
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
