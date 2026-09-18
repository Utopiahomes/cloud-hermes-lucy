"""Store exact signed authority and monotonic activation heads.

Revision ID: 0003_signed_release_authority
Revises: 0002_route_settlement_retention
Create Date: 2026-09-17
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003_signed_release_authority"
down_revision: str | None = "0002_route_settlement_retention"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE tiamat.trust_inventories (
            environment text NOT NULL CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
            inventory_generation bigint NOT NULL CHECK (inventory_generation >= 1),
            exact_jws bytea NOT NULL CHECK (octet_length(exact_jws) BETWEEN 1 AND 131072),
            jws_sha256 text NOT NULL CHECK (jws_sha256 ~ '^[0-9a-f]{64}$'),
            previous_inventory_digest text CHECK (
                previous_inventory_digest IS NULL
                OR previous_inventory_digest ~ '^[0-9a-f]{64}$'
            ),
            root_key_id text NOT NULL CHECK (length(root_key_id) BETWEEN 1 AND 128),
            state text NOT NULL CHECK (state IN ('staged', 'active', 'superseded')),
            received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            activated_at timestamptz,
            activation_recovery_generation bigint CHECK (activation_recovery_generation >= 1),
            PRIMARY KEY (environment, inventory_generation),
            UNIQUE (environment, jws_sha256),
            CHECK (
                (state = 'staged' AND activated_at IS NULL
                    AND activation_recovery_generation IS NULL)
                OR (state IN ('active', 'superseded') AND activated_at IS NOT NULL
                    AND activation_recovery_generation IS NOT NULL)
            )
        );
        CREATE UNIQUE INDEX trust_inventory_one_active_idx
        ON tiamat.trust_inventories (environment) WHERE state = 'active'
        """
    )
    op.execute(
        """
        CREATE TABLE tiamat.signed_releases (
            environment text NOT NULL CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
            issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 128),
            caller_id text NOT NULL CHECK (length(caller_id) BETWEEN 1 AND 255),
            realm text NOT NULL CHECK (realm ~ '^[a-z][a-z0-9-]{0,63}$'),
            release_type text NOT NULL CHECK (
                release_type IN (
                    'execution_profile', 'privacy_policy', 'spending_grant', 'revocation'
                )
            ),
            subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 128),
            release_id text NOT NULL CHECK (length(release_id) BETWEEN 1 AND 128),
            sequence bigint NOT NULL CHECK (sequence >= 1),
            predecessor_release_id text CHECK (length(predecessor_release_id) BETWEEN 1 AND 128),
            signing_key_id text NOT NULL CHECK (length(signing_key_id) BETWEEN 1 AND 128),
            not_before timestamptz NOT NULL,
            not_after timestamptz NOT NULL,
            content_digest text NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
            exact_jws bytea NOT NULL CHECK (octet_length(exact_jws) BETWEEN 1 AND 131072),
            jws_sha256 text NOT NULL CHECK (jws_sha256 ~ '^[0-9a-f]{64}$'),
            state text NOT NULL CHECK (state IN ('staged', 'active', 'superseded', 'revoked')),
            received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            activated_at timestamptz,
            revoked_at timestamptz,
            PRIMARY KEY (
                environment, issuer, caller_id, realm, release_type, subject_id, release_id
            ),
            UNIQUE (environment, jws_sha256),
            UNIQUE (environment, issuer, caller_id, realm, release_type, subject_id, sequence),
            CHECK (not_before < not_after),
            CHECK (state <> 'active' OR activated_at IS NOT NULL),
            CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
        )
        """
    )
    op.execute(
        """
        CREATE TABLE tiamat.release_heads (
            environment text NOT NULL CHECK (environment ~ '^[a-z][a-z0-9-]{0,63}$'),
            issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 128),
            caller_id text NOT NULL CHECK (length(caller_id) BETWEEN 1 AND 255),
            realm text NOT NULL CHECK (realm ~ '^[a-z][a-z0-9-]{0,63}$'),
            release_type text NOT NULL CHECK (
                release_type IN (
                    'execution_profile', 'privacy_policy', 'spending_grant', 'revocation'
                )
            ),
            subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 128),
            active_release_id text NOT NULL CHECK (length(active_release_id) BETWEEN 1 AND 128),
            active_jws_sha256 text NOT NULL CHECK (active_jws_sha256 ~ '^[0-9a-f]{64}$'),
            active_sequence bigint NOT NULL CHECK (active_sequence >= 1),
            head_state text NOT NULL DEFAULT 'active' CHECK (head_state IN ('active', 'revoked')),
            revocation_release_id text CHECK (length(revocation_release_id) BETWEEN 1 AND 128),
            recovery_generation bigint NOT NULL CHECK (recovery_generation >= 1),
            eligibility_generation bigint NOT NULL CHECK (eligibility_generation >= 1),
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (environment, issuer, caller_id, realm, release_type, subject_id),
            CHECK ((head_state = 'revoked') = (revocation_release_id IS NOT NULL))
        )
        """
    )
    for table in ("trust_inventories", "signed_releases", "release_heads"):
        op.execute(f"ALTER TABLE tiamat.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE tiamat.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY trust_inventories_scope ON tiamat.trust_inventories
        USING (environment = current_setting('tiamat.environment', true))
        WITH CHECK (environment = current_setting('tiamat.environment', true))
        """
    )
    for table in ("signed_releases", "release_heads"):
        op.execute(
            f"""
            CREATE POLICY {table}_scope ON tiamat.{table}
            USING (
                environment = current_setting('tiamat.environment', true)
                AND caller_id = current_setting('tiamat.caller_id', true)
                AND realm = current_setting('tiamat.realm', true)
            )
            WITH CHECK (
                environment = current_setting('tiamat.environment', true)
                AND caller_id = current_setting('tiamat.caller_id', true)
                AND realm = current_setting('tiamat.realm', true)
            )
            """
        )


def downgrade() -> None:
    raise RuntimeError("Tiamat authority downgrades are intentionally unsupported")
